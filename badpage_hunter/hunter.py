import ctypes
from ctypes import wintypes
import datetime
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import numpy as np

from .bcd_manager import get_existing_bad_pfns, update_bcd_badmemory
from .pfn_resolver import enable_privileges, kernel32, resolve_vas_to_pfns

kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualLock.restype = wintypes.BOOL
kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def get_memory_status() -> Tuple[float, float, int]:
    """Return (total_gb, avail_gb, memory_load_percent)."""
    ms = MEMORYSTATUSEX(dwLength=ctypes.sizeof(MEMORYSTATUSEX))
    kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    return (
        ms.ullTotalPhys / (1024 ** 3),
        ms.ullAvailPhys / (1024 ** 3),
        int(ms.dwMemoryLoad),
    )


def recommend_hunter_params() -> Dict[str, Any]:
    """Calculate safe, adaptive FIFO sliding-window parameters for the current system's RAM."""
    total_gb, avail_gb, _ = get_memory_status()
    if total_gb >= 48.0:
        min_avail = max(12.0, round(total_gb * 0.25, 1))
        batch_gb = 4.0
        window_batches = 3
        block_mb = 256
    elif total_gb >= 24.0:
        min_avail = max(6.0, round(total_gb * 0.25, 1))
        batch_gb = 2.0
        window_batches = 3
        block_mb = 128
    elif total_gb >= 12.0:
        min_avail = 4.0
        batch_gb = 1.0
        window_batches = 3
        block_mb = 64
    else:
        min_avail = max(2.0, round(avail_gb * 0.4, 1))
        batch_gb = 0.5
        window_batches = 2
        block_mb = 32

    # Ensure min_avail leaves room for at least 1 batch if currently low on free RAM
    if avail_gb - min_avail < batch_gb:
        min_avail = max(2.0, round(avail_gb * 0.5, 1))
        batch_gb = max(0.5, round((avail_gb - min_avail) / 2.0, 1))

    return {
        "window_batches": window_batches,
        "batch_gb": batch_gb,
        "block_mb": block_mb,
        "min_avail_gb": min_avail,
        "soak_seconds": 10.0,
    }


class BadPageHunter:
    """
    Low-memory FIFO sliding-window DRAM charge-retention bit-flip hunter.
    Cycles through free physical pages without starving the OS, pins any page exhibiting
    bit-flips via VirtualLock, translates its VA to a hardware PFN via Superfetch, and
    records the faulty PFN (+ DRAM row-twin siblings) into Windows BCD {badmemory}.
    """

    def __init__(
        self,
        window_batches: int = 3,
        batch_gb: float = 6.0,
        block_mb: int = 256,
        min_avail_gb: float = 16.0,
        soak_seconds: float = 15.0,
        include_row_twins: bool = True,
        log_file: Optional[str] = "bad_page_hunter.log",
        on_log: Optional[Callable[[str], None]] = None,
        on_stats: Optional[Callable[[Dict[str, Any]], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ):
        self.window_batches = window_batches
        self.batch_gb = float(batch_gb)
        self.block_mb = int(block_mb)
        self.min_avail_gb = float(min_avail_gb)
        self.soak_seconds = float(soak_seconds)
        self.include_row_twins = include_row_twins
        self.log_file = log_file
        self.on_log = on_log
        self.on_stats = on_stats
        self._stop_event = stop_event or threading.Event()

        self.block_sz = self.block_mb * 1024 * 1024
        self.qwords_per_block = self.block_sz // 8
        self.blocks_per_batch = max(1, int((self.batch_gb * 1024) // self.block_mb))

        self.patterns = [
            np.uint64(0xFFFFFFFFFFFFFFFF),
            np.uint64(0xFFFFDF87873AF040),
            np.uint64(0xFFFF808FD6286258),
            np.uint64(0xFFFF9889F6F1C038),
        ]
        enable_privileges()
        self.bad_pfns: Set[int] = get_existing_bad_pfns()
        self.pinned_blocks: List[int] = []
        self.total_flips_caught: int = 0
        self.newly_isolated_pfns: Set[int] = set()

    def stop(self) -> None:
        """Signal the hunter loop to stop immediately and clean up allocated test buffers."""
        self._stop_event.set()

    def _emit_stats(self, cycle: int, active_batches: int, active_gb: float, phase: str, soak_progress: float = 0.0) -> None:
        if self.on_stats:
            try:
                self.on_stats({
                    "cycle": cycle,
                    "active_batches": active_batches,
                    "active_gb": active_gb,
                    "total_flips": self.total_flips_caught,
                    "bad_pfns_count": len(self.bad_pfns),
                    "newly_isolated_count": len(self.newly_isolated_pfns),
                    "pinned_count": len(self.pinned_blocks),
                    "phase": phase,
                    "soak_progress": soak_progress,
                })
            except Exception:
                pass

    def log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        if sys.stdout is not None:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
        if self.on_log:
            try:
                self.on_log(line)
            except Exception:
                pass

    def inspect_and_free_block(self, base_va: int, expected_val: np.uint64, label: str) -> int:
        arr = np.ctypeslib.as_array((ctypes.c_uint64 * self.qwords_per_block).from_address(base_va))
        mismatch_indices = np.flatnonzero(arr != expected_val)
        flips = len(mismatch_indices)
        if flips == 0:
            kernel32.VirtualFree(base_va, 0, MEM_RELEASE)
            return 0

        self.total_flips_caught += flips
        bad_page_vas: Set[int] = set()
        flip_details = []
        for m_idx in mismatch_indices[:64]:
            actual_val = int(arr[m_idx])
            diff = actual_val ^ int(expected_val)
            bad_va = base_va + int(m_idx) * 8
            page_va = bad_va & ~0xFFF
            kernel32.VirtualLock(page_va, 4096)
            bad_page_vas.add(page_va)
            flip_details.append((int(m_idx) * 8, actual_val, diff, bad_va, page_va))

        pfn_map = resolve_vas_to_pfns(bad_page_vas)
        newly_caught: List[int] = []
        for offset, actual_val, diff, bad_va, page_va in flip_details:
            pfn = pfn_map.get(page_va)
            pfn_str = f"0x{pfn:X} (PhysAddr 0x{pfn << 12:012X})" if pfn else "Unknown"
            self.log(f"  [!] BIT FLIP CAUGHT in {label}, offset 0x{offset:X} (page_offset=0x{offset & 0xFFF:03X}):")
            self.log(f"      Expected: 0x{int(expected_val):016X}")
            self.log(f"      Actual  : 0x{actual_val:016X} (XOR=0x{diff:016X})")
            self.log(f"      VA      : 0x{bad_va:016X} -> Physical PFN: {pfn_str}")
            if pfn:
                newly_caught.append(pfn)
                self.newly_isolated_pfns.add(pfn)

        if newly_caught:
            updated_set, bcd_msg = update_bcd_badmemory(newly_caught, include_row_twins=self.include_row_twins)
            self.bad_pfns = updated_set
            self.log(
                f"  [BCD UPDATED] Isolated {[hex(x) for x in newly_caught]} "
                f"(total isolated PFNs: {len(self.bad_pfns)}) | {bcd_msg}"
            )

        min_bad_page = min(bad_page_vas)
        max_bad_page = max(bad_page_vas) + 4096
        if min_bad_page > base_va:
            kernel32.VirtualFree(base_va, min_bad_page - base_va, MEM_DECOMMIT)
        if max_bad_page < base_va + self.block_sz:
            kernel32.VirtualFree(max_bad_page, (base_va + self.block_sz) - max_bad_page, MEM_DECOMMIT)
        self.pinned_blocks.append(base_va)
        self.log(f"  [PINNED] Locked bad 4KB page(s) in RAM and decommitted healthy pages of {label}.")
        return flips

    def run(self, max_cycles: Optional[int] = None) -> Set[int]:
        fifo_queue: List[Tuple[int, List[Tuple[int, np.uint64]]]] = []
        cycle = 0
        self.log(
            f"=== Started BadPageHunter (Window={self.window_batches}x{self.batch_gb}GB, "
            f"MinAvailFloor={self.min_avail_gb}GB, Soak={self.soak_seconds}s, "
            f"ExistingBadPFNs={len(self.bad_pfns)}) ==="
        )
        try:
            while not self._stop_event.is_set() and (max_cycles is None or cycle < max_cycles):
                cycle += 1
                _, avail_gb, load = get_memory_status()

                while not self._stop_event.is_set() and (
                    len(fifo_queue) >= self.window_batches
                    or (len(fifo_queue) > 0 and avail_gb - self.batch_gb < self.min_avail_gb)
                ):
                    old_cycle, old_blocks = fifo_queue.pop(0)
                    active_blocks = sum(len(b) for _, b in fifo_queue)
                    self._emit_stats(cycle, len(fifo_queue), active_blocks * self.block_mb / 1024.0, f"Verifying Batch c{old_cycle}")
                    flips = 0
                    for blk_i, (base_va, pat) in enumerate(old_blocks):
                        flips += self.inspect_and_free_block(base_va, pat, f"c{old_cycle}.{blk_i}")
                    _, avail_gb, load = get_memory_status()
                    self.log(
                        f"[Cycle {cycle}] Verified & released Batch c{old_cycle}: "
                        f"flips={flips}, TotalBadPFNs={len(self.bad_pfns)}, Pinned={len(self.pinned_blocks)} | "
                        f"AvailPhys={avail_gb:.2f}GB (Load={load}%)"
                    )

                if self._stop_event.is_set():
                    break

                pat = self.patterns[cycle % len(self.patterns)]
                new_blocks: List[Tuple[int, np.uint64]] = []
                for blk_idx in range(self.blocks_per_batch):
                    if self._stop_event.is_set():
                        break
                    _, avail_now, _ = get_memory_status()
                    if avail_now < self.min_avail_gb:
                        break
                    base_va = kernel32.VirtualAlloc(None, self.block_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                    if not base_va:
                        break
                    arr = np.ctypeslib.as_array((ctypes.c_uint64 * self.qwords_per_block).from_address(base_va))
                    arr.fill(np.uint64(~pat))
                    arr.fill(pat)
                    new_blocks.append((base_va, pat))
                    active_blocks = sum(len(b) for _, b in fifo_queue) + len(new_blocks)
                    self._emit_stats(
                        cycle,
                        len(fifo_queue) + 1,
                        active_blocks * self.block_mb / 1024.0,
                        f"Allocating Batch c{cycle} ({blk_idx + 1}/{self.blocks_per_batch})",
                    )
                    time.sleep(0.03)

                if new_blocks:
                    fifo_queue.append((cycle, new_blocks))
                    _, avail_after, load_after = get_memory_status()
                    self.log(
                        f"[Cycle {cycle}] Queued Batch c{cycle} "
                        f"({len(new_blocks) * self.block_mb / 1024:.2f}GB, pat=0x{int(pat):016X}). "
                        f"ActiveWindow={len(fifo_queue)} batches | AvailPhys={avail_after:.2f}GB (Load={load_after}%)"
                    )

                active_blocks = sum(len(b) for _, b in fifo_queue)
                active_gb = active_blocks * self.block_mb / 1024.0
                soak_start = time.monotonic()
                while not self._stop_event.is_set():
                    elapsed = time.monotonic() - soak_start
                    if elapsed >= self.soak_seconds:
                        break
                    pct = min(100.0, (elapsed / max(0.1, self.soak_seconds)) * 100.0)
                    self._emit_stats(
                        cycle,
                        len(fifo_queue),
                        active_gb,
                        f"Charge-Retention Soak ({elapsed:.1f}s / {self.soak_seconds:.1f}s)",
                        soak_progress=pct,
                    )
                    time.sleep(0.1)
        except KeyboardInterrupt:
            self.log("Interrupted by user. Cleaning up healthy test buffers...")
        finally:
            if self._stop_event.is_set():
                self.log("Stopping BadPageHunter and releasing healthy test buffers...")
            for _, blocks in fifo_queue:
                for base_va, _ in blocks:
                    kernel32.VirtualFree(base_va, 0, MEM_RELEASE)
            self._emit_stats(cycle, 0, 0.0, "Stopped", soak_progress=0.0)
            self.log("=== BadPageHunter stopped. All healthy test buffers released. ===")
        return self.bad_pfns

