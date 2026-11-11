import ctypes
import json
import os
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if IS_WINDOWS else 0
BCDEDIT_TIMEOUT_SEC = 15.0


def _posix_store_path() -> str:
    base = os.path.expanduser("~/.config/win-badpage-hunter")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "isolated_pfns.json")


def _run_bcdedit(args: List[str], timeout: float = BCDEDIT_TIMEOUT_SEC) -> Tuple[int, str]:
    try:
        res = subprocess.run(
            ["bcdedit"] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=CREATE_NO_WINDOW,
            timeout=timeout,
        )
        out = (res.stdout or res.stderr or "").strip()
        return res.returncode, out
    except subprocess.TimeoutExpired:
        return 1, f"bcdedit timed out after {timeout:.0f}s"
    except Exception as exc:
        return 1, str(exc)


def _write_bcd_dll_pfns(sorted_pfns: List[int]) -> bool:
    """Write badmemorylist directly via native bcd.dll (avoids Windows 32 KB CLI length cap)."""
    if not IS_WINDOWS or not sorted_pfns:
        return False
    try:
        import struct
        from ctypes import wintypes

        bcd = ctypes.WinDLL("bcd.dll")
        hStore = wintypes.HANDLE()
        if (bcd.BcdOpenSystemStore(ctypes.byref(hStore)) & 0xFFFFFFFF) == 0:
            try:
                guid_badmem = ctypes.c_void_p.in_dll(bcd, "GUID_BAD_MEMORY_GROUP")
                hObj = wintypes.HANDLE()
                if (bcd.BcdOpenObject(hStore, ctypes.byref(guid_badmem), ctypes.byref(hObj)) & 0xFFFFFFFF) == 0:
                    try:
                        blob = struct.pack(f"<{len(sorted_pfns)}Q", *sorted_pfns)
                        st = bcd.BcdSetElementData(hObj, 0x1700000A, blob, len(blob)) & 0xFFFFFFFF
                        if st == 0:
                            _run_bcdedit(["/set", "{badmemory}", "badmemoryaccess", "no"])
                            return True
                    finally:
                        bcd.BcdCloseObject(hObj)
            finally:
                bcd.BcdCloseStore(hStore)
    except Exception:
        pass
    return False


def is_admin() -> bool:
    """Return True if the current process is running with Administrator / root privileges."""
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def get_existing_bad_pfns() -> Set[int]:
    """Read currently configured PFNs in Windows BCD {badmemory} (via native bcd.dll or fallback bcdedit)."""
    if not IS_WINDOWS:
        store = _posix_store_path()
        if os.path.exists(store):
            try:
                with open(store, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return {int(str(x), 0) for x in data.get("pfns", [])}
            except Exception:
                return set()
        return set()

    try:
        import struct
        from ctypes import wintypes

        bcd = ctypes.WinDLL("bcd.dll")
        hStore = wintypes.HANDLE()
        if (bcd.BcdOpenSystemStore(ctypes.byref(hStore)) & 0xFFFFFFFF) == 0:
            try:
                guid_badmem = ctypes.c_void_p.in_dll(bcd, "GUID_BAD_MEMORY_GROUP")
                hObj = wintypes.HANDLE()
                if (bcd.BcdOpenObject(hStore, ctypes.byref(guid_badmem), ctypes.byref(hObj)) & 0xFFFFFFFF) == 0:
                    try:
                        sz = wintypes.ULONG(0)
                        bcd.BcdGetElementData(hObj, 0x1700000A, None, ctypes.byref(sz))
                        if sz.value > 0 and sz.value % 8 == 0:
                            buf = ctypes.create_string_buffer(sz.value)
                            st = bcd.BcdGetElementData(hObj, 0x1700000A, buf, ctypes.byref(sz)) & 0xFFFFFFFF
                            if st == 0:
                                return set(struct.unpack(f"<{sz.value // 8}Q", buf.raw))
                    finally:
                        bcd.BcdCloseObject(hObj)
            finally:
                bcd.BcdCloseStore(hStore)
    except Exception:
        pass

    _rc, stdout = _run_bcdedit(["/enum", "{badmemory}"])
    pfns: Set[int] = set()
    in_list = False
    for line in stdout.splitlines():
        low = line.lower()
        if "badmemorylist" in low:
            in_list = True
            parts = line.split()[1:]
            for p in parts:
                try:
                    pfns.add(int(p, 0))
                except ValueError:
                    pass
        elif in_list:
            if line.startswith(" ") or line.startswith("\t"):
                for p in line.split():
                    try:
                        pfns.add(int(p, 0))
                    except ValueError:
                        pass
            else:
                in_list = False
    return pfns


def infer_dram_row_twins(pfns: Iterable[int]) -> Set[int]:
    """
    In dual-channel interleaved DDR4/DDR5 architectures, every 8 consecutive 4KB pages
    (Group = PFN >> 3, 32KB) map to the same DRAM row/bank activation cluster where
    page offsets +3 and +5 (hex suffixes 3/5 or B/D) share coupled bitlines.
    """
    expanded: Set[int] = set(pfns)
    for pfn in list(pfns):
        group = pfn >> 3
        expanded.add((group << 3) | 3)
        expanded.add((group << 3) | 5)
    return expanded


def synthesize_imc_bank_pfns(pfns: Iterable[int], offsets: Tuple[int, ...] = (0, 3, 4, 5, 7)) -> Set[int]:
    """
    Given a seed set of faulty PFNs on an Intel Alder Lake / Raptor Lake dual-channel IMC,
    synthesize the full algebraic family of 8-page groups sharing the same defective DRAM Bank
    and Sub-Array column across active rank prefixes (Group = PFN >> 3):
      b0 = b1 ^ (((b2 & 1) ^ ((b2 >> 3) & 1)) << 3) ^ ((((b2 >> 1) & 1) ^ ((b2 >> 2) & 1) ^ r) << 2)
      where b1 in {0, 1, 2, 3, 8, 9, 10, 11} ((b1 & 4) == 0).
    """
    expanded: Set[int] = set(pfns)
    prefixes = {(p >> 15) for p in pfns}
    max_b2 = max((((p >> 3) >> 8) & 0xF for p in pfns), default=8)
    for pref in prefixes:
        r = (pref >> 7) & 1
        base_grp = pref << 12
        for b2 in range(0, max_b2 + 1):
            bit3 = (b2 & 1) ^ ((b2 >> 3) & 1)
            bit2 = ((b2 >> 1) & 1) ^ ((b2 >> 2) & 1) ^ r
            mask = (bit3 << 3) | (bit2 << 2)
            for b1 in (0, 1, 2, 3, 8, 9, 10, 11):
                b0 = b1 ^ mask
                grp = base_grp | (b2 << 8) | (b1 << 4) | b0
                for rem in offsets:
                    expanded.add((grp << 3) | rem)
    return expanded


def analyze_pfn_clusters(pfns: Iterable[int], total_ram_gb: float = 0.0) -> Dict[str, Any]:
    """
    Analyze physical DRAM clustering, 1 GB rank-band locality, +3/+5 row-twin coverage,
    and compute an overall DRAM containment health score (0..100).
    """
    sorted_pfns = sorted(set(pfns))
    count = len(sorted_pfns)
    if count == 0:
        return {
            "isolated_pages": 0,
            "isolated_kb": 0,
            "contiguous_runs": 0,
            "row_groups_affected": 0,
            "rank_bands_gb": {},
            "missing_row_twins": [],
            "health_score": 100,
            "severity": "CLEAN",
        }

    pfn_set = set(sorted_pfns)
    runs = 1
    for prev, cur in zip(sorted_pfns, sorted_pfns[1:]):
        if cur != prev + 1:
            runs += 1

    row_groups = {p >> 3 for p in sorted_pfns}
    rank_bands: Dict[str, int] = {}
    missing_twins: List[str] = []
    for p in sorted_pfns:
        gb_band = p >> 18  # 1 GiB = 262,144 x 4KB pages (2^18)
        band_key = f"{gb_band}GB..{gb_band + 1}GB"
        rank_bands[band_key] = rank_bands.get(band_key, 0) + 1
        if (p & 7) in (3, 5):
            twin = p ^ 6
            if twin not in pfn_set:
                missing_twins.append(f"0x{twin:x}")

    bands_count = len(rank_bands)
    # Health score: localized clusters (<=2 rank bands, <=256 pages) remain highly rescuable via BCD excision
    penalty = min(40, len(row_groups) // 2) + max(0, (bands_count - 2) * 10) + min(20, len(missing_twins) * 2)
    if count > 2048:
        penalty += 25
    score = max(10, 100 - penalty)

    if count <= 256 and bands_count <= 2:
        severity = "CONTAINED_CLUSTER"
    elif count <= 2048 and bands_count <= 6:
        severity = "MULTI_RANK_DECAY"
    else:
        severity = "SEVERE_SCATTER"

    pct_ram = round((count * 4096) / (total_ram_gb * (1024 ** 3)) * 100.0, 6) if total_ram_gb > 0 else None
    return {
        "isolated_pages": count,
        "isolated_kb": count * 4,
        "isolated_ram_pct": pct_ram,
        "contiguous_runs": runs,
        "row_groups_affected": len(row_groups),
        "rank_bands_gb": rank_bands,
        "missing_row_twins": sorted(set(missing_twins)),
        "health_score": score,
        "severity": severity,
    }


def diff_status_snapshots(old_snap: Dict[str, Any], new_snap: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two status snapshots to identify newly isolated PFNs, newly excised frames, and cluster growth."""
    old_pfns = {int(str(x), 0) for x in old_snap.get("isolated_pfns_hex", [])}
    new_pfns = {int(str(x), 0) for x in new_snap.get("isolated_pfns_hex", [])}

    added = sorted(new_pfns - old_pfns)
    removed = sorted(old_pfns - new_pfns)

    old_excised = {int(str(x), 0) for x in old_snap.get("excised_pfns_hex", [])}
    new_excised = {int(str(x), 0) for x in new_snap.get("excised_pfns_hex", [])}
    newly_excised = sorted(new_excised - old_excised)

    old_bands = set((old_snap.get("cluster_analysis") or {}).get("rank_bands_gb", {}).keys())
    new_bands = set((new_snap.get("cluster_analysis") or {}).get("rank_bands_gb", {}).keys())
    new_rank_bands = sorted(new_bands - old_bands)

    old_score = int((old_snap.get("cluster_analysis") or {}).get("health_score", 100))
    new_score = int((new_snap.get("cluster_analysis") or {}).get("health_score", 100))

    return {
        "old_isolated_count": len(old_pfns),
        "new_isolated_count": len(new_pfns),
        "added_pfns_hex": [f"0x{p:x}" for p in added],
        "removed_pfns_hex": [f"0x{p:x}" for p in removed],
        "newly_excised_pfns_hex": [f"0x{p:x}" for p in newly_excised],
        "new_rank_bands": new_rank_bands,
        "old_ranges_count": len(old_snap.get("physical_ranges", [])),
        "new_ranges_count": len(new_snap.get("physical_ranges", [])),
        "health_score_delta": new_score - old_score,
        "old_health_score": old_score,
        "new_health_score": new_score,
        "status": "STABLE" if not added else ("EXPANDED_NEW_BAND" if new_rank_bands else "NEW_PAGES_IN_EXISTING_BAND"),
    }


def update_bcd_badmemory(new_pfns: Iterable[int], include_row_twins: bool = True) -> Tuple[Set[int], str]:
    """
    Merge new PFNs into Windows BCD {badmemory} badmemorylist (or Linux soft_offline_page + store).
    Returns (all_isolated_pfns, status_message).
    """
    pfns = get_existing_bad_pfns()
    pfns.update(new_pfns)
    if include_row_twins:
        pfns = infer_dram_row_twins(pfns)

    if not pfns:
        return pfns, "No PFNs to write."

    if not IS_WINDOWS:
        store = _posix_store_path()
        sorted_pfns = sorted(pfns)
        with open(store, "w", encoding="utf-8") as f:
            json.dump({"pfns": [f"0x{p:x}" for p in sorted_pfns]}, f, indent=2)
        offlined = 0
        if IS_LINUX and os.path.exists("/sys/devices/system/memory/soft_offline_page"):
            for p in new_pfns:
                try:
                    with open("/sys/devices/system/memory/soft_offline_page", "w", encoding="utf-8") as sf:
                        sf.write(f"0x{p << 12:x}\n")
                    offlined += 1
                except Exception:
                    pass
        grub_arg = " ".join(f"memmap=4K\\$0x{p << 12:x}" for p in sorted_pfns[:8])
        return pfns, f"Saved {len(pfns)} PFNs (soft-offlined={offlined}). GRUB: {grub_arg}"

    sorted_pfns = sorted(pfns)
    if _write_bcd_dll_pfns(sorted_pfns):
        return pfns, f"Written {len(sorted_pfns)} PFNs via native bcd.dll (NTSTATUS=0x00000000)"

    hex_list: List[str] = [f"0x{x:x}" for x in sorted_pfns]
    _rc, out = _run_bcdedit(["/set", "{badmemory}", "badmemorylist"] + hex_list)
    _run_bcdedit(["/set", "{badmemory}", "badmemoryaccess", "no"])
    _run_bcdedit(["/set", "{globalsettings}", "badmemoryaccess", "no"])
    return pfns, out


def remove_bcd_badmemory_pfns(pfns_to_remove: Iterable[int]) -> Tuple[Set[int], str]:
    """
    Remove specific PFNs from Windows BCD {badmemory} badmemorylist.
    Returns (remaining_pfns, output).
    """
    existing = get_existing_bad_pfns()
    remaining = existing - set(pfns_to_remove)
    if not remaining:
        _ok, msg = clear_bcd_badmemory()
        return set(), msg

    sorted_rem = sorted(remaining)
    if not IS_WINDOWS:
        store = _posix_store_path()
        with open(store, "w", encoding="utf-8") as f:
            json.dump({"pfns": [f"0x{p:x}" for p in sorted_rem]}, f, indent=2)
        return remaining, f"Updated PFN store ({len(remaining)} remaining)."

    if _write_bcd_dll_pfns(sorted_rem):
        return remaining, f"Updated {len(sorted_rem)} PFNs via native bcd.dll (NTSTATUS=0x00000000)"

    hex_list: List[str] = [f"0x{x:x}" for x in sorted_rem]
    _rc, out = _run_bcdedit(["/set", "{badmemory}", "badmemorylist"] + hex_list)
    return remaining, out


def clear_bcd_badmemory() -> Tuple[bool, str]:
    """
    Delete the badmemorylist value from Windows BCD {badmemory}.
    Returns (success, output).
    """
    if not IS_WINDOWS:
        store = _posix_store_path()
        if os.path.exists(store):
            os.remove(store)
        return True, "Cleared local isolated PFN store."

    rc, out = _run_bcdedit(["/deletevalue", "{badmemory}", "badmemorylist"])
    return rc == 0, out
