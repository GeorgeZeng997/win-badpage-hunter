import ctypes
import json
import os
import subprocess
import sys
from typing import Iterable, List, Set, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if IS_WINDOWS else 0


def _posix_store_path() -> str:
    base = os.path.expanduser("~/.config/win-badpage-hunter")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "isolated_pfns.json")


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

    res = subprocess.run(
        ["bcdedit", "/enum", "{badmemory}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=CREATE_NO_WINDOW,
    )
    pfns: Set[int] = set()
    in_list = False
    for line in res.stdout.splitlines():
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
                            subprocess.run(
                                ["bcdedit", "/set", "{badmemory}", "badmemoryaccess", "no"],
                                capture_output=True,
                                creationflags=CREATE_NO_WINDOW,
                            )
                            return pfns, f"Written {len(sorted_pfns)} PFNs via native bcd.dll (NTSTATUS=0x00000000)"
                    finally:
                        bcd.BcdCloseObject(hObj)
            finally:
                bcd.BcdCloseStore(hStore)
    except Exception:
        pass

    hex_list: List[str] = [f"0x{x:x}" for x in sorted_pfns]
    cmd = ["bcdedit", "/set", "{badmemory}", "badmemorylist"] + hex_list
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=CREATE_NO_WINDOW,
    )
    subprocess.run(
        ["bcdedit", "/set", "{badmemory}", "badmemoryaccess", "no"],
        capture_output=True,
        creationflags=CREATE_NO_WINDOW,
    )
    subprocess.run(
        ["bcdedit", "/set", "{globalsettings}", "badmemoryaccess", "no"],
        capture_output=True,
        creationflags=CREATE_NO_WINDOW,
    )
    return pfns, (res.stdout or res.stderr).strip()


def remove_bcd_badmemory_pfns(pfns_to_remove: Iterable[int]) -> Tuple[Set[int], str]:
    """
    Remove specific PFNs from Windows BCD {badmemory} badmemorylist.
    Returns (remaining_pfns, output).
    """
    existing = get_existing_bad_pfns()
    remaining = existing - set(pfns_to_remove)
    if not remaining:
        ok, msg = clear_bcd_badmemory()
        return set(), msg

    if not IS_WINDOWS:
        store = _posix_store_path()
        with open(store, "w", encoding="utf-8") as f:
            json.dump({"pfns": [f"0x{p:x}" for p in sorted(remaining)]}, f, indent=2)
        return remaining, f"Updated PFN store ({len(remaining)} remaining)."

    hex_list: List[str] = [f"0x{x:x}" for x in sorted(remaining)]
    cmd = ["bcdedit", "/set", "{badmemory}", "badmemorylist"] + hex_list
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=CREATE_NO_WINDOW,
    )
    return remaining, (res.stdout or res.stderr).strip()


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

    res = subprocess.run(
        ["bcdedit", "/deletevalue", "{badmemory}", "badmemorylist"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=CREATE_NO_WINDOW,
    )
    out = (res.stdout or res.stderr).strip()
    return res.returncode == 0, out
