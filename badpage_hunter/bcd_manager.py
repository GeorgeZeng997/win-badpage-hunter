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
    """Read currently configured PFNs in Windows BCD {badmemory} (or local PFN store on Linux/macOS)."""
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

    hex_list: List[str] = [f"0x{x:x}" for x in sorted(pfns)]
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
