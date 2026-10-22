import subprocess
from typing import Iterable, List, Set, Tuple


def get_existing_bad_pfns() -> Set[int]:
    """Read currently configured PFNs in Windows BCD {badmemory} badmemorylist."""
    res = subprocess.run(
        ["bcdedit", "/enum", "{badmemory}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
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
    Merge new PFNs into Windows BCD {badmemory} badmemorylist and enforce badmemoryaccess=no.
    Returns (all_isolated_pfns, bcdedit_output).
    """
    pfns = get_existing_bad_pfns()
    pfns.update(new_pfns)
    if include_row_twins:
        pfns = infer_dram_row_twins(pfns)

    if not pfns:
        return pfns, "No PFNs to write."

    hex_list: List[str] = [f"0x{x:x}" for x in sorted(pfns)]
    cmd = ["bcdedit", "/set", "{badmemory}", "badmemorylist"] + hex_list
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    subprocess.run(["bcdedit", "/set", "{badmemory}", "badmemoryaccess", "no"], capture_output=True)
    subprocess.run(["bcdedit", "/set", "{globalsettings}", "badmemoryaccess", "no"], capture_output=True)
    return pfns, (res.stdout or res.stderr).strip()
