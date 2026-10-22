import ctypes
from ctypes import wintypes
import struct
from typing import Dict, Iterable, List, Set, Tuple
import winreg

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32")

SE_LOCK_MEMORY_PRIVILEGE = 4
SE_PROFILE_SINGLE_PROCESS_PRIVILEGE = 13
SE_DEBUG_PRIVILEGE = 20

SYSTEM_SUPERFETCH_INFORMATION = 79
SUPERFETCH_VERSION = 45
SUPERFETCH_MAGIC = 0x6B756843  # 'Chuk'
SUPERFETCH_PFN_QUERY = 6


class SUPERFETCH_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("Magic", wintypes.ULONG),
        ("InfoClass", wintypes.ULONG),
        ("Pad0", wintypes.ULONG),
        ("Data", ctypes.c_void_p),
        ("Length", wintypes.ULONG),
        ("Pad1", wintypes.ULONG),
    ]


def enable_privileges() -> Dict[int, int]:
    """Enable SeProfileSingleProcessPrivilege, SeLockMemoryPrivilege, and SeDebugPrivilege."""
    results: Dict[int, int] = {}
    for priv in (SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, SE_LOCK_MEMORY_PRIVILEGE, SE_DEBUG_PRIVILEGE):
        old_priv = wintypes.BOOLEAN()
        status = ntdll.RtlAdjustPrivilege(priv, True, False, ctypes.byref(old_priv)) & 0xFFFFFFFF
        results[priv] = status
    return results


def get_kernel_physical_memory_ranges() -> List[Tuple[int, int, float]]:
    """
    Read the active kernel physical memory map from
    HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated.
    Returns a list of (start_pfn, end_pfn, size_mb).
    """
    key_path = r"HARDWARE\RESOURCEMAP\System Resources\Physical Memory"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        val, _ = winreg.QueryValueEx(key, ".Translated")

    cnt = struct.unpack_from("<I", val, 16)[0]
    off = 20
    ranges: List[Tuple[int, int, float]] = []
    for _ in range(cnt):
        rtype, share, flags = struct.unpack_from("<BBH", val, off)
        start_phys, length_raw = struct.unpack_from("<QI", val, off + 4)
        if flags & 0x0200:
            byte_len = length_raw << 8
        elif flags & 0x0400:
            byte_len = length_raw << 16
        elif flags & 0x0800:
            byte_len = length_raw << 32
        else:
            byte_len = length_raw
        start_pfn = start_phys >> 12
        npages = byte_len >> 12
        if npages > 0:
            ranges.append((start_pfn, start_pfn + npages, byte_len / (1024 * 1024)))
        off += 20
    return ranges


def resolve_vas_to_pfns(target_page_vas: Iterable[int]) -> Dict[int, int]:
    """
    Translate a set of 4KB page-aligned user-mode virtual addresses (allocated via VirtualAlloc
    and locked in working set) to their hardware Page Frame Numbers (PFNs) using
    NtQuerySystemInformation(SystemSuperfetchInformation, SuperfetchPfnQuery).
    """
    enable_privileges()
    remaining: Set[int] = {va & ~0xFFF for va in target_page_vas}
    found: Dict[int, int] = {}
    if not remaining:
        return found

    chunk = 65536
    header_sz = 0xC0  # Windows 10/11 (including Win11 24H2 Build 26100) PF_PFN_PRIO_REQUEST header size
    buf_sz = header_sz + 24 * chunk
    buf = ctypes.create_string_buffer(buf_sz)
    pfn_arr = ctypes.cast(ctypes.byref(buf, header_sz), ctypes.POINTER(ctypes.c_uint64 * (3 * chunk))).contents
    ret_len = wintypes.ULONG(0)

    ranges = get_kernel_physical_memory_ranges()
    for start_pfn, end_pfn, _ in ranges:
        cur = start_pfn
        while cur < end_pfn and remaining:
            n = min(chunk, end_pfn - cur)
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = 1  # Version = 1
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[1] = 1  # RequestFlags = 1
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint64))[1] = n  # PfnCount = n
            for i in range(n):
                pfn_arr[i * 3 + 1] = cur + i

            sf = SUPERFETCH_INFORMATION(
                Version=SUPERFETCH_VERSION,
                Magic=SUPERFETCH_MAGIC,
                InfoClass=SUPERFETCH_PFN_QUERY,
                Data=ctypes.cast(buf, ctypes.c_void_p),
                Length=header_sz + 24 * n,
            )
            st = ntdll.NtQuerySystemInformation(
                SYSTEM_SUPERFETCH_INFORMATION,
                ctypes.byref(sf),
                ctypes.sizeof(sf),
                ctypes.byref(ret_len),
            ) & 0xFFFFFFFF
            if st == 0:
                for i in range(n):
                    va_page = pfn_arr[i * 3 + 2] & ~0xFFF
                    if va_page in remaining:
                        pfn = cur + i
                        found[va_page] = pfn
                        remaining.remove(va_page)
                        if not remaining:
                            break
            cur += n
    return found


def query_pfn_database_status(pfns: List[int]) -> List[Tuple[int, int, int, int]]:
    """
    Query the kernel _MMPFN identity status individually for each PFN in `pfns`.
    Returns a list of (pfn, ntstatus, u1, va) tuples.
    If a PFN has been excised by the Windows Boot Loader ({badmemory}) at boot,
    the kernel rejects it with STATUS_INVALID_PARAMETER_2 (0xC00000F0) and leaves u1=0.
    """
    enable_privileges()
    if not pfns:
        return []
    header_sz = 0xC0
    buf_sz = header_sz + 24
    buf = ctypes.create_string_buffer(buf_sz)
    pfn_arr = ctypes.cast(ctypes.byref(buf, header_sz), ctypes.POINTER(ctypes.c_uint64 * 3)).contents
    ret_len = wintypes.ULONG(0)

    records: List[Tuple[int, int, int, int]] = []
    for p in pfns:
        ctypes.memset(buf, 0, buf_sz)
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[0] = 1
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint32))[1] = 1
        ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint64))[1] = 1
        pfn_arr[1] = p

        sf = SUPERFETCH_INFORMATION(
            Version=SUPERFETCH_VERSION,
            Magic=SUPERFETCH_MAGIC,
            InfoClass=SUPERFETCH_PFN_QUERY,
            Data=ctypes.cast(buf, ctypes.c_void_p),
            Length=buf_sz,
        )
        st = ntdll.NtQuerySystemInformation(
            SYSTEM_SUPERFETCH_INFORMATION,
            ctypes.byref(sf),
            ctypes.sizeof(sf),
            ctypes.byref(ret_len),
        ) & 0xFFFFFFFF
        records.append((p, st, int(pfn_arr[0]), int(pfn_arr[2])))
    return records
