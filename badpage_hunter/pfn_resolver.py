import ctypes
import os
import struct
import sys
from typing import Dict, Iterable, List, Set, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

if IS_WINDOWS:
    from ctypes import wintypes
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
else:
    ntdll = None
    kernel32 = None


def enable_privileges() -> Dict[int, int]:
    """Enable SeProfileSingleProcessPrivilege, SeLockMemoryPrivilege, and SeDebugPrivilege on Windows."""
    if not IS_WINDOWS:
        return {}
    results: Dict[int, int] = {}
    for priv in (SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, SE_LOCK_MEMORY_PRIVILEGE, SE_DEBUG_PRIVILEGE):
        old_priv = wintypes.BOOLEAN()
        status = ntdll.RtlAdjustPrivilege(priv, True, False, ctypes.byref(old_priv)) & 0xFFFFFFFF
        results[priv] = status
    return results


def get_kernel_physical_memory_ranges() -> List[Tuple[int, int, float]]:
    """
    Read active physical memory PFN ranges:
    - Windows: HKLM\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory\\.Translated
    - Linux: /proc/iomem ("System RAM") or /proc/meminfo fallback
    - macOS: sysctl hw.memsize
    Returns a list of (start_pfn, end_pfn, size_mb).
    """
    if IS_WINDOWS:
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

    if IS_LINUX:
        ranges = []
        try:
            with open("/proc/iomem", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "System RAM" in line:
                        addr_part = line.strip().split(":")[0].strip()
                        s_hex, e_hex = addr_part.split("-")
                        start_phys = int(s_hex, 16)
                        end_phys = int(e_hex, 16) + 1
                        if end_phys > start_phys:
                            s_pfn = start_phys >> 12
                            e_pfn = end_phys >> 12
                            if e_pfn > s_pfn:
                                ranges.append((s_pfn, e_pfn, (end_phys - start_phys) / (1024 * 1024)))
        except Exception:
            pass
        if not ranges:
            try:
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            pages = kb // 4
                            ranges.append((0, pages, kb / 1024.0))
                            break
            except Exception:
                pass
        return ranges

    # macOS / POSIX fallback
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_sz = os.sysconf("SC_PAGE_SIZE")
        total_bytes = pages * page_sz
        total_4k_pages = total_bytes >> 12
        return [(0, total_4k_pages, total_bytes / (1024 * 1024))]
    except Exception:
        return []


def resolve_vas_to_pfns(target_page_vas: Iterable[int]) -> Dict[int, int]:
    """
    Translate 4KB page-aligned user-mode virtual addresses to hardware Page Frame Numbers (PFNs):
    - Windows: NtQuerySystemInformation(SystemSuperfetchInformation=79, SuperfetchPfnQuery=6)
    - Linux: /proc/self/pagemap (bits 0..54 when bit 63 page-present is set)
    """
    remaining: Set[int] = {va & ~0xFFF for va in target_page_vas}
    found: Dict[int, int] = {}
    if not remaining:
        return found

    if IS_WINDOWS:
        enable_privileges()
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

    if IS_LINUX and os.path.exists("/proc/self/pagemap"):
        try:
            with open("/proc/self/pagemap", "rb") as f:
                for va_page in list(remaining):
                    vpn = va_page >> 12
                    f.seek(vpn * 8)
                    raw = f.read(8)
                    if len(raw) == 8:
                        entry = struct.unpack("<Q", raw)[0]
                        present = (entry >> 63) & 1
                        pfn = entry & ((1 << 55) - 1)
                        if present and pfn > 0:
                            found[va_page] = pfn
        except Exception:
            pass
    return found


def query_pfn_database_status(pfns: List[int]) -> List[Tuple[int, int, int, int]]:
    """
    Query kernel page frame status for each PFN in `pfns`.
    Returns a list of (pfn, ntstatus, u1, va) tuples.
    - Windows: STATUS_INVALID_PARAMETER_2 (0xC00000F0) indicates excised by winload.efi {badmemory}.
    - Linux: checks /proc/kpageflags for KPF_HWPOISON (bit 19) or KPF_NOPAGE (bit 20).
    """
    if not pfns:
        return []

    if IS_WINDOWS:
        enable_privileges()
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

    if IS_LINUX and os.path.exists("/proc/kpageflags"):
        records = []
        try:
            with open("/proc/kpageflags", "rb") as f:
                for p in pfns:
                    f.seek(p * 8)
                    raw = f.read(8)
                    if len(raw) == 8:
                        flags = struct.unpack("<Q", raw)[0]
                        # KPF_HWPOISON (bit 19) or KPF_NOPAGE (bit 20)
                        if flags & ((1 << 19) | (1 << 20)):
                            records.append((p, 0xC00000F0, 0, 0))
                        else:
                            records.append((p, 0, flags, 1))
                    else:
                        records.append((p, 0xC00000F0, 0, 0))
            return records
        except Exception:
            pass

    return [(p, 0, 1, 1) for p in pfns]
