import glob
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

REGISTER_NAMES = [
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP",
]

BUGCHECK_NAMES: Dict[int, str] = {
    0x0000000A: "IRQL_NOT_LESS_OR_EQUAL",
    0x0000001A: "MEMORY_MANAGEMENT",
    0x0000001E: "KMODE_EXCEPTION_NOT_HANDLED",
    0x0000003B: "SYSTEM_SERVICE_EXCEPTION",
    0x00000050: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x0000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    0x1000007E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
    0x0000007F: "UNEXPECTED_KERNEL_MODE_TRAP",
    0x1000007F: "UNEXPECTED_KERNEL_MODE_TRAP_M",
    0x000000EF: "CRITICAL_PROCESS_DIED",
    0x00000139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x00000154: "UNEXPECTED_STORE_EXCEPTION",
}

MIN_PAGEDU64_HEADER_BYTES = 0x2050
CONTEXT_REG_OFFSET = 0x78
CONTEXT_REG_BYTES = 17 * 8  # 136 bytes


def detect_noncanonical_bitflip(val: int) -> Optional[Tuple[int, int]]:
    """
    Detect if a 64-bit register value looks like a canonical Windows x64 kernel pointer
    (sign-extension bits 47..63 = all 1s) that suffered a single-bit 1->0 flip in bits 47..63.
    Returns (flipped_bit_index, repaired_canonical_value) or None.
    """
    upper16 = (val >> 48) & 0xFFFF
    bit47 = (val >> 47) & 1

    # Case 1: Bit 47 is 1, and exactly one bit in [48..63] flipped 1 -> 0
    if bit47 == 1 and upper16 not in (0xFFFF, 0x0000):
        xor_mask = upper16 ^ 0xFFFF
        if xor_mask != 0 and (xor_mask & (xor_mask - 1)) == 0:
            bit_in_upper = xor_mask.bit_length() - 1
            bit_idx = 48 + bit_in_upper
            repaired = val | (0xFFFF << 48)
            return bit_idx, repaired

    # Case 2: Upper 16 bits are 0xFFFF, and bit 47 itself flipped 1 -> 0 (non-canonical 0xFFFF0000..0xFFFF7FFF)
    if upper16 == 0xFFFF and bit47 == 0:
        repaired = val | (1 << 47)
        return 47, repaired

    return None


def resolve_driver_address(addr: int, drivers: List[Tuple[int, int, str, int]]) -> Optional[str]:
    for base, size, name, _ in drivers:
        if size > 0 and base <= addr < base + size:
            short_name = name.split("\\")[-1]
            return f"{short_name}+0x{addr - base:X}"
    return None


def parse_minidump(filepath: str) -> Dict[str, Any]:
    """Parse a Windows x64 Kernel Triage Minidump (PAGEDU64) in pure Python with full bounds validation."""
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 8 or data[:8] != b"PAGEDU64":
        raise ValueError(f"Unsupported dump signature in {filepath}: {data[:8]!r}")
    if len(data) < MIN_PAGEDU64_HEADER_BYTES:
        raise ValueError(
            f"Truncated PAGEDU64 dump in {filepath}: {len(data)} bytes (< {MIN_PAGEDU64_HEADER_BYTES} bytes required)"
        )

    major, minor = struct.unpack_from("<II", data, 0x08)
    _machine, nprocs, _ = struct.unpack_from("<III", data, 0x30)
    bugcheck = struct.unpack_from("<I", data, 0x38)[0]
    p1, p2, p3, p4 = struct.unpack_from("<QQQQ", data, 0x40)
    dump_type = struct.unpack_from("<I", data, 0xF98)[0]

    (
        ctx_off, _exc_off, _mm_off, _unl_off, _prcb_off, _proc_off,
        _thd_off, stk_off, stk_sz, drv_off, drv_cnt, _str_off, _str_sz
    ) = struct.unpack_from("<13I", data, 0x200C)
    top_of_stack = struct.unpack_from("<Q", data, 0x2048)[0]

    drivers: List[Tuple[int, int, str, int]] = []
    max_drivers = min(drv_cnt, 1024)
    for i in range(max_drivers):
        ent_off = drv_off + i * 0x90
        if ent_off < 0 or ent_off + 0x90 > len(data):
            break
        name_off = struct.unpack_from("<I", data, ent_off)[0]
        base = struct.unpack_from("<Q", data, ent_off + 0x38)[0]
        size = struct.unpack_from("<I", data, ent_off + 0x48)[0]
        ts = struct.unpack_from("<I", data, ent_off + 0x88)[0]
        name = ""
        if 0 < name_off <= len(data) - 4:
            nlen = min(struct.unpack_from("<I", data, name_off)[0], 512)
            end_str = min(len(data), name_off + 4 + nlen * 2)
            name = data[name_off + 4 : end_str].decode("utf-16le", errors="ignore")
        drivers.append((base, size, name, ts))

    def read_context(offset: int) -> Optional[Dict[str, int]]:
        reg_start = offset + CONTEXT_REG_OFFSET
        if offset < 0 or reg_start + CONTEXT_REG_BYTES > len(data):
            return None
        vals = struct.unpack_from("<17Q", data, reg_start)
        return dict(zip(REGISTER_NAMES, vals))

    primary_ctx = read_context(ctx_off)
    if primary_ctx is None:
        raise ValueError(f"Primary CPU CONTEXT at offset 0x{ctx_off:X} exceeds dump size ({len(data)} bytes)")

    saved_ctx: Optional[Dict[str, int]] = None

    # Check if Param3 (for 0x3B) or Param4 (for 0x7E/0x1000007E) points to a CONTEXT inside the saved call stack
    if stk_sz >= 0x4D0:
        for candidate_ptr in (p3, p4):
            if top_of_stack <= candidate_ptr <= top_of_stack + stk_sz - 0x4D0:
                rel_off = int(stk_off + (candidate_ptr - top_of_stack))
                cand = read_context(rel_off)
                if cand is not None:
                    saved_ctx = cand
                    break

    # Fallback: check embedded exception CONTEXT at 0x348 if its RIP matches Param2
    if saved_ctx is None and len(data) >= 0x348 + 0x4D0:
        cand_ctx = read_context(0x348)
        if cand_ctx is not None and cand_ctx.get("RIP") == p2 and (cand_ctx.get("RSP", 0) >> 48) == 0xFFFF:
            saved_ctx = cand_ctx

    active_ctx = saved_ctx if saved_ctx else primary_ctx
    bitflips = []
    for reg_name, reg_val in active_ctx.items():
        bf = detect_noncanonical_bitflip(reg_val)
        if bf:
            bit_idx, repaired = bf
            bitflips.append((reg_name, reg_val, bit_idx, repaired))

    stack_symbols = []
    max_scan = min(max(0, stk_sz - 7), 0x2000)
    for s_off in range(0, max_scan, 8):
        pos = stk_off + s_off
        if pos < 0 or pos + 8 > len(data):
            break
        val = struct.unpack_from("<Q", data, pos)[0]
        sym = resolve_driver_address(val, drivers)
        if sym:
            stack_symbols.append((top_of_stack + s_off, val, sym))

    return {
        "file": os.path.basename(filepath),
        "path": filepath,
        "version": f"{major}.{minor}",
        "processors": nprocs,
        "dump_type": dump_type,
        "bugcheck": bugcheck,
        "bugcheck_name": BUGCHECK_NAMES.get(bugcheck, "UNKNOWN_BUGCHECK"),
        "params": [p1, p2, p3, p4],
        "param_symbols": [resolve_driver_address(p, drivers) for p in (p1, p2, p3, p4)],
        "context": active_ctx,
        "rip_symbol": resolve_driver_address(active_ctx["RIP"], drivers),
        "bitflips": bitflips,
        "stack_symbols": stack_symbols[:20],
    }


def analyze_minidump_directory(dump_dir: str = r"C:\Windows\Minidump") -> List[Dict[str, Any]]:
    files = sorted(glob.glob(os.path.join(dump_dir, "*.dmp")))
    results = []
    for fpath in files:
        try:
            results.append(parse_minidump(fpath))
        except Exception as exc:
            results.append({"file": os.path.basename(fpath), "error": str(exc)})
    return results


def summarize_minidump_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate hardware bit-flip findings across multiple parsed BSOD minidumps."""
    parsed_ok = [r for r in results if "error" not in r]
    errors = [r for r in results if "error" in r]
    bitflip_dumps = [r for r in parsed_ok if r.get("bitflips")]
    bit_hist: Dict[str, int] = {}
    total_flipped_regs = 0
    for r in bitflip_dumps:
        for _reg, _val, bit_idx, _rep in r["bitflips"]:
            total_flipped_regs += 1
            key = f"bit_{bit_idx}"
            bit_hist[key] = bit_hist.get(key, 0) + 1

    if not results:
        verdict = "NO_DUMPS"
    elif bitflip_dumps:
        verdict = "HARDWARE_DRAM_BITFLIP_CONFIRMED"
    elif parsed_ok:
        verdict = "NO_UPPER_BITFLIP_DETECTED"
    else:
        verdict = "PARSE_ERRORS_ONLY"

    return {
        "total_dumps": len(results),
        "parsed_ok": len(parsed_ok),
        "parse_errors": len(errors),
        "bitflip_dumps": len(bitflip_dumps),
        "total_bitflip_registers": total_flipped_regs,
        "flipped_bit_histogram": bit_hist,
        "verdict": verdict,
    }
