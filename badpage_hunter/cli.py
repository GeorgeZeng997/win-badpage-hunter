import argparse
import sys

from .bcd_manager import get_existing_bad_pfns, update_bcd_badmemory
from .dmp_analyzer import analyze_minidump_directory
from .hunter import BadPageHunter, get_memory_status
from .pfn_resolver import get_kernel_physical_memory_ranges, query_pfn_database_status


def cmd_analyze_dumps(args: argparse.Namespace) -> int:
    results = analyze_minidump_directory(args.dir)
    if not results:
        print(f"No .dmp files found in {args.dir}")
        return 0

    print(f"Analyzed {len(results)} crash dump(s) in {args.dir}:\n")
    for r in results:
        print("=" * 78)
        if "error" in r:
            print(f"FILE: {r['file']} -> Error: {r['error']}")
            continue
        print(f"FILE    : {r['file']} (OS {r['version']}, {r['processors']} logical CPUs)")
        print(f"BUGCHECK: 0x{r['bugcheck']:08X} ({r['bugcheck_name']})")
        for idx, (p, sym) in enumerate(zip(r["params"], r["param_symbols"]), 1):
            sym_str = f" -> {sym}" if sym else ""
            print(f"  Param{idx}: 0x{p:016X}{sym_str}")
        print(f"CRASH RIP: 0x{r['context']['RIP']:016X} ({r['rip_symbol'] or 'Unknown'})")
        if r["bitflips"]:
            print("  [!] HARDWARE SINGLE-BIT FLIP DETECTED IN CPU REGISTERS:")
            for reg_name, reg_val, bit_idx, repaired in r["bitflips"]:
                print(
                    f"      {reg_name}: 0x{reg_val:016X} (Bit {bit_idx} flipped 1->0! "
                    f"Expected canonical kernel pointer: 0x{repaired:016X})"
                )
        else:
            print("  [*] No non-canonical upper-bit register flip in primary frame.")
        if r["stack_symbols"]:
            print("  Top Stack Modules:")
            for sp, addr, sym in r["stack_symbols"][:8]:
                print(f"    [0x{sp:016X}] 0x{addr:016X} -> {sym}")
    print("=" * 78)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    total_gb, avail_gb, load = get_memory_status()
    print(f"System Physical RAM : {total_gb:.2f} GB total | {avail_gb:.2f} GB available ({load}% load)")

    ranges = get_kernel_physical_memory_ranges()
    print(f"\nKernel Physical Memory Map ({len(ranges)} active descriptor ranges):")
    for idx, (start_pfn, end_pfn, mb) in enumerate(ranges):
        print(f"  Range {idx:2d}: PFN 0x{start_pfn:07X} .. 0x{end_pfn:07X} ({end_pfn - start_pfn:8d} pages, {mb:9.2f} MB)")

    bad_pfns = sorted(get_existing_bad_pfns())
    print(f"\nWindows BCD {{badmemory}} Isolated PFNs ({len(bad_pfns)} pages = {len(bad_pfns) * 4} KB):")
    if not bad_pfns:
        print("  (None configured)")
        return 0

    for i in range(0, len(bad_pfns), 6):
        chunk = bad_pfns[i : i + 6]
        print("  " + "  ".join(f"0x{p:06x}" for p in chunk))

    records = query_pfn_database_status(bad_pfns)
    excised = [r for r in records if r[1] == 0xC00000F0 or (r[2] == 0 and r[3] <= 2)]
    staged = [r for r in records if not (r[1] == 0xC00000F0 or (r[2] == 0 and r[3] <= 2))]
    print(
        f"\nKernel _MMPFN Verification ({len(excised)}/{len(records)} active kernel-excised, "
        f"{len(staged)}/{len(records)} staged for next reboot):"
    )
    for pfn, st, u1, va in records[:12]:
        state = (
            "EXCISED_BY_BOOTLOADER (NTSTATUS=0xC00000F0)"
            if (st == 0xC00000F0 or (u1 == 0 and va <= 2))
            else f"STAGED_PENDING_REBOOT (NTSTATUS=0x{st:08X})"
        )
        print(f"  PFN 0x{pfn:06X} (PhysAddr 0x{pfn << 12:012X}): {state}")
    if len(records) > 12:
        print(f"  ... ({len(records) - 12} more isolated PFNs verified)")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    hunter = BadPageHunter(
        window_batches=args.window_batches,
        batch_gb=args.batch_gb,
        block_mb=args.block_mb,
        min_avail_gb=args.min_avail_gb,
        soak_seconds=args.soak,
        include_row_twins=not args.no_row_twins,
        log_file=args.log_file,
    )
    hunter.run(max_cycles=args.max_cycles)
    return 0


def cmd_isolate(args: argparse.Namespace) -> int:
    pfns = [int(x, 0) for x in args.pfns]
    updated, msg = update_bcd_badmemory(pfns, include_row_twins=not args.no_row_twins)
    print(f"BCD Update Result: {msg}")
    print(f"Total Isolated PFNs in {{badmemory}} ({len(updated)} pages = {len(updated) * 4} KB):")
    for p in sorted(updated):
        print(f"  0x{p:06x} (PhysAddr 0x{p << 12:012X})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="badpage-hunter",
        description="Hunt down leaky DRAM bit-flip pages in user-mode and surgically isolate their physical PFNs via Windows BCD.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_dmp = sub.add_parser("analyze-dumps", help="Parse Windows PAGEDU64 Minidumps and detect hardware single-bit flips.")
    p_dmp.add_argument("--dir", default=r"C:\Windows\Minidump", help="Path to Minidump directory (default: C:\\Windows\\Minidump)")
    p_dmp.set_defaults(func=cmd_analyze_dumps)

    p_status = sub.add_parser("status", help="Show active kernel physical memory map, BCD badmemorylist, and PFN excision status.")
    p_status.set_defaults(func=cmd_status)

    p_hunt = sub.add_parser("hunt", help="Run the low-memory FIFO sliding-window DRAM retention bit-flip hunter.")
    p_hunt.add_argument("--window-batches", type=int, default=3, help="Number of active batches in FIFO sliding window (default: 3)")
    p_hunt.add_argument("--batch-gb", type=float, default=6.0, help="Size per batch in GB (default: 6.0)")
    p_hunt.add_argument("--block-mb", type=int, default=256, help="Allocation block size in MB (default: 256)")
    p_hunt.add_argument("--min-avail-gb", type=float, default=16.0, help="Safety floor for free system RAM in GB (default: 16.0)")
    p_hunt.add_argument("--soak", type=float, default=15.0, help="Retention soak duration per cycle in seconds (default: 15.0)")
    p_hunt.add_argument("--max-cycles", type=int, default=None, help="Stop after N cycles (default: run continuously)")
    p_hunt.add_argument("--no-row-twins", action="store_true", help="Do not automatically add paired DRAM row (+3/+5) twin pages")
    p_hunt.add_argument("--log-file", default="bad_page_hunter.log", help="Log file path")
    p_hunt.set_defaults(func=cmd_hunt)

    p_iso = sub.add_parser("isolate", help="Manually add one or more PFNs to Windows BCD {badmemory} badmemorylist.")
    p_iso.add_argument("pfns", nargs="+", help="PFN values in hex (e.g. 0x2c0555) or decimal")
    p_iso.add_argument("--no-row-twins", action="store_true", help="Do not automatically add paired DRAM row (+3/+5) twin pages")
    p_iso.set_defaults(func=cmd_isolate)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
