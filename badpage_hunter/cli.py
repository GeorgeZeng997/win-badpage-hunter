import argparse
import ctypes
import datetime
import json
import os
import sys
from typing import Any, Dict

from . import __version__
from .bcd_manager import (
    analyze_pfn_clusters,
    diff_status_snapshots,
    get_existing_bad_pfns,
    update_bcd_badmemory,
)
from .dmp_analyzer import (
    analyze_minidump_directory,
    parse_minidump,
    summarize_minidump_results,
)
from .hunter import BadPageHunter, get_memory_status
from .pfn_resolver import get_kernel_physical_memory_ranges, query_pfn_database_status


def _ensure_console_attached() -> None:
    """When frozen with --windowed (no console), attach to parent terminal if invoked with CLI args."""
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        try:
            if ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:
            pass


def build_status_snapshot() -> Dict[str, Any]:
    """Collect a structured diagnostic snapshot of RAM, descriptor ranges, BCD {badmemory}, and _MMPFN excision."""
    total_gb, avail_gb, load = get_memory_status()
    ranges = get_kernel_physical_memory_ranges()
    bad_pfns = sorted(get_existing_bad_pfns())
    cluster = analyze_pfn_clusters(bad_pfns, total_ram_gb=total_gb)

    sample_pfns = (
        bad_pfns
        if len(bad_pfns) <= 128
        else (bad_pfns[:32] + bad_pfns[len(bad_pfns) // 2 : len(bad_pfns) // 2 + 32] + bad_pfns[-32:])
    )
    records = query_pfn_database_status(sample_pfns) if sample_pfns else []
    excised_pfns = [r[0] for r in records if r[1] == 0xC00000F0 or (r[2] == 0 and r[3] <= 2)]
    staged_pfns = [r[0] for r in records if not (r[1] == 0xC00000F0 or (r[2] == 0 and r[3] <= 2))]

    return {
        "tool": "win-badpage-hunter",
        "version": __version__,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ram": {
            "total_gb": round(total_gb, 3),
            "avail_gb": round(avail_gb, 3),
            "load_pct": load,
        },
        "physical_ranges": [
            {
                "index": idx,
                "start_pfn_hex": f"0x{s:07x}",
                "end_pfn_hex": f"0x{e:07x}",
                "pages": e - s,
                "size_mb": round(mb, 2),
            }
            for idx, (s, e, mb) in enumerate(ranges)
        ],
        "isolated_pfns_hex": [f"0x{p:x}" for p in bad_pfns],
        "excised_pfns_hex": [f"0x{p:x}" for p in excised_pfns],
        "staged_pfns_hex": [f"0x{p:x}" for p in staged_pfns],
        "mmpfn_sampled_count": len(records),
        "mmpfn_records": [
            {
                "pfn_hex": f"0x{pfn:x}",
                "phys_addr_hex": f"0x{pfn << 12:012x}",
                "ntstatus_hex": f"0x{st:08x}",
                "excised": bool(st == 0xC00000F0 or (u1 == 0 and va <= 2)),
            }
            for pfn, st, u1, va in records
        ],
        "cluster_analysis": cluster,
    }


def cmd_gui(args: argparse.Namespace) -> int:
    from .gui import launch_gui

    return launch_gui(lang=getattr(args, "lang", "en"))


def cmd_analyze_dumps(args: argparse.Namespace) -> int:
    target = args.dir
    if os.path.isfile(target):
        try:
            results = [parse_minidump(target)]
        except Exception as exc:
            results = [{"file": os.path.basename(target), "error": str(exc)}]
    else:
        results = analyze_minidump_directory(target)

    summary = summarize_minidump_results(results)
    payload = {
        "tool": "win-badpage-hunter",
        "version": __version__,
        "target": target,
        "summary": summary,
        "dumps": results,
    }

    if args.export:
        out_dir = os.path.dirname(os.path.abspath(args.export))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    if not results:
        print(f"No .dmp files found in {target}")
        return 0

    print(
        f"Analyzed {summary['total_dumps']} crash dump(s) in {target} "
        f"[Verdict: {summary['verdict']} | Hardware Bit-Flip Dumps: {summary['bitflip_dumps']}/{summary['parsed_ok']}]:\n"
    )
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
    if args.export:
        print(f"Exported JSON report to: {args.export}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    snap = build_status_snapshot()
    if args.export:
        out_dir = os.path.dirname(os.path.abspath(args.export))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.export, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)

    if args.json:
        print(json.dumps(snap, indent=2))
        return 0

    ram = snap["ram"]
    cluster = snap["cluster_analysis"]
    print(f"System Physical RAM : {ram['total_gb']:.2f} GB total | {ram['avail_gb']:.2f} GB available ({ram['load_pct']}% load)")
    print(
        f"DRAM Health Verdict : {cluster['health_score']}/100 [{cluster['severity']}] "
        f"(Row Groups: {cluster['row_groups_affected']}, Rank Bands: {len(cluster['rank_bands_gb'])})"
    )

    ranges = snap["physical_ranges"]
    print(f"\nKernel Physical Memory Map ({len(ranges)} active descriptor ranges):")
    for r in ranges:
        print(
            f"  Range {r['index']:2d}: PFN {r['start_pfn_hex'].upper()} .. {r['end_pfn_hex'].upper()} "
            f"({r['pages']:8d} pages, {r['size_mb']:9.2f} MB)"
        )

    bad_pfns = [int(x, 16) for x in snap["isolated_pfns_hex"]]
    print(f"\nWindows BCD {{badmemory}} Isolated PFNs ({len(bad_pfns)} pages = {len(bad_pfns) * 4 / 1024:.2f} MB):")
    if not bad_pfns:
        print("  (None configured)")
        if args.export:
            print(f"\nExported diagnostic snapshot to: {args.export}")
        return 0

    if len(bad_pfns) <= 60:
        for i in range(0, len(bad_pfns), 6):
            chunk = bad_pfns[i : i + 6]
            print("  " + "  ".join(f"0x{p:06x}" for p in chunk))
    else:
        runs = []
        r_start = r_prev = bad_pfns[0]
        for p in bad_pfns[1:]:
            if p == r_prev + 1:
                r_prev = p
            else:
                runs.append((r_start, r_prev))
                r_start = r_prev = p
        runs.append((r_start, r_prev))
        print(f"  Summary ({len(runs)} contiguous range(s)):")
        for s, e in runs[:20]:
            cnt = e - s + 1
            print(f"    PFN 0x{s:06X} .. 0x{e:06X} ({cnt:6d} pages, {cnt * 4 / 1024:6.2f} MB)")
        if len(runs) > 20:
            print(f"    ... ({len(runs) - 20} more range(s))")

    records = snap["mmpfn_records"]
    excised_cnt = len(snap["excised_pfns_hex"])
    staged_cnt = len(snap["staged_pfns_hex"])
    print(
        f"\nKernel _MMPFN Verification ({excised_cnt}/{len(records)} sampled active kernel-excised, "
        f"{staged_cnt}/{len(records)} staged for next reboot):"
    )
    for rec in records[:12]:
        state = (
            "EXCISED_BY_BOOTLOADER (NTSTATUS=0xC00000F0)"
            if rec["excised"]
            else f"STAGED_PENDING_REBOOT (NTSTATUS={rec['ntstatus_hex'].upper()})"
        )
        print(f"  PFN {rec['pfn_hex'].upper()} (PhysAddr {rec['phys_addr_hex'].upper()}): {state}")
    if len(records) > 12:
        print(f"  ... ({len(records) - 12} more isolated PFNs verified)")
    if args.export:
        print(f"\nExported diagnostic snapshot to: {args.export}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    with open(args.baseline, "r", encoding="utf-8") as f:
        old_snap = json.load(f)
    if args.target:
        with open(args.target, "r", encoding="utf-8") as f:
            new_snap = json.load(f)
        target_label = args.target
    else:
        new_snap = build_status_snapshot()
        target_label = "LIVE_SYSTEM"

    delta = diff_status_snapshots(old_snap, new_snap)
    if args.json:
        print(json.dumps(delta, indent=2))
        return 0

    print("=" * 78)
    print(f"Win-BadPage-Hunter Snapshot Diff: {args.baseline} -> {target_label}")
    print("=" * 78)
    print(f"Cluster Trajectory : {delta['status']}")
    print(
        f"Health Score       : {delta['old_health_score']}/100 -> {delta['new_health_score']}/100 "
        f"({delta['health_score_delta']:+d})"
    )
    print(
        f"Isolated PFNs      : {delta['old_isolated_count']} -> {delta['new_isolated_count']} "
        f"(+{len(delta['added_pfns_hex'])} added, -{len(delta['removed_pfns_hex'])} removed)"
    )
    print(f"Descriptor Ranges  : {delta['old_ranges_count']} -> {delta['new_ranges_count']}")
    print(f"Newly Excised PFNs : {len(delta['newly_excised_pfns_hex'])}")
    if delta["added_pfns_hex"]:
        print(f"  Added PFNs       : {', '.join(delta['added_pfns_hex'][:16])}")
    if delta["new_rank_bands"]:
        print(f"  [!] New 1GB Rank Bands Affected: {', '.join(delta['new_rank_bands'])}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="badpage-hunter",
        description="Hunt down leaky DRAM bit-flip pages in user-mode and surgically isolate their physical PFNs via Windows BCD.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gui = sub.add_parser("gui", help="Launch the graphical user interface (default when run with no arguments).")
    p_gui.add_argument("--lang", choices=["en"], default="en", help="UI language (default: en)")
    p_gui.set_defaults(func=cmd_gui)

    p_dmp = sub.add_parser("analyze-dumps", help="Parse Windows PAGEDU64 Minidumps and detect hardware single-bit flips.")
    p_dmp.add_argument(
        "--dir",
        default=r"C:\Windows\Minidump",
        help="Path to Minidump directory or single .dmp file (default: C:\\Windows\\Minidump)",
    )
    p_dmp.add_argument("--json", action="store_true", help="Output structured JSON report")
    p_dmp.add_argument("--export", default="", help="Write JSON minidump triage report to file")
    p_dmp.set_defaults(func=cmd_analyze_dumps)

    p_status = sub.add_parser(
        "status",
        help="Show active kernel physical memory map, DRAM cluster health score, BCD badmemorylist, and _MMPFN excision status.",
    )
    p_status.add_argument("--json", action="store_true", help="Output structured JSON diagnostic snapshot")
    p_status.add_argument("--export", default="", help="Export diagnostic snapshot JSON to file")
    p_status.set_defaults(func=cmd_status)

    p_diff = sub.add_parser(
        "diff",
        help="Compare a saved diagnostic snapshot JSON against live system state (or a second snapshot JSON).",
    )
    p_diff.add_argument("baseline", help="Path to baseline status snapshot JSON")
    p_diff.add_argument("target", nargs="?", default="", help="Optional path to newer snapshot JSON (defaults to live system)")
    p_diff.add_argument("--json", action="store_true", help="Output diff result as JSON")
    p_diff.set_defaults(func=cmd_diff)

    p_hunt = sub.add_parser("hunt", help="Run the low-memory FIFO sliding-window DRAM retention bit-flip hunter.")
    p_hunt.add_argument(
        "--window-batches", type=int, default=3, help="Number of active batches in FIFO sliding window (default: 3)"
    )
    p_hunt.add_argument("--batch-gb", type=float, default=6.0, help="Size per batch in GB (default: 6.0)")
    p_hunt.add_argument("--block-mb", type=int, default=256, help="Allocation block size in MB (default: 256)")
    p_hunt.add_argument(
        "--min-avail-gb", type=float, default=16.0, help="Safety floor for free system RAM in GB (default: 16.0)"
    )
    p_hunt.add_argument(
        "--soak", type=float, default=15.0, help="Retention soak duration per cycle in seconds (default: 15.0)"
    )
    p_hunt.add_argument("--max-cycles", type=int, default=None, help="Stop after N cycles (default: run continuously)")
    p_hunt.add_argument(
        "--no-row-twins", action="store_true", help="Do not automatically add paired DRAM row (+3/+5) twin pages"
    )
    p_hunt.add_argument("--log-file", default="bad_page_hunter.log", help="Log file path")
    p_hunt.set_defaults(func=cmd_hunt)

    p_iso = sub.add_parser("isolate", help="Manually add one or more PFNs to Windows BCD {badmemory} badmemorylist.")
    p_iso.add_argument("pfns", nargs="+", help="PFN values in hex (e.g. 0x2c0555) or decimal")
    p_iso.add_argument(
        "--no-row-twins", action="store_true", help="Do not automatically add paired DRAM row (+3/+5) twin pages"
    )
    p_iso.set_defaults(func=cmd_isolate)
    return parser


def main() -> int:
    if len(sys.argv) == 1:
        from .gui import launch_gui

        return launch_gui()

    _ensure_console_attached()
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
