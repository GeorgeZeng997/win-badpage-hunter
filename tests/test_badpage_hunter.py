import struct
import tempfile
import unittest
from pathlib import Path

from badpage_hunter.bcd_manager import (
    analyze_pfn_clusters,
    diff_status_snapshots,
    infer_dram_row_twins,
    synthesize_imc_bank_pfns,
)
from badpage_hunter.dmp_analyzer import (
    detect_noncanonical_bitflip,
    parse_minidump,
    resolve_driver_address,
    summarize_minidump_results,
)
from badpage_hunter.hunter import compute_decommit_spans, recommend_hunter_params


def _build_synthetic_pagedu64(flipped_rcx: int) -> bytes:
    """Construct a valid minimal Windows x64 PAGEDU64 triage minidump binary for testing."""
    buf = bytearray(0x3000)
    buf[0:8] = b"PAGEDU64"
    struct.pack_into("<II", buf, 0x08, 15, 26100)  # Windows 11 24H2
    struct.pack_into("<III", buf, 0x30, 0x8664, 12, 0x0000003B)
    struct.pack_into("<I", buf, 0x38, 0x0000003B)  # SYSTEM_SERVICE_EXCEPTION

    ntos_base = 0xFFFFF803B8C00000
    rip_val = ntos_base + 0x3884E8
    struct.pack_into("<QQQQ", buf, 0x40, 0xC0000005, rip_val, 0, 0)
    struct.pack_into("<I", buf, 0xF98, 4)  # Triage dump

    ctx_off = 0x2200
    stk_off = 0x2800
    stk_sz = 0x100
    drv_off = 0x2900
    drv_cnt = 1
    name_off = 0x2A00

    struct.pack_into(
        "<13I",
        buf,
        0x200C,
        ctx_off,
        0,
        0,
        0,
        0,
        0,
        0,
        stk_off,
        stk_sz,
        drv_off,
        drv_cnt,
        0,
        0,
    )
    top_of_stack = 0xFFFFFA89973FE000
    struct.pack_into("<Q", buf, 0x2048, top_of_stack)

    # Driver entry (ntoskrnl.exe)
    drv_name = "\\SystemRoot\\system32\\ntoskrnl.exe"
    encoded_name = drv_name.encode("utf-16le")
    struct.pack_into("<I", buf, name_off, len(drv_name))
    buf[name_off + 4 : name_off + 4 + len(encoded_name)] = encoded_name

    struct.pack_into("<I", buf, drv_off, name_off)
    struct.pack_into("<Q", buf, drv_off + 0x38, ntos_base)
    struct.pack_into("<I", buf, drv_off + 0x48, 0x1000000)
    struct.pack_into("<I", buf, drv_off + 0x88, 0x65000000)

    # Primary CPU CONTEXT registers (17 QWORDs at ctx_off + 0x78)
    regs = [0] * 17
    regs[1] = flipped_rcx  # RCX
    regs[4] = top_of_stack  # RSP
    regs[16] = rip_val  # RIP
    struct.pack_into("<17Q", buf, ctx_off + 0x78, *regs)

    # One return address on stack
    struct.pack_into("<Q", buf, stk_off, ntos_base + 0x205EF5)
    return bytes(buf)


class TestMinidumpForensics(unittest.TestCase):
    def test_detect_noncanonical_bitflip(self) -> None:
        # Bit 56 flipped 1 -> 0 (0xFFFF -> 0xFEFF)
        self.assertEqual(
            detect_noncanonical_bitflip(0xFEFFDF87873AF040),
            (56, 0xFFFFDF87873AF040),
        )
        # Bit 57 flipped 1 -> 0 (0xFFFF -> 0xFDFF)
        self.assertEqual(
            detect_noncanonical_bitflip(0xFDFF9889F6F1C038),
            (57, 0xFFFF9889F6F1C038),
        )
        # Bit 47 flipped 1 -> 0 while upper 16 bits remain 0xFFFF
        self.assertEqual(
            detect_noncanonical_bitflip(0xFFFF008FD6286258),
            (47, 0xFFFF808FD6286258),
        )
        # Canonical kernel & user pointers must return None
        self.assertIsNone(detect_noncanonical_bitflip(0xFFFFDF87873AF040))
        self.assertIsNone(detect_noncanonical_bitflip(0x00007FF812345678))
        # Multi-bit corruption in upper 16 bits should not be misclassified as single-bit flip
        self.assertIsNone(detect_noncanonical_bitflip(0xFCFFDF87873AF040))

    def test_resolve_driver_address(self) -> None:
        drivers = [(0xFFFFF80098200000, 0x1000000, r"\SystemRoot\system32\ntoskrnl.exe", 0)]
        self.assertEqual(
            resolve_driver_address(0xFFFFF80098405EF5, drivers),
            "ntoskrnl.exe+0x205EF5",
        )
        self.assertIsNone(resolve_driver_address(0xFFFFF80099900000, drivers))

    def test_parse_synthetic_and_truncated_minidump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            valid_path = Path(tmp) / "crash_01.dmp"
            valid_path.write_bytes(_build_synthetic_pagedu64(0xFEFFDF87873AF040))

            parsed = parse_minidump(str(valid_path))
            self.assertEqual(parsed["bugcheck"], 0x3B)
            self.assertEqual(parsed["rip_symbol"], "ntoskrnl.exe+0x3884E8")
            self.assertEqual(len(parsed["bitflips"]), 1)
            self.assertEqual(parsed["bitflips"][0], ("RCX", 0xFEFFDF87873AF040, 56, 0xFFFFDF87873AF040))
            self.assertEqual(parsed["stack_symbols"][0][2], "ntoskrnl.exe+0x205EF5")

            summary = summarize_minidump_results([parsed])
            self.assertEqual(summary["verdict"], "HARDWARE_DRAM_BITFLIP_CONFIRMED")
            self.assertEqual(summary["flipped_bit_histogram"], {"bit_56": 1})

            # Truncated PAGEDU64 dump must raise clean ValueError rather than struct.error
            trunc_path = Path(tmp) / "truncated.dmp"
            trunc_path.write_bytes(b"PAGEDU64" + b"\x00" * 32)
            with self.assertRaises(ValueError):
                parse_minidump(str(trunc_path))


class TestDramClusterAndHunterMath(unittest.TestCase):
    def test_infer_dram_row_twins_and_imc_synthesis(self) -> None:
        twins = infer_dram_row_twins([0x2C008B])
        self.assertIn(0x2C008B, twins)
        self.assertIn(0x2C008D, twins)
        self.assertEqual(0x2C008B ^ 6, 0x2C008D)

        bank_family = synthesize_imc_bank_pfns([0x2C008B])
        self.assertGreater(len(bank_family), 10)
        self.assertIn(0x2C008B, bank_family)

    def test_analyze_pfn_clusters_and_snapshot_diff(self) -> None:
        clean = analyze_pfn_clusters([], total_ram_gb=64.0)
        self.assertEqual(clean["health_score"], 100)
        self.assertEqual(clean["severity"], "CLEAN")

        # 0x2C008B without its 0x2C008D twin should report missing twin
        partial = analyze_pfn_clusters([0x2C008B], total_ram_gb=64.0)
        self.assertEqual(partial["missing_row_twins"], ["0x2c008d"])
        self.assertEqual(partial["severity"], "CONTAINED_CLUSTER")

        paired = analyze_pfn_clusters([0x2C008B, 0x2C008D], total_ram_gb=64.0)
        self.assertEqual(paired["missing_row_twins"], [])

        snap_old = {
            "isolated_pfns_hex": ["0x2c008b", "0x2c008d"],
            "excised_pfns_hex": [],
            "physical_ranges": [{"index": 0}],
            "cluster_analysis": paired,
        }
        snap_new = {
            "isolated_pfns_hex": ["0x2c008b", "0x2c008d", "0x6c28cb", "0x6c28cd"],
            "excised_pfns_hex": ["0x2c008b", "0x2c008d"],
            "physical_ranges": [{"index": 0}, {"index": 1}, {"index": 2}],
            "cluster_analysis": analyze_pfn_clusters(
                [0x2C008B, 0x2C008D, 0x6C28CB, 0x6C28CD], total_ram_gb=64.0
            ),
        }
        diff = diff_status_snapshots(snap_old, snap_new)
        self.assertEqual(diff["status"], "EXPANDED_NEW_BAND")
        self.assertEqual(diff["added_pfns_hex"], ["0x6c28cb", "0x6c28cd"])
        self.assertEqual(diff["newly_excised_pfns_hex"], ["0x2c008b", "0x2c008d"])

    def test_compute_decommit_spans_and_autotune(self) -> None:
        base = 0x10000000
        block_sz = 10 * 4096  # 10 pages
        # Bad pages at page 2 and page 7 -> healthy spans [0..2), [3..7), [8..10)
        spans = compute_decommit_spans(base, block_sz, [base + 2 * 4096, base + 7 * 4096])
        self.assertEqual(
            spans,
            [
                (base, 2 * 4096),
                (base + 3 * 4096, 4 * 4096),
                (base + 8 * 4096, 2 * 4096),
            ],
        )
        rec = recommend_hunter_params()
        self.assertGreaterEqual(rec["window_batches"], 2)
        self.assertGreater(rec["batch_gb"], 0.0)


if __name__ == "__main__":
    unittest.main()
