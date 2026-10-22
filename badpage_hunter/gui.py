import ctypes
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional, Set

from . import __version__
from .bcd_manager import (
    clear_bcd_badmemory,
    get_existing_bad_pfns,
    infer_dram_row_twins,
    is_admin,
    remove_bcd_badmemory_pfns,
    update_bcd_badmemory,
)
from .dmp_analyzer import analyze_minidump_directory, parse_minidump
from .hunter import BadPageHunter, get_memory_status, recommend_hunter_params
from .pfn_resolver import (
    enable_privileges,
    get_kernel_physical_memory_ranges,
    query_pfn_database_status,
)

# Color Palette (Modern Dark Hardware Diagnostics Theme)
BG_ROOT = "#0B1120"
BG_PANEL = "#111827"
BG_CARD = "#1E293B"
BG_INPUT = "#0F172A"
FG_PRIMARY = "#F8FAFC"
FG_SECONDARY = "#94A3B8"
FG_MUTED = "#64748B"
ACCENT_BLUE = "#38BDF8"
ACCENT_HOVER = "#0284C7"
COLOR_OK = "#22C55E"
COLOR_WARN = "#F59E0B"
COLOR_DANGER = "#EF4444"
BORDER_COLOR = "#334155"


I18N: Dict[str, Dict[str, str]] = {
    "zh": {
        "app_title": f"Win-BadPage-Hunter v{__version__} — 内存位翻转猎手与内核级物理坏页隔离工具",
        "header_subtitle": "用户态 DRAM 电荷衰减位翻转猎手 · PAGEDU64 蓝屏转储取证 · Windows BCD {badmemory} 物理页帧手术刀",
        "admin_ok": "✔ 管理员权限 & Superfetch 已就绪",
        "admin_no": "⚠ 当前非管理员权限 (点击以管理员身份重启)",
        "lang_btn": "🌐 English",
        "ram_status_fmt": "物理内存: 可用 {avail:.2f} GB / 总计 {total:.2f} GB (负载 {load}%)",
        "tab_status": " 📊 内核与物理内存概览 ",
        "tab_hunter": " 🎯 实时坏页猎手 (DRAM Hunter) ",
        "tab_dmp": " 🔍 蓝屏转储取证 (Minidump) ",
        "tab_bcd": " 🛡️ BCD 坏页隔离管理 ",
        # Status tab
        "card_ram_title": "系统物理内存 (RAM)",
        "card_ranges_title": "内核物理内存活动段",
        "card_isolated_title": "BCD 已隔离坏页总数",
        "card_excised_title": "引导层已切除 (_MMPFN)",
        "btn_refresh_status": "🔄 刷新内核与 BCD 状态",
        "lbl_phys_ranges": "MmPhysicalMemoryBlock 活动物理内存段 (注册表 .Translated)",
        "lbl_pfn_verify": "Windows BCD {badmemory} 坏页在内核 _MMPFN 数据库中的实时状态",
        "col_range_id": "段序号",
        "col_start_pfn": "起始 PFN",
        "col_end_pfn": "结束 PFN",
        "col_pages": "页数 (4KB)",
        "col_size_mb": "容量 (MB)",
        "col_pfn": "PFN (Hex)",
        "col_phys_addr": "物理地址 (PhysAddr)",
        "col_row_group": "DRAM 行簇 (PFN>>3)",
        "col_offset": "簇内偏移",
        "col_kernel_state": "内核状态 (_MMPFN)",
        "state_excised": "✔ 已由引导层切除 (0xC00000F0)",
        "state_staged": "⏳ 已写入 BCD (重启后切除)",
        # Hunter tab
        "lbl_hunter_cfg": "FIFO 滑动窗口电荷保持扫描参数",
        "lbl_window_batches": "滑动窗口批次数 (Batches):",
        "lbl_batch_gb": "单批次容量 (GB):",
        "lbl_block_mb": "单块分配粒度 (MB):",
        "lbl_min_avail_gb": "系统保底空闲内存 (GB):",
        "lbl_soak_sec": "电荷保持静置时间 (秒):",
        "lbl_max_cycles": "最大循环轮次 (0=持续运行):",
        "chk_row_twins": "捕获坏页时自动推导并隔离同簇 +3/+5 耦合孪生页 (PFN ^ 6)",
        "btn_autotune": "⚡ 智能推荐本机参数",
        "btn_start_hunt": "▶ 启动实时坏页猎手",
        "btn_stop_hunt": "⏹ 停止并释放测试内存",
        "btn_clear_log": "🧹 清空日志",
        "btn_export_log": "💾 导出日志",
        "stat_cycle": "当前扫描轮次",
        "stat_window": "活动窗口占用",
        "stat_flips": "捕获位翻转数",
        "stat_new_pfns": "本次新增坏页",
        "stat_pinned": "运行期锁定页 (VirtualLock)",
        "phase_idle": "就绪 — 点击「启动实时坏页猎手」开始后台低内存滑动窗口扫描",
        # Dmp tab
        "lbl_dmp_dir": "蓝屏转储目录 / 文件:",
        "btn_browse_dir": "📂 选择目录",
        "btn_browse_file": "📄 选择单个 .dmp",
        "btn_analyze_dmp": "🔍 扫描并分析转储",
        "col_dmp_file": "转储文件名",
        "col_dmp_os": "OS 版本",
        "col_dmp_bugcheck": "蓝屏代码 (BugCheck)",
        "col_dmp_rip": "崩溃地址 (RIP)",
        "col_dmp_verdict": "硬件单比特翻转判定",
        "verdict_flip": "🚨 检测到硬件位翻转 ({count} 处)",
        "verdict_clean": "✔ 未见高16位非规范指针翻转",
        "verdict_error": "❌ 解析失败: {err}",
        "lbl_dmp_detail": "转储取证详情 (CPU 寄存器上下文、非规范指针位翻转还原与调用栈)",
        # BCD tab
        "lbl_bcd_input": "手动添加隔离 PFN (支持十六进制如 0x2c008d 或十进制，以空格/逗号分隔):",
        "btn_bcd_add": "➕ 写入 BCD 隔离列表",
        "btn_bcd_preview": "🔍 预览 +3/+5 孪生推导",
        "btn_bcd_remove": "🗑 移除选中 PFN",
        "btn_bcd_clear": "🧹 清空全部 BCD 坏页",
        "btn_bcd_export": "📤 导出坏页列表",
        "btn_bcd_import": "📥 导入坏页列表",
        "btn_bcd_copy_cmd": "📋 复制 bcdedit 命令",
        "col_idx": "#",
        "col_pfn_dec": "PFN (十进制)",
        "col_twin": "配对孪生页 (PFN^6)",
        "col_twin_status": "孪生页状态",
        "twin_included": "✔ 已同时隔离",
        "twin_missing": "⚠ 未隔离",
        "twin_na": "非 +3/+5 偏移",
        "reboot_notice": "💡 提示：修改 Windows BCD {badmemory} 后，请重启一次电脑，以便 winload.efi 在内核初始化阶段将坏页从物理内存映射表中彻底切除。",
    },
    "en": {
        "app_title": f"Win-BadPage-Hunter v{__version__} — DRAM Bit-Flip Hunter & Kernel BCD Page Isolator",
        "header_subtitle": "User-Mode DRAM Charge-Retention Hunter · PAGEDU64 BSOD Forensics · Windows BCD {badmemory} Excision",
        "admin_ok": "✔ Administrator & Superfetch Ready",
        "admin_no": "⚠ Not Elevated (Click to Restart as Admin)",
        "lang_btn": "🌐 中文",
        "ram_status_fmt": "Physical RAM: {avail:.2f} GB Free / {total:.2f} GB Total ({load}% Load)",
        "tab_status": " 📊 Kernel & Memory Status ",
        "tab_hunter": " 🎯 Live DRAM Bit-Flip Hunter ",
        "tab_dmp": " 🔍 BSOD Minidump Analyzer ",
        "tab_bcd": " 🛡️ BCD {badmemory} Manager ",
        # Status tab
        "card_ram_title": "System Physical RAM",
        "card_ranges_title": "Active Kernel Memory Ranges",
        "card_isolated_title": "BCD Isolated Bad Pages",
        "card_excised_title": "Bootloader Excised (_MMPFN)",
        "btn_refresh_status": "🔄 Refresh Kernel & BCD Status",
        "lbl_phys_ranges": "MmPhysicalMemoryBlock Active Descriptor Ranges (Registry .Translated)",
        "lbl_pfn_verify": "Live Kernel _MMPFN Database Verification for BCD {badmemory} PFNs",
        "col_range_id": "Range #",
        "col_start_pfn": "Start PFN",
        "col_end_pfn": "End PFN",
        "col_pages": "Pages (4KB)",
        "col_size_mb": "Size (MB)",
        "col_pfn": "PFN (Hex)",
        "col_phys_addr": "Physical Address",
        "col_row_group": "DRAM Row Group (PFN>>3)",
        "col_offset": "Row Offset",
        "col_kernel_state": "Kernel _MMPFN Status",
        "state_excised": "✔ EXCISED_BY_BOOTLOADER (0xC00000F0)",
        "state_staged": "⏳ STAGED_PENDING_REBOOT",
        # Hunter tab
        "lbl_hunter_cfg": "FIFO Sliding-Window Charge-Retention Hunter Configuration",
        "lbl_window_batches": "Sliding Window Batches:",
        "lbl_batch_gb": "Batch Size (GB):",
        "lbl_block_mb": "Block Allocation Size (MB):",
        "lbl_min_avail_gb": "Safety Free RAM Floor (GB):",
        "lbl_soak_sec": "Retention Soak Duration (s):",
        "lbl_max_cycles": "Max Cycles (0 = Continuous):",
        "chk_row_twins": "Automatically infer & isolate coupled +3/+5 DRAM row-twin pages (PFN ^ 6)",
        "btn_autotune": "⚡ Auto-Tune for This PC",
        "btn_start_hunt": "▶ Start Bit-Flip Hunter",
        "btn_stop_hunt": "⏹ Stop & Release Buffers",
        "btn_clear_log": "🧹 Clear Log",
        "btn_export_log": "💾 Export Log",
        "stat_cycle": "Current Cycle",
        "stat_window": "Active Window",
        "stat_flips": "Bit-Flips Caught",
        "stat_new_pfns": "Newly Isolated PFNs",
        "stat_pinned": "Runtime Pinned (VirtualLock)",
        "phase_idle": "Ready — Click 'Start Bit-Flip Hunter' to begin low-memory FIFO retention scanning",
        # Dmp tab
        "lbl_dmp_dir": "Minidump Folder / File:",
        "btn_browse_dir": "📂 Browse Folder",
        "btn_browse_file": "📄 Single .dmp File",
        "btn_analyze_dmp": "🔍 Analyze Minidumps",
        "col_dmp_file": "Dump File",
        "col_dmp_os": "OS Build",
        "col_dmp_bugcheck": "BugCheck Code",
        "col_dmp_rip": "Crash RIP",
        "col_dmp_verdict": "Hardware Bit-Flip Verdict",
        "verdict_flip": "🚨 HARDWARE BIT-FLIP DETECTED ({count})",
        "verdict_clean": "✔ No upper-bit non-canonical flip",
        "verdict_error": "❌ Parse Error: {err}",
        "lbl_dmp_detail": "Forensic Inspection (CPU Register Context, Non-Canonical Bit-Flip Repair & Call Stack)",
        # BCD tab
        "lbl_bcd_input": "Add PFNs to Isolate (Hex e.g. 0x2c008d or Decimal, comma/space separated):",
        "btn_bcd_add": "➕ Isolate in BCD {badmemory}",
        "btn_bcd_preview": "🔍 Preview +3/+5 Row Twins",
        "btn_bcd_remove": "🗑 Remove Selected PFNs",
        "btn_bcd_clear": "🧹 Clear All BCD Bad Pages",
        "btn_bcd_export": "📤 Export PFN List",
        "btn_bcd_import": "📥 Import PFN List",
        "btn_bcd_copy_cmd": "📋 Copy bcdedit Command",
        "col_idx": "#",
        "col_pfn_dec": "PFN (Dec)",
        "col_twin": "Row Twin (PFN^6)",
        "col_twin_status": "Twin Status",
        "twin_included": "✔ Isolated Together",
        "twin_missing": "⚠ Twin Not Isolated",
        "twin_na": "Non +3/+5 Offset",
        "reboot_notice": "💡 Tip: After modifying Windows BCD {badmemory}, reboot Windows once so winload.efi excises those physical frames from MmPhysicalMemoryBlock.",
    },
}


def enable_dpi_and_dark_mode() -> None:
    """Enable High-DPI scaling on Windows so the UI looks crisp on 1080p/2K/4K screens."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def apply_dark_titlebar(root: tk.Tk) -> None:
    """Enable Windows 10/11 Immersive Dark Mode on the native window titlebar."""
    if sys.platform != "win32":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        if not hwnd:
            hwnd = root.winfo_id()
        val = ctypes.c_int(1)
        # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Win10 20H1+ & Win11)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(val), ctypes.sizeof(val))
    except Exception:
        pass


def resource_path(rel_path: str) -> str:
    """Resolve resource path both in normal Python execution and inside PyInstaller _MEIPASS."""
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    return os.path.join(base, rel_path)


class BadPageHunterGUI:
    def __init__(self, root: tk.Tk, lang: str = "zh") -> None:
        self.root = root
        self.lang = lang
        self.ui_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self.hunter: Optional[BadPageHunter] = None
        self.hunter_thread: Optional[threading.Thread] = None
        self.dmp_results: List[Dict[str, Any]] = []

        enable_privileges()
        self._setup_window()
        self._setup_styles()
        self._build_ui()
        apply_dark_titlebar(self.root)

        self.on_autotune(silent=True)
        self.refresh_status_and_bcd()
        self.run_dmp_analysis()
        self._schedule_periodic_tasks()

    def t(self, key: str) -> str:
        return I18N.get(self.lang, I18N["zh"]).get(key, key)

    def _setup_window(self) -> None:
        self.root.title(self.t("app_title"))
        self.root.geometry("1220x820")
        self.root.minsize(1024, 700)
        self.root.configure(bg=BG_ROOT)
        icon_file = resource_path(os.path.join("assets", "icon.ico"))
        if os.path.exists(icon_file):
            try:
                self.root.iconbitmap(icon_file)
            except Exception:
                pass
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=BG_ROOT, foreground=FG_PRIMARY, font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background=BG_ROOT)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("Card.TFrame", background=BG_CARD)

        style.configure("TLabel", background=BG_ROOT, foreground=FG_PRIMARY, font=("Microsoft YaHei UI", 10))
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_PRIMARY, font=("Microsoft YaHei UI", 10))
        style.configure("Muted.TLabel", background=BG_PANEL, foreground=FG_SECONDARY, font=("Microsoft YaHei UI", 9))
        style.configure("CardTitle.TLabel", background=BG_CARD, foreground=FG_SECONDARY, font=("Microsoft YaHei UI", 9))
        style.configure("CardValue.TLabel", background=BG_CARD, foreground=ACCENT_BLUE, font=("Consolas", 16, "bold"))

        # Notebook
        style.configure(
            "TNotebook",
            background=BG_ROOT,
            borderwidth=0,
            tabmargins=[4, 6, 4, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=BG_CARD,
            foreground=FG_SECONDARY,
            padding=[16, 9],
            font=("Microsoft YaHei UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT_BLUE), ("active", "#334155")],
            foreground=[("selected", "#0B1120"), ("active", FG_PRIMARY)],
        )

        # Treeview
        style.configure(
            "Treeview",
            background=BG_INPUT,
            fieldbackground=BG_INPUT,
            foreground=FG_PRIMARY,
            rowheight=28,
            borderwidth=1,
            font=("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=BG_CARD,
            foreground=FG_PRIMARY,
            font=("Microsoft YaHei UI", 9, "bold"),
            padding=[6, 6],
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#0369A1")],
            foreground=[("selected", "#FFFFFF")],
        )
        style.map("Treeview.Heading", background=[("active", "#334155")])

        # Buttons
        style.configure(
            "Accent.TButton",
            background=ACCENT_BLUE,
            foreground="#0B1120",
            font=("Microsoft YaHei UI", 10, "bold"),
            padding=[14, 7],
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", ACCENT_HOVER), ("disabled", "#334155")],
            foreground=[("disabled", FG_MUTED)],
        )

        style.configure(
            "Danger.TButton",
            background=COLOR_DANGER,
            foreground="#FFFFFF",
            font=("Microsoft YaHei UI", 10, "bold"),
            padding=[14, 7],
            borderwidth=0,
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#DC2626"), ("disabled", "#334155")],
            foreground=[("disabled", FG_MUTED)],
        )

        style.configure(
            "Secondary.TButton",
            background=BG_CARD,
            foreground=FG_PRIMARY,
            font=("Microsoft YaHei UI", 9),
            padding=[12, 6],
            borderwidth=1,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#334155"), ("disabled", "#1E293B")],
            foreground=[("disabled", FG_MUTED)],
        )

        # Progressbar
        style.configure(
            "Cyan.Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            background=ACCENT_BLUE,
            bordercolor=BG_INPUT,
            lightcolor=ACCENT_BLUE,
            darkcolor=ACCENT_BLUE,
            thickness=12,
        )

        # Checkbutton
        style.configure(
            "Panel.TCheckbutton",
            background=BG_PANEL,
            foreground=FG_PRIMARY,
            font=("Microsoft YaHei UI", 10),
        )
        style.map("Panel.TCheckbutton", background=[("active", BG_PANEL)])

    def _build_ui(self) -> None:
        # 1. Top Header Bar
        header = tk.Frame(self.root, bg=BG_PANEL, padx=18, pady=12, highlightthickness=1, highlightbackground=BORDER_COLOR)
        header.pack(fill="x", side="top")

        title_box = tk.Frame(header, bg=BG_PANEL)
        title_box.pack(side="left", fill="y")

        self.lbl_main_title = tk.Label(
            title_box,
            text=f"⚡ Win-BadPage-Hunter v{__version__}",
            bg=BG_PANEL,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 16, "bold"),
        )
        self.lbl_main_title.pack(anchor="w")

        self.lbl_subtitle = tk.Label(
            title_box,
            text=self.t("header_subtitle"),
            bg=BG_PANEL,
            fg=FG_SECONDARY,
            font=("Microsoft YaHei UI", 9),
        )
        self.lbl_subtitle.pack(anchor="w", pady=(2, 0))

        right_box = tk.Frame(header, bg=BG_PANEL)
        right_box.pack(side="right", fill="y")

        top_btn_row = tk.Frame(right_box, bg=BG_PANEL)
        top_btn_row.pack(anchor="e")

        admin_flag = is_admin()
        self.btn_admin = tk.Button(
            top_btn_row,
            text=self.t("admin_ok") if admin_flag else self.t("admin_no"),
            bg="#14532D" if admin_flag else "#78350F",
            fg="#86EFAC" if admin_flag else "#FDE68A",
            activebackground="#166534" if admin_flag else "#92400E",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=10,
            pady=4,
            font=("Microsoft YaHei UI", 9, "bold"),
            cursor="hand2" if not admin_flag else "arrow",
            command=self._relaunch_as_admin if not admin_flag else lambda: None,
        )
        self.btn_admin.pack(side="left", padx=(0, 8))

        self.btn_lang = tk.Button(
            top_btn_row,
            text=self.t("lang_btn"),
            bg=BG_CARD,
            fg=FG_PRIMARY,
            activebackground="#334155",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=10,
            pady=4,
            font=("Microsoft YaHei UI", 9),
            cursor="hand2",
            command=self.toggle_language,
        )
        self.btn_lang.pack(side="left")

        self.lbl_ram_header = tk.Label(
            right_box,
            text="",
            bg=BG_PANEL,
            fg=FG_PRIMARY,
            font=("Consolas", 10, "bold"),
        )
        self.lbl_ram_header.pack(anchor="e", pady=(6, 0))

        # 2. Notebook Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(8, 14))

        self.tab_status = ttk.Frame(self.notebook, style="Panel.TFrame")
        self.tab_hunter = ttk.Frame(self.notebook, style="Panel.TFrame")
        self.tab_dmp = ttk.Frame(self.notebook, style="Panel.TFrame")
        self.tab_bcd = ttk.Frame(self.notebook, style="Panel.TFrame")

        self.notebook.add(self.tab_status, text=self.t("tab_status"))
        self.notebook.add(self.tab_hunter, text=self.t("tab_hunter"))
        self.notebook.add(self.tab_dmp, text=self.t("tab_dmp"))
        self.notebook.add(self.tab_bcd, text=self.t("tab_bcd"))

        self._build_tab_status()
        self._build_tab_hunter()
        self._build_tab_dmp()
        self._build_tab_bcd()

    # =========================================================================
    # TAB 1: Kernel & Physical Memory Status
    # =========================================================================
    def _build_tab_status(self) -> None:
        container = tk.Frame(self.tab_status, bg=BG_PANEL, padx=14, pady=14)
        container.pack(fill="both", expand=True)

        # Top 4 KPI Cards
        cards_row = tk.Frame(container, bg=BG_PANEL)
        cards_row.pack(fill="x", pady=(0, 12))
        for i in range(4):
            cards_row.columnconfigure(i, weight=1)

        self.card_ram_lbl, self.card_ram_val = self._make_kpi_card(cards_row, 0, self.t("card_ram_title"), "--")
        self.card_ranges_lbl, self.card_ranges_val = self._make_kpi_card(cards_row, 1, self.t("card_ranges_title"), "--")
        self.card_isolated_lbl, self.card_isolated_val = self._make_kpi_card(cards_row, 2, self.t("card_isolated_title"), "--")
        self.card_excised_lbl, self.card_excised_val = self._make_kpi_card(cards_row, 3, self.t("card_excised_title"), "--")

        # Action Toolbar
        bar = tk.Frame(container, bg=BG_PANEL)
        bar.pack(fill="x", pady=(0, 10))
        self.btn_refresh_status = ttk.Button(
            bar, text=self.t("btn_refresh_status"), style="Accent.TButton", command=self.refresh_status_and_bcd
        )
        self.btn_refresh_status.pack(side="left")

        self.lbl_reboot_tip_status = tk.Label(
            bar, text=self.t("reboot_notice"), bg=BG_PANEL, fg=FG_SECONDARY, font=("Microsoft YaHei UI", 9)
        )
        self.lbl_reboot_tip_status.pack(side="left", padx=14)

        # Split Panes for Physical Memory Ranges & _MMPFN Verification
        split = tk.Frame(container, bg=BG_PANEL)
        split.pack(fill="both", expand=True)
        split.columnconfigure(0, weight=5)
        split.columnconfigure(1, weight=6)
        split.rowconfigure(0, weight=1)

        # Left: Kernel Physical Memory Map
        left_frame = tk.Frame(split, bg=BG_PANEL)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.lbl_phys_ranges = tk.Label(
            left_frame, text=self.t("lbl_phys_ranges"), bg=BG_PANEL, fg=ACCENT_BLUE, font=("Microsoft YaHei UI", 10, "bold")
        )
        self.lbl_phys_ranges.pack(anchor="w", pady=(0, 6))

        cols_range = ("idx", "start", "end", "pages", "mb")
        self.tree_ranges = ttk.Treeview(left_frame, columns=cols_range, show="headings", selectmode="browse")
        self.tree_ranges.heading("idx", text=self.t("col_range_id"))
        self.tree_ranges.heading("start", text=self.t("col_start_pfn"))
        self.tree_ranges.heading("end", text=self.t("col_end_pfn"))
        self.tree_ranges.heading("pages", text=self.t("col_pages"))
        self.tree_ranges.heading("mb", text=self.t("col_size_mb"))
        self.tree_ranges.column("idx", width=65, anchor="center")
        self.tree_ranges.column("start", width=110, anchor="center")
        self.tree_ranges.column("end", width=110, anchor="center")
        self.tree_ranges.column("pages", width=105, anchor="e")
        self.tree_ranges.column("mb", width=95, anchor="e")

        sb_ranges = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree_ranges.yview)
        self.tree_ranges.configure(yscrollcommand=sb_ranges.set)
        self.tree_ranges.pack(side="left", fill="both", expand=True)
        sb_ranges.pack(side="right", fill="y")

        # Right: _MMPFN Verification
        right_frame = tk.Frame(split, bg=BG_PANEL)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.lbl_pfn_verify = tk.Label(
            right_frame, text=self.t("lbl_pfn_verify"), bg=BG_PANEL, fg=ACCENT_BLUE, font=("Microsoft YaHei UI", 10, "bold")
        )
        self.lbl_pfn_verify.pack(anchor="w", pady=(0, 6))

        cols_verify = ("pfn", "phys", "group", "offset", "state")
        self.tree_verify = ttk.Treeview(right_frame, columns=cols_verify, show="headings", selectmode="browse")
        self.tree_verify.heading("pfn", text=self.t("col_pfn"))
        self.tree_verify.heading("phys", text=self.t("col_phys_addr"))
        self.tree_verify.heading("group", text=self.t("col_row_group"))
        self.tree_verify.heading("offset", text=self.t("col_offset"))
        self.tree_verify.heading("state", text=self.t("col_kernel_state"))
        self.tree_verify.column("pfn", width=95, anchor="center")
        self.tree_verify.column("phys", width=135, anchor="center")
        self.tree_verify.column("group", width=115, anchor="center")
        self.tree_verify.column("offset", width=75, anchor="center")
        self.tree_verify.column("state", width=220, anchor="w")
        self.tree_verify.tag_configure("excised", foreground=COLOR_OK)
        self.tree_verify.tag_configure("staged", foreground=COLOR_WARN)

        sb_verify = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree_verify.yview)
        self.tree_verify.configure(yscrollcommand=sb_verify.set)
        self.tree_verify.pack(side="left", fill="both", expand=True)
        sb_verify.pack(side="right", fill="y")

    def _make_kpi_card(self, parent: tk.Widget, col: int, title: str, initial_val: str) -> tuple[tk.Label, tk.Label]:
        card = tk.Frame(parent, bg=BG_CARD, padx=14, pady=10, highlightthickness=1, highlightbackground=BORDER_COLOR)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 6, 0 if col == 3 else 6))
        lbl_t = tk.Label(card, text=title, bg=BG_CARD, fg=FG_SECONDARY, font=("Microsoft YaHei UI", 9))
        lbl_t.pack(anchor="w")
        lbl_v = tk.Label(card, text=initial_val, bg=BG_CARD, fg=ACCENT_BLUE, font=("Consolas", 15, "bold"))
        lbl_v.pack(anchor="w", pady=(4, 0))
        return lbl_t, lbl_v

    # =========================================================================
    # TAB 2: Live DRAM Bit-Flip Hunter
    # =========================================================================
    def _build_tab_hunter(self) -> None:
        container = tk.Frame(self.tab_hunter, bg=BG_PANEL, padx=14, pady=14)
        container.pack(fill="both", expand=True)

        # Config Box
        cfg_box = tk.Frame(container, bg=BG_CARD, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER_COLOR)
        cfg_box.pack(fill="x", pady=(0, 12))

        self.lbl_hunter_cfg = tk.Label(
            cfg_box, text=self.t("lbl_hunter_cfg"), bg=BG_CARD, fg=ACCENT_BLUE, font=("Microsoft YaHei UI", 10, "bold")
        )
        self.lbl_hunter_cfg.pack(anchor="w", pady=(0, 8))

        grid_f = tk.Frame(cfg_box, bg=BG_CARD)
        grid_f.pack(fill="x")

        self.var_window_batches = tk.StringVar(value="3")
        self.var_batch_gb = tk.StringVar(value="2.0")
        self.var_block_mb = tk.StringVar(value="128")
        self.var_min_avail_gb = tk.StringVar(value="8.0")
        self.var_soak_sec = tk.StringVar(value="10.0")
        self.var_max_cycles = tk.StringVar(value="0")
        self.var_row_twins = tk.BooleanVar(value=True)

        self.lbl_w_batches = self._add_cfg_field(grid_f, 0, 0, self.t("lbl_window_batches"), self.var_window_batches)
        self.lbl_b_gb = self._add_cfg_field(grid_f, 0, 2, self.t("lbl_batch_gb"), self.var_batch_gb)
        self.lbl_blk_mb = self._add_cfg_field(grid_f, 0, 4, self.t("lbl_block_mb"), self.var_block_mb)
        self.lbl_min_av = self._add_cfg_field(grid_f, 1, 0, self.t("lbl_min_avail_gb"), self.var_min_avail_gb)
        self.lbl_soak = self._add_cfg_field(grid_f, 1, 2, self.t("lbl_soak_sec"), self.var_soak_sec)
        self.lbl_max_c = self._add_cfg_field(grid_f, 1, 4, self.t("lbl_max_cycles"), self.var_max_cycles)

        ctrl_row = tk.Frame(cfg_box, bg=BG_CARD)
        ctrl_row.pack(fill="x", pady=(10, 0))

        self.chk_twins_widget = tk.Checkbutton(
            ctrl_row,
            text=self.t("chk_row_twins"),
            variable=self.var_row_twins,
            bg=BG_CARD,
            fg=FG_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=FG_PRIMARY,
            font=("Microsoft YaHei UI", 9),
        )
        self.chk_twins_widget.pack(side="left")

        btn_box = tk.Frame(ctrl_row, bg=BG_CARD)
        btn_box.pack(side="right")

        self.btn_autotune = ttk.Button(
            btn_box, text=self.t("btn_autotune"), style="Secondary.TButton", command=self.on_autotune
        )
        self.btn_autotune.pack(side="left", padx=(0, 8))

        self.btn_start_hunt = ttk.Button(
            btn_box, text=self.t("btn_start_hunt"), style="Accent.TButton", command=self.start_hunter
        )
        self.btn_start_hunt.pack(side="left", padx=(0, 8))

        self.btn_stop_hunt = ttk.Button(
            btn_box, text=self.t("btn_stop_hunt"), style="Danger.TButton", command=self.stop_hunter, state="disabled"
        )
        self.btn_stop_hunt.pack(side="left")

        # Live Telemetry Strip (5 mini cards)
        stats_row = tk.Frame(container, bg=BG_PANEL)
        stats_row.pack(fill="x", pady=(0, 8))
        for i in range(5):
            stats_row.columnconfigure(i, weight=1)

        self.lbl_st_cycle_t, self.lbl_st_cycle_v = self._make_mini_stat(stats_row, 0, self.t("stat_cycle"), "0")
        self.lbl_st_win_t, self.lbl_st_win_v = self._make_mini_stat(stats_row, 1, self.t("stat_window"), "0.00 GB")
        self.lbl_st_flips_t, self.lbl_st_flips_v = self._make_mini_stat(stats_row, 2, self.t("stat_flips"), "0")
        self.lbl_st_new_t, self.lbl_st_new_v = self._make_mini_stat(stats_row, 3, self.t("stat_new_pfns"), "0")
        self.lbl_st_pin_t, self.lbl_st_pin_v = self._make_mini_stat(stats_row, 4, self.t("stat_pinned"), "0")

        # Phase + Soak Progress Bar
        prog_frame = tk.Frame(container, bg=BG_PANEL)
        prog_frame.pack(fill="x", pady=(0, 8))

        self.lbl_hunter_phase = tk.Label(
            prog_frame, text=self.t("phase_idle"), bg=BG_PANEL, fg=ACCENT_BLUE, font=("Consolas", 10, "bold")
        )
        self.lbl_hunter_phase.pack(side="left")

        btn_log_box = tk.Frame(prog_frame, bg=BG_PANEL)
        btn_log_box.pack(side="right")
        self.btn_clear_log = ttk.Button(
            btn_log_box, text=self.t("btn_clear_log"), style="Secondary.TButton", command=self.clear_hunter_log
        )
        self.btn_clear_log.pack(side="left", padx=(0, 6))
        self.btn_export_log = ttk.Button(
            btn_log_box, text=self.t("btn_export_log"), style="Secondary.TButton", command=self.export_hunter_log
        )
        self.btn_export_log.pack(side="left")

        self.soak_progress = ttk.Progressbar(
            container, style="Cyan.Horizontal.TProgressbar", orient="horizontal", mode="determinate", maximum=100.0
        )
        self.soak_progress.pack(fill="x", pady=(0, 8))

        # Log Console
        log_wrap = tk.Frame(container, bg=BG_INPUT, highlightthickness=1, highlightbackground=BORDER_COLOR)
        log_wrap.pack(fill="both", expand=True)

        self.txt_hunter_log = tk.Text(
            log_wrap,
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=8,
            state="disabled",
        )
        self.txt_hunter_log.tag_configure("flip", foreground=COLOR_DANGER, font=("Consolas", 10, "bold"))
        self.txt_hunter_log.tag_configure("bcd", foreground=COLOR_OK, font=("Consolas", 10, "bold"))
        self.txt_hunter_log.tag_configure("banner", foreground=ACCENT_BLUE, font=("Consolas", 10, "bold"))
        self.txt_hunter_log.tag_configure("normal", foreground=FG_PRIMARY)

        sb_log = ttk.Scrollbar(log_wrap, orient="vertical", command=self.txt_hunter_log.yview)
        self.txt_hunter_log.configure(yscrollcommand=sb_log.set)
        self.txt_hunter_log.pack(side="left", fill="both", expand=True)
        sb_log.pack(side="right", fill="y")

    def _add_cfg_field(self, parent: tk.Widget, r: int, c: int, label_text: str, var: tk.StringVar) -> tk.Label:
        lbl = tk.Label(parent, text=label_text, bg=BG_CARD, fg=FG_SECONDARY, font=("Microsoft YaHei UI", 9))
        lbl.grid(row=r, column=c, sticky="w", padx=(0 if c == 0 else 16, 6), pady=4)
        ent = tk.Entry(
            parent,
            textvariable=var,
            width=10,
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            relief="flat",
            font=("Consolas", 10, "bold"),
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            highlightcolor=ACCENT_BLUE,
        )
        ent.grid(row=r, column=c + 1, sticky="w", pady=4)
        return lbl

    def _make_mini_stat(self, parent: tk.Widget, col: int, title: str, val: str) -> tuple[tk.Label, tk.Label]:
        card = tk.Frame(parent, bg=BG_CARD, padx=10, pady=8, highlightthickness=1, highlightbackground=BORDER_COLOR)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 5, 0 if col == 4 else 5))
        lt = tk.Label(card, text=title, bg=BG_CARD, fg=FG_SECONDARY, font=("Microsoft YaHei UI", 8))
        lt.pack(anchor="w")
        lv = tk.Label(card, text=val, bg=BG_CARD, fg=FG_PRIMARY, font=("Consolas", 13, "bold"))
        lv.pack(anchor="w", pady=(2, 0))
        return lt, lv

    # =========================================================================
    # TAB 3: BSOD Minidump Analyzer
    # =========================================================================
    def _build_tab_dmp(self) -> None:
        container = tk.Frame(self.tab_dmp, bg=BG_PANEL, padx=14, pady=14)
        container.pack(fill="both", expand=True)

        top_bar = tk.Frame(container, bg=BG_CARD, padx=12, pady=10, highlightthickness=1, highlightbackground=BORDER_COLOR)
        top_bar.pack(fill="x", pady=(0, 10))

        self.lbl_dmp_dir = tk.Label(top_bar, text=self.t("lbl_dmp_dir"), bg=BG_CARD, fg=FG_PRIMARY, font=("Microsoft YaHei UI", 9))
        self.lbl_dmp_dir.pack(side="left", padx=(0, 8))

        self.var_dmp_path = tk.StringVar(value=r"C:\Windows\Minidump")
        ent_dmp = tk.Entry(
            top_bar,
            textvariable=self.var_dmp_path,
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            relief="flat",
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        ent_dmp.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=4)

        self.btn_browse_dir = ttk.Button(
            top_bar, text=self.t("btn_browse_dir"), style="Secondary.TButton", command=self.browse_dmp_folder
        )
        self.btn_browse_dir.pack(side="left", padx=(0, 6))

        self.btn_browse_file = ttk.Button(
            top_bar, text=self.t("btn_browse_file"), style="Secondary.TButton", command=self.browse_dmp_file
        )
        self.btn_browse_file.pack(side="left", padx=(0, 6))

        self.btn_analyze_dmp = ttk.Button(
            top_bar, text=self.t("btn_analyze_dmp"), style="Accent.TButton", command=self.run_dmp_analysis
        )
        self.btn_analyze_dmp.pack(side="left")

        # Upper Treeview: Dump List
        tree_wrap = tk.Frame(container, bg=BG_PANEL, height=220)
        tree_wrap.pack(fill="x", pady=(0, 10))

        cols_dmp = ("file", "os", "bugcheck", "rip", "verdict")
        self.tree_dmp = ttk.Treeview(tree_wrap, columns=cols_dmp, show="headings", height=7, selectmode="browse")
        self.tree_dmp.heading("file", text=self.t("col_dmp_file"))
        self.tree_dmp.heading("os", text=self.t("col_dmp_os"))
        self.tree_dmp.heading("bugcheck", text=self.t("col_dmp_bugcheck"))
        self.tree_dmp.heading("rip", text=self.t("col_dmp_rip"))
        self.tree_dmp.heading("verdict", text=self.t("col_dmp_verdict"))
        self.tree_dmp.column("file", width=200, anchor="w")
        self.tree_dmp.column("os", width=110, anchor="center")
        self.tree_dmp.column("bugcheck", width=280, anchor="w")
        self.tree_dmp.column("rip", width=240, anchor="w")
        self.tree_dmp.column("verdict", width=260, anchor="w")
        self.tree_dmp.tag_configure("flip", foreground=COLOR_DANGER)
        self.tree_dmp.tag_configure("clean", foreground=COLOR_OK)
        self.tree_dmp.tag_configure("error", foreground=COLOR_WARN)
        self.tree_dmp.bind("<<TreeviewSelect>>", self._on_dmp_selected)

        sb_dmp = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree_dmp.yview)
        self.tree_dmp.configure(yscrollcommand=sb_dmp.set)
        self.tree_dmp.pack(side="left", fill="both", expand=True)
        sb_dmp.pack(side="right", fill="y")

        # Lower Forensic Detail Viewer
        self.lbl_dmp_detail = tk.Label(
            container, text=self.t("lbl_dmp_detail"), bg=BG_PANEL, fg=ACCENT_BLUE, font=("Microsoft YaHei UI", 10, "bold")
        )
        self.lbl_dmp_detail.pack(anchor="w", pady=(0, 6))

        detail_wrap = tk.Frame(container, bg=BG_INPUT, highlightthickness=1, highlightbackground=BORDER_COLOR)
        detail_wrap.pack(fill="both", expand=True)

        self.txt_dmp_detail = tk.Text(
            detail_wrap,
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            font=("Consolas", 10),
            relief="flat",
            padx=12,
            pady=10,
            state="disabled",
        )
        self.txt_dmp_detail.tag_configure("alert", foreground=COLOR_DANGER, font=("Consolas", 10, "bold"))
        self.txt_dmp_detail.tag_configure("header", foreground=ACCENT_BLUE, font=("Consolas", 10, "bold"))
        self.txt_dmp_detail.tag_configure("ok", foreground=COLOR_OK, font=("Consolas", 10, "bold"))

        sb_det = ttk.Scrollbar(detail_wrap, orient="vertical", command=self.txt_dmp_detail.yview)
        self.txt_dmp_detail.configure(yscrollcommand=sb_det.set)
        self.txt_dmp_detail.pack(side="left", fill="both", expand=True)
        sb_det.pack(side="right", fill="y")

    # =========================================================================
    # TAB 4: BCD {badmemory} Isolator Manager
    # =========================================================================
    def _build_tab_bcd(self) -> None:
        container = tk.Frame(self.tab_bcd, bg=BG_PANEL, padx=14, pady=14)
        container.pack(fill="both", expand=True)

        input_card = tk.Frame(container, bg=BG_CARD, padx=14, pady=12, highlightthickness=1, highlightbackground=BORDER_COLOR)
        input_card.pack(fill="x", pady=(0, 10))

        self.lbl_bcd_input = tk.Label(
            input_card, text=self.t("lbl_bcd_input"), bg=BG_CARD, fg=ACCENT_BLUE, font=("Microsoft YaHei UI", 9, "bold")
        )
        self.lbl_bcd_input.pack(anchor="w", pady=(0, 6))

        in_row = tk.Frame(input_card, bg=BG_CARD)
        in_row.pack(fill="x")

        self.var_bcd_pfns = tk.StringVar()
        ent_pfns = tk.Entry(
            in_row,
            textvariable=self.var_bcd_pfns,
            bg=BG_INPUT,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            relief="flat",
            font=("Consolas", 10),
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        ent_pfns.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=5)

        self.var_bcd_twins = tk.BooleanVar(value=True)
        self.chk_bcd_twins = tk.Checkbutton(
            in_row,
            text="+3/+5 Row Twins",
            variable=self.var_bcd_twins,
            bg=BG_CARD,
            fg=FG_PRIMARY,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            activeforeground=FG_PRIMARY,
            font=("Consolas", 9, "bold"),
        )
        self.chk_bcd_twins.pack(side="left", padx=(0, 8))

        self.btn_bcd_preview = ttk.Button(
            in_row, text=self.t("btn_bcd_preview"), style="Secondary.TButton", command=self.preview_bcd_twins
        )
        self.btn_bcd_preview.pack(side="left", padx=(0, 6))

        self.btn_bcd_add = ttk.Button(
            in_row, text=self.t("btn_bcd_add"), style="Accent.TButton", command=self.add_bcd_pfns
        )
        self.btn_bcd_add.pack(side="left")

        # Action Bar for existing BCD table
        act_bar = tk.Frame(container, bg=BG_PANEL)
        act_bar.pack(fill="x", pady=(0, 8))

        self.btn_bcd_remove = ttk.Button(
            act_bar, text=self.t("btn_bcd_remove"), style="Secondary.TButton", command=self.remove_selected_bcd_pfns
        )
        self.btn_bcd_remove.pack(side="left", padx=(0, 6))

        self.btn_bcd_clear = ttk.Button(
            act_bar, text=self.t("btn_bcd_clear"), style="Danger.TButton", command=self.clear_all_bcd_pfns
        )
        self.btn_bcd_clear.pack(side="left", padx=(0, 14))

        self.btn_bcd_export = ttk.Button(
            act_bar, text=self.t("btn_bcd_export"), style="Secondary.TButton", command=self.export_bcd_pfns
        )
        self.btn_bcd_export.pack(side="left", padx=(0, 6))

        self.btn_bcd_import = ttk.Button(
            act_bar, text=self.t("btn_bcd_import"), style="Secondary.TButton", command=self.import_bcd_pfns
        )
        self.btn_bcd_import.pack(side="left", padx=(0, 6))

        self.btn_bcd_copy_cmd = ttk.Button(
            act_bar, text=self.t("btn_bcd_copy_cmd"), style="Secondary.TButton", command=self.copy_bcdedit_command
        )
        self.btn_bcd_copy_cmd.pack(side="left")

        # BCD Table
        tbl_wrap = tk.Frame(container, bg=BG_PANEL)
        tbl_wrap.pack(fill="both", expand=True)

        cols_bcd = ("idx", "pfn_hex", "pfn_dec", "phys", "group", "offset", "twin", "twin_status")
        self.tree_bcd = ttk.Treeview(tbl_wrap, columns=cols_bcd, show="headings", selectmode="extended")
        self.tree_bcd.heading("idx", text=self.t("col_idx"))
        self.tree_bcd.heading("pfn_hex", text=self.t("col_pfn"))
        self.tree_bcd.heading("pfn_dec", text=self.t("col_pfn_dec"))
        self.tree_bcd.heading("phys", text=self.t("col_phys_addr"))
        self.tree_bcd.heading("group", text=self.t("col_row_group"))
        self.tree_bcd.heading("offset", text=self.t("col_offset"))
        self.tree_bcd.heading("twin", text=self.t("col_twin"))
        self.tree_bcd.heading("twin_status", text=self.t("col_twin_status"))

        self.tree_bcd.column("idx", width=55, anchor="center")
        self.tree_bcd.column("pfn_hex", width=115, anchor="center")
        self.tree_bcd.column("pfn_dec", width=110, anchor="e")
        self.tree_bcd.column("phys", width=180, anchor="center")
        self.tree_bcd.column("group", width=140, anchor="center")
        self.tree_bcd.column("offset", width=95, anchor="center")
        self.tree_bcd.column("twin", width=130, anchor="center")
        self.tree_bcd.column("twin_status", width=160, anchor="center")
        self.tree_bcd.tag_configure("ok", foreground=COLOR_OK)
        self.tree_bcd.tag_configure("warn", foreground=COLOR_WARN)

        sb_bcd = ttk.Scrollbar(tbl_wrap, orient="vertical", command=self.tree_bcd.yview)
        self.tree_bcd.configure(yscrollcommand=sb_bcd.set)
        self.tree_bcd.pack(side="left", fill="both", expand=True)
        sb_bcd.pack(side="right", fill="y")

    # =========================================================================
    # Actions & Event Handlers
    # =========================================================================
    def toggle_language(self) -> None:
        self.lang = "en" if self.lang == "zh" else "zh"
        self.root.title(self.t("app_title"))
        self.lbl_subtitle.configure(text=self.t("header_subtitle"))
        admin_flag = is_admin()
        self.btn_admin.configure(text=self.t("admin_ok") if admin_flag else self.t("admin_no"))
        self.btn_lang.configure(text=self.t("lang_btn"))

        self.notebook.tab(0, text=self.t("tab_status"))
        self.notebook.tab(1, text=self.t("tab_hunter"))
        self.notebook.tab(2, text=self.t("tab_dmp"))
        self.notebook.tab(3, text=self.t("tab_bcd"))

        # Tab 1 labels
        self.card_ram_lbl.configure(text=self.t("card_ram_title"))
        self.card_ranges_lbl.configure(text=self.t("card_ranges_title"))
        self.card_isolated_lbl.configure(text=self.t("card_isolated_title"))
        self.card_excised_lbl.configure(text=self.t("card_excised_title"))
        self.btn_refresh_status.configure(text=self.t("btn_refresh_status"))
        self.lbl_reboot_tip_status.configure(text=self.t("reboot_notice"))
        self.lbl_phys_ranges.configure(text=self.t("lbl_phys_ranges"))
        self.lbl_pfn_verify.configure(text=self.t("lbl_pfn_verify"))

        # Tab 2 labels
        self.lbl_hunter_cfg.configure(text=self.t("lbl_hunter_cfg"))
        self.lbl_w_batches.configure(text=self.t("lbl_window_batches"))
        self.lbl_b_gb.configure(text=self.t("lbl_batch_gb"))
        self.lbl_blk_mb.configure(text=self.t("lbl_block_mb"))
        self.lbl_min_av.configure(text=self.t("lbl_min_avail_gb"))
        self.lbl_soak.configure(text=self.t("lbl_soak_sec"))
        self.lbl_max_c.configure(text=self.t("lbl_max_cycles"))
        self.chk_twins_widget.configure(text=self.t("chk_row_twins"))
        self.btn_autotune.configure(text=self.t("btn_autotune"))
        self.btn_start_hunt.configure(text=self.t("btn_start_hunt"))
        self.btn_stop_hunt.configure(text=self.t("btn_stop_hunt"))
        self.btn_clear_log.configure(text=self.t("btn_clear_log"))
        self.btn_export_log.configure(text=self.t("btn_export_log"))
        self.lbl_st_cycle_t.configure(text=self.t("stat_cycle"))
        self.lbl_st_win_t.configure(text=self.t("stat_window"))
        self.lbl_st_flips_t.configure(text=self.t("stat_flips"))
        self.lbl_st_new_t.configure(text=self.t("stat_new_pfns"))
        self.lbl_st_pin_t.configure(text=self.t("stat_pinned"))
        if not (self.hunter_thread and self.hunter_thread.is_alive()):
            self.lbl_hunter_phase.configure(text=self.t("phase_idle"))

        # Tab 3 labels
        self.lbl_dmp_dir.configure(text=self.t("lbl_dmp_dir"))
        self.btn_browse_dir.configure(text=self.t("btn_browse_dir"))
        self.btn_browse_file.configure(text=self.t("btn_browse_file"))
        self.btn_analyze_dmp.configure(text=self.t("btn_analyze_dmp"))
        self.lbl_dmp_detail.configure(text=self.t("lbl_dmp_detail"))

        # Tab 4 labels
        self.lbl_bcd_input.configure(text=self.t("lbl_bcd_input"))
        self.btn_bcd_add.configure(text=self.t("btn_bcd_add"))
        self.btn_bcd_preview.configure(text=self.t("btn_bcd_preview"))
        self.btn_bcd_remove.configure(text=self.t("btn_bcd_remove"))
        self.btn_bcd_clear.configure(text=self.t("btn_bcd_clear"))
        self.btn_bcd_export.configure(text=self.t("btn_bcd_export"))
        self.btn_bcd_import.configure(text=self.t("btn_bcd_import"))
        self.btn_bcd_copy_cmd.configure(text=self.t("btn_bcd_copy_cmd"))

        self.refresh_status_and_bcd()

    def _relaunch_as_admin(self) -> None:
        if sys.platform != "win32":
            return
        try:
            if getattr(sys, "frozen", False):
                exe = sys.executable
                params = ""
            else:
                exe = sys.executable
                params = f'-m badpage_hunter gui'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, os.getcwd(), 1)
            self.root.after(300, self._on_close)
        except Exception as exc:
            messagebox.showerror("Privilege Elevation Failed", str(exc))

    def _update_ram_telemetry(self) -> None:
        try:
            total_gb, avail_gb, load = get_memory_status()
            self.lbl_ram_header.configure(text=self.t("ram_status_fmt").format(avail=avail_gb, total=total_gb, load=load))
            self.card_ram_val.configure(text=f"{avail_gb:.1f} / {total_gb:.1f} GB ({load}%)")
        except Exception:
            pass

    def refresh_status_and_bcd(self) -> None:
        self._update_ram_telemetry()

        # 1. Physical Memory Ranges
        for item in self.tree_ranges.get_children():
            self.tree_ranges.delete(item)
        try:
            ranges = get_kernel_physical_memory_ranges()
            self.card_ranges_val.configure(text=f"{len(ranges)} Ranges")
            for idx, (s_pfn, e_pfn, mb) in enumerate(ranges):
                self.tree_ranges.insert(
                    "",
                    "end",
                    values=(f"#{idx}", f"0x{s_pfn:07X}", f"0x{e_pfn:07X}", f"{e_pfn - s_pfn:,}", f"{mb:,.2f}"),
                )
        except Exception as exc:
            self.card_ranges_val.configure(text="Error")

        # 2. BCD Bad PFNs & _MMPFN Verification
        for item in self.tree_verify.get_children():
            self.tree_verify.delete(item)
        for item in self.tree_bcd.get_children():
            self.tree_bcd.delete(item)

        bad_pfns = sorted(get_existing_bad_pfns())
        self.card_isolated_val.configure(text=f"{len(bad_pfns)} ({len(bad_pfns) * 4} KB)")

        bad_set = set(bad_pfns)
        for idx, p in enumerate(bad_pfns, 1):
            group = p >> 3
            offset = p & 7
            if offset in (3, 5):
                twin = p ^ 6
                twin_str = f"0x{twin:06X}"
                twin_ok = twin in bad_set
                t_status = self.t("twin_included") if twin_ok else self.t("twin_missing")
                tag = "ok" if twin_ok else "warn"
            else:
                twin_str = "—"
                t_status = self.t("twin_na")
                tag = "ok"
            self.tree_bcd.insert(
                "",
                "end",
                iid=str(p),
                values=(
                    idx,
                    f"0x{p:06X}",
                    f"{p:,}",
                    f"0x{p << 12:012X}",
                    f"0x{group:05X}",
                    f"+{offset}",
                    twin_str,
                    t_status,
                ),
                tags=(tag,),
            )

        if not bad_pfns:
            self.card_excised_val.configure(text="0 / 0")
            return

        records = query_pfn_database_status(bad_pfns)
        excised_count = 0
        for pfn, st, u1, va in records:
            is_excised = st == 0xC00000F0 or (u1 == 0 and va <= 2)
            if is_excised:
                excised_count += 1
            state_str = self.t("state_excised") if is_excised else f"{self.t('state_staged')} (0x{st:08X})"
            tag = "excised" if is_excised else "staged"
            self.tree_verify.insert(
                "",
                "end",
                values=(
                    f"0x{pfn:06X}",
                    f"0x{pfn << 12:012X}",
                    f"0x{pfn >> 3:05X}",
                    f"+{pfn & 7}",
                    state_str,
                ),
                tags=(tag,),
            )
        self.card_excised_val.configure(
            text=f"{excised_count} / {len(records)}",
            fg=COLOR_OK if excised_count == len(records) else COLOR_WARN,
        )

    # =========================================================================
    # Hunter Controls
    # =========================================================================
    def on_autotune(self, silent: bool = False) -> None:
        rec = recommend_hunter_params()
        self.var_window_batches.set(str(rec["window_batches"]))
        self.var_batch_gb.set(str(rec["batch_gb"]))
        self.var_block_mb.set(str(rec["block_mb"]))
        self.var_min_avail_gb.set(str(rec["min_avail_gb"]))
        self.var_soak_sec.set(str(rec["soak_seconds"]))
        if not silent:
            total_gb, avail_gb, _ = get_memory_status()
            self._append_hunter_log(
                f"[Auto-Tune] System RAM={total_gb:.1f}GB (Avail={avail_gb:.1f}GB) -> "
                f"Window={rec['window_batches']}x{rec['batch_gb']}GB, Block={rec['block_mb']}MB, "
                f"MinAvailFloor={rec['min_avail_gb']}GB, Soak={rec['soak_seconds']}s"
            )

    def start_hunter(self) -> None:
        if self.hunter_thread and self.hunter_thread.is_alive():
            return
        try:
            w_batches = max(1, int(self.var_window_batches.get()))
            b_gb = max(0.25, float(self.var_batch_gb.get()))
            blk_mb = max(16, int(self.var_block_mb.get()))
            min_av = max(1.0, float(self.var_min_avail_gb.get()))
            soak_s = max(0.5, float(self.var_soak_sec.get()))
            max_c_raw = int(self.var_max_cycles.get() or "0")
            max_cycles = max_c_raw if max_c_raw > 0 else None
        except ValueError as exc:
            messagebox.showerror("Invalid Parameter", f"Please enter valid numeric parameters:\n{exc}")
            return

        stop_evt = threading.Event()
        self.hunter = BadPageHunter(
            window_batches=w_batches,
            batch_gb=b_gb,
            block_mb=blk_mb,
            min_avail_gb=min_av,
            soak_seconds=soak_s,
            include_row_twins=self.var_row_twins.get(),
            log_file="bad_page_hunter.log",
            on_log=lambda line: self.ui_queue.put(("log", line)),
            on_stats=lambda st: self.ui_queue.put(("stats", st)),
            stop_event=stop_evt,
        )

        self.btn_start_hunt.configure(state="disabled")
        self.btn_stop_hunt.configure(state="normal")

        def _worker() -> None:
            try:
                assert self.hunter is not None
                self.hunter.run(max_cycles=max_cycles)
            except Exception as exc:
                self.ui_queue.put(("log", f"[ERROR] Hunter thread exception: {exc}"))
            finally:
                self.ui_queue.put(("done", None))

        self.hunter_thread = threading.Thread(target=_worker, daemon=True)
        self.hunter_thread.start()

    def stop_hunter(self) -> None:
        if self.hunter:
            self.hunter.stop()
            self.btn_stop_hunt.configure(state="disabled")

    def _append_hunter_log(self, line: str) -> None:
        self.txt_hunter_log.configure(state="normal")
        tag = "normal"
        if "BIT FLIP CAUGHT" in line or "[!]" in line or "[ERROR]" in line:
            tag = "flip"
        elif "[BCD UPDATED]" in line or "[PINNED]" in line:
            tag = "bcd"
        elif "===" in line or "[Auto-Tune]" in line:
            tag = "banner"
        self.txt_hunter_log.insert("end", line + "\n", tag)
        self.txt_hunter_log.see("end")
        self.txt_hunter_log.configure(state="disabled")

    def clear_hunter_log(self) -> None:
        self.txt_hunter_log.configure(state="normal")
        self.txt_hunter_log.delete("1.0", "end")
        self.txt_hunter_log.configure(state="disabled")

    def export_hunter_log(self) -> None:
        content = self.txt_hunter_log.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Export Log", "Log console is empty.")
            return
        fpath = filedialog.asksaveasfilename(
            title="Export Hunter Log",
            defaultextension=".log",
            initialfile="bad_page_hunter_export.log",
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if fpath:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            messagebox.showinfo("Export Log", f"Saved log to:\n{fpath}")

    # =========================================================================
    # Minidump Analyzer Controls
    # =========================================================================
    def browse_dmp_folder(self) -> None:
        folder = filedialog.askdirectory(title="Select Minidump Directory", initialdir=self.var_dmp_path.get())
        if folder:
            self.var_dmp_path.set(folder)
            self.run_dmp_analysis()

    def browse_dmp_file(self) -> None:
        fpath = filedialog.askopenfilename(
            title="Select Windows Minidump (.dmp)",
            filetypes=[("Crash Dump files", "*.dmp"), ("All files", "*.*")],
        )
        if fpath:
            self.var_dmp_path.set(fpath)
            self.run_dmp_analysis()

    def run_dmp_analysis(self) -> None:
        target = self.var_dmp_path.get().strip()
        for item in self.tree_dmp.get_children():
            self.tree_dmp.delete(item)
        self.dmp_results.clear()

        if os.path.isfile(target):
            try:
                self.dmp_results = [parse_minidump(target)]
            except Exception as exc:
                self.dmp_results = [{"file": os.path.basename(target), "error": str(exc)}]
        elif os.path.isdir(target):
            self.dmp_results = analyze_minidump_directory(target)
        else:
            self._set_dmp_detail_text(f"Directory or file not found: {target}")
            return

        if not self.dmp_results:
            self._set_dmp_detail_text(
                f"No .dmp files found in: {target}\n\n"
                "Note: Windows writes kernel triage minidumps to C:\\Windows\\Minidump when a BSOD occurs.\n"
                "If your system has not crashed recently or C:\\Windows\\Minidump is empty, you can use Tab 2 (DRAM Hunter) "
                "to proactively scan physical memory in live user-mode."
            )
            return

        first_iid = None
        for idx, r in enumerate(self.dmp_results):
            iid = str(idx)
            if first_iid is None:
                first_iid = iid
            if "error" in r:
                self.tree_dmp.insert(
                    "",
                    "end",
                    iid=iid,
                    values=(r["file"], "—", "—", "—", self.t("verdict_error").format(err=r["error"])),
                    tags=("error",),
                )
            else:
                bc_str = f"0x{r['bugcheck']:08X} ({r['bugcheck_name']})"
                rip_str = f"0x{r['context']['RIP']:016X} ({r['rip_symbol'] or 'Unknown'})"
                flips = r["bitflips"]
                if flips:
                    verdict = self.t("verdict_flip").format(count=len(flips))
                    tag = "flip"
                else:
                    verdict = self.t("verdict_clean")
                    tag = "clean"
                self.tree_dmp.insert(
                    "",
                    "end",
                    iid=iid,
                    values=(r["file"], f"{r['version']} ({r['processors']} CPUs)", bc_str, rip_str, verdict),
                    tags=(tag,),
                )

        if first_iid is not None:
            self.tree_dmp.selection_set(first_iid)
            self._render_dmp_detail(self.dmp_results[0])

    def _on_dmp_selected(self, _event: Any) -> None:
        sel = self.tree_dmp.selection()
        if not sel:
            return
        idx = int(sel[0])
        if 0 <= idx < len(self.dmp_results):
            self._render_dmp_detail(self.dmp_results[idx])

    def _set_dmp_detail_text(self, text: str) -> None:
        self.txt_dmp_detail.configure(state="normal")
        self.txt_dmp_detail.delete("1.0", "end")
        self.txt_dmp_detail.insert("end", text)
        self.txt_dmp_detail.configure(state="disabled")

    def _render_dmp_detail(self, r: Dict[str, Any]) -> None:
        self.txt_dmp_detail.configure(state="normal")
        self.txt_dmp_detail.delete("1.0", "end")
        if "error" in r:
            self.txt_dmp_detail.insert("end", f"FILE: {r['file']}\nERROR: {r['error']}\n", "alert")
            self.txt_dmp_detail.configure(state="disabled")
            return

        self.txt_dmp_detail.insert(
            "end",
            f"FILE     : {r['file']}  (OS Build {r['version']}, {r['processors']} Logical CPUs)\n"
            f"BUGCHECK : 0x{r['bugcheck']:08X} ({r['bugcheck_name']})\n",
            "header",
        )
        for idx, (p, sym) in enumerate(zip(r["params"], r["param_symbols"]), 1):
            sym_s = f" -> {sym}" if sym else ""
            self.txt_dmp_detail.insert("end", f"  Param{idx} : 0x{p:016X}{sym_s}\n")
        self.txt_dmp_detail.insert(
            "end", f"CRASH RIP: 0x{r['context']['RIP']:016X} ({r['rip_symbol'] or 'Unknown'})\n\n"
        )

        if r["bitflips"]:
            self.txt_dmp_detail.insert(
                "end",
                "[!] HARDWARE SINGLE-BIT RETENTION FLIP DETECTED IN CPU REGISTERS:\n",
                "alert",
            )
            for reg_name, reg_val, bit_idx, repaired in r["bitflips"]:
                self.txt_dmp_detail.insert(
                    "end",
                    f"    {reg_name:<4}: 0x{reg_val:016X}  -->  Bit {bit_idx} flipped 1->0! "
                    f"(Expected canonical kernel pointer: 0x{repaired:016X})\n",
                    "alert",
                )
            self.txt_dmp_detail.insert("end", "\n")
        else:
            self.txt_dmp_detail.insert(
                "end", "[*] No non-canonical upper-bit (bits 48..63) single-bit flip in active trap frame.\n\n", "ok"
            )

        self.txt_dmp_detail.insert("end", "CPU Register Context (64-bit):\n", "header")
        regs = list(r["context"].items())
        for i in range(0, len(regs), 3):
            chunk = regs[i : i + 3]
            line = "  " + "    ".join(f"{k:<3}: 0x{v:016X}" for k, v in chunk)
            self.txt_dmp_detail.insert("end", line + "\n")

        if r["stack_symbols"]:
            self.txt_dmp_detail.insert("end", "\nResolved Call Stack Symbols:\n", "header")
            for sp, addr, sym in r["stack_symbols"]:
                self.txt_dmp_detail.insert("end", f"  [RSP 0x{sp:016X}]  0x{addr:016X} -> {sym}\n")

        self.txt_dmp_detail.configure(state="disabled")

    # =========================================================================
    # BCD {badmemory} Manager Controls
    # =========================================================================
    def _parse_input_pfns(self) -> List[int]:
        raw = self.var_bcd_pfns.get().strip()
        if not raw:
            return []
        tokens = [t for t in re.split(r"[\s,;]+", raw) if t]
        pfns: List[int] = []
        for tok in tokens:
            pfns.append(int(tok, 0))
        return pfns

    def preview_bcd_twins(self) -> None:
        try:
            pfns = self._parse_input_pfns()
        except ValueError as exc:
            messagebox.showerror("Invalid PFN", f"Could not parse PFN token:\n{exc}")
            return
        if not pfns:
            messagebox.showinfo("Preview Row Twins", "Please enter one or more PFNs first (e.g. 0x2c008d).")
            return
        expanded = sorted(infer_dram_row_twins(pfns))
        lines = []
        for p in expanded:
            origin = "Input" if p in pfns else "Inferred +3/+5 Twin"
            lines.append(f"0x{p:06X}  (PhysAddr 0x{p << 12:012X}, Group 0x{p >> 3:05X}, Offset +{p & 7})  [{origin}]")
        messagebox.showinfo(
            "DRAM +3/+5 Row-Twin Preview",
            f"Input PFNs: {len(pfns)} -> Expanded with +3/+5 Row Twins: {len(expanded)} pages ({len(expanded) * 4} KB)\n\n"
            + "\n".join(lines[:25]),
        )

    def add_bcd_pfns(self) -> None:
        try:
            pfns = self._parse_input_pfns()
        except ValueError as exc:
            messagebox.showerror("Invalid PFN", f"Could not parse PFN value:\n{exc}")
            return
        if not pfns:
            messagebox.showwarning("Input Required", "Please enter at least one PFN (e.g. 0x2c008d).")
            return
        updated, msg = update_bcd_badmemory(pfns, include_row_twins=self.var_bcd_twins.get())
        self.var_bcd_pfns.set("")
        self.refresh_status_and_bcd()
        messagebox.showinfo(
            "BCD {badmemory} Updated",
            f"bcdedit result: {msg}\nTotal Isolated PFNs: {len(updated)} pages ({len(updated) * 4} KB)\n\n"
            f"{self.t('reboot_notice')}",
        )

    def remove_selected_bcd_pfns(self) -> None:
        sel = self.tree_bcd.selection()
        if not sel:
            messagebox.showinfo("Remove PFNs", "Please select one or more rows in the table first.")
            return
        to_remove = [int(iid) for iid in sel]
        if not messagebox.askyesno(
            "Confirm Removal",
            f"Remove {len(to_remove)} selected PFN(s) from Windows BCD {{badmemory}}?",
        ):
            return
        remaining, msg = remove_bcd_badmemory_pfns(to_remove)
        self.refresh_status_and_bcd()
        messagebox.showinfo("BCD Updated", f"{msg}\nRemaining isolated PFNs: {len(remaining)}")

    def clear_all_bcd_pfns(self) -> None:
        existing = get_existing_bad_pfns()
        if not existing:
            messagebox.showinfo("Clear BCD", "BCD {badmemory} list is already empty.")
            return
        if not messagebox.askyesno(
            "Clear All BCD {badmemory}",
            f"Are you sure you want to delete all {len(existing)} isolated PFNs from Windows BCD {{badmemory}}?",
        ):
            return
        ok, msg = clear_bcd_badmemory()
        self.refresh_status_and_bcd()
        messagebox.showinfo("Clear BCD {badmemory}", f"Status: {'Success' if ok else 'Failed'}\n{msg}")

    def export_bcd_pfns(self) -> None:
        pfns = sorted(get_existing_bad_pfns())
        if not pfns:
            messagebox.showinfo("Export PFNs", "No isolated PFNs currently configured in BCD {badmemory}.")
            return
        fpath = filedialog.asksaveasfilename(
            title="Export BCD Bad Page List",
            defaultextension=".json",
            initialfile="badmemory_pfns_backup.json",
            filetypes=[("JSON Backup", "*.json"), ("Hex Text List", "*.txt")],
        )
        if not fpath:
            return
        if fpath.lower().endswith(".txt"):
            with open(fpath, "w", encoding="utf-8") as f:
                for p in pfns:
                    f.write(f"0x{p:x}\n")
        else:
            payload = {
                "tool": "win-badpage-hunter",
                "version": __version__,
                "count": len(pfns),
                "pfns_hex": [f"0x{p:x}" for p in pfns],
                "pfns_int": pfns,
                "bcdedit_command": "bcdedit /set {badmemory} badmemorylist " + " ".join(f"0x{p:x}" for p in pfns),
            }
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        messagebox.showinfo("Export Complete", f"Exported {len(pfns)} PFNs to:\n{fpath}")

    def import_bcd_pfns(self) -> None:
        fpath = filedialog.askopenfilename(
            title="Import PFN List",
            filetypes=[("PFN Backup files", "*.json *.txt"), ("All files", "*.*")],
        )
        if not fpath:
            return
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if fpath.lower().endswith(".json"):
                data = json.loads(raw)
                items = data.get("pfns_hex") or data.get("pfns_int") or []
                pfns = [int(str(x), 0) for x in items]
            else:
                tokens = [t for t in re.split(r"[\s,;]+", raw) if t]
                pfns = [int(t, 0) for t in tokens]
        except Exception as exc:
            messagebox.showerror("Import Error", f"Failed to parse file:\n{exc}")
            return

        if not pfns:
            messagebox.showwarning("Import PFNs", "No PFN numbers found in the selected file.")
            return
        updated, msg = update_bcd_badmemory(pfns, include_row_twins=self.var_bcd_twins.get())
        self.refresh_status_and_bcd()
        messagebox.showinfo(
            "Import Complete",
            f"Imported {len(pfns)} PFNs into BCD {{badmemory}}.\nTotal isolated: {len(updated)} pages.\n{msg}",
        )

    def copy_bcdedit_command(self) -> None:
        pfns = sorted(get_existing_bad_pfns())
        if not pfns:
            messagebox.showinfo("Copy Command", "No PFNs currently in BCD {badmemory}.")
            return
        cmd = "bcdedit /set {badmemory} badmemorylist " + " ".join(f"0x{p:x}" for p in pfns)
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        messagebox.showinfo("Copied to Clipboard", f"Copied command ({len(pfns)} PFNs):\n\n{cmd[:240]}...")

    # =========================================================================
    # Background Queue & Timers
    # =========================================================================
    def _schedule_periodic_tasks(self) -> None:
        self._drain_ui_queue()
        self._update_ram_telemetry()
        self.root.after(250, self._schedule_periodic_tasks)

    def _drain_ui_queue(self) -> None:
        while True:
            try:
                kind, payload = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self._append_hunter_log(str(payload))
            elif kind == "stats":
                st = payload
                self.lbl_st_cycle_v.configure(text=str(st["cycle"]))
                self.lbl_st_win_v.configure(text=f"{st['active_gb']:.2f} GB ({st['active_batches']}b)")
                self.lbl_st_flips_v.configure(
                    text=str(st["total_flips"]),
                    fg=COLOR_DANGER if st["total_flips"] > 0 else FG_PRIMARY,
                )
                self.lbl_st_new_v.configure(
                    text=str(st["newly_isolated_count"]),
                    fg=COLOR_OK if st["newly_isolated_count"] > 0 else FG_PRIMARY,
                )
                self.lbl_st_pin_v.configure(text=str(st["pinned_count"]))
                self.lbl_hunter_phase.configure(text=st["phase"])
                self.soak_progress["value"] = st.get("soak_progress", 0.0)
            elif kind == "done":
                self.btn_start_hunt.configure(state="normal")
                self.btn_stop_hunt.configure(state="disabled")
                self.soak_progress["value"] = 0.0
                self.refresh_status_and_bcd()

    def _on_close(self) -> None:
        if self.hunter_thread and self.hunter_thread.is_alive() and self.hunter:
            self.hunter.stop()
            self.hunter_thread.join(timeout=2.5)
        self.root.destroy()


def launch_gui(lang: str = "zh") -> int:
    enable_dpi_and_dark_mode()
    root = tk.Tk()
    BadPageHunterGUI(root, lang=lang)
    root.mainloop()
    return 0
