#!/usr/bin/env python3
"""zipcrack 图形界面。

方便选择要破解的 ZIP 文件、设置攻击参数，并实时显示破解进度。
直接运行本文件，或不带参数运行 zipcrack.py 即可打开。
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import threading
import time
import traceback
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

import zipcrack

CHARSET_OPTIONS = [
    ("digits", "digits — 纯数字 (0-9)"),
    ("lower", "lower — 小写字母 (a-z)"),
    ("upper", "upper — 大写字母 (A-Z)"),
    ("alpha", "alpha — 大小写字母 (a-zA-Z)"),
    ("lowerdigit", "lowerdigit — 小写+数字"),
    ("alnum", "alnum — 大小写+数字"),
    ("hex", "hex — 十六进制 (0-9a-f)"),
    ("printable", "printable — 全部可打印字符"),
    ("custom", "custom — 自定义字符…"),
]
CHARSET_KEYS = [key for key, _ in CHARSET_OPTIONS]

ENCODINGS = ["utf-8", "gbk", "utf-8-sig", "latin-1"]

GREEN = "#1a7f37"
RED = "#cf222e"
GRAY = "#666666"

AUTO_STAGES_TEXT = "数字 1-8 位 → 小写 1-6 位 → 小写+数字 1-5 位"


def fmt_secs(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} 秒"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes} 分 {secs} 秒"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} 小时 {minutes} 分"


def fmt_rate(rate: float) -> str:
    if rate >= 1e6:
        return f"{rate / 1e6:.2f} M/s"
    if rate >= 1e3:
        return f"{rate / 1e3:.1f} K/s"
    return f"{rate:.0f} 次/s"


def set_children_state(widget: tk.Widget, state: str) -> None:
    for child in widget.winfo_children():
        try:
            child.configure(state=state)
        except tk.TclError:
            pass
        set_children_state(child, state)


class CrackApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.events: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.running = False
        self.found_password: bytes | None = None
        self.start_time = 0.0
        self._last_push = 0.0

        root.title("ZIP 密码破解工具 — ZipCrypto 高速爆破")
        root.geometry("880x780")
        root.minsize(800, 720)

        self.setup_style()
        self.build_vars()
        self.build_ui()
        self.toggle_states()
        self.update_space_label()

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(80, self.poll_events)

    # ---------------- 界面搭建 ----------------

    def setup_style(self) -> None:
        style = ttk.Style(self.root)
        for theme in ("vista", "winnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        for name in ("TkDefaultFont", "TkTextFont", "TkHeadingFont", "TkMenuFont"):
            try:
                tkfont.nametofont(name).configure(family="Microsoft YaHei UI", size=9)
            except tk.TclError:
                pass
        style.configure("TProgressbar", thickness=18)
        style.configure("Bold.TLabel", font=("Microsoft YaHei UI", 9, "bold"))

    def build_vars(self) -> None:
        self.zip_path = tk.StringVar()
        self.use_common = tk.BooleanVar(value=True)
        self.use_dict = tk.BooleanVar(value=False)
        self.wordlist = tk.StringVar()
        self.use_brute = tk.BooleanVar(value=True)
        self.brute_mode = tk.StringVar(value="auto")
        self.custom_charset = tk.StringVar()
        self.min_len = tk.IntVar(value=1)
        self.max_len = tk.IntVar(value=8)
        self.prefix = tk.StringVar()
        self.suffix = tk.StringVar()
        self.workers = tk.IntVar(value=0)
        self.timeout = tk.StringVar(value="0")
        self.encoding = tk.StringVar(value="utf-8")

        self.info_var = tk.StringVar(value="请选择要破解的 ZIP 文件（仅支持传统 ZipCrypto 加密，不支持 WinZip AES）。")
        self.space_var = tk.StringVar(value="")
        self.stage_var = tk.StringVar(value="等待开始")
        self.tested_var = tk.StringVar(value="")
        self.speed_var = tk.StringVar(value="")
        self.eta_var = tk.StringVar(value="")
        self.elapsed_var = tk.StringVar(value="")
        self.pct_var = tk.StringVar(value="")
        self.result_var = tk.StringVar()
        self.status_var = tk.StringVar(value="就绪")

        for var in (self.min_len, self.max_len, self.custom_charset, self.brute_mode):
            var.trace_add("write", lambda *_: self.update_space_label())

    def build_ui(self) -> None:
        pad = {"padx": 10, "pady": 4}
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        # ① 文件选择
        file_box = ttk.LabelFrame(main, text=" ① 选择加密 ZIP 文件 ", padding=8)
        file_box.grid(row=0, column=0, sticky="ew", **pad)
        file_box.columnconfigure(0, weight=1)
        self.zip_entry = ttk.Entry(file_box, textvariable=self.zip_path)
        self.zip_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.zip_entry.bind("<Return>", lambda *_: self.inspect_zip())
        self.zip_entry.bind("<FocusOut>", lambda *_: self.inspect_zip())
        self.zip_browse = ttk.Button(file_box, text="浏览…", command=self.browse_zip)
        self.zip_browse.grid(row=0, column=1)
        self.info_label = ttk.Label(file_box, textvariable=self.info_var, foreground=GRAY, wraplength=800)
        self.info_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # ② 攻击方式
        attack_box = ttk.LabelFrame(main, text=" ② 攻击方式 ", padding=8)
        attack_box.grid(row=1, column=0, sticky="ew", **pad)
        attack_box.columnconfigure(1, weight=1)
        self.settings_widgets = [file_box, attack_box]

        self.common_check = ttk.Checkbutton(
            attack_box, text="内置常见口令（123456、admin123 等 130+ 条，并按文件名自动变形，先试这个最快）",
            variable=self.use_common,
        )
        self.common_check.grid(row=0, column=0, columnspan=3, sticky="w")

        self.dict_check = ttk.Checkbutton(attack_box, text="字典文件（一行一个密码）", variable=self.use_dict, command=self.toggle_states)
        self.dict_check.grid(row=1, column=0, sticky="w")
        self.dict_entry = ttk.Entry(attack_box, textvariable=self.wordlist)
        self.dict_entry.grid(row=1, column=1, sticky="ew", padx=6)
        self.dict_browse = ttk.Button(attack_box, text="浏览…", command=self.browse_wordlist, width=8)
        self.dict_browse.grid(row=1, column=2)

        self.brute_check = ttk.Checkbutton(attack_box, text="暴力破解（按字符集逐个尝试）", variable=self.use_brute, command=self.toggle_states)
        self.brute_check.grid(row=2, column=0, columnspan=3, sticky="w", pady=(2, 0))

        self.brute_box = ttk.Frame(attack_box, padding=(24, 2, 0, 0))
        self.brute_box.grid(row=3, column=0, columnspan=3, sticky="ew")
        self.brute_box.columnconfigure(1, weight=1)

        self.radio_auto = ttk.Radiobutton(
            self.brute_box, text=f"自动组合（{AUTO_STAGES_TEXT}）",
            variable=self.brute_mode, value="auto", command=self.toggle_states,
        )
        self.radio_auto.grid(row=0, column=0, columnspan=6, sticky="w")

        self.radio_custom = ttk.Radiobutton(
            self.brute_box, text="自定义：", variable=self.brute_mode, value="custom", command=self.toggle_states,
        )
        self.radio_custom.grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.charset_combo = ttk.Combobox(
            self.brute_box, state="readonly", width=30,
            values=[label for _, label in CHARSET_OPTIONS],
        )
        self.charset_combo.current(0)
        self.charset_combo.grid(row=1, column=1, sticky="w", pady=(4, 0))
        self.charset_combo.bind("<<ComboboxSelected>>", lambda *_: self.toggle_states())

        self.custom_entry = ttk.Entry(self.brute_box, textvariable=self.custom_charset, width=22)
        self.custom_entry.grid(row=1, column=2, sticky="w", padx=(6, 0), pady=(4, 0))

        ttk.Label(self.brute_box, text="长度").grid(row=1, column=3, padx=(12, 4), pady=(4, 0))
        self.min_spin = ttk.Spinbox(self.brute_box, from_=1, to=16, width=4, textvariable=self.min_len, command=self.update_space_label)
        self.min_spin.grid(row=1, column=4, pady=(4, 0))
        ttk.Label(self.brute_box, text="到").grid(row=1, column=5, padx=4, pady=(4, 0))
        self.max_spin = ttk.Spinbox(self.brute_box, from_=1, to=16, width=4, textvariable=self.max_len, command=self.update_space_label)
        self.max_spin.grid(row=1, column=6, pady=(4, 0))
        self.space_label = ttk.Label(self.brute_box, textvariable=self.space_var, foreground=GRAY)
        self.space_label.grid(row=1, column=7, padx=(12, 0), pady=(4, 0), sticky="w")

        # ③ 高级选项
        adv_box = ttk.LabelFrame(main, text=" ③ 高级选项（可留空） ", padding=8)
        adv_box.grid(row=2, column=0, sticky="ew", **pad)
        self.settings_widgets.append(adv_box)

        ttk.Label(adv_box, text="密码前缀").grid(row=0, column=0, sticky="w")
        ttk.Entry(adv_box, textvariable=self.prefix, width=10).grid(row=0, column=1, padx=(4, 12))
        ttk.Label(adv_box, text="密码后缀").grid(row=0, column=2, sticky="w")
        ttk.Entry(adv_box, textvariable=self.suffix, width=10).grid(row=0, column=3, padx=(4, 12))
        ttk.Label(adv_box, text="编码").grid(row=0, column=4, sticky="w")
        ttk.Combobox(adv_box, textvariable=self.encoding, values=ENCODINGS, state="readonly", width=9).grid(row=0, column=5, padx=(4, 12))
        ttk.Label(adv_box, text="进程数 (0=自动)").grid(row=0, column=6, sticky="w")
        ttk.Spinbox(adv_box, from_=0, to=64, width=4, textvariable=self.workers).grid(row=0, column=7, padx=(4, 12))
        ttk.Label(adv_box, text="超时秒 (0=不限)").grid(row=0, column=8, sticky="w")
        ttk.Entry(adv_box, textvariable=self.timeout, width=7).grid(row=0, column=9, padx=(4, 0))

        # 进度区
        prog_box = ttk.LabelFrame(main, text=" 进度 ", padding=8)
        prog_box.grid(row=3, column=0, sticky="ew", **pad)
        prog_box.columnconfigure(0, weight=1)

        self.progressbar = ttk.Progressbar(prog_box, mode="determinate", maximum=100)
        self.progressbar.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Label(prog_box, textvariable=self.pct_var, width=8, anchor="e", style="Bold.TLabel").grid(row=0, column=1)

        ttk.Label(prog_box, textvariable=self.stage_var, style="Bold.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
        info_line = ttk.Frame(prog_box)
        info_line.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        ttk.Label(info_line, textvariable=self.tested_var, foreground=GRAY).pack(side="left")
        ttk.Label(info_line, textvariable=self.elapsed_var, foreground=GRAY).pack(side="right")
        speed_line = ttk.Frame(prog_box)
        speed_line.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        ttk.Label(speed_line, textvariable=self.speed_var, foreground=GRAY).pack(side="left")
        ttk.Label(speed_line, textvariable=self.eta_var, foreground=GRAY).pack(side="right")

        # 结果区
        result_box = ttk.Frame(main)
        result_box.grid(row=4, column=0, sticky="ew", **pad)
        result_box.columnconfigure(1, weight=1)
        ttk.Label(result_box, text="结果:", style="Bold.TLabel").grid(row=0, column=0, sticky="w")
        self.result_entry = tk.Entry(
            result_box, textvariable=self.result_var, state="readonly",
            readonlybackground="white", foreground=GREEN,
            font=("Consolas", 12, "bold"), relief="solid", bd=1,
        )
        self.result_entry.grid(row=0, column=1, sticky="ew", padx=6)
        self.copy_btn = ttk.Button(result_box, text="复制密码", command=self.copy_password, state="disabled")
        self.copy_btn.grid(row=0, column=2, padx=(0, 4))
        self.extract_btn = ttk.Button(result_box, text="解压全部文件…", command=self.extract_all, state="disabled")
        self.extract_btn.grid(row=0, column=3)

        # 日志区
        log_box = ttk.LabelFrame(main, text=" 日志 ", padding=6)
        log_box.grid(row=5, column=0, sticky="nsew", **pad)
        log_box.columnconfigure(0, weight=1)
        log_box.rowconfigure(0, weight=1)
        self.log_text = tk.Text(log_box, height=9, wrap="word", state="disabled", font=("Consolas", 9), relief="solid", bd=1)
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # 底部按钮 + 状态栏
        bottom = ttk.Frame(main)
        bottom.grid(row=6, column=0, sticky="ew", padx=10, pady=(6, 2))
        self.start_btn = tk.Button(
            bottom, text="开始破解", command=self.start, width=14,
            bg=GREEN, fg="white", activebackground="#2da44e", activeforeground="white",
            font=("Microsoft YaHei UI", 10, "bold"), relief="flat", cursor="hand2",
        )
        self.start_btn.pack(side="left")
        self.stop_btn = tk.Button(
            bottom, text="停 止", command=self.stop, width=10, state="disabled",
            bg=RED, fg="white", activebackground="#a40e26", activeforeground="white",
            font=("Microsoft YaHei UI", 10, "bold"), relief="flat", cursor="hand2",
        )
        self.stop_btn.pack(side="left", padx=(8, 0))
        ttk.Button(bottom, text="清空日志", command=self.clear_log).pack(side="left", padx=(16, 0))
        ttk.Label(bottom, textvariable=self.status_var, foreground=GRAY).pack(side="right")

    # ---------------- 界面状态 ----------------

    def toggle_states(self) -> None:
        dict_state = "normal" if self.use_dict.get() else "disabled"
        self.dict_entry.configure(state=dict_state)
        self.dict_browse.configure(state=dict_state)

        brute = self.use_brute.get()
        set_children_state(self.brute_box, "normal" if brute else "disabled")
        if brute:
            custom = self.brute_mode.get() == "custom"
            for widget in (self.charset_combo, self.custom_entry, self.min_spin, self.max_spin):
                widget.configure(state=("readonly" if widget is self.charset_combo else "normal") if custom else "disabled")
            if not custom or self.charset_combo.current() != len(CHARSET_OPTIONS) - 1:
                self.custom_entry.configure(state="disabled")
        self.update_space_label()

    def set_running(self, running: bool) -> None:
        self.running = running
        for box in self.settings_widgets:
            set_children_state(box, "disabled" if running else "normal")
        if not running:
            self.toggle_states()
        self.start_btn.configure(
            state="disabled" if running else "normal",
            bg="#9fd3ac" if running else GREEN,
        )
        self.stop_btn.configure(
            state="normal" if running else "disabled",
            bg=RED if running else "#e3a1a6",
        )
        if running:
            self.copy_btn.configure(state="disabled")
            self.extract_btn.configure(state="disabled")

    def reset_progress_display(self) -> None:
        self.progressbar.configure(value=0)
        self.pct_var.set("")
        self.stage_var.set("准备中…")
        self.tested_var.set("")
        self.speed_var.set("")
        self.eta_var.set("")
        self.elapsed_var.set("")

    # ---------------- 文件与参数 ----------------

    def browse_zip(self) -> None:
        path = filedialog.askopenfilename(
            title="选择加密的 ZIP 文件",
            filetypes=[("ZIP 压缩包", "*.zip"), ("所有文件", "*.*")],
        )
        if path:
            self.zip_path.set(path)
            self.inspect_zip()

    def browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="选择字典文件",
            filetypes=[("文本文件", "*.txt;*.dic;*.lst"), ("所有文件", "*.*")],
        )
        if path:
            self.wordlist.set(path)
            self.use_dict.set(True)
            self.toggle_states()

    def inspect_zip(self) -> bool:
        path = self.zip_path.get().strip()
        if not path:
            return False
        if not os.path.isfile(path):
            self.info_var.set(f"找不到文件: {path}")
            self.info_label.configure(foreground=RED)
            return False
        try:
            total = encrypted = aes = 0
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    total += 1
                    if info.flag_bits & 0x1:
                        encrypted += 1
                        if zipcrack.has_aes(info):
                            aes += 1
        except Exception as exc:
            self.info_var.set(f"无法读取文件: {exc}")
            self.info_label.configure(foreground=RED)
            return False
        zipcrypto = encrypted - aes
        if encrypted == 0:
            self.info_var.set(f"共 {total} 个文件，没有加密文件，无需破解。")
            self.info_label.configure(foreground=RED)
            return False
        msg = f"共 {total} 个文件，其中加密 {encrypted} 个（ZipCrypto {zipcrypto} 个"
        if aes:
            msg += f"，AES {aes} 个"
        msg += "）"
        if zipcrypto == 0:
            msg += " — 全是 WinZip AES 加密，本工具无法破解。"
            self.info_label.configure(foreground=RED)
            return False
        if aes:
            msg += "，AES 文件不参与校验"
        msg += "，可以开始。"
        self.info_var.set(msg)
        self.info_label.configure(foreground=GREEN)
        return True

    def charset_spec(self) -> str:
        key = CHARSET_KEYS[self.charset_combo.current()]
        if key == "custom":
            return self.custom_charset.get()
        return key

    def brute_space(self) -> int | None:
        try:
            if self.brute_mode.get() == "auto":
                specs = [(name, lo, hi) for _, name, lo, hi in zipcrack.default_stages()]
            else:
                lo = max(1, int(self.min_len.get()))
                hi = min(16, int(self.max_len.get()))
                if hi < lo:
                    return None
                specs = [(self.charset_spec(), lo, hi)]
            total = 0
            for spec, lo, hi in specs:
                _, charset = zipcrack.parse_charset(spec)
                total += sum(len(charset) ** length for length in range(lo, hi + 1))
            return total
        except (SystemExit, tk.TclError, ValueError):
            return None

    def update_space_label(self) -> None:
        if not self.use_brute.get():
            self.space_var.set("")
            return
        space = self.brute_space()
        if space is None:
            self.space_var.set("空间: 参数无效")
        else:
            self.space_var.set(f"空间: 约 {zipcrack.fmt_num(space)}")

    def collect_config(self) -> dict | None:
        path = self.zip_path.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("提示", "请先选择要破解的 ZIP 文件。")
            return None
        if not (self.use_common.get() or self.use_dict.get() or self.use_brute.get()):
            messagebox.showwarning("提示", "请至少选择一种攻击方式。")
            return None

        wordlist = ""
        if self.use_dict.get():
            wordlist = self.wordlist.get().strip()
            if not wordlist or not os.path.isfile(wordlist):
                messagebox.showwarning("提示", "勾选了字典攻击，请选择存在的字典文件。")
                return None

        stages: list[tuple] = []
        if self.use_brute.get():
            if self.brute_mode.get() == "auto":
                stages = zipcrack.default_stages()
            else:
                try:
                    lo, hi = int(self.min_len.get()), int(self.max_len.get())
                except (tk.TclError, ValueError):
                    messagebox.showwarning("提示", "长度必须是数字。")
                    return None
                if not (1 <= lo <= hi <= 16):
                    messagebox.showwarning("提示", "长度范围无效：需满足 1 ≤ 最小 ≤ 最大 ≤ 16。")
                    return None
                spec = self.charset_spec()
                if not spec:
                    messagebox.showwarning("提示", "自定义字符集不能为空。")
                    return None
                stages = [("charset", spec, lo, hi)]
                space = self.brute_space()
                if space is not None and space > 1e11:
                    estimate = fmt_secs(space / 5e7)
                    if not messagebox.askyesno(
                        "搜索空间很大",
                        f"当前设置的搜索空间约为 {zipcrack.fmt_num(space)} 个密码。\n"
                        f"按每秒 5000 万次估算需要 {estimate}。\n\n确定要继续吗？",
                    ):
                        return None

        encoding = self.encoding.get()
        try:
            prefix = self.prefix.get().encode(encoding)
            suffix = self.suffix.get().encode(encoding)
        except UnicodeEncodeError:
            messagebox.showwarning("提示", f"前缀或后缀无法用 {encoding} 编码。")
            return None

        try:
            timeout = float(self.timeout.get() or 0)
            if timeout < 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("提示", "超时必须是大于等于 0 的数字（秒）。")
            return None

        try:
            workers = int(self.workers.get())
        except (tk.TclError, ValueError):
            workers = 0

        return {
            "path": os.path.abspath(path),
            "stages": stages,
            "wordlist": wordlist or None,
            "include_common": self.use_common.get(),
            "prefix": prefix,
            "suffix": suffix,
            "encoding": encoding,
            "workers": workers or None,
            "timeout": timeout,
        }

    # ---------------- 破解流程 ----------------

    def start(self) -> None:
        if self.running:
            return
        cfg = self.collect_config()
        if cfg is None:
            return
        self.found_password = None
        self.result_var.set("")
        self.cancel_event.clear()
        self._last_push = 0.0
        self.start_time = time.perf_counter()
        self.reset_progress_display()
        self.set_running(True)
        self.status_var.set("初始化引擎…")
        self.log(f"开始破解: {cfg['path']}")
        self.worker = threading.Thread(target=self.worker_main, args=(cfg,), daemon=True)
        self.worker.start()

    def stop(self) -> None:
        if self.running:
            self.cancel_event.set()
            self.status_var.set("正在停止…")
            self.log("收到停止请求，等待工作进程退出…")

    def worker_main(self, cfg: dict) -> None:
        try:
            dll = zipcrack.build_dll()
            zipcrack.engine_self_check(dll)
            started = time.perf_counter()
            deadline = started + cfg["timeout"] if cfg["timeout"] > 0 else None
            found = zipcrack.crack_zip(
                cfg["path"],
                stages=cfg["stages"],
                workers=cfg["workers"],
                deadline=deadline,
                prefix=cfg["prefix"],
                suffix=cfg["suffix"],
                wordlist=cfg["wordlist"],
                encoding=cfg["encoding"],
                include_common=cfg["include_common"],
                dll_path=dll,
                progress_cb=self.on_progress,
                log_cb=self.on_log,
                cancel_event=self.cancel_event,
            )
            self.events.put(("done", found, time.perf_counter() - started, self.cancel_event.is_set()))
        except SystemExit as exc:
            self.events.put(("error", str(exc) or "参数错误"))
        except Exception:
            self.events.put(("error", "发生异常:\n" + traceback.format_exc()))

    def on_log(self, msg: str) -> None:
        self.events.put(("log", msg))

    def on_progress(self, tested: int, total: int, rate: float, remain: float, label: str, length: int) -> None:
        now = time.perf_counter()
        if now - self._last_push < 0.1 and tested < total:
            return
        self._last_push = now
        self.events.put(("progress", tested, total, rate, remain, label, length))

    # ---------------- 事件轮询 ----------------

    def poll_events(self) -> None:
        try:
            for _ in range(60):
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self.log(event[1])
                elif kind == "progress":
                    self.show_progress(*event[1:])
                elif kind == "done":
                    self.on_done(event[1], event[2], event[3])
                elif kind == "error":
                    self.on_error(event[1])
                elif kind == "info_dialog":
                    messagebox.showinfo(event[1], event[2])
        except queue.Empty:
            pass
        if self.running:
            self.elapsed_var.set(f"已用 {fmt_secs(time.perf_counter() - self.start_time)}")
        self.root.after(80, self.poll_events)

    def show_progress(self, tested: int, total: int, rate: float, remain: float, label: str, length: int) -> None:
        pct = tested / total * 100 if total else 0.0
        self.progressbar.configure(value=min(pct, 100))
        self.pct_var.set(f"{pct:.1f}%")
        self.stage_var.set(f"{label} · 长度 {length}" if length else label)
        self.tested_var.set(f"已测 {zipcrack.fmt_num(tested)} / {zipcrack.fmt_num(total)}")
        self.speed_var.set(f"速度 {fmt_rate(rate)}")
        self.eta_var.set(f"剩余约 {fmt_secs(remain)}" if remain > 0 else "")
        self.status_var.set("运行中")

    def on_done(self, found: bytes | None, elapsed: float, cancelled: bool) -> None:
        self.set_running(False)
        self.elapsed_var.set(f"已用 {fmt_secs(elapsed)}")
        if cancelled:
            self.stage_var.set("已停止")
            self.status_var.set("已停止")
            self.log(f"已停止。耗时 {elapsed:.1f} 秒。")
            return
        if found is None:
            self.stage_var.set("未找到密码")
            self.status_var.set("完成 — 未找到")
            self.log(f"未找到密码。耗时 {elapsed:.1f} 秒。")
            self.log("建议：换用更合适的字符集/长度，或使用更大的字典文件。")
            return
        self.found_password = found
        text = zipcrack.display_password(found)
        self.result_var.set(text)
        self.progressbar.configure(value=100)
        self.pct_var.set("100%")
        self.stage_var.set("破解成功！")
        self.status_var.set(f"完成，耗时 {fmt_secs(elapsed)}")
        self.log(f"破解成功！密码: {text}（耗时 {elapsed:.1f} 秒）")
        if not found.isascii():
            self.log(f"密码十六进制: {found.hex()}")
        self.copy_btn.configure(state="normal")
        self.extract_btn.configure(state="normal")
        self.root.bell()

    def on_error(self, msg: str) -> None:
        self.set_running(False)
        self.stage_var.set("出错")
        self.status_var.set("出错")
        self.log(msg)
        messagebox.showerror("出错", msg)

    # ---------------- 结果操作 ----------------

    def copy_password(self) -> None:
        if self.found_password is None:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(zipcrack.display_password(self.found_password))
        self.status_var.set("密码已复制到剪贴板")

    def extract_all(self) -> None:
        if self.found_password is None:
            return
        zip_path = self.zip_path.get().strip()
        outdir = filedialog.askdirectory(
            title="选择解压输出目录",
            initialdir=os.path.dirname(zip_path) or os.getcwd(),
        )
        if not outdir:
            return
        self.extract_btn.configure(state="disabled")
        self.status_var.set("正在解压…")
        thread = threading.Thread(target=self.extract_worker, args=(zip_path, outdir, self.found_password), daemon=True)
        thread.start()

    def extract_worker(self, zip_path: str, outdir: str, password: bytes) -> None:
        ok = fail = 0
        try:
            with zipfile.ZipFile(zip_path) as archive:
                archive.setpassword(password)
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    try:
                        archive.extract(info, outdir)
                        ok += 1
                    except Exception as exc:
                        fail += 1
                        self.on_log(f"解压失败 {info.filename}: {exc}")
        except Exception as exc:
            self.events.put(("error", f"解压出错: {exc}"))
            return
        self.on_log(f"解压完成: 成功 {ok} 个，失败 {fail} 个 → {outdir}")
        self.events.put(("info_dialog", "解压完成", f"成功解压 {ok} 个文件，失败 {fail} 个。\n\n输出目录:\n{outdir}"))

    # ---------------- 日志与关闭 ----------------

    def log(self, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        for i, line in enumerate(str(msg).splitlines() or [""]):
            prefix = f"[{stamp}] " if i == 0 else " " * 11
            self.log_text.insert("end", prefix + line + "\n")
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 1500:
            self.log_text.delete("1.0", f"{line_count - 1200}.0")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def on_close(self) -> None:
        if self.running:
            if not messagebox.askyesno("正在破解", "破解仍在进行，确定要退出吗？"):
                return
            self.cancel_event.set()
            self.status_var.set("正在退出…")
            self._close_when_worker_done(0)
            return
        self.root.destroy()

    def _close_when_worker_done(self, ticks: int) -> None:
        worker = self.worker
        if worker is None or not worker.is_alive() or ticks > 100:
            self.root.destroy()
            return
        self.root.after(100, lambda: self._close_when_worker_done(ticks + 1))


def main() -> int:
    root = tk.Tk()
    CrackApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
