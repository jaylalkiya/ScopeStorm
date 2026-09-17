#!/usr/bin/env python3
"""
ScopeStorm - GUI  ::  terminal / phosphor theme
====================================================================

A Tkinter front-end that sits on TOP of the engine in
`scopestorm.py`. All logic (RoE scope enforcement, time-window
locking, hash-chained audit log, auto-abort, reporting) is reused unchanged
from that module -- this file is presentation only.

Look & feel: a green-phosphor "operator console" -- monospace throughout,
a glowing status core that pulses, a blinking command cursor, a live hex
data-stream ticker, and a short boot sequence. All animation is driven by
lightweight `after()` timers; none of it touches the engine or the audit path.

Run:
    python scopestorm_gui.py
"""

from __future__ import annotations

import json
import queue
import random
import time
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# Reuse the audited engine -- no logic is redefined here.
from scopestorm import (
    RulesOfEngagement,
    LoadTestEngine,
    AuditLog,
    build_report,
    percentile,
    knee_sample,
    user_agent,
    parse_headers,
    PATTERNS,
    DEFAULT_MARKER_HEADER,
    MAX_BODY_SIZE,
)

# a monospace stack that degrades gracefully across machines
MONO = "Cascadia Mono"
MONO_FALLBACK = "Consolas"

# one-line brief for each resilience scenario, shown under the pattern picker
PATTERN_DESC = {
    "constant": "flat full load — baseline stress",
    "ramp-up":  "linear 0→full — find the degradation point",
    "step":     "4-level staircase — isolate the breaking step",
    "spike":    "low + burst spikes — flash-crowd / surge test",
    "wave":     "sinusoidal — sustained oscillating pressure",
    "soak":     "steady ~50% — endurance / resource-leak hunt",
}


def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb):
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(c))) for c in rgb)


def _blend(fg, bg, t):
    """Blend fg->bg by t in [0,1]. t=0 => fg, t=1 => bg."""
    a, b = _hex_to_rgb(fg), _hex_to_rgb(bg)
    return _rgb_to_hex(tuple(a[i] + (b[i] - a[i]) * t for i in range(3)))


class LatencyGraph:
    """A phosphor oscilloscope: plots per-request latency over time, overlays
    the live P95 and the RoE auto-abort threshold, and pulses the newest read.
    Pure Tkinter Canvas drawing -- no external plotting dependency."""

    WINDOW = 200  # most-recent samples kept on screen

    def __init__(self, canvas, app):
        self.c = canvas
        self.app = app
        self.marker = None
        canvas.bind("<Configure>", lambda e: self.redraw(app.latency_series,
                                                          app._graph_abort))

    def pulse(self, color):
        if self.marker is not None:
            try:
                self.c.itemconfig(self.marker, outline=color)
            except tk.TclError:
                pass

    @staticmethod
    def knee_index(data, threshold, win=15):
        """Degradation knee for the on-screen trace -- delegates to the engine's
        shared, correctly-sorted implementation."""
        return knee_sample(data, threshold, win)

    def redraw(self, series, abort_p95):
        c, app = self.c, self.app
        try:
            c.delete("all")
        except tk.TclError:
            return
        self.marker = None
        w, h = c.winfo_width(), c.winfo_height()
        if w < 40 or h < 40:
            return

        pl, pr, pt, pb = 48, 14, 14, 22
        x0, y0, x1, y1 = pl, pt, w - pr, h - pb

        # CRT scanlines
        for yy in range(int(y0), int(y1), 3):
            c.create_line(x0, yy, x1, yy, fill="#08160f")
        c.create_rectangle(x0, y0, x1, y1, outline=app.BORDER)
        c.create_text(x0, y0 - 4, text="latency ms", anchor="sw",
                      fill=app.DIM, font=(MONO, 8, "bold"))

        data = [l for l, _ in series][-self.WINDOW:]
        oks = [o for _, o in series][-self.WINDOW:]
        if not data:
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2,
                          text="awaiting telemetry …", fill=app.FAINT,
                          font=(MONO, 9))
            return

        ymax = max(max(data) * 1.25, 10)
        if abort_p95 and abort_p95 <= max(data) * 2.0:
            ymax = max(ymax, abort_p95 * 1.12)

        for k in range(5):
            gy = y0 + (y1 - y0) * k / 4
            c.create_line(x0, gy, x1, gy, fill=app.GRID)
            c.create_text(x0 - 6, gy, text=f"{ymax * (1 - k / 4):.0f}", anchor="e",
                          fill=app.FAINT, font=(MONO, 8))

        n = len(data)

        def X(i):
            return x0 + (x1 - x0) * (i / max(n - 1, 1))

        def Y(v):
            return y1 - (y1 - y0) * (min(v, ymax) / ymax)

        # auto-abort threshold
        if abort_p95 and abort_p95 <= ymax:
            ay = Y(abort_p95)
            for xx in range(int(x0), int(x1), 10):
                c.create_line(xx, ay, min(xx + 5, x1), ay, fill=app.BAD)
            c.create_text(x1 - 2, ay - 7, text=f"ABORT p95 {abort_p95:.0f}",
                          anchor="e", fill=app.BAD, font=(MONO, 8, "bold"))
        elif abort_p95:
            c.create_text(x1 - 2, y0 + 4, text=f"abort @ {abort_p95:.0f}ms ↑",
                          anchor="ne", fill=app.BAD, font=(MONO, 8))

        # live P95
        p95 = percentile(data, 95)
        if 0 < p95 <= ymax:
            py = Y(p95)
            for xx in range(int(x0), int(x1), 8):
                c.create_line(xx, py, min(xx + 4, x1), py, fill=app.CYAN)
            c.create_text(x0 + 3, py - 7, text=f"p95 {p95:.0f}", anchor="w",
                          fill=app.CYAN, font=(MONO, 8, "bold"))

        # trend line + points
        pts = []
        for i, v in enumerate(data):
            pts += [X(i), Y(v)]
        if len(pts) >= 4:
            c.create_line(*pts, fill=_blend(app.GREEN, app.PANEL2, 0.45), width=1)
        for i, (v, o) in enumerate(zip(data, oks)):
            col = app.GREEN if o else app.BAD
            x, y = X(i), Y(v)
            c.create_oval(x - 1.6, y - 1.6, x + 1.6, y + 1.6, fill=col, outline="")

        # ramp-knee: mark where P95 first crossed the abort threshold
        knee = self.knee_index(data, abort_p95)
        if knee is not None:
            kx = X(knee)
            for yy in range(int(y0), int(y1), 7):
                c.create_line(kx, yy, kx, min(yy + 4, y1), fill=app.WARN)
            c.create_text(kx, y1 + 2, text="KNEE", anchor="n", fill=app.WARN,
                          font=(MONO, 8, "bold"))

        # pulsing latest reading
        lx, ly = X(n - 1), Y(data[-1])
        self.marker = c.create_oval(lx - 4, ly - 4, lx + 4, ly + 4,
                                    outline=app.GREEN, width=2)


class App:
    # ---- phosphor palette --------------------------------------------
    BG = "#03070a"          # deep console black
    SIDEBAR = "#04090d"
    PANEL = "#0a1014"       # card surface
    PANEL2 = "#060b0f"      # inset field / tile
    BORDER = "#123024"      # dim green hairline
    GRID = "#0e241b"
    TEXT = "#b9f5c9"        # soft phosphor text
    DIM = "#4f8f6a"         # dim green
    FAINT = "#2f5a44"
    GREEN = "#22ff88"       # primary accent (bright phosphor)
    CYAN = "#25e8ff"
    WARN = "#ffb000"        # amber
    BAD = "#ff2b4d"         # alert red
    ACCENT_DK = "#02150c"

    SIDEBAR_W = 440

    def __init__(self, root):
        self.root = root
        self.root.title("scopestorm :: authorized console")
        self.root.geometry("1340x860")
        self.root.minsize(1160, 740)
        self.root.configure(bg=self.BG)

        # resolve monospace font once (fall back if Cascadia is absent)
        try:
            import tkinter.font as tkfont
            fams = set(tkfont.families(self.root))
            global MONO
            if MONO not in fams:
                MONO = MONO_FALLBACK if MONO_FALLBACK in fams else "Courier New"
        except Exception:
            MONO = MONO_FALLBACK

        self.roe: RulesOfEngagement | None = None
        self.engine: LoadTestEngine | None = None
        self.audit: AuditLog | None = None
        self.config = None
        self.result_queue = queue.Queue()
        self.results = []
        self.metric_labels = {}

        # live-graph state
        self.latency_series = []      # (latency_ms, ok) per request
        self._graph_abort = None      # abort p95 threshold for the current run
        self._last_snap = None        # last engine snapshot (for redraw on resize)

        # animation state
        self._pulse_t = 0.0
        self._status_color = self.DIM
        self._cursor_on = True
        self._stream_buf = self._rand_hex(90)
        self._alive = True

        self._setup_style()
        self._build_ui()

        # timers: engine polling + presentation animation
        self.root.after(200, self._poll_results)
        self.root.after(500, self._update_metrics)
        self.root.after(60, self._animate_pulse)
        self.root.after(530, self._animate_cursor)
        self.root.after(90, self._animate_stream)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._boot_sequence()

    # ---------------------------------------------------------------- styling
    def _f(self, size, weight="normal"):
        return (MONO, size, weight)

    def _setup_style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")

        s.configure(".", background=self.PANEL, foreground=self.TEXT,
                    fieldbackground=self.PANEL2, bordercolor=self.BORDER,
                    focuscolor=self.GREEN, font=self._f(10))

        s.configure("TFrame", background=self.PANEL)
        s.configure("TLabel", background=self.PANEL, foreground=self.TEXT)

        s.configure("TEntry", fieldbackground=self.PANEL2, foreground=self.GREEN,
                    insertcolor=self.GREEN, bordercolor=self.BORDER,
                    lightcolor=self.BORDER, darkcolor=self.BORDER, padding=6)
        s.map("TEntry", bordercolor=[("focus", self.GREEN)])
        s.configure("TSpinbox", fieldbackground=self.PANEL2, foreground=self.GREEN,
                    arrowcolor=self.DIM, bordercolor=self.BORDER,
                    lightcolor=self.BORDER, darkcolor=self.BORDER, padding=5)
        s.map("TSpinbox", bordercolor=[("focus", self.GREEN)])
        s.configure("TCombobox", fieldbackground=self.PANEL2, foreground=self.GREEN,
                    arrowcolor=self.DIM, bordercolor=self.BORDER,
                    lightcolor=self.BORDER, darkcolor=self.BORDER, padding=5,
                    selectbackground=self.PANEL2, selectforeground=self.GREEN)
        s.map("TCombobox", fieldbackground=[("readonly", self.PANEL2)],
              foreground=[("readonly", self.GREEN)])
        self.root.option_add("*TCombobox*Listbox.background", self.PANEL2)
        self.root.option_add("*TCombobox*Listbox.foreground", self.GREEN)
        self.root.option_add("*TCombobox*Listbox.font", self._f(10))
        self.root.option_add("*TCombobox*Listbox.selectBackground", self.GREEN)
        self.root.option_add("*TCombobox*Listbox.selectForeground", self.ACCENT_DK)

        s.configure("TCheckbutton", background=self.PANEL, foreground=self.TEXT)
        s.map("TCheckbutton", background=[("active", self.PANEL)],
              indicatorcolor=[("selected", self.GREEN), ("!selected", self.PANEL2)],
              foreground=[("active", self.GREEN)])

        s.configure("TButton", background=self.PANEL2, foreground=self.DIM,
                    bordercolor=self.BORDER, lightcolor=self.BORDER,
                    darkcolor=self.BORDER, padding=(12, 8), font=self._f(9, "bold"))
        s.map("TButton", background=[("active", self.GRID)],
              foreground=[("active", self.GREEN), ("disabled", self.FAINT)],
              bordercolor=[("active", self.GREEN)])
        s.configure("Accent.TButton", background=self.GREEN, foreground=self.ACCENT_DK,
                    bordercolor=self.GREEN, lightcolor=self.GREEN,
                    darkcolor=self.GREEN, padding=(16, 11), font=self._f(11, "bold"))
        s.map("Accent.TButton",
              background=[("active", "#5bffa8"), ("disabled", "#0f3323")],
              foreground=[("disabled", self.FAINT)])
        s.configure("Danger.TButton", background="#2a0a12", foreground=self.BAD,
                    bordercolor="#5a1522", lightcolor="#5a1522", darkcolor="#5a1522",
                    padding=(16, 11), font=self._f(11, "bold"))
        s.map("Danger.TButton",
              background=[("active", "#43101c"), ("disabled", self.PANEL)],
              foreground=[("disabled", self.FAINT)])

        s.configure("TNotebook", background=self.PANEL, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=self.PANEL2, foreground=self.DIM,
                    padding=(16, 7), borderwidth=0, font=self._f(9, "bold"))
        s.map("TNotebook.Tab", background=[("selected", self.GRID)],
              foreground=[("selected", self.GREEN), ("active", self.TEXT)])

        s.configure("Run.Horizontal.TProgressbar", troughcolor=self.PANEL2,
                    background=self.GREEN, bordercolor=self.PANEL2,
                    lightcolor=self.GREEN, darkcolor=self.GREEN, thickness=10)

        s.configure("Treeview", background=self.PANEL2, foreground=self.TEXT,
                    fieldbackground=self.PANEL2, rowheight=24, borderwidth=0,
                    font=self._f(9))
        s.configure("Treeview.Heading", background="#08120d", foreground=self.DIM,
                    relief="flat", padding=7, font=self._f(8, "bold"), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", "#08120d")])
        s.map("Treeview", background=[("selected", "#0f3a29")],
              foreground=[("selected", self.GREEN)])

        s.configure("Vertical.TScrollbar", background=self.GRID, troughcolor=self.BG,
                    bordercolor=self.BG, arrowcolor=self.DIM, lightcolor=self.GRID,
                    darkcolor=self.GRID)

    # ---- tiny builders ----------------------------------------------------
    def _card(self, parent, bg=None):
        return tk.Frame(parent, bg=bg or self.PANEL,
                        highlightbackground=self.BORDER, highlightthickness=1, bd=0)

    def _section(self, parent, text, bg=None):
        return tk.Label(parent, text=text, bg=bg or self.PANEL, fg=self.GREEN,
                        font=self._f(9, "bold"))

    def _flabel(self, parent, text, bg=None):
        return tk.Label(parent, text=text, bg=bg or self.PANEL, fg=self.DIM,
                        font=self._f(8, "bold"))

    def _textbox(self, parent, height):
        return tk.Text(parent, height=height, bg=self.PANEL2, fg=self.GREEN,
                       insertbackground=self.GREEN, relief="flat",
                       highlightthickness=1, highlightbackground=self.BORDER,
                       highlightcolor=self.GREEN, wrap="word", font=self._f(9),
                       padx=8, pady=6)

    # -------------------------------------------------------------------- UI
    def _build_ui(self):
        top = tk.Frame(self.root, bg=self.BG)
        top.pack(fill="x", padx=18, pady=(14, 0))

        tk.Label(top, text="[█]", bg=self.BG, fg=self.GREEN,
                 font=self._f(16, "bold")).pack(side="left", padx=(0, 10))
        tbox = tk.Frame(top, bg=self.BG)
        tbox.pack(side="left")
        tk.Label(tbox, text="scopestorm", bg=self.BG, fg=self.GREEN,
                 font=self._f(16, "bold")).pack(side="left")
        self.header_cursor = tk.Label(tbox, text="█", bg=self.BG, fg=self.GREEN,
                                      font=self._f(16, "bold"))
        self.header_cursor.pack(side="left")
        tk.Label(tbox, text="  authorized red-team console", bg=self.BG, fg=self.DIM,
                 font=self._f(10)).pack(side="left")

        pill = tk.Frame(top, bg=self.PANEL, highlightbackground=self.BORDER,
                        highlightthickness=1)
        pill.pack(side="right")
        self.status_dot = tk.Label(pill, text="●", bg=self.PANEL, fg=self.DIM,
                                   font=self._f(12))
        self.status_dot.pack(side="left", padx=(12, 6), pady=6)
        self.status_var = tk.StringVar(value="NO RoE LOADED")
        self.status_lbl = tk.Label(pill, textvariable=self.status_var, bg=self.PANEL,
                                   fg=self.TEXT, font=self._f(9, "bold"))
        self.status_lbl.pack(side="left", padx=(0, 14), pady=6)

        # live hex data-stream ticker
        self.stream_lbl = tk.Label(self.root, anchor="w", bg=self.BG, fg=self.FAINT,
                                   font=self._f(8), justify="left")
        self.stream_lbl.pack(fill="x", padx=18, pady=(8, 0))
        tk.Frame(self.root, bg=self.BORDER, height=1).pack(fill="x", pady=(6, 0))

        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True, padx=18, pady=16)

        sidebar = tk.Frame(body, bg=self.SIDEBAR, width=self.SIDEBAR_W)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        tk.Frame(body, bg=self.BG, width=16).pack(side="left", fill="y")

        dash = tk.Frame(body, bg=self.BG)
        dash.pack(side="left", fill="both", expand=True)
        self._build_dashboard(dash)

    # ---- sidebar -----------------------------------------------------------
    def _build_sidebar(self, parent):
        canvas = tk.Canvas(parent, bg=self.SIDEBAR, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        col = tk.Frame(canvas, bg=self.SIDEBAR)
        wid = canvas.create_window((0, 0), window=col, anchor="nw")

        def _cfg(_=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfigure(wid, width=canvas.winfo_width())
        col.bind("<Configure>", _cfg)
        canvas.bind("<Configure>", _cfg)

        def _wheel(e):
            # Route the wheel to whatever is under the pointer. A global
            # bind_all fires *in addition to* each widget's own class binding,
            # so without this the sidebar scrolls at the same time as the
            # results table / text boxes. Let scrollable widgets handle their
            # own wheel, and only scroll the sidebar when truly over it.
            node = self.root.winfo_containing(e.x_root, e.y_root)
            while node is not None:
                if isinstance(node, (tk.Text, ttk.Treeview)):
                    return                      # widget scrolls itself
                if node is canvas:
                    if canvas.winfo_height() < col.winfo_reqheight():
                        canvas.yview_scroll(-int(e.delta / 120), "units")
                    return
                node = getattr(node, "master", None)
        canvas.bind_all("<MouseWheel>", _wheel)

        self._build_roe_card(col)
        self._build_target_card(col)
        self._build_load_card(col)
        self._build_advanced_card(col)
        self._build_playbook_card(col)
        self._build_controls_card(col)
        self._refresh_playbooks()

    def _build_roe_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        head = tk.Frame(inner, bg=self.PANEL)
        head.pack(fill="x")
        self._section(head, "// RULES OF ENGAGEMENT").pack(side="left")
        ttk.Button(head, text="load roe…", command=self._load_roe).pack(
            side="right")
        self.roe_summary = tk.Label(
            inner, bg=self.PANEL, fg=self.DIM, justify="left", anchor="w",
            font=self._f(9),
            text="[ no roe loaded ]\nload a signed engagement file to arm testing.")
        self.roe_summary.pack(fill="x", pady=(10, 0))

    def _build_target_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        self._section(inner, "// TARGET").pack(anchor="w")
        self._flabel(inner, "ENDPOINT URL  (must be in roe scope)").pack(
            anchor="w", pady=(10, 3))
        self.url_var = tk.StringVar(value="http://localhost:8099/")
        ttk.Entry(inner, textvariable=self.url_var).pack(fill="x")
        self._flabel(inner, "METHOD").pack(anchor="w", pady=(10, 3))
        self.method_var = tk.StringVar(value="GET")
        ttk.Combobox(inner, textvariable=self.method_var, state="readonly",
                     values=["GET", "POST", "PUT", "PATCH", "DELETE"]).pack(fill="x")

    def _build_load_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        self._section(inner, "// LOAD PROFILE").pack(anchor="w")
        tk.Label(inner, text="clamped to roe ceilings and hard caps.",
                 bg=self.PANEL, fg=self.FAINT, font=self._f(8)).pack(
            anchor="w", pady=(2, 8))
        self.concurrency_var = tk.IntVar(value=3)
        self.rps_var = tk.IntVar(value=5)
        self.duration_var = tk.IntVar(value=30)
        self.pattern_var = tk.StringVar(value="constant")
        grid = tk.Frame(inner, bg=self.PANEL)
        grid.pack(fill="x")
        specs = [("CONCURRENCY", self.concurrency_var, 1, 25),
                 ("REQ / SEC", self.rps_var, 1, 20),
                 ("DURATION s", self.duration_var, 1, 300)]
        for i, (label, var, lo, hi) in enumerate(specs):
            cell = tk.Frame(grid, bg=self.PANEL)
            cell.grid(row=0, column=i, sticky="ew", padx=(0, 8 if i < 2 else 0))
            grid.columnconfigure(i, weight=1)
            self._flabel(cell, label).pack(anchor="w", pady=(0, 3))
            ttk.Spinbox(cell, from_=lo, to=hi, textvariable=var, width=8).pack(
                fill="x")
        self._flabel(inner, "SCENARIO").pack(anchor="w", pady=(10, 3))
        ttk.Combobox(inner, textvariable=self.pattern_var, state="readonly",
                     values=list(PATTERNS)).pack(fill="x")
        self.pattern_desc = tk.Label(
            inner, text=PATTERN_DESC.get("constant", ""), bg=self.PANEL,
            fg=self.CYAN, font=self._f(8), anchor="w", justify="left")
        self.pattern_desc.pack(fill="x", pady=(4, 0))
        self.pattern_var.trace_add(
            "write", lambda *_: self.pattern_desc.config(
                text=PATTERN_DESC.get(self.pattern_var.get(), "")))

    def _build_advanced_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        self._section(inner, "// REQUEST DETAIL").pack(anchor="w", pady=(0, 8))
        nb = ttk.Notebook(inner)
        nb.pack(fill="both", expand=True)
        htab = tk.Frame(nb, bg=self.PANEL)
        nb.add(htab, text="headers")
        tk.Label(htab, text="one  'Header-Name: value'  per line", bg=self.PANEL,
                 fg=self.FAINT, font=self._f(8)).pack(anchor="w", pady=(8, 4))
        self.headers_text = self._textbox(htab, 5)
        self.headers_text.pack(fill="both", expand=True)
        btab = tk.Frame(nb, bg=self.PANEL)
        nb.add(btab, text="body")
        tk.Label(btab, text="optional payload (post / put / patch)", bg=self.PANEL,
                 fg=self.FAINT, font=self._f(8)).pack(anchor="w", pady=(8, 4))
        self.body_text = self._textbox(btab, 5)
        self.body_text.pack(fill="both", expand=True)

        etab = tk.Frame(nb, bg=self.PANEL)
        nb.add(etab, text="journey")
        tk.Label(etab, text="multi-endpoint journey — one per line, "
                            "'METHOD url' or just url.\nblank = use the single "
                            "target above. every url is scope-checked.",
                 bg=self.PANEL, fg=self.FAINT, font=self._f(8),
                 justify="left").pack(anchor="w", pady=(8, 4))
        self.endpoints_text = self._textbox(etab, 5)
        self.endpoints_text.pack(fill="both", expand=True)

        # per-request token templating toggle
        self.template_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            inner, variable=self.template_var,
            text="inject tokens per request  {{uuid}} {{seq}} {{rand}} {{ts}}  "
                 "(cache-bust)").pack(anchor="w", pady=(8, 0))

    def _build_playbook_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        self._section(inner, "// ENGAGEMENT PLAYBOOKS").pack(anchor="w")
        tk.Label(inner,
                 text="save / reload a full attack profile (target, scenario,\n"
                      "headers, body) as a named playbook.",
                 bg=self.PANEL, fg=self.FAINT, font=self._f(8),
                 justify="left").pack(anchor="w", pady=(2, 8))
        self.playbook_var = tk.StringVar(value="")
        self.playbook_box = ttk.Combobox(inner, textvariable=self.playbook_var,
                                         state="readonly", values=[])
        self.playbook_box.pack(fill="x")
        btns = tk.Frame(inner, bg=self.PANEL)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="load", command=self._load_playbook).pack(
            side="left", fill="x", expand=True)
        ttk.Button(btns, text="save…", command=self._save_playbook).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(btns, text="del", command=self._delete_playbook).pack(
            side="left", fill="x", expand=True)

    def _build_controls_card(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(0, 4))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        self.confirm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            inner, variable=self.confirm_var,
            text="[x] client owns this target & authorized this test\n"
                 "    under the loaded roe.").pack(anchor="w", pady=(0, 12))
        btns = tk.Frame(inner, bg=self.PANEL)
        btns.pack(fill="x")
        self.start_btn = ttk.Button(btns, text="▶ EXECUTE", style="Accent.TButton",
                                    command=self.start_test)
        self.start_btn.pack(side="left", fill="x", expand=True)
        self.stop_btn = ttk.Button(btns, text="■ ABORT", style="Danger.TButton",
                                   command=self.stop_test, state="disabled")
        self.stop_btn.pack(side="left", fill="x", expand=True, padx=(8, 0))

    # ---- dashboard (right pane) --------------------------------------------
    def _build_dashboard(self, parent):
        self._build_metrics(parent)
        self._build_progress(parent)
        self._build_midband(parent)
        self._build_results(parent)
        self._build_toolbar(parent)

    def _build_midband(self, parent):
        mid = tk.Frame(parent, bg=self.BG)
        mid.pack(fill="x", pady=(0, 12))

        # left: live latency oscilloscope
        gcard = self._card(mid)
        gcard.pack(side="left", fill="both", expand=True)
        gin = tk.Frame(gcard, bg=self.PANEL)
        gin.pack(fill="both", expand=True, padx=12, pady=10)
        self._section(gin, "// LIVE LATENCY  [oscilloscope]").pack(anchor="w",
                                                                   pady=(0, 6))
        gcanvas = tk.Canvas(gin, bg=self.PANEL2, height=210, highlightthickness=1,
                            highlightbackground=self.BORDER, bd=0)
        gcanvas.pack(fill="both", expand=True)
        self.lat_graph = LatencyGraph(gcanvas, self)

        # right: live status-code distribution
        ccard = self._card(mid)
        ccard.pack(side="left", fill="y", padx=(12, 0))
        cin = tk.Frame(ccard, bg=self.PANEL, width=272)
        cin.pack(fill="both", expand=True, padx=12, pady=10)
        cin.pack_propagate(False)
        self._section(cin, "// RESPONSE CODES").pack(anchor="w", pady=(0, 6))
        self.codes_canvas = tk.Canvas(cin, bg=self.PANEL2, width=248, height=210,
                                      highlightthickness=1,
                                      highlightbackground=self.BORDER, bd=0)
        self.codes_canvas.pack(fill="both", expand=True)
        self.codes_canvas.bind("<Configure>",
                               lambda e: self._draw_codes(self._last_snap))

    def _build_metrics(self, parent):
        wrap = tk.Frame(parent, bg=self.BG)
        wrap.pack(fill="x")
        # (canonical key, display, accent-strip color)
        tiles = [("Elapsed", "ELAPSED", self.DIM),
                 ("Requests", "REQUESTS", self.CYAN),
                 ("Success", "SUCCESS", self.GREEN),
                 ("Failed", "FAILED", self.BAD),
                 ("Error rate", "ERROR RATE", self.WARN),
                 ("Throughput", "THROUGHPUT", self.CYAN),
                 ("P95 latency", "P95 ms", self.DIM),
                 ("P99 latency", "P99 ms", self.DIM)]
        for i in range(4):
            wrap.columnconfigure(i, weight=1, uniform="m")
        for idx, (key, disp, accent) in enumerate(tiles):
            r, c = divmod(idx, 4)
            tile = self._card(wrap, bg=self.PANEL2)
            tile.grid(row=r, column=c, sticky="nsew",
                      padx=(0 if c == 0 else 6, 0), pady=(0 if r == 0 else 10, 0))
            tk.Frame(tile, bg=accent, height=3).pack(fill="x")
            b = tk.Frame(tile, bg=self.PANEL2)
            b.pack(fill="both", expand=True, padx=14, pady=(9, 12))
            tk.Label(b, text=disp, bg=self.PANEL2, fg=self.DIM,
                     font=self._f(8, "bold")).pack(anchor="w")
            val = tk.Label(b, text="—", bg=self.PANEL2, fg=self.TEXT,
                           font=self._f(20, "bold"))
            val.pack(anchor="w", pady=(4, 0))
            self.metric_labels[key] = val

    def _build_progress(self, parent):
        card = self._card(parent)
        card.pack(fill="x", pady=(12, 12))
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="x", padx=14, pady=12)
        row = tk.Frame(inner, bg=self.PANEL)
        row.pack(fill="x")
        self._section(row, "// RUN PROGRESS").pack(side="left")
        self.progress_label = tk.Label(row, text="idle", bg=self.PANEL, fg=self.FAINT,
                                       font=self._f(9))
        self.progress_label.pack(side="right")
        self.progress = ttk.Progressbar(inner, style="Run.Horizontal.TProgressbar",
                                        mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(8, 0))

    def _build_results(self, parent):
        card = self._card(parent)
        card.pack(fill="both", expand=True)
        inner = tk.Frame(card, bg=self.PANEL)
        inner.pack(fill="both", expand=True, padx=14, pady=12)
        head = tk.Frame(inner, bg=self.PANEL)
        head.pack(fill="x", pady=(0, 8))
        self._section(head, "// LIVE REQUEST LOG").pack(side="left")
        self.log_count = tk.Label(head, text="0 total", bg=self.PANEL, fg=self.FAINT,
                                  font=self._f(8))
        self.log_count.pack(side="right")
        table = tk.Frame(inner, bg=self.PANEL)
        table.pack(fill="both", expand=True)
        cols = ("time", "method", "status", "code", "latency", "size", "error")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", height=12)
        heads = {"time": "TIME", "method": "METHOD", "status": "STATUS",
                 "code": "HTTP", "latency": "LATENCY", "size": "SIZE",
                 "error": "ERROR"}
        widths = {"time": 150, "method": 78, "status": 88, "code": 64,
                  "latency": 96, "size": 84, "error": 320}
        anchors = {"latency": "e", "size": "e", "code": "center", "method": "center",
                   "status": "center"}
        for col in cols:
            self.tree.heading(col, text=heads[col])
            self.tree.column(col, width=widths[col], anchor=anchors.get(col, "w"),
                             stretch=(col == "error"))
        ys = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.tree.tag_configure("success", foreground=self.GREEN)
        self.tree.tag_configure("error", foreground=self.BAD)
        self.tree.tag_configure("odd", background="#08110c")
        self.tree.tag_configure("even", background=self.PANEL2)

    def _build_toolbar(self, parent):
        bar = tk.Frame(parent, bg=self.BG)
        bar.pack(fill="x", pady=(12, 0))
        ttk.Button(bar, text="⬇ report.json",
                   command=self.export_report).pack(side="left")
        ttk.Button(bar, text="⬇ results.csv",
                   command=self.export_csv).pack(side="left", padx=8)
        ttk.Button(bar, text="✓ verify audit chain",
                   command=self.verify_audit).pack(side="left")
        ttk.Button(bar, text="\U0001f6e1 blue-team view",
                   command=self.blue_team_view).pack(side="left", padx=8)

    # ---- status-code distribution panel -----------------------------------
    def _code_color(self, code):
        try:
            c = int(code)
        except (TypeError, ValueError):
            return self.DIM
        if 200 <= c < 300:
            return self.GREEN
        if 300 <= c < 400:
            return self.CYAN
        if 400 <= c < 500:
            return self.WARN
        if c >= 500:
            return self.BAD
        return self.DIM

    def _draw_codes(self, snap):
        c = self.codes_canvas
        try:
            c.delete("all")
        except tk.TclError:
            return
        w, h = c.winfo_width(), c.winfo_height()
        if w < 20 or h < 20:
            return
        rows = []
        if snap:
            for code, v in sorted(snap.get("status_counts", {}).items(),
                                  key=lambda kv: -kv[1]):
                rows.append((f"HTTP {code}", v, self._code_color(code)))
            for et, v in sorted(snap.get("error_types", {}).items(),
                                key=lambda kv: -kv[1]):
                rows.append((f"! {et}"[:14], v, self.BAD))
        if not rows:
            c.create_text(w / 2, h / 2, text="no responses yet", fill=self.FAINT,
                          font=(MONO, 9))
            return
        pad, rh, gap, barx = 12, 16, 10, 96
        maxv = max(v for _, v, _ in rows) or 1
        barw = w - barx - 42
        y = pad
        for label, v, col in rows[:8]:
            c.create_text(pad, y + rh / 2, text=label, anchor="w", fill=self.TEXT,
                          font=(MONO, 9))
            c.create_rectangle(barx, y + 3, barx + max(barw * v / maxv, 2),
                               y + rh - 3, fill=col, outline="")
            c.create_text(w - pad, y + rh / 2, text=str(v), anchor="e", fill=self.DIM,
                          font=(MONO, 9))
            y += rh + gap

    # ---------------------------------------------------------- animations
    def _rand_hex(self, n):
        return " ".join(f"{random.randint(0, 255):02X}" for _ in range(n))

    def _safe_after(self, ms, fn):
        if self._alive:
            try:
                self.root.after(ms, fn)
            except tk.TclError:
                pass

    def _animate_pulse(self):
        """Breathing glow on the status core, keyed to the current state color."""
        self._pulse_t += 0.18
        import math
        # 0.35..1.0 brightness
        b = 0.5 + 0.5 * math.sin(self._pulse_t)
        glow = _blend("#000000", self._status_color, 0.35 + 0.65 * b)
        try:
            self.status_dot.config(fg=glow)
        except tk.TclError:
            return
        if getattr(self, "lat_graph", None):
            self.lat_graph.pulse(_blend("#000000", self.GREEN, 0.4 + 0.6 * b))
        self._safe_after(60, self._animate_pulse)

    def _animate_cursor(self):
        self._cursor_on = not self._cursor_on
        try:
            self.header_cursor.config(
                fg=self.GREEN if self._cursor_on else self.BG)
        except tk.TclError:
            return
        self._safe_after(530, self._animate_cursor)

    def _animate_stream(self):
        # shift the hex buffer left and append fresh bytes -> flowing data feel
        parts = self._stream_buf.split(" ")
        shift = random.randint(1, 3)
        parts = parts[shift:] + [f"{random.randint(0, 255):02X}" for _ in range(shift)]
        self._stream_buf = " ".join(parts)
        prefix = ">> " if not self.engine else ">> tx "
        try:
            self.stream_lbl.config(text=prefix + self._stream_buf,
                                   fg=self.DIM if self.engine else self.FAINT)
        except tk.TclError:
            return
        self._safe_after(90, self._animate_stream)

    def _boot_sequence(self):
        lines = [
            ("booting scopestorm core ................ ok", self.DIM),
            ("loading scope-enforcement module .......... ok", self.DIM),
            ("arming hash-chained audit writer .......... ok", self.DIM),
            ("safety auto-abort watchdog ................ ok", self.GREEN),
            ("awaiting rules-of-engagement .............. idle", self.WARN),
        ]

        def step(i=0):
            if i >= len(lines) or not self._alive:
                return
            text, color = lines[i]
            try:
                self.tree.insert("", "end", tags=("even",),
                                 values=("boot", "SYS", "OK", "", "", "", text))
                self.tree.yview_moveto(1.0)
            except tk.TclError:
                return
            self._safe_after(180, lambda: step(i + 1))
        self._safe_after(250, step)

    # ------------------------------------------------------------- behaviour
    def _set_status(self, text, color=None):
        self.status_var.set(text)
        self._status_color = color or self.DIM
        try:
            self.status_lbl.config(fg=_blend(self._status_color, self.TEXT, 0.15))
        except tk.TclError:
            pass

    def _load_roe(self):
        path = filedialog.askopenfilename(
            title="Load Rules of Engagement",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            roe = RulesOfEngagement.load(path)
        except Exception as exc:  # noqa: BLE001 - surface any RoE problem to user
            messagebox.showerror("Invalid RoE", str(exc))
            return
        self.roe = roe
        self.roe_path = path
        window = (f"{roe.window_start}-{roe.window_end}"
                  if roe.window_start and roe.window_end else "any time")
        self.roe_summary.config(
            fg=self.TEXT,
            text=(f"id       {roe.engagement_id}\n"
                  f"client   {roe.client}\n"
                  f"operator {roe.operator_label}\n"
                  f"scope    {', '.join(roe.authorized_hosts)}\n"
                  f"ceilings {roe.max_concurrency}w / {roe.max_rps}rps / "
                  f"{roe.max_duration}s\n"
                  f"window   {window}\n"
                  f"abort    err>{roe.abort_error_rate:.0%} | "
                  f"p95>{roe.abort_p95_latency_ms:.0f}ms"))
        self.concurrency_var.set(min(self.concurrency_var.get(), roe.max_concurrency))
        self.rps_var.set(min(self.rps_var.get(), roe.max_rps))
        self.duration_var.set(min(self.duration_var.get(), roe.max_duration))
        self._set_status("ARMED / READY", self.GREEN)

    def start_test(self):
        if not self.roe:
            messagebox.showerror("No RoE", "Load a Rules-of-Engagement file first.")
            return
        if not self.confirm_var.get():
            messagebox.showerror("Not confirmed",
                                 "You must tick the authorization confirmation.")
            return
        url = self.url_var.get().strip()
        # parse an optional multi-endpoint journey
        endpoints = []
        for ln in self.endpoints_text.get("1.0", "end").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in {
                    "GET", "POST", "PUT", "PATCH", "DELETE"}:
                endpoints.append({"method": parts[0].upper(),
                                  "url": parts[1].strip()})
            else:
                endpoints.append({"method": self.method_var.get(), "url": ln})
        # scope-check: the single target (if no journey) or every journey hop
        check_urls = [e["url"] for e in endpoints] if endpoints else [url]
        try:
            for u in check_urls:
                self.roe.authorizes(u)
        except ValueError as exc:
            messagebox.showerror("Out of scope", str(exc))
            return
        if endpoints:
            url = endpoints[0]["url"]   # primary target for the report/audit
        if not self.roe.in_allowed_window():
            messagebox.showerror(
                "Outside window",
                f"Testing is only allowed {self.roe.window_start}-"
                f"{self.roe.window_end}.")
            return
        try:
            headers = parse_headers(
                [ln for ln in self.headers_text.get("1.0", "end").splitlines()
                 if ln.strip()])
        except ValueError as exc:
            messagebox.showerror("Bad header", str(exc))
            return
        body = self.body_text.get("1.0", "end-1c")
        if len(body.encode("utf-8")) > MAX_BODY_SIZE:
            messagebox.showerror("Body too large",
                                 f"Body exceeds {MAX_BODY_SIZE} bytes.")
            return

        concurrency = min(int(self.concurrency_var.get()), self.roe.max_concurrency)
        rps = min(int(self.rps_var.get()), self.roe.max_rps)
        duration = min(int(self.duration_var.get()), self.roe.max_duration)

        for e in endpoints:                       # per-hop body defaults to shared
            e.setdefault("body", body)
        self.config = {
            "url": url, "method": self.method_var.get(),
            "pattern": self.pattern_var.get(), "concurrency": concurrency,
            "rps": rps, "duration": duration, "timeout": self.roe.timeout,
            "headers": headers, "body": body, "marker_header": DEFAULT_MARKER_HEADER,
            "endpoints": endpoints, "templating": bool(self.template_var.get()),
        }

        self.results.clear()
        self.latency_series.clear()
        self._graph_abort = self.roe.abort_p95_latency_ms
        self._last_snap = None
        self.lat_graph.redraw(self.latency_series, self._graph_abort)
        self._draw_codes(None)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.result_queue = queue.Queue()
        self.progress.config(value=0)
        self.progress_label.config(text=f"0.0s / {duration}s", fg=self.GREEN)

        audit_path = str(Path(self.roe_path).with_name(
            f"audit_{self.roe.engagement_id}.jsonl"))
        self.audit = AuditLog(audit_path, self.roe.engagement_id)
        self.audit.record("test_start", operator=self.roe.operator_label, target=url,
                          method=self.config["method"], pattern=self.config["pattern"],
                          concurrency=concurrency, rps=rps, duration=duration,
                          endpoints=len(endpoints) or 1,
                          templating=bool(self.template_var.get()), source="gui")

        self.engine = LoadTestEngine(self.config, self.roe, self.audit,
                                     self.result_queue)
        self.engine.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._set_status(f"RUNNING • {self.roe.engagement_id}", self.GREEN)

    def stop_test(self):
        if self.engine:
            self.engine.stop("operator stop (GUI)")
            self._set_status("ABORTING", self.WARN)
        self.stop_btn.config(state="disabled")

    def _poll_results(self):
        drained = 0
        for _ in range(2000):
            try:
                r = self.result_queue.get_nowait()
            except queue.Empty:
                break
            self.results.append(r)
            self.latency_series.append((r.latency_ms, r.status == "success"))
            status_tag = "success" if r.status == "success" else "error"
            zebra = "odd" if (len(self.results) & 1) else "even"
            self.tree.insert("", "end", tags=(zebra, status_tag), values=(
                r.timestamp, r.method, r.status.upper(), r.status_code,
                f"{r.latency_ms:.1f} ms", f"{r.response_size} B", r.error))
            drained += 1
        if drained:
            if len(self.latency_series) > 4000:
                self.latency_series = self.latency_series[-2000:]
            kids = self.tree.get_children()
            if len(kids) > 500:
                for item in kids[:-500]:
                    self.tree.delete(item)
            self.tree.yview_moveto(1.0)
            self.log_count.config(text=f"{len(self.results)} total")
            self.lat_graph.redraw(self.latency_series, self._graph_abort)
        self.root.after(200, self._poll_results)

    def _update_metrics(self):
        if self.engine and self.engine.start_time:
            snap = self.engine.metrics.snapshot()
            self._last_snap = snap
            elapsed = max(time.monotonic() - self.engine.start_time, 0.001)
            lat = snap["latencies"]
            p95 = percentile(lat, 95)
            vals = {
                "Elapsed": f"{elapsed:.1f}s",
                "Requests": str(snap["total"]),
                "Success": str(snap["successful"]),
                "Failed": str(snap["failed"]),
                "Error rate": f"{snap['error_rate']:.0%}",
                "Throughput": f"{snap['total'] / elapsed:.2f}/s",
                "P95 latency": f"{p95:.0f}",
                "P99 latency": f"{percentile(lat, 99):.0f}",
            }
            for k, v in vals.items():
                if k in self.metric_labels:
                    self.metric_labels[k].config(text=v)

            er = snap["error_rate"]
            self.metric_labels["Error rate"].config(
                fg=self.BAD if er > self.roe.abort_error_rate else
                self.WARN if er > 0 else self.GREEN)
            self.metric_labels["P95 latency"].config(
                fg=self.BAD if p95 > self.roe.abort_p95_latency_ms else self.TEXT)

            dur = max(self.config.get("duration", 1), 1)
            self.progress.config(value=min(elapsed / dur * 100, 100))
            self.progress_label.config(text=f"{elapsed:.1f}s / {dur}s", fg=self.GREEN)

            self._draw_codes(snap)

            if self.engine.finished_event.is_set():
                self._finish_run(elapsed, snap)
        self.root.after(500, self._update_metrics)

    def _finish_run(self, elapsed, snap):
        report = build_report(self.roe, self.config, self.engine.metrics,
                              elapsed, self.engine.abort_reason)
        self.last_report = report
        self.audit.record("test_end", terminated_by=report["terminated_by"],
                          totals=report["totals"])
        dur = self.config.get("duration", 0)
        self.progress.config(value=100)
        if self.engine.abort_reason and "AUTO-ABORT" in self.engine.abort_reason:
            self.progress_label.config(text=f"{elapsed:.1f}s / {dur}s  :: ABORTED",
                                       fg=self.BAD)
            self._set_status("AUTO-ABORTED", self.BAD)
            messagebox.showwarning("Auto-abort", self.engine.abort_reason)
        else:
            self.progress_label.config(text=f"{elapsed:.1f}s / {dur}s  :: DONE",
                                       fg=self.GREEN)
            self._set_status("COMPLETE", self.CYAN)
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.engine = None

    def export_report(self):
        if not getattr(self, "last_report", None):
            messagebox.showinfo("Export", "Run a test first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile=f"report_{self.last_report['engagement_id']}.json")
        if path:
            Path(path).write_text(json.dumps(self.last_report, indent=2),
                                  encoding="utf-8")
            messagebox.showinfo("Export", f"Report written:\n{path}")

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "method", "url", "status", "status_code",
                        "latency_ms", "response_size", "error"])
            for r in self.results:
                w.writerow([r.timestamp, r.method, r.url, r.status, r.status_code,
                            r.latency_ms, r.response_size, r.error])
        messagebox.showinfo("Export", f"CSV written:\n{path}")

    def verify_audit(self):
        if not self.audit:
            messagebox.showinfo("Audit", "No audit log yet — run a test first.")
            return
        ok = self.audit.verify()
        (messagebox.showinfo if ok else messagebox.showerror)(
            "Audit chain",
            "Chain intact — the audit log has not been tampered with." if ok
            else "CHAIN BROKEN — the audit log was modified after the fact.")

    # ---- engagement playbooks ---------------------------------------------
    def _playbook_dir(self):
        d = Path(__file__).resolve().parent / "playbooks"
        d.mkdir(exist_ok=True)
        return d

    SEED_PLAYBOOKS = [
        {"name": "health-check", "url": "http://localhost:8099/health",
         "method": "GET", "pattern": "constant", "concurrency": 2, "rps": 3,
         "duration": 30, "headers": "", "body": ""},
        {"name": "spike-survival", "url": "http://localhost:8099/", "method": "GET",
         "pattern": "spike", "concurrency": 5, "rps": 8, "duration": 60,
         "headers": "", "body": ""},
        {"name": "soak-endurance", "url": "http://localhost:8099/", "method": "GET",
         "pattern": "soak", "concurrency": 3, "rps": 4, "duration": 120,
         "headers": "", "body": ""},
    ]

    def _seed_playbooks(self):
        """Write a few ready-made playbooks once (tracked by a .seeded marker)."""
        d = self._playbook_dir()
        marker = d / ".seeded"
        if marker.exists():
            return
        for pb in self.SEED_PLAYBOOKS:
            f = d / f"{pb['name']}.json"
            if not f.exists():
                f.write_text(json.dumps(pb, indent=2), encoding="utf-8")
        try:
            marker.write_text("seeded\n", encoding="utf-8")
        except OSError:
            pass

    def _refresh_playbooks(self, select=None):
        self._seed_playbooks()
        names = sorted(p.stem for p in self._playbook_dir().glob("*.json"))
        self.playbook_box.config(values=names)
        if select and select in names:
            self.playbook_var.set(select)
        elif names and not self.playbook_var.get():
            self.playbook_var.set(names[0])

    def _save_playbook(self):
        name = simpledialog.askstring("Save playbook",
                                      "Playbook name:", parent=self.root)
        if not name:
            return
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_ ").strip()
        if not safe:
            messagebox.showerror("Playbook", "Please use a plain alphanumeric name.")
            return
        data = {
            "name": safe,
            "url": self.url_var.get().strip(),
            "method": self.method_var.get(),
            "pattern": self.pattern_var.get(),
            "concurrency": int(self.concurrency_var.get()),
            "rps": int(self.rps_var.get()),
            "duration": int(self.duration_var.get()),
            "headers": self.headers_text.get("1.0", "end-1c"),
            "body": self.body_text.get("1.0", "end-1c"),
        }
        (self._playbook_dir() / f"{safe}.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8")
        self._refresh_playbooks(select=safe)
        messagebox.showinfo("Playbook", f"Saved playbook '{safe}'.")

    def _load_playbook(self):
        name = self.playbook_var.get()
        if not name:
            messagebox.showinfo("Playbook", "No playbook selected.")
            return
        path = self._playbook_dir() / f"{name}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Playbook", f"Could not load '{name}':\n{exc}")
            return
        self.url_var.set(data.get("url", ""))
        self.method_var.set(data.get("method", "GET"))
        if data.get("pattern") in PATTERNS:
            self.pattern_var.set(data["pattern"])
        # clamp intensity to the RoE ceilings if one is loaded
        cc = int(data.get("concurrency", self.concurrency_var.get()))
        rp = int(data.get("rps", self.rps_var.get()))
        du = int(data.get("duration", self.duration_var.get()))
        if self.roe:
            cc = min(cc, self.roe.max_concurrency)
            rp = min(rp, self.roe.max_rps)
            du = min(du, self.roe.max_duration)
        self.concurrency_var.set(cc)
        self.rps_var.set(rp)
        self.duration_var.set(du)
        self.headers_text.delete("1.0", "end")
        self.headers_text.insert("1.0", data.get("headers", ""))
        self.body_text.delete("1.0", "end")
        self.body_text.insert("1.0", data.get("body", ""))
        self._set_status(f"PLAYBOOK '{name}' LOADED",
                         self.GREEN if self.roe else self.CYAN)

    def _delete_playbook(self):
        name = self.playbook_var.get()
        if not name:
            return
        if not messagebox.askyesno("Playbook", f"Delete playbook '{name}'?"):
            return
        try:
            (self._playbook_dir() / f"{name}.json").unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Playbook", str(exc))
            return
        self.playbook_var.set("")
        self._refresh_playbooks()

    # ---- blue-team deconfliction view -------------------------------------
    def blue_team_view(self):
        """Show exactly what the SOC/blue team sees for every request, so the
        engagement can be pre-cleared and a real attack told apart from us."""
        if not self.roe:
            messagebox.showinfo("Blue-team view",
                                "Load a Rules-of-Engagement file first.")
            return
        roe = self.roe
        ua = user_agent(roe.engagement_id)
        target = (self.config or {}).get("url") or self.url_var.get().strip()
        method = (self.config or {}).get("method") or self.method_var.get()
        try:
            host = target.split("://", 1)[-1].split("/", 1)[0]
        except Exception:  # noqa: BLE001
            host = "<target-host>"

        win = tk.Toplevel(self.root)
        win.title("blue-team deconfliction view")
        win.configure(bg=self.BG)
        win.geometry("640x560")
        pad = tk.Frame(win, bg=self.BG)
        pad.pack(fill="both", expand=True, padx=16, pady=16)
        tk.Label(pad, text="\U0001f6e1  BLUE-TEAM DECONFLICTION VIEW", bg=self.BG,
                 fg=self.CYAN, font=self._f(13, "bold")).pack(anchor="w")
        tk.Label(pad, text="what the SOC will observe for EVERY request from "
                           "this tool", bg=self.BG, fg=self.DIM,
                 font=self._f(9)).pack(anchor="w", pady=(2, 10))

        txt = tk.Text(pad, bg=self.PANEL2, fg=self.GREEN, insertbackground=self.GREEN,
                      relief="flat", highlightthickness=1,
                      highlightbackground=self.BORDER, wrap="word", font=self._f(9),
                      padx=12, pady=10)
        txt.pack(fill="both", expand=True)

        def render():
            content = f"""\
ENGAGEMENT IDENTITY
  engagement id      {roe.engagement_id}
  client             {roe.client}
  operator           {roe.operator_label}
  emergency contact  {roe.emergency_contact}

DECONFLICTION SIGNATURE  (attached to every request)
  marker header      {DEFAULT_MARKER_HEADER}: {roe.engagement_id}
  user-agent         {ua}

SAMPLE REQUEST AS LOGGED BY THE TARGET / WAF / SOC
  {method} {target}
  Host: {host}
  User-Agent: {ua}
  {DEFAULT_MARKER_HEADER}: {roe.engagement_id}

HOW TO TELL THIS APART FROM A REAL ATTACK
  * every packet carries the '{DEFAULT_MARKER_HEADER}' header above;
    a genuine attacker will NOT send it.
  * source is a single, known operator host (no spoofing / no botnet).
  * volume is capped: <= {roe.max_rps} req/s, <= {roe.max_concurrency}
    concurrent, and the run auto-stops on error>{roe.abort_error_rate:.0%}
    or p95>{roe.abort_p95_latency_ms:.0f}ms.
  * allowed scope: {', '.join(roe.authorized_hosts)}

LIVE
  marked requests sent this session   {len(self.results)}
"""
            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.insert("1.0", content)
            txt.config(state="disabled")

        render()
        btnrow = tk.Frame(pad, bg=self.BG)
        btnrow.pack(fill="x", pady=(10, 0))
        ttk.Button(btnrow, text="refresh live count", command=render).pack(
            side="left")
        ttk.Button(btnrow, text="close", command=win.destroy).pack(side="right")

    def _on_close(self):
        self._alive = False
        if self.engine:
            self.engine.stop("window closed")
            self.root.after(300, self.root.destroy)
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
