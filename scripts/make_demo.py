"""Scripted demo capture for ScopeStorm -> animated GIF.

Launches the real GUI, drives a full engagement (load RoE, journey + templating,
spike scenario against a target whose latency climbs), and grabs frames of the
live window into docs/scopestorm_demo.gif.
"""
import itertools
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# this script lives in scripts/ -- put the project root on the path and send
# all generated artifacts to docs/
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

import tkinter as tk
from PIL import ImageGrab

import scopestorm_gui as g

PORT = 8093
FRAMES = []
GIF_W = 900          # downscale width for a reasonable file size

# ---- mock target: latency climbs over time so we get a rising curve + knee ----
_counter = itertools.count()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        n = next(_counter)
        time.sleep(min(0.02 + n * 0.006, 1.2))   # climbs ~20ms -> ~1.2s
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def serve():
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


def main():
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(0.6)

    # a demo RoE (alias set -> showcases pseudonymous attribution; low p95 cap
    # so the climbing latency triggers a live auto-abort)
    import json
    roe = {
        "engagement_id": "ENG-DEMO-01",
        "client": "Acme Corp (staging)",
        "operator": "",                       # left blank on purpose
        "operator_alias": "rt-op-7",          # runs under a handle
        "authorized_hosts": ["localhost"],
        "max_concurrency": 6, "max_rps": 10, "max_duration": 60, "timeout": 10,
        "window_start": "", "window_end": "",
        "abort_error_rate": 0.9, "abort_p95_latency_ms": 350,
        "emergency_contact": "SOC on-call +00 000 000",
    }
    roe_path = ROOT / "_roe_demo_tmp.json"
    roe_path.write_text(json.dumps(roe, indent=2), encoding="utf-8")

    # silence modal dialogs so the scripted run never blocks, and feed the file
    # picker our demo RoE so app._load_roe() runs the *real* code path.
    g.messagebox.showwarning = lambda *a, **k: None
    g.messagebox.showerror = lambda *a, **k: None
    g.messagebox.showinfo = lambda *a, **k: None
    g.filedialog.askopenfilename = lambda *a, **k: str(roe_path)

    root = tk.Tk()
    # fit the window to the actual screen so nothing is clipped on capture
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    win_w = min(1340, sw)
    win_h = min(840, sh - 60)
    root.geometry(f"{win_w}x{win_h}+0+0")
    app = g.App(root)
    root.update()
    root.lift()
    root.attributes("-topmost", True)
    root.update()

    def grab():
        try:
            x, y = root.winfo_rootx(), root.winfo_rooty()
            w, h = root.winfo_width(), root.winfo_height()
            img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
            if GIF_W < w:
                img = img.resize((GIF_W, int(h * GIF_W / w)))
            FRAMES.append(img.convert("RGB"))
        except Exception as exc:
            print("grab skipped:", exc)

    def pump(seconds, fps=7):
        """Advance the Tk loop for `seconds`, grabbing frames at `fps`."""
        end = time.time() + seconds
        interval = 1.0 / fps
        nxt = 0
        while time.time() < end:
            root.update_idletasks()
            root.update()
            if time.time() >= nxt:
                grab()
                nxt = time.time() + interval
            time.sleep(0.01)


    # --- 1) boot sequence + empty console ---
    pump(1.6)

    # --- 2) load the RoE (real code path via patched file picker) ---
    app._load_roe()
    root.update()
    pump(1.4)

    # --- 3) configure the engagement: journey + templating + spike ---
    app.url_var.set(f"http://localhost:{PORT}/")
    app.endpoints_text.insert("1.0",
                              f"GET http://localhost:{PORT}/\n"
                              f"GET http://localhost:{PORT}/api?q={{{{seq}}}}")
    app.template_var.set(True)
    app.pattern_var.set("spike")
    app.concurrency_var.set(6)
    app.rps_var.set(10)
    app.duration_var.set(30)
    app.confirm_var.set(True)
    root.update()
    pump(1.6)

    # --- 4) EXECUTE: live run (latency climbs -> knee -> auto-abort) ---
    app.start_test()
    # run until the engine finishes (auto-abort) or a hard cap of ~22s
    t0 = time.time()
    while app.engine is not None and time.time() - t0 < 22:
        pump(0.6)

    # --- 5) linger on the final state (AUTO-ABORTED + KNEE on the graph) ---
    pump(2.2)

    root.attributes("-topmost", False)
    app._alive = False
    root.destroy()

    # --- write outputs to docs/ and clean up the temp RoE ---
    try:
        roe_path.unlink()
    except OSError:
        pass
    if not FRAMES:
        print("NO FRAMES CAPTURED"); return
    gif = DOCS / "scopestorm_demo.gif"
    FRAMES[0].save(gif, save_all=True, append_images=FRAMES[1:],
                   duration=140, loop=0, optimize=True)
    print(f"frames={len(FRAMES)}  gif={gif}")


if __name__ == "__main__":
    main()
