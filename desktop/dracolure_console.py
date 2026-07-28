#!/usr/bin/env python3
"""DracoLure Desktop Console.

A cross-platform Tkinter GUI (standard library only) that connects to a running
DracoLure server over its /api/v1 surface and shows the live threat picture:
summary tiles, top sources, and a streaming events feed. Operators can block or
release source IPs from the UI.

Run:
    python desktop/dracolure_console.py
    python desktop/dracolure_console.py --url http://host:5000 --api-key KEY

Only the standard library is required (tkinter ships with CPython on Windows and
macOS; on Debian/Ubuntu: `sudo apt install python3-tk`). It reuses the bundled
SDK if present, otherwise falls back to a built-in urllib client.
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

# Prefer the bundled SDK so behaviour matches the middleware exactly.
_SDK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "integrations", "python-sdk")
if os.path.isdir(_SDK):
    sys.path.insert(0, _SDK)

try:
    from dracolure import DracoLureClient, DracoLureError  # type: ignore
except Exception:  # pragma: no cover - fallback keeps the console standalone
    import json
    import urllib.error
    import urllib.request

    class DracoLureError(Exception):
        pass

    class DracoLureClient:
        def __init__(self, base_url="http://localhost:5000", api_key=None, timeout=3.0):
            self.base_url = base_url.rstrip("/")
            self.api_key = api_key
            self.timeout = timeout

        def _req(self, method, path, payload=None):
            url = f"{self.base_url}/api/v1{path}"
            data = json.dumps(payload).encode() if payload is not None else None
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode() or "{}")
            except (urllib.error.URLError, OSError, ValueError) as e:
                raise DracoLureError(str(e))

        def stats(self):
            return self._req("GET", "/stats")

        def events(self, limit=100, min_score=0):
            return self._req(
                "GET", f"/events?limit={int(limit)}&min_score={int(min_score)}"
            ).get("events", [])

        def block(self, ip, ttl_seconds=None):
            p = {"ip": ip}
            if ttl_seconds is not None:
                p["ttl_seconds"] = ttl_seconds
            return self._req("POST", "/block", p)

        def unblock(self, ip):
            return self._req("POST", "/unblock", {"ip": ip})

        def health(self):
            return self._req("GET", "/health")


SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#d9534f",
    "medium": "#e0a800",
    "low": "#6c757d",
    "none": "#6c757d",
}


class Console(tk.Tk):
    def __init__(self, url: str, api_key: str = ""):
        super().__init__()
        self.title("DracoLure — Threat Console")
        self.geometry("1040x680")
        self.minsize(880, 560)

        self.client: DracoLureClient | None = None
        self.poll_queue: "queue.Queue" = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.connected = False

        self._build_toolbar(url, api_key)
        self._build_tiles()
        self._build_tables()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(200, self._drain_queue)
        if url:
            self.connect()

    # ---- layout ----------------------------------------------------------
    def _build_toolbar(self, url, api_key):
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Label(bar, text="Server").pack(side="left")
        self.url_var = tk.StringVar(value=url or "http://localhost:5000")
        ttk.Entry(bar, textvariable=self.url_var, width=34).pack(side="left", padx=(4, 12))
        ttk.Label(bar, text="API key").pack(side="left")
        self.key_var = tk.StringVar(value=api_key or "")
        ttk.Entry(bar, textvariable=self.key_var, width=18, show="•").pack(side="left", padx=(4, 12))
        ttk.Label(bar, text="Refresh").pack(side="left")
        self.interval_var = tk.StringVar(value="3s")
        ttk.Combobox(bar, textvariable=self.interval_var, width=5, state="readonly",
                     values=["2s", "3s", "5s", "10s"]).pack(side="left", padx=(4, 12))
        self.connect_btn = ttk.Button(bar, text="Connect", command=self.connect)
        self.connect_btn.pack(side="left")

    def _build_tiles(self):
        wrap = ttk.Frame(self, padding=(8, 4))
        wrap.pack(fill="x")
        self.tiles: dict[str, tk.StringVar] = {}
        for key, label in [
            ("tracked_sources", "Tracked sources"),
            ("blocked_now", "Blocked now"),
            ("blocks_total", "Blocks total"),
            ("events_seen", "Events (feed)"),
            ("block_threshold", "Block threshold"),
        ]:
            card = ttk.Frame(wrap, relief="groove", padding=10)
            card.pack(side="left", expand=True, fill="x", padx=4)
            var = tk.StringVar(value="—")
            self.tiles[key] = var
            tk.Label(card, textvariable=var, font=("Segoe UI", 20, "bold")).pack()
            ttk.Label(card, text=label).pack()

    def _build_tables(self):
        panes = ttk.Panedwindow(self, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8, pady=4)

        src_frame = ttk.Labelframe(panes, text="Top sources", padding=4)
        self.src_tree = ttk.Treeview(
            src_frame, columns=("ip", "score", "hits", "blocked"),
            show="headings", height=6)
        for col, w in [("ip", 220), ("score", 90), ("hits", 90), ("blocked", 90)]:
            self.src_tree.heading(col, text=col.title())
            self.src_tree.column(col, width=w, anchor="w")
        self.src_tree.pack(fill="both", expand=True, side="left")
        sb1 = ttk.Scrollbar(src_frame, command=self.src_tree.yview)
        sb1.pack(side="right", fill="y")
        self.src_tree.configure(yscrollcommand=sb1.set)
        panes.add(src_frame, weight=1)

        ev_frame = ttk.Labelframe(panes, text="Recent events", padding=4)
        self.ev_tree = ttk.Treeview(
            ev_frame,
            columns=("time", "ip", "method", "path", "score", "severity", "categories"),
            show="headings", height=12)
        widths = {"time": 150, "ip": 130, "method": 60, "path": 240,
                  "score": 60, "severity": 90, "categories": 200}
        for col, w in widths.items():
            self.ev_tree.heading(col, text=col.title())
            self.ev_tree.column(col, width=w, anchor="w")
        for sev, color in SEVERITY_COLORS.items():
            self.ev_tree.tag_configure(sev, foreground=color)
        self.ev_tree.pack(fill="both", expand=True, side="left")
        sb2 = ttk.Scrollbar(ev_frame, command=self.ev_tree.yview)
        sb2.pack(side="right", fill="y")
        self.ev_tree.configure(yscrollcommand=sb2.set)
        panes.add(ev_frame, weight=2)

        actions = ttk.Frame(self, padding=(8, 4))
        actions.pack(fill="x")
        ttk.Button(actions, text="Block IP…", command=self._block_dialog).pack(side="left")
        ttk.Button(actions, text="Unblock selected", command=self._unblock_selected).pack(side="left", padx=6)
        ttk.Button(actions, text="Refresh now", command=lambda: self._poll_once(force=True)).pack(side="left")

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Disconnected")
        bar = ttk.Frame(self, relief="sunken", padding=4)
        bar.pack(fill="x", side="bottom")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")

    # ---- connection / polling -------------------------------------------
    def connect(self):
        self.stop_flag.set()
        time.sleep(0.05)
        self.client = DracoLureClient(
            base_url=self.url_var.get().strip(),
            api_key=self.key_var.get().strip() or None,
        )
        self.stop_flag = threading.Event()
        self.worker = threading.Thread(target=self._poll_loop, daemon=True)
        self.worker.start()
        self._set_status(f"Connecting to {self.url_var.get().strip()} …")

    def _interval_seconds(self) -> float:
        return {"2s": 2, "3s": 3, "5s": 5, "10s": 10}.get(self.interval_var.get(), 3)

    def _poll_loop(self):
        while not self.stop_flag.is_set():
            self._poll_once()
            self.stop_flag.wait(self._interval_seconds())

    def _poll_once(self, force=False):
        client = self.client
        if client is None:
            return
        try:
            stats = client.stats()
            events = client.events(limit=100)
            self.poll_queue.put(("data", stats, events))
        except DracoLureError as exc:
            self.poll_queue.put(("error", str(exc), None))

    def _drain_queue(self):
        try:
            while True:
                kind, a, b = self.poll_queue.get_nowait()
                if kind == "data":
                    self._render(a, b)
                else:
                    self.connected = False
                    self._set_status(f"⚠ {a}")
        except queue.Empty:
            pass
        self.after(300, self._drain_queue)

    # ---- rendering -------------------------------------------------------
    def _render(self, stats: dict, events: list):
        self.connected = True
        self.tiles["tracked_sources"].set(str(stats.get("tracked_sources", 0)))
        self.tiles["blocked_now"].set(str(stats.get("blocked_now", 0)))
        self.tiles["blocks_total"].set(str(stats.get("blocks_total", 0)))
        self.tiles["block_threshold"].set(str(stats.get("block_threshold", 0)))
        self.tiles["events_seen"].set(str(len(events)))

        self.src_tree.delete(*self.src_tree.get_children())
        for s in stats.get("top_sources", []):
            self.src_tree.insert("", "end", values=(
                s.get("ip"), s.get("score"), s.get("hits"),
                "yes" if s.get("blocked") else "no"))

        self.ev_tree.delete(*self.ev_tree.get_children())
        for e in events:
            sev = e.get("severity", "none")
            cats = e.get("categories") or []
            self.ev_tree.insert("", "end", tags=(sev,), values=(
                (e.get("timestamp") or "").replace("T", " ")[:19],
                e.get("source_ip"), e.get("method"),
                (e.get("path") or "")[:60], e.get("threat_score"),
                sev, ", ".join(cats)))
        self._set_status(
            f"Connected · {stats.get('tracked_sources', 0)} sources · "
            f"{stats.get('blocked_now', 0)} blocked · updated {time.strftime('%H:%M:%S')}")

    def _set_status(self, text: str):
        self.status_var.set(text)

    # ---- actions ---------------------------------------------------------
    def _selected_ip(self) -> str | None:
        for tree in (self.src_tree, self.ev_tree):
            sel = tree.selection()
            if sel:
                vals = tree.item(sel[0], "values")
                # ip is column 0 for sources, column 1 for events
                return vals[0] if tree is self.src_tree else vals[1]
        return None

    def _block_dialog(self):
        if not self.client:
            return
        top = tk.Toplevel(self)
        top.title("Block IP")
        top.transient(self)
        ttk.Label(top, text="IP address to quarantine:", padding=8).pack()
        ip_var = tk.StringVar(value=self._selected_ip() or "")
        ttk.Entry(top, textvariable=ip_var, width=30).pack(padx=8)

        def do_block():
            ip = ip_var.get().strip()
            if not ip:
                return
            try:
                self.client.block(ip)
                self._set_status(f"Blocked {ip}")
                self._poll_once(force=True)
            except DracoLureError as exc:
                messagebox.showerror("DracoLure", f"Block failed: {exc}")
            top.destroy()

        ttk.Button(top, text="Block", command=do_block).pack(pady=8)

    def _unblock_selected(self):
        ip = self._selected_ip()
        if not ip or not self.client:
            messagebox.showinfo("DracoLure", "Select a source or event row first.")
            return
        try:
            self.client.unblock(ip)
            self._set_status(f"Unblocked {ip}")
            self._poll_once(force=True)
        except DracoLureError as exc:
            messagebox.showerror("DracoLure", f"Unblock failed: {exc}")

    def _on_close(self):
        self.stop_flag.set()
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description="DracoLure Desktop Console")
    parser.add_argument("--url", default=os.environ.get("DRACOLURE_URL", "http://localhost:5000"))
    parser.add_argument("--api-key", default=os.environ.get("DRACOLURE_API_KEY", ""))
    args = parser.parse_args()
    Console(url=args.url, api_key=args.api_key).mainloop()


if __name__ == "__main__":
    main()
