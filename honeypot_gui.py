#!/usr/bin/env python3
"""
WiFi Honeypot — Desktop GUI
----------------------------
App that starts hostapd and dnsmasq on a dedicated AP adapter and shows a live, organized table of every device that
connects — plus a running text log underneath.

Must be run as root, since it drives hostapd/dnsmasq/ip directly.
Use the provided launcher (run.sh) or a desktop icon —
see setup notes at the bottom of this file.
"""

import subprocess
import shlex
import shutil
from pathlib import Path
import sqlite3
import re
import os
import threading
import queue
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ---------------- Configuration ----------------
INTERFACE = os.environ.get("HONEYPOT_INTERFACE", "wlan0")
AP_IP = os.environ.get("HONEYPOT_IP", "192.168.50.1/24")
HOSTAPD_CONF = os.environ.get("HONEYPOT_HOSTAPD_CONF", str(Path(__file__).with_name("hostapd.conf")))
DNSMASQ_CONF = os.environ.get("HONEYPOT_DNSMASQ_CONF", str(Path(__file__).with_name("dnsmasq.conf")))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

DHCP_RE = re.compile(
    r"DHCP(DISCOVER|OFFER|REQUEST|ACK|NAK)\((?P<iface>[^)]+)\)\s+"
    r"(?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+)?"
    r"(?P<mac>[0-9a-fA-F:]{17})?"
    r"(?:\s+(?P<hostname>\S+))?"
)
DNS_QUERY_RE = re.compile(
    r"query\[(?P<qtype>\w+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def run(cmd, check=False):
    return subprocess.run(shlex.split(cmd) if isinstance(cmd, str) else cmd,
                          check=check, capture_output=True, text=True, timeout=15)


class HoneypotApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Honeypot Monitor")
        self.root.geometry("1000x600")
        self.root.configure(bg="#1e1e1e")

        self.dnsmasq_proc = None
        self.hostapd_proc = None
        self.address_added = False
        self.startup_thread = None
        self.ui_thread = threading.get_ident()
        self.reader_thread = None
        self.stop_flag = threading.Event()
        self.event_queue = queue.Queue()

        self.db_conn = self._init_db()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(150, self._poll_queue)

    # ---------------- UI ----------------
    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#252526", foreground="#d4d4d4",
                         fieldbackground="#252526", rowheight=24, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white",
                         font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#0a5")])

        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(fill="x", padx=10, pady=8)

        self.start_btn = tk.Button(top, text="Start Honeypot", command=self.start_honeypot,
                                    bg="#2e7d32", fg="white", font=("Segoe UI", 11, "bold"),
                                    padx=14, pady=6, relief="flat")
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = tk.Button(top, text="Stop", command=self.stop_honeypot,
                                   bg="#b71c1c", fg="white", font=("Segoe UI", 11, "bold"),
                                   padx=14, pady=6, relief="flat", state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 8))

        self.status_label = tk.Label(top, text="Status: idle", bg="#1e1e1e", fg="#aaaaaa",
                                      font=("Segoe UI", 11))
        self.status_label.pack(side="left", padx=12)

        clear_btn = tk.Button(top, text="Clear Table", command=self.clear_table,
                               bg="#37474f", fg="white", relief="flat", padx=10)
        clear_btn.pack(side="right")

        # Device table
        columns = ("time", "event", "ip", "mac", "hostname", "detail")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=14)
        headings = {"time": "Time", "event": "Event", "ip": "IP", "mac": "MAC",
                    "hostname": "Hostname", "detail": "Detail"}
        widths = {"time": 90, "event": 110, "ip": 120, "mac": 140, "hostname": 160, "detail": 260}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # Raw log output
        log_label = tk.Label(self.root, text="Raw log", bg="#1e1e1e", fg="#888888",
                              font=("Segoe UI", 9))
        log_label.pack(anchor="w", padx=12)
        self.log_box = scrolledtext.ScrolledText(self.root, height=8, bg="#111111",
                                                   fg="#8bc34a", font=("Consolas", 9),
                                                   insertbackground="white")
        self.log_box.pack(fill="both", expand=False, padx=10, pady=(0, 10))
        self.log_box.configure(state="disabled")

    def _init_db(self):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, event_type TEXT, ip TEXT,
                mac TEXT, hostname TEXT, extra TEXT
            )
        """)
        conn.commit()
        return conn

    # ---------------- Log helpers ----------------
    def _append_log(self, text):
        if threading.get_ident() != self.ui_thread:
            self.event_queue.put(("raw", text))
            return
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_status(self, text, color="#aaaaaa"):
        self.status_label.config(text=f"Status: {text}", fg=color)

    # ---------------- Startup sequence ----------------
    def start_honeypot(self):
        if os.geteuid() != 0:
            messagebox.showerror("Permission needed",
                                  "This app must be run as root (it starts hostapd/dnsmasq).\n"
                                  "Launch it with: sudo python3 honeypot_gui.py")
            return

        for config in (HOSTAPD_CONF, DNSMASQ_CONF):
            if not Path(config).is_file():
                messagebox.showerror("Configuration needed", f"Missing {config}. See README.md.")
                return
        for command in ("hostapd", "dnsmasq", "ip"):
            if not shutil.which(command):
                messagebox.showerror("Missing dependency", f"Install {command} first; see README.md.")
                return
        self.stop_flag.clear()
        self.start_btn.config(state="disabled")
        self._set_status("starting…", "#ffb300")
        self._append_log("=== Starting honeypot sequence ===")

        self.startup_thread = threading.Thread(target=self._startup_sequence, daemon=True)
        self.startup_thread.start()

    def _startup_sequence(self):
        try:
            # Use a dedicated, already configured AP interface. Never stop global
            # networking services or terminate processes owned by other apps.
            run(["ip", "link", "set", INTERFACE, "up"], check=True)
            addresses = run(["ip", "-o", "addr", "show", "dev", INTERFACE], check=True)
            if AP_IP not in addresses.stdout.split():
                run(["ip", "addr", "add", AP_IP, "dev", INTERFACE], check=True)
                self.address_added = True
            self.hostapd_proc = subprocess.Popen(
                ["hostapd", HOSTAPD_CONF], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if self.stop_flag.wait(1) or self.hostapd_proc.poll() is not None:
                raise RuntimeError("hostapd stopped; check config and AP support on the dedicated adapter")
            self.dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", DNSMASQ_CONF, "-d", "--log-queries"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            if self.stop_flag.wait(0.5) or self.dnsmasq_proc.poll() is not None:
                raise RuntimeError("dnsmasq stopped; check config, address, and port conflicts")
            self.event_queue.put(("status_running", None))
            self.reader_thread = threading.Thread(target=self._read_dnsmasq_output, daemon=True)
            self.reader_thread.start()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            self._cleanup()
            self.event_queue.put(("status_error", str(error)))

    def _read_dnsmasq_output(self):
        if not self.dnsmasq_proc:
            return
        for line in self.dnsmasq_proc.stdout:
            if self.stop_flag.is_set():
                break
            line = line.strip()
            if not line:
                continue
            self.event_queue.put(("raw", line))

            dhcp_match = DHCP_RE.search(line)
            if dhcp_match:
                event = "DHCP-" + dhcp_match.group(1)
                ip = dhcp_match.group("ip") or ""
                mac = dhcp_match.group("mac") or ""
                hostname = dhcp_match.group("hostname") or ""
                self._store_and_emit(event, ip, mac, hostname, "")
                continue

            # DNS queries are intentionally not added to the device table —
            # only DHCP events (actual device connections) show there.
            # They still appear in the raw log box above via the "raw" event.

    def _store_and_emit(self, event_type, ip, mac, hostname, extra):
        ts_full = datetime.now().isoformat()
        ts_short = datetime.now().strftime("%H:%M:%S")
        self.event_queue.put(("record", (ts_full, ts_short, event_type, ip, mac, hostname, extra)))

    # ---------------- Queue polling (thread-safe UI updates) ----------------
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "record":
                    full, short, event, ip, mac, hostname, extra = payload
                    self.db_conn.execute(
                        "INSERT INTO events (timestamp, event_type, ip, mac, hostname, extra) VALUES (?,?,?,?,?,?)",
                        (full, event, ip, mac, hostname, extra))
                    self.db_conn.commit()
                    self.tree.insert("", 0, values=(short, event, ip, mac, hostname, extra))
                elif kind == "row":
                    self.tree.insert("", 0, values=payload)
                elif kind == "raw":
                    self._append_log(payload)
                elif kind == "status_running":
                    self._set_status("running — waiting for connections", "#66bb6a")
                    self.stop_btn.config(state="normal")
                elif kind == "status_error":
                    self._set_status(payload, "#ef5350")
                    self.start_btn.config(state="normal")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    # ---------------- Shutdown ----------------
    def _cleanup(self):
        self.stop_flag.set()
        for process in (self.dnsmasq_proc, self.hostapd_proc):
            if process is not None:
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                if process.stdout:
                    process.stdout.close()
        self.dnsmasq_proc = self.hostapd_proc = None
        if self.address_added:
            try:
                run(["ip", "addr", "del", AP_IP, "dev", INTERFACE], check=True)
                self.address_added = False
            except (OSError, subprocess.SubprocessError) as error:
                self._append_log(f"Could not remove AP address: {error}")

    def stop_honeypot(self):
        self._cleanup()
        if self.reader_thread:
            self.reader_thread.join(timeout=3)
        self._set_status("stopped")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._append_log("Stopped owned AP processes and removed the address added by this app.")

    def on_close(self):
        self.stop_flag.set()
        if self.startup_thread and self.startup_thread.is_alive():
            self._set_status("waiting for startup to finish…")
            self.root.after(100, self.on_close)
            return
        self.stop_honeypot()
        self.db_conn.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = HoneypotApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
