#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
NetQuota for Windows - per-app traffic monitor with pause/resume and quotas.

How it works
  * pydivert (WinDivert) SNIFFS TCP/UDP packets (read-only copy; traffic is never held or modified).
  * psutil's socket table maps each packet's ports to an owning process.
  * Totals are saved in SQLite: %LOCALAPPDATA%\\NetQuota\\usage.sqlite3
  * Pause / quota blocks are Windows Firewall rules named "NetQuota-<hash>-IN/OUT".

Needs Administrator rights. Byte counts are IP packet bytes (slightly above payload bytes).
"""
__version__ = "1.0.0"

import os
import sys


def configure_tk_environment(environment, frozen, bundle_root=None):
    if frozen:
        for variable, directory in (("TCL_LIBRARY", "_tcl_data"), ("TK_LIBRARY", "_tk_data")):
            bundled_path = os.path.join(bundle_root, directory) if bundle_root else ""
            if bundled_path and os.path.isdir(bundled_path):
                environment[variable] = bundled_path
            else:
                environment.pop(variable, None)

    for variable in ("TCLLIBPATH", "PYTHONHOME", "PYTHONPATH"):
        environment.pop(variable, None)
    if not frozen:
        environment.pop("TCL_LIBRARY", None)
        environment.pop("TK_LIBRARY", None)


configure_tk_environment(
    os.environ,
    getattr(sys, "frozen", False),
    getattr(sys, "_MEIPASS", None),
)

import traceback, sys, time, queue, socket, sqlite3, threading, subprocess, ctypes, hashlib
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except ImportError:
    print("This Python was installed without tkinter (Tcl/Tk).\n"
          "Open Settings > Apps > Python > Modify > Modify, and tick 'tcl/tk and IDLE'.")
    raise SystemExit(3)
from pathlib import Path
from datetime import datetime, date

APP = "NetQuota"
BASE = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "NetQuota"
DB_PATH = BASE / "usage.sqlite3"
LOG_PATH = BASE / "netquota.log"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
UNATTR = "[unattributed]"


def is_lo(a):
    return a.startswith("127.") or a == "::1"


# ----------------------------------------------------------------- helpers
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def log(msg):
    try:
        BASE.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")
    except Exception:
        pass


def fmt_bytes(n):
    n = float(max(0, n))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_quota(text):
    """'500 MB' / '2 GB' / '750 MiB'. A bare number means MB."""
    s = text.strip().upper().replace(" ", "")
    table = (("GIB", 1024**3), ("GB", 1000**3), ("MIB", 1024**2), ("MB", 1000**2),
             ("KIB", 1024), ("KB", 1000), ("B", 1))
    mult = 1000**2
    for suffix, m in table:
        if s.endswith(suffix):
            mult, s = m, s[:-len(suffix)]
            break
    value = float(s)
    if value <= 0:
        raise ValueError("Quota must be greater than zero.")
    return int(value * mult)


def rule_names(exe):
    rid = hashlib.sha1(os.path.normcase(os.path.abspath(exe)).encode("utf-8", "ignore")).hexdigest()[:12]
    return f"NetQuota-{rid}-OUT", f"NetQuota-{rid}-IN"


def set_block(exe, block):
    """Create or delete this tool's firewall rules for one executable."""
    exe = os.path.abspath(exe)
    out_name, in_name = rule_names(exe)
    for name in (out_name, in_name):  # delete only our own exact-named rules
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True, text=True, creationflags=NOWIN)
    if not block:
        return
    if not os.path.isfile(exe):
        raise RuntimeError("Executable path no longer exists.")
    for name, direction in ((out_name, "out"), (in_name, "in")):
        p = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                            f"dir={direction}", "action=block", f"program={exe}",
                            "enable=yes", "profile=any"],
                           capture_output=True, text=True, errors="replace", creationflags=NOWIN)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "netsh failed").strip())


# ----------------------------------------------------------------- capture
class Capture(threading.Thread):
    """Sniffs packets, attributes them to processes, pushes batches to a queue."""

    def __init__(self, out_q):
        super().__init__(daemon=True)
        self.q = out_q
        self.running = True
        self.full = {}      # (proto, lip, lport, rip, rport) -> pid
        self.ports = {}     # (proto, lport) -> pid
        self.map_time = 0.0
        self.procs = {}     # pid -> (name, exe, fetched_at)

    def refresh_map(self):
        import psutil
        full, ports = {}, {}
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.pid or not c.laddr:
                    continue
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
                full[(proto, c.laddr.ip, c.laddr.port, rip, rport)] = c.pid
                ports[(proto, c.laddr.port)] = c.pid
        except Exception as e:
            log(f"socket map error: {e}")
        self.full, self.ports = full, ports
        self.map_time = time.monotonic()

    def proc_info(self, pid):
        import psutil
        hit = self.procs.get(pid)
        if hit and time.monotonic() - hit[2] < 30:
            return hit[0], hit[1]
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except Exception:
                exe = ""
        except Exception:
            name, exe = f"PID {pid}", ""
        if not exe:
            exe = f"[system:{name}]"
        self.procs[pid] = (name, exe, time.monotonic())
        return name, exe

    def lookup(self, proto, lip, lport, rip, rport):
        return self.full.get((proto, lip, lport, rip, rport)) or self.ports.get((proto, lport))

    def run(self):
        try:
            import pydivert
            flt = "tcp or udp"
            with pydivert.WinDivert(flt, flags=pydivert.Flag.SNIFF) as w:
                self.q.put(("status", "Capturing (read-only sniff mode)"))
                self.refresh_map()
                pending, last_flush = {}, time.monotonic()
                while self.running:
                    try:
                        pkt = w.recv()
                    except Exception as e:
                        if self.running:
                            self.q.put(("status", f"Capture error: {e}"[:110]))
                            log(f"recv error: {e}")
                        time.sleep(0.2)
                        continue
                    now = time.monotonic()
                    proto = "TCP" if pkt.protocol[0] == 6 else "UDP" if pkt.protocol[0] == 17 else None
                    if proto and not (is_lo(pkt.src_addr) or is_lo(pkt.dst_addr)):
                        sp, dp = int(pkt.src_port or 0), int(pkt.dst_port or 0)
                        if pkt.is_outbound:
                            args, key = (proto, pkt.src_addr, sp, pkt.dst_addr, dp), 0
                        else:
                            args, key = (proto, pkt.dst_addr, dp, pkt.src_addr, sp), 1
                        pid = self.lookup(*args)
                        if not pid and now - self.map_time > 0.25:  # new socket? refresh, throttled
                            self.refresh_map()
                            pid = self.lookup(*args)
                        if now - self.map_time > 2.0:
                            self.refresh_map()
                        if pid:
                            name, exe = self.proc_info(pid)
                        else:
                            name, exe = "Unattributed", UNATTR
                        rec = pending.setdefault(exe, [name, 0, 0])
                        rec[1 + key] += len(pkt.raw)   # [name, sent, received]
                    if now - last_flush >= 0.5 and pending:
                        self.q.put(("batch", [(e, v[0], v[1], v[2]) for e, v in pending.items()]))
                        pending.clear()
                        last_flush = now
        except Exception as e:
            self.q.put(("status", f"Packet capture unavailable: {e}"[:110]))
            log(f"capture failed: {e}")


# ----------------------------------------------------------------- UI app
# ===================================================================== UI
import base64, zlib, struct
from collections import deque
from datetime import timedelta

BG = "#0b1020"; PANEL = "#141b2d"; PANEL2 = "#1a2238"; STRIPE = "#171f35"; BORDER = "#26304a"
TEXT = "#e8ecf6"; MUTED = "#8b97b5"; ACCENT = "#4f8cff"
GREEN = "#34d399"; ORANGE = "#fb923c"; RED = "#f87171"; AMBER = "#fbbf24"; SEL = "#24365f"
FONT = "Segoe UI"


# ---- logo: drawn in pure Python (rounded square, blue->violet gradient, down/up arrows)
def _in_tri(x, y, a, b, c):
    def s(p, q, r):
        return (p[0] - r[0]) * (q[1] - r[1]) - (q[0] - r[0]) * (p[1] - r[1])
    p = (x, y)
    d1, d2, d3 = s(p, a, b), s(p, b, c), s(p, c, a)
    return not ((d1 < 0 or d2 < 0 or d3 < 0) and (d1 > 0 or d2 > 0 or d3 > 0))


def _logo_px(x, y):
    r = 0.22
    dx, dy = abs(x - .5) - (.5 - r), abs(y - .5) - (.5 - r)
    if abs(x - .5) > .5 or abs(y - .5) > .5 or (dx > 0 and dy > 0 and dx * dx + dy * dy > r * r):
        return None
    if (.295 <= x <= .365 and .22 <= y <= .52) or _in_tri(x, y, (.33, .77), (.19, .50), (.47, .50)):
        return (255, 255, 255)
    if (.635 <= x <= .705 and .48 <= y <= .78) or _in_tri(x, y, (.67, .23), (.53, .50), (.81, .50)):
        return (165, 243, 252)
    return (int(59 + 65 * y), int(130 - 72 * y), int(246 - 9 * y))


def render_logo_png(size, ss=3):
    n = size * ss
    out = bytearray()
    for py in range(size):
        out.append(0)
        for pxl in range(size):
            r = g = b = a = 0
            for sy in range(ss):
                for sx in range(ss):
                    c = _logo_px((pxl * ss + sx + .5) / n, (py * ss + sy + .5) / n)
                    if c:
                        r += c[0]; g += c[1]; b += c[2]; a += 1
            if a:
                out += bytes((r // a, g // a, b // a, 255 * a // (ss * ss)))
            else:
                out += b"\0\0\0\0"

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(out), 9)) + chunk(b"IEND", b""))


def make_photo(size):
    return tk.PhotoImage(data=base64.b64encode(render_logo_png(size)))


def apply_theme(root, px):
    st = ttk.Style(root)
    st.theme_use("clam")
    root.configure(bg=BG)
    st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, borderwidth=0,
                 rowheight=px(34), font=(FONT, 10))
    st.configure("Treeview.Heading", background=BG, foreground=MUTED, relief="flat", borderwidth=0,
                 font=(FONT, 9, "bold"), padding=(px(8), px(8)))
    st.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
    st.map("Treeview.Heading", background=[("active", BG)], foreground=[("active", TEXT)])
    st.configure("Vertical.TScrollbar", background=BORDER, troughcolor=BG, bordercolor=BG,
                 arrowcolor=MUTED, relief="flat", borderwidth=0)
    st.map("Vertical.TScrollbar", background=[("active", "#3a4668")])
    for name, bg, hover, press, fg in (
            ("Accent", ACCENT, "#6aa0ff", "#3a74e0", "#ffffff"),
            ("Danger", "#e5484d", "#f26065", "#c93a3f", "#ffffff"),
            ("Success", "#12b981", "#2cd196", "#0e9468", "#ffffff"),
            ("Ghost", PANEL2, "#25304f", "#1e2842", TEXT)):
        st.configure(f"{name}.TButton", background=bg, foreground=fg, borderwidth=0, focusthickness=0,
                     focuscolor=bg, padding=(px(14), px(8)), font=(FONT, 10, "bold"), relief="flat")
        st.map(f"{name}.TButton", background=[("pressed", press), ("active", hover)])
    st.configure("Dark.TEntry", fieldbackground=PANEL2, foreground=TEXT, insertcolor=TEXT, bordercolor=BORDER,
                 lightcolor=BORDER, darkcolor=BORDER, padding=px(7))
    st.configure("TNotebook", background=BG, borderwidth=0)
    st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(px(16), px(7)),
                 font=(FONT, 10, "bold"), borderwidth=0)
    st.map("TNotebook.Tab", background=[("selected", PANEL2)], foreground=[("selected", TEXT)])


# ============================================================ VirusTotal
import json, uuid, webbrowser
VT_API = "https://www.virustotal.com/api/v3"
VT_FIELDS = ("sha256", "mtime", "size", "malicious", "suspicious", "harmless", "undetected", "status", "detail", "ts")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_request(method, url, key, body=None, ctype=None, timeout=30):
    import urllib.request, urllib.error
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("x-apikey", key)
    req.add_header("accept", "application/json")
    req.add_header("User-Agent", "NetQuota/1.0")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}


def vt_http_error(code, js):
    if code in (401, 403):
        return "VirusTotal rejected the API key (check it in API key & settings)."
    if code == 429:
        return "VirusTotal rate limit or daily quota reached. Wait a few minutes and try again."
    msg = (js.get("error") or {}).get("message", "")
    return f"VirusTotal returned HTTP {code}. {msg}".strip()


def vt_status(mal, sus, total):
    if total == 0:
        return "unknown"
    if mal >= 3:
        return "malicious"
    if mal >= 1 or sus >= 1:
        return "suspicious"
    return "clean"


def parse_vt_report(js):
    a = (js.get("data") or {}).get("attributes") or {}
    s = a.get("last_analysis_stats") or {}
    mal, sus = s.get("malicious", 0), s.get("suspicious", 0)
    har, und = s.get("harmless", 0), s.get("undetected", 0)
    flagged = sorted(f"{e}: {r.get('result')}" for e, r in (a.get("last_analysis_results") or {}).items()
                     if r.get("category") in ("malicious", "suspicious"))
    label = ((a.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    detail = (f"Threat label: {label}\n" if label else "") + "\n".join(flagged[:40])
    return {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": und,
            "status": vt_status(mal, sus, mal + sus + har + und), "detail": detail}


def vt_multipart(path):
    b = uuid.uuid4().hex
    with open(path, "rb") as f:
        data = f.read()
    name = os.path.basename(path).replace('"', "_")
    head = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n').encode("utf-8", "replace")
    return head + data + f"\r\n--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


def vt_upload(path, size, sha, key, wait, say):
    if size > 64 * 1024 * 1024:
        return {"status": "error", "detail": "File is larger than 64 MB. Upload it manually at virustotal.com."}
    say("Uploading to VirusTotal...")
    body, ctype = vt_multipart(path)
    wait()
    code, js = vt_request("POST", f"{VT_API}/files", key, body, ctype, timeout=600)
    if code != 200:
        return {"status": "error", "detail": vt_http_error(code, js)}
    aid = js["data"]["id"]
    an = None
    for i in range(36):
        say(f"VirusTotal is scanning... ({i * 20}s)")
        time.sleep(20)
        wait()
        code, js = vt_request("GET", f"{VT_API}/analyses/{aid}", key)
        if code == 200 and (js.get("data") or {}).get("attributes", {}).get("status") == "completed":
            an = js
            break
    if not an:
        return {"status": "error", "detail": "The scan is still running. Click Scan again in a few minutes."}
    wait()
    code, js = vt_request("GET", f"{VT_API}/files/{sha}", key)
    if code == 200:
        res = parse_vt_report(js)
    else:
        s = an["data"]["attributes"].get("stats", {})
        mal, sus, har, und = (s.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
        res = {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": und,
               "status": vt_status(mal, sus, mal + sus + har + und), "detail": ""}
    res["uploaded"] = True
    return res


class QuotaDialog(tk.Toplevel):
    def __init__(self, parent, app, title, subtitle):
        super().__init__(parent)
        self.result = None
        self.configure(bg=PANEL)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        pad = app.px(22)
        tk.Label(self, text=title, bg=PANEL, fg=TEXT, font=(FONT, 15, "bold")).pack(anchor="w", padx=pad, pady=(pad, 2))
        tk.Label(self, text=subtitle, bg=PANEL, fg=MUTED, font=(FONT, 10), justify="left").pack(anchor="w", padx=pad)
        self.var = tk.StringVar(value="1 GB")
        e = ttk.Entry(self, textvariable=self.var, font=(FONT, 13), style="Dark.TEntry", width=26)
        e.pack(fill="x", padx=pad, pady=(14, 8))
        e.focus_set()
        e.selection_range(0, "end")
        row = tk.Frame(self, bg=PANEL)
        row.pack(fill="x", padx=pad)
        for p in ("500 MB", "1 GB", "5 GB", "10 GB", "50 GB"):
            ttk.Button(row, text=p, style="Ghost.TButton", command=lambda p=p: self.var.set(p)).pack(side="left", padx=(0, 6))
        tk.Label(self, text="Counts download + upload. Examples: 750 MiB, 2 GB, 300",
                 bg=PANEL, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=pad, pady=(10, 0))
        btns = tk.Frame(self, bg=PANEL)
        btns.pack(fill="x", padx=pad, pady=pad)
        ttk.Button(btns, text="Set quota", style="Accent.TButton", command=self.ok).pack(side="right")
        ttk.Button(btns, text="Cancel", style="Ghost.TButton", command=self.destroy).pack(side="right", padx=8)
        self.bind("<Return>", lambda ev: self.ok())
        self.bind("<Escape>", lambda ev: self.destroy())
        self.update_idletasks()
        self._place_center(parent)
        self.grab_set()
        self.wait_window(self)

    def _place_center(self, parent):
        self.update_idletasks()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        ow, oh = self.winfo_width(), self.winfo_height()
        if pw > 0 and ph > 0:
            x = parent.winfo_rootx() + max(0, (pw - ow) // 2)
            y = parent.winfo_rooty() + max(0, (ph - oh) // 3)
        else:
            x, y = 100, 100
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

    def ok(self):
        self.result = self.var.get().strip()
        self.destroy()


class NetQuotaApp:
    COLS = ("app", "down", "up", "today", "month", "quota", "vt", "state", "path")
    HEADS = {"app": "APPLICATION", "down": "DOWNLOAD", "up": "UPLOAD", "today": "TODAY",
             "month": "THIS MONTH", "quota": "QUOTA", "vt": "VIRUSTOTAL", "state": "NETWORK", "path": "EXECUTABLE"}
    WIDTHS = {"app": 170, "down": 100, "up": 100, "today": 160, "month": 160, "quota": 200, "vt": 150, "state": 110, "path": 320}

    def __init__(self, root):
        self.root = root
        self.s = max(1.0, root.winfo_fpixels("1i") / 96.0)
        root.title("NetQuota")
        root.geometry(f"{self.px(1240)}x{self.px(820)}")
        root.minsize(self.px(980), self.px(640))
        apply_theme(root, self.px)
        self.icon = make_photo(64)
        root.iconphoto(True, self.icon)
        BASE.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(DB_PATH)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS usage(day TEXT, exe TEXT, name TEXT,
                sent INTEGER DEFAULT 0, received INTEGER DEFAULT 0, PRIMARY KEY(day, exe));
            CREATE TABLE IF NOT EXISTS quota(exe TEXT PRIMARY KEY, bytes_limit INTEGER, period TEXT);
            CREATE TABLE IF NOT EXISTS blocked(exe TEXT PRIMARY KEY, reason TEXT, since TEXT);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS vt(exe TEXT PRIMARY KEY, sha256 TEXT, mtime REAL, size INTEGER,
                malicious INTEGER, suspicious INTEGER, harmless INTEGER, undetected INTEGER,
                status TEXT, detail TEXT, ts REAL);
        """)
        self.db.commit()
        self.q = queue.Queue()
        self.current, self.prev, self.names = {}, {}, {}
        self.hist = deque(maxlen=60)
        self.sort_key, self.sort_rev = "down", True
        self.blocked = dict(self.db.execute("SELECT exe, reason FROM blocked"))
        self.quotas = {e: (l, p) for e, l, p in self.db.execute("SELECT exe, bytes_limit, period FROM quota")}
        for exe, name in self.db.execute("SELECT exe, name FROM usage GROUP BY exe"):
            self.names[exe] = name
        self.apikey = self.get_setting("vt_key", "")
        self.vt_free = self.get_setting("vt_free", "1") == "1"
        self.vt, self.vt_msg, self.vt_err, self.vt_pending = {}, {}, {}, set()
        for row in self.db.execute("SELECT exe," + ",".join(VT_FIELDS) + " FROM vt"):
            self.vt[row[0]] = dict(zip(VT_FIELDS, row[1:]))
        self.vtq = queue.Queue()
        threading.Thread(target=self.vt_worker, daemon=True).start()
        self._build()
        self.set_status("Starting...")
        self.cap = Capture(self.q)
        self.cap.start()
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.timer_id = root.after(1000, self.tick)

    def px(self, n):
        return int(n * self.s)

    # ------------------------------------------------------------ layout
    def _build(self):
        px, root = self.px, self.root
        pad = px(20)
        # header
        head = tk.Frame(root, bg=BG)
        head.pack(fill="x", padx=pad, pady=(px(16), px(10)))
        self.logo = make_photo(px(46))
        tk.Label(head, image=self.logo, bg=BG).pack(side="left")
        tt = tk.Frame(head, bg=BG)
        tt.pack(side="left", padx=px(12))
        tk.Label(tt, text="NetQuota", bg=BG, fg=TEXT, font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(tt, text="Per-app internet monitor & firewall control", bg=BG, fg=MUTED,
                 font=(FONT, 10)).pack(anchor="w")
        pill = tk.Frame(head, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        pill.pack(side="right")
        self.dot = tk.Canvas(pill, width=px(14), height=px(14), bg=PANEL, highlightthickness=0)
        self.dot.pack(side="left", padx=(px(12), px(2)), pady=px(8))
        self.dot_id = self.dot.create_oval(px(2), px(2), px(12), px(12), fill=AMBER, outline="")
        self.status_lbl = tk.Label(pill, text="", bg=PANEL, fg=TEXT, font=(FONT, 10))
        self.status_lbl.pack(side="left", padx=(0, px(14)))

        # stat cards
        cards = tk.Frame(root, bg=BG)
        cards.pack(fill="x", padx=pad)
        self.card = {}
        for i, (key, title, color) in enumerate((
                ("down", "DOWNLOAD NOW", GREEN), ("up", "UPLOAD NOW", ORANGE), ("today", "TODAY", ACCENT),
                ("month", "THIS MONTH", "#a78bfa"), ("guard", "PROTECTION", AMBER))):
            cards.columnconfigure(i, weight=1, uniform="c")
            f = tk.Frame(cards, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            f.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else px(10), 0))
            tk.Frame(f, bg=color, height=px(3)).pack(fill="x")
            tk.Label(f, text=title, bg=PANEL, fg=MUTED, font=(FONT, 9, "bold")).pack(anchor="w", padx=px(14), pady=(px(10), 0))
            v = tk.Label(f, text="-", bg=PANEL, fg=color, font=(FONT, 20, "bold"))
            v.pack(anchor="w", padx=px(14))
            sub = tk.Label(f, text=" ", bg=PANEL, fg=MUTED, font=(FONT, 9))
            sub.pack(anchor="w", padx=px(14), pady=(0, px(10)))
            self.card[key] = (v, sub)

        # live graph
        gp = tk.Frame(root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        gp.pack(fill="x", padx=pad, pady=(px(12), 0))
        self.graph = tk.Canvas(gp, height=px(120), bg=PANEL, highlightthickness=0)
        self.graph.pack(fill="x", padx=px(6), pady=px(4))

        # toolbar
        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", padx=pad, pady=(px(14), px(8)))
        for text, style, cmd in (
                ("Pause app", "Danger", lambda: self.pause(True)),
                ("Resume app", "Success", lambda: self.pause(False)),
                ("Daily quota", "Ghost", lambda: self.set_quota("daily")),
                ("Monthly quota", "Ghost", lambda: self.set_quota("monthly")),
                ("Remove quota", "Ghost", self.remove_quota),
                ("Usage history", "Accent", self.show_history)):
            ttk.Button(bar, text=text, style=f"{style}.TButton", command=cmd).pack(side="left", padx=(0, px(8)))
        self.search = tk.StringVar()
        ttk.Entry(bar, textvariable=self.search, style="Dark.TEntry", width=24, font=(FONT, 10)).pack(side="right")
        tk.Label(bar, text="Search  ", bg=BG, fg=MUTED, font=(FONT, 10)).pack(side="right")

        vbar = tk.Frame(root, bg=BG)
        vbar.pack(fill="x", padx=pad, pady=(0, px(8)))
        tk.Label(vbar, text="VIRUSTOTAL", bg=BG, fg=MUTED, font=(FONT, 9, "bold")).pack(side="left", padx=(0, px(10)))
        for text, style, cmd in (("Scan selected app", "Accent", self.vt_scan_selected),
                                 ("Scan all listed apps", "Ghost", self.vt_scan_all),
                                 ("View report", "Ghost", self.show_vt_report),
                                 ("API key & settings", "Ghost", self.vt_settings)):
            ttk.Button(vbar, text=text, style=f"{style}.TButton", command=cmd).pack(side="left", padx=(0, px(8)))

        # table
        wrap = tk.Frame(root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        wrap.pack(fill="both", expand=True, padx=pad)
        self.tree = ttk.Treeview(wrap, columns=self.COLS, show="headings", selectmode="browse")
        for c in self.COLS:
            self.tree.heading(c, text=self.HEADS[c], command=lambda c=c: self.sort_by(c),
                              anchor="w")
            self.tree.column(c, width=px(self.WIDTHS[c]), minwidth=px(60), stretch=(c == "path"), anchor="w")
        sb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("odd", background=PANEL)
        self.tree.tag_configure("even", background=STRIPE)
        self.tree.tag_configure("blocked", background="#2a1620", foreground="#ff9aa2")
        self.tree.tag_configure("warn", background="#2b2415", foreground=AMBER)
        self.tree.tag_configure("vtbad", background="#33141c", foreground="#ff6b7a")
        self.empty = tk.Label(wrap, text="Waiting for network activity...\nOpen a website or start a download.",
                              bg=PANEL, fg=MUTED, font=(FONT, 12), justify="center")
        self.menu = tk.Menu(root, tearoff=0, bg=PANEL2, fg=TEXT, activebackground=ACCENT, activeforeground="white",
                            bd=0, font=(FONT, 10))
        items = (("Pause app", lambda: self.pause(True)), ("Resume app", lambda: self.pause(False)), None,
                 ("Set daily quota...", lambda: self.set_quota("daily")),
                 ("Set monthly quota...", lambda: self.set_quota("monthly")),
                 ("Remove quota", self.remove_quota), None,
                 ("Scan with VirusTotal", self.vt_scan_selected), ("VirusTotal report", self.show_vt_report), None,
                 ("Usage history", self.show_history))
        for item in items:
            if item is None:
                self.menu.add_separator()
            else:
                self.menu.add_command(label=item[0], command=item[1])
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<Double-1>", lambda e: self.show_history() if self.tree.selection() else None)
        self.footer = tk.Label(root, text="", bg=BG, fg=MUTED, font=(FONT, 9), anchor="w")
        self.footer.pack(fill="x", padx=pad, pady=(px(8), px(12)))
        self.update_headings()

    def set_status(self, text):
        low = text.lower()
        color = GREEN if low.startswith("capturing") else RED if any(
            w in low for w in ("unavailable", "error", "failed", "crash")) else AMBER
        self.dot.itemconfigure(self.dot_id, fill=color)
        self.status_lbl.configure(text=text)

    def update_headings(self):
        for c in self.COLS:
            arrow = (" \u25BC" if self.sort_rev else " \u25B2") if c == self.sort_key else ""
            self.tree.heading(c, text=self.HEADS[c] + arrow)

    def sort_by(self, col):
        if col == self.sort_key:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_key, self.sort_rev = col, col != "app"
        self.update_headings()
        self.refresh()

    def on_right_click(self, ev):
        row = self.tree.identify_row(ev.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    # ------------------------------------------------------------ actions
    def selected(self, need_real=True):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP, "Select an application row first.")
            return None
        exe = sel[0]
        if need_real and not os.path.isfile(exe):
            messagebox.showwarning(APP, "This row has no real executable path, so it can't be controlled.")
            return None
        return exe

    def mark_blocked(self, exe, reason):
        self.blocked[exe] = reason
        self.db.execute("INSERT OR REPLACE INTO blocked VALUES(?,?,?)",
                        (exe, reason, datetime.now().isoformat(timespec="seconds")))
        self.db.commit()

    def mark_unblocked(self, exe):
        self.blocked.pop(exe, None)
        self.db.execute("DELETE FROM blocked WHERE exe=?", (exe,))
        self.db.commit()

    def pause(self, block):
        exe = self.selected()
        if not exe:
            return
        try:
            set_block(exe, block)
            self.mark_blocked(exe, "manual pause") if block else self.mark_unblocked(exe)
            self.refresh()
        except Exception as e:
            messagebox.showerror(APP, str(e))

    def set_quota(self, period):
        exe = self.selected()
        if not exe:
            return
        self.timer_id = self.root.after_idle(self._unpause_quota_timer, period)
        dlg = QuotaDialog(self.root, self, f"{period.title()} quota",
                          f"Limit for {Path(exe).name}. Internet is blocked automatically\nwhen the app reaches it.")
        self.root.after_cancel(self.timer_id)
        self.timer_id = None
        if not dlg.result:
            return
        try:
            limit = parse_quota(dlg.result)
        except Exception as e:
            messagebox.showerror(APP, f"Invalid quota: {e}")
            return
        self.db.execute("INSERT OR REPLACE INTO quota VALUES(?,?,?)", (exe, limit, period))
        self.db.commit()
        self.quotas[exe] = (limit, period)
        self.check_quota(exe)
        self.refresh()

    def _unpause_quota_timer(self, period):
        if self.timer_id is not None:
            self.root.after_cancel(self.timer_id)
            self.timer_id = None
        self.timer_id = self.root.after(1000, self.tick)

    def remove_quota(self):
        exe = self.selected(need_real=False)
        if not exe:
            return
        self.db.execute("DELETE FROM quota WHERE exe=?", (exe,))
        self.db.commit()
        self.quotas.pop(exe, None)
        if self.blocked.get(exe, "").startswith("quota"):
            try:
                set_block(exe, False)
                self.mark_unblocked(exe)
            except Exception as e:
                messagebox.showerror(APP, str(e))
        self.refresh()

    # ------------------------------------------------------------ VirusTotal
    def get_setting(self, k, default=""):
        r = self.db.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
        return r[0] if r else default

    def set_setting(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, v))
        self.db.commit()

    def vt_stale(self, exe):
        d = self.vt.get(exe)
        try:
            st = os.stat(exe)
            return bool(d) and (abs(st.st_mtime - d["mtime"]) > 1 or st.st_size != d["size"])
        except OSError:
            return False

    def vt_rank(self, exe):
        d = self.vt.get(exe)
        return -1 if not d else {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}.get(d["status"], -1)

    def vt_text(self, exe):
        if exe in self.vt_msg:
            return self.vt_msg[exe]
        d = self.vt.get(exe)
        if not d:
            return "-"
        if self.vt_stale(exe):
            return "File changed - rescan"
        tot = d["malicious"] + d["suspicious"] + d["harmless"] + d["undetected"]
        flagged = d["malicious"] + d["suspicious"]
        return {"clean": f"Clean 0/{tot}", "suspicious": f"Suspicious {flagged}/{tot}",
                "malicious": f"MALICIOUS {d['malicious']}/{tot}", "unknown": "Not in VirusTotal"}.get(d["status"], "-")

    def need_key(self):
        if not self.apikey:
            messagebox.showinfo(APP, "Add your free VirusTotal API key first.")
            self.vt_settings()
        return bool(self.apikey)

    def vt_enqueue(self, exe, upload=False, manual=False):
        if exe in self.vt_pending:
            return False
        self.vt_pending.add(exe)
        self.vt_msg[exe] = "Queued..."
        self.vtq.put((exe, upload, manual, self.apikey, self.vt_free))
        return True

    def vt_scan_selected(self):
        exe = self.selected()
        if not exe or not self.need_key():
            return
        if self.vt_enqueue(exe, False, True):
            self.set_status(f"VirusTotal: scanning {Path(exe).name}...")
        else:
            messagebox.showinfo(APP, "That file is already queued.")

    def vt_scan_all(self):
        if not self.need_key():
            return
        n = 0
        for exe in list(self.current):
            if not os.path.isfile(exe):
                continue
            d = self.vt.get(exe)
            if d and not self.vt_stale(exe) and time.time() - d["ts"] < 7 * 86400:
                continue
            n += bool(self.vt_enqueue(exe))
        mins = int(n * (15.5 if self.vt_free else 1.0) / 60) + 1
        self.set_status(f"VirusTotal: {n} file(s) queued (about {mins} min)" if n else
                        "VirusTotal: everything was scanned within the last 7 days")

    def vt_worker(self):
        last = [0.0]
        while True:
            exe, upload, manual, key, free = self.vtq.get()
            gap = 15.5 if free else 1.0

            def wait():
                d = last[0] + gap - time.monotonic()
                if d > 0:
                    time.sleep(d)
                last[0] = time.monotonic()

            def say(t):
                self.q.put(("vtmsg", (exe, t)))
            try:
                st = os.stat(exe)
                say("Hashing file...")
                sha = sha256_file(exe)
                say("Asking VirusTotal...")
                wait()
                code, js = vt_request("GET", f"{VT_API}/files/{sha}", key)
                if code == 200:
                    res = parse_vt_report(js)
                elif code == 404:
                    if upload:
                        res = vt_upload(exe, st.st_size, sha, key, wait, say)
                    else:
                        res = {"status": "unknown", "malicious": 0, "suspicious": 0, "harmless": 0,
                               "undetected": 0, "detail": ""}
                else:
                    res = {"status": "error", "detail": vt_http_error(code, js)}
                res.update(sha256=sha, mtime=st.st_mtime, size=st.st_size, ts=time.time())
            except Exception as e:
                res = {"status": "error", "detail": f"{type(e).__name__}: {e}  (is the internet reachable?)"}
            self.q.put(("vt", (exe, res, manual)))

    def vt_done(self, exe, res, manual):
        self.vt_pending.discard(exe)
        name = Path(exe).name
        if res["status"] == "error":
            self.vt_msg[exe] = "Error - click View report"
            self.vt_err[exe] = res["detail"]
            self.set_status(f"VirusTotal error: {res['detail']}"[:100])
            if manual:
                messagebox.showerror(APP, res["detail"])
            return
        self.vt_msg.pop(exe, None)
        self.vt_err.pop(exe, None)
        row = {k: res.get(k, 0) for k in VT_FIELDS}
        row["detail"] = res.get("detail", "")
        self.db.execute("INSERT OR REPLACE INTO vt VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (exe,) + tuple(row[k] for k in VT_FIELDS))
        self.db.commit()
        self.vt[exe] = row
        self.set_status(f"VirusTotal: {name} - {self.vt_text(exe)}")
        if res["status"] == "unknown" and manual and not res.get("uploaded"):
            if messagebox.askyesno(APP, f"VirusTotal has never seen {name}.\n\nUpload it for scanning? "
                                   "This SHARES THE FILE with VirusTotal and its security partners.\n"
                                   "Do not upload private or confidential files."):
                self.vt_enqueue(exe, True, True)
                return
        if manual:
            self.show_vt_report(exe)

    def show_vt_report(self, exe=None):
        exe = exe or self.selected(need_real=False)
        if not exe:
            return
        px = self.px
        d = self.vt.get(exe)
        name = self.names.get(exe) or Path(exe).name
        win = tk.Toplevel(self.root)
        win.configure(bg=BG)
        win.title(f"{name} - VirusTotal report")
        win.geometry(f"{px(680)}x{px(560)}")
        win.iconphoto(False, self.icon)
        pad = px(20)
        tk.Label(win, text=name, bg=BG, fg=TEXT, font=(FONT, 18, "bold")).pack(anchor="w", padx=pad, pady=(pad, 0))
        tk.Label(win, text=exe, bg=BG, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=pad)
        if not d:
            err = self.vt_err.get(exe)
            msg = f"Last attempt failed:\n{err}" if err else "Not scanned yet.\nSelect the app and click 'Scan selected app'."
            tk.Label(win, text=msg, bg=BG, fg=MUTED, font=(FONT, 11), justify="left", wraplength=px(600)).pack(
                anchor="w", padx=pad, pady=pad)
            return
        label, color = {"clean": ("CLEAN", GREEN), "suspicious": ("SUSPICIOUS", AMBER), "malicious": ("MALICIOUS", RED),
                        "unknown": ("NOT IN VIRUSTOTAL", MUTED)}[d["status"]]
        tot = d["malicious"] + d["suspicious"] + d["harmless"] + d["undetected"]
        card = tk.Frame(win, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="x", padx=pad, pady=(px(14), px(10)))
        tk.Frame(card, bg=color, height=px(4)).pack(fill="x")
        tk.Label(card, text=label, bg=PANEL, fg=color, font=(FONT, 22, "bold")).pack(anchor="w", padx=px(16), pady=(px(10), 0))
        if tot:
            line = (f"{d['malicious']} malicious, {d['suspicious']} suspicious, {d['harmless']} harmless, "
                    f"{d['undetected']} undetected  ({tot} engines)")
        else:
            line = "VirusTotal has no scan results for this file."
        tk.Label(card, text=line, bg=PANEL, fg=TEXT, font=(FONT, 10)).pack(anchor="w", padx=px(16))
        when = datetime.fromtimestamp(d["ts"]).strftime("%Y-%m-%d %H:%M")
        tk.Label(card, text=f"SHA-256: {d['sha256']}\nChecked: {when}", bg=PANEL, fg=MUTED, font=(FONT, 9),
                 justify="left").pack(anchor="w", padx=px(16), pady=(px(6), px(12)))
        tk.Label(win, text="Engines that flagged this file", bg=BG, fg=MUTED, font=(FONT, 9, "bold")).pack(
            anchor="w", padx=pad)
        txt = tk.Text(win, bg=PANEL, fg=TEXT, relief="flat", font=("Consolas", 10), height=8,
                      highlightthickness=1, highlightbackground=BORDER, padx=px(10), pady=px(8))
        txt.insert("1.0", d["detail"] or "None. No engine flagged this file.")
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True, padx=pad, pady=(px(4), px(8)))
        tk.Label(win, text="Tip: 1-2 detections are often false positives. A clean result does not guarantee a file is safe.",
                 bg=BG, fg=MUTED, font=(FONT, 9), wraplength=px(620), justify="left").pack(anchor="w", padx=pad)
        btns = tk.Frame(win, bg=BG)
        btns.pack(fill="x", padx=pad, pady=pad)
        ttk.Button(btns, text="Open on VirusTotal", style="Accent.TButton",
                   command=lambda: webbrowser.open(f"https://www.virustotal.com/gui/file/{d['sha256']}")).pack(side="left")

        def rescan():
            if self.need_key():
                self.vt_enqueue(exe, False, True)
                win.destroy()
        ttk.Button(btns, text="Rescan", style="Ghost.TButton", command=rescan).pack(side="left", padx=8)

    def vt_settings(self):
        px = self.px
        win = tk.Toplevel(self.root)
        win.configure(bg=PANEL)
        win.title("VirusTotal settings")
        win.transient(self.root)
        win.resizable(False, False)
        pad = px(22)
        tk.Label(win, text="VirusTotal settings", bg=PANEL, fg=TEXT, font=(FONT, 15, "bold")).pack(anchor="w", padx=pad, pady=(pad, 2))
        tk.Label(win, text="Paste your API key. Get a free one by signing up at virustotal.com\n"
                 "(profile menu > API key). Stored on this PC only, unencrypted.",
                 bg=PANEL, fg=MUTED, font=(FONT, 10), justify="left").pack(anchor="w", padx=pad)
        kv = tk.StringVar(value=self.apikey)
        e = ttk.Entry(win, textvariable=kv, show="*", style="Dark.TEntry", font=(FONT, 11), width=58)
        e.pack(fill="x", padx=pad, pady=(px(12), px(8)))
        e.focus_set()
        fv = tk.IntVar(value=1 if self.vt_free else 0)
        tk.Checkbutton(win, text="Free API key (slower: 4 lookups/min, 500/day, personal use only)", variable=fv,
                       bg=PANEL, fg=TEXT, selectcolor=PANEL2, activebackground=PANEL, activeforeground=TEXT,
                       font=(FONT, 10)).pack(anchor="w", padx=pad)
        tk.Label(win, text="Files are checked by SHA-256 hash only. A file is uploaded to VirusTotal only if you\n"
                 "click Yes when asked, and only for unknown files up to 64 MB.",
                 bg=PANEL, fg=MUTED, font=(FONT, 9), justify="left").pack(anchor="w", padx=pad, pady=(px(10), 0))
        btns = tk.Frame(win, bg=PANEL)
        btns.pack(fill="x", padx=pad, pady=pad)

        def save():
            self.apikey = kv.get().strip()
            self.vt_free = bool(fv.get())
            self.set_setting("vt_key", self.apikey)
            self.set_setting("vt_free", "1" if self.vt_free else "0")
            win.destroy()
        ttk.Button(btns, text="Save", style="Accent.TButton", command=save).pack(side="right")
        ttk.Button(btns, text="Cancel", style="Ghost.TButton", command=win.destroy).pack(side="right", padx=8)
        ttk.Button(btns, text="Get a free API key", style="Ghost.TButton",
                   command=lambda: webbrowser.open("https://www.virustotal.com/gui/my-apikey")).pack(side="left")
        win.bind("<Return>", lambda ev: save())
        win.bind("<Escape>", lambda ev: win.destroy())
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 3
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.grab_set()
        win.wait_window(win)

    # ------------------------------------------------------------ history window
    def make_table(self, parent, heads, rows):
        f = tk.Frame(parent, bg=PANEL)
        t = ttk.Treeview(f, columns=[str(i) for i in range(len(heads))], show="headings")
        for i, h in enumerate(heads):
            t.heading(str(i), text=h.upper(), anchor="w")
            t.column(str(i), width=self.px(150), anchor="w")
        t.tag_configure("odd", background=PANEL)
        t.tag_configure("even", background=STRIPE)
        for i, r in enumerate(rows):
            t.insert("", "end", values=r, tags=("even" if i % 2 else "odd",))
        sb = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return f

    def show_history(self):
        exe = self.selected(need_real=False)
        if not exe:
            return
        px = self.px
        name = self.names.get(exe) or Path(exe).name
        win = tk.Toplevel(self.root)
        win.configure(bg=BG)
        win.title(f"{name} - usage history")
        win.geometry(f"{px(820)}x{px(640)}")
        win.iconphoto(False, self.icon)
        data = {d: (s, r) for d, s, r in self.db.execute("SELECT day, sent, received FROM usage WHERE exe=?", (exe,))}
        days = [(date.today() - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
        vals = [data.get(d, (0, 0)) for d in days]
        total30 = sum(s + r for s, r in vals)
        tk.Label(win, text=name, bg=BG, fg=TEXT, font=(FONT, 18, "bold")).pack(anchor="w", padx=px(20), pady=(px(16), 0))
        tk.Label(win, text=f"{exe}\nLast 30 days: {fmt_bytes(total30)} total", bg=BG, fg=MUTED, font=(FONT, 9),
                 justify="left").pack(anchor="w", padx=px(20), pady=(0, px(10)))
        cv = tk.Canvas(win, height=px(210), bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        cv.pack(fill="x", padx=px(20))

        def draw(_=None):
            cv.delete("all")
            w, h = cv.winfo_width(), cv.winfo_height()
            if w < 50:
                return
            l, r_, t, b = px(58), px(14), px(26), px(26)
            mx = max([s + r for s, r in vals] + [1024]) * 1.1
            for k in range(4):
                y = t + (h - t - b) * k / 3
                cv.create_line(l, y, w - r_, y, fill=BORDER, dash=(2, 4))
                cv.create_text(l - 8, y, text=fmt_bytes(mx * (1 - k / 3)), anchor="e", fill=MUTED, font=(FONT, 8))
            bw = (w - l - r_) / len(days)
            for i, (s, rcv) in enumerate(vals):
                x0 = l + i * bw + bw * .18
                x1 = l + (i + 1) * bw - bw * .18
                yb = h - b
                yd = yb - (h - t - b) * rcv / mx
                yu = yd - (h - t - b) * s / mx
                if rcv:
                    cv.create_rectangle(x0, yd, x1, yb, fill=GREEN, outline="")
                if s:
                    cv.create_rectangle(x0, yu, x1, yd, fill=ORANGE, outline="")
            for i in (0, 14, 29):
                cv.create_text(l + (i + .5) * bw, h - b + 12, text=days[i][5:], fill=MUTED, font=(FONT, 8))
            cv.create_text(l, 10, text="\u25CF Download", anchor="w", fill=GREEN, font=(FONT, 9, "bold"))
            cv.create_text(l + px(100), 10, text="\u25CF Upload", anchor="w", fill=ORANGE, font=(FONT, 9, "bold"))
        cv.bind("<Configure>", draw)

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=px(20), pady=px(14))
        daily = [(d, fmt_bytes(r), fmt_bytes(s), fmt_bytes(s + r)) for d, s, r in self.db.execute(
            "SELECT day, sent, received FROM usage WHERE exe=? ORDER BY day DESC LIMIT 120", (exe,))]
        monthly = [(m, fmt_bytes(r), fmt_bytes(s), fmt_bytes(s + r)) for m, s, r in self.db.execute(
            "SELECT substr(day,1,7), SUM(sent), SUM(received) FROM usage WHERE exe=? GROUP BY 1 ORDER BY 1 DESC", (exe,))]
        nb.add(self.make_table(nb, ("Day", "Downloaded", "Uploaded", "Total"), daily), text="Daily")
        nb.add(self.make_table(nb, ("Month", "Downloaded", "Uploaded", "Total"), monthly), text="Monthly")

    # ------------------------------------------------------------ accounting
    def record(self, batch):
        today = date.today().isoformat()
        for exe, name, sent, received in batch:
            st = self.current.setdefault(exe, {"name": name, "sent": 0, "received": 0, "up": 0.0, "down": 0.0})
            st["sent"] += sent
            st["received"] += received
            self.names[exe] = name
            self.db.execute("""INSERT INTO usage(day,exe,name,sent,received) VALUES(?,?,?,?,?)
                               ON CONFLICT(day,exe) DO UPDATE SET name=excluded.name,
                               sent=sent+excluded.sent, received=received+excluded.received""",
                            (today, exe, name, sent, received))
        self.db.commit()

    def period_total(self, exe, period):
        if period == "daily":
            sql, arg = "SELECT COALESCE(SUM(sent+received),0) FROM usage WHERE exe=? AND day=?", date.today().isoformat()
        else:
            sql, arg = ("SELECT COALESCE(SUM(sent+received),0) FROM usage WHERE exe=? AND substr(day,1,7)=?",
                        date.today().isoformat()[:7])
        return self.db.execute(sql, (exe, arg)).fetchone()[0]

    def check_quota(self, exe):
        q = self.quotas.get(exe)
        if not q:
            return
        limit, period = q
        total = self.period_total(exe, period)
        reason = self.blocked.get(exe, "")
        try:
            if total >= limit and exe not in self.blocked:
                set_block(exe, True)
                self.mark_blocked(exe, f"quota ({period})")
                self.set_status(f"Blocked {Path(exe).name}: {period} quota reached")
            elif total < limit and reason.startswith("quota"):
                set_block(exe, False)
                self.mark_unblocked(exe)
                self.set_status(f"Quota period reset: resumed {Path(exe).name}")
        except Exception as e:
            log(f"quota enforcement failed for {exe}: {e}")
            self.set_status(f"Quota block failed: {e}"[:100])

    # ------------------------------------------------------------ refresh
    def tick(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "batch":
                    self.record(payload)
                elif kind == "status":
                    self.set_status(payload)
                elif kind == "vtmsg":
                    self.vt_msg[payload[0]] = payload[1]
                elif kind == "vt":
                    self.vt_done(*payload)
        except queue.Empty:
            pass
        now = time.time()
        for exe, st in self.current.items():
            p = self.prev.get(exe)
            if p:
                dt = max(0.25, now - p[0])
                st["up"], st["down"] = (st["sent"] - p[1]) / dt, (st["received"] - p[2]) / dt
            self.prev[exe] = (now, st["sent"], st["received"])
        self.hist.append((sum(s["down"] for s in self.current.values()),
                          sum(s["up"] for s in self.current.values())))
        for exe in list(self.quotas):
            self.check_quota(exe)
        self.refresh()
        self.root.after(1000, self.tick)

    def refresh(self):
        today = date.today().isoformat()
        month = today[:7]
        day = {e: (s, r) for e, s, r in self.db.execute("SELECT exe,sent,received FROM usage WHERE day=?", (today,))}
        mon = {e: (s, r) for e, s, r in self.db.execute(
            "SELECT exe,SUM(sent),SUM(received) FROM usage WHERE substr(day,1,7)=? GROUP BY exe", (month,))}
        flt = self.search.get().strip().lower()
        rows = []
        for exe in set(self.current) | set(self.blocked) | set(self.quotas):
            name = self.names.get(exe) or Path(exe).name
            if flt and flt not in name.lower() and flt not in exe.lower():
                continue
            st = self.current.get(exe, {"up": 0, "down": 0})
            d, m, q = day.get(exe, (0, 0)), mon.get(exe, (0, 0)), self.quotas.get(exe)
            qtext, pct = "-", 0
            if q:
                used = sum(d) if q[1] == "daily" else sum(m)
                pct = used * 100.0 / q[0] if q[0] else 0
                qtext = f"{fmt_bytes(used)} of {fmt_bytes(q[0])} {q[1]} ({pct:.0f}%)"
            if exe in self.blocked:
                state = "Blocked (quota)" if self.blocked[exe].startswith("quota") else "Blocked (paused)"
            else:
                state = "Active"
            speed = lambda v: fmt_bytes(v) + "/s" if v >= 1 else "-"
            rows.append({
                "exe": exe,
                "values": (name, speed(st["down"]), speed(st["up"]),
                           f"\u2193 {fmt_bytes(d[1])}   \u2191 {fmt_bytes(d[0])}",
                           f"\u2193 {fmt_bytes(m[1])}   \u2191 {fmt_bytes(m[0])}", qtext, self.vt_text(exe), state, exe),
                "sort": {"app": name.lower(), "down": st["down"], "up": st["up"], "today": sum(d), "month": sum(m),
                         "quota": pct, "vt": self.vt_rank(exe), "state": exe in self.blocked, "path": exe.lower()},
                "blocked": exe in self.blocked, "warn": pct >= 80, "vtbad": self.vt_rank(exe) >= 2})
        rows.sort(key=lambda r: r["sort"][self.sort_key], reverse=self.sort_rev)
        keep = set()
        for i, r in enumerate(rows):
            tag = "blocked" if r["blocked"] else "vtbad" if r["vtbad"] else "warn" if r["warn"] else ("even" if i % 2 else "odd")
            if self.tree.exists(r["exe"]):
                self.tree.item(r["exe"], values=r["values"], tags=(tag,))
            else:
                self.tree.insert("", "end", iid=r["exe"], values=r["values"], tags=(tag,))
            self.tree.move(r["exe"], "", i)
            keep.add(r["exe"])
        for iid in self.tree.get_children():
            if iid not in keep:
                self.tree.delete(iid)
        if rows:
            self.empty.place_forget()
        else:
            self.empty.place(relx=.5, rely=.5, anchor="center")

        down = sum(s["down"] for s in self.current.values())
        up = sum(s["up"] for s in self.current.values())
        tds, tdr = sum(v[0] for v in day.values()), sum(v[1] for v in day.values())
        tms, tmr = sum(v[0] for v in mon.values()), sum(v[1] for v in mon.values())
        sp = lambda v: fmt_bytes(v) + "/s"
        self.card["down"][0].configure(text=sp(down)); self.card["down"][1].configure(text=f"Today: {fmt_bytes(tdr)}")
        self.card["up"][0].configure(text=sp(up)); self.card["up"][1].configure(text=f"Today: {fmt_bytes(tds)}")
        self.card["today"][0].configure(text=fmt_bytes(tds + tdr))
        self.card["today"][1].configure(text=f"\u2193 {fmt_bytes(tdr)}   \u2191 {fmt_bytes(tds)}")
        self.card["month"][0].configure(text=fmt_bytes(tms + tmr))
        self.card["month"][1].configure(text=f"\u2193 {fmt_bytes(tmr)}   \u2191 {fmt_bytes(tms)}")
        self.card["guard"][0].configure(text=f"{len(self.blocked)} blocked")
        self.card["guard"][1].configure(text=f"{len(self.quotas)} quota(s) active")
        self.footer.configure(text=f"Data: {DB_PATH}   |   Firewall blocks stay active after you close NetQuota "
                                   f"until you resume the app.   |   Right-click a row for actions.")
        self.draw_graph()

    def draw_graph(self):
        c = self.graph
        w, h = c.winfo_width(), c.winfo_height()
        if w < 60 or h < 40:
            return
        c.delete("all")
        px = self.px
        l, r, t, b = px(70), px(14), px(22), px(8)
        data = [(0, 0)] * (60 - len(self.hist)) + list(self.hist)
        mx = max([max(d, u) for d, u in data] + [1024]) * 1.2
        for k in range(3):
            y = t + (h - t - b) * k / 2
            c.create_line(l, y, w - r, y, fill=BORDER, dash=(2, 4))
            c.create_text(l - 8, y, text=fmt_bytes(mx * (1 - k / 2)) + "/s", anchor="e", fill=MUTED, font=(FONT, 8))
        for idx, color, fill in ((0, GREEN, "#10372f"), (1, ORANGE, "#3d2a1a")):
            pts = []
            for i, v in enumerate(data):
                x = l + (w - l - r) * i / 59
                y = h - b - (h - t - b) * v[idx] / mx
                pts.append((x, y))
            c.create_polygon(pts + [(w - r, h - b), (l, h - b)], fill=fill, outline="")
            c.create_line(pts, fill=color, width=2, smooth=True)
        c.create_text(l, 9, text="\u25CF Download", anchor="w", fill=GREEN, font=(FONT, 9, "bold"))
        c.create_text(l + px(100), 9, text="\u25CF Upload", anchor="w", fill=ORANGE, font=(FONT, 9, "bold"))
        c.create_text(w - r, 9, text="last 60 seconds", anchor="e", fill=MUTED, font=(FONT, 8))

    def close(self):
        self.cap.running = False
        try:
            self.db.commit(); self.db.close()
        except Exception:
            pass
        try:
            if self.timer_id is not None:
                self.root.after_cancel(self.timer_id)
                self.timer_id = None
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass


def _main():
    if "--version" in sys.argv:
        print(f"NetQuota {__version__}")
        return 0
    if os.name != "nt":
        print("NetQuota is Windows-only.")
        return 1
    if not is_admin():
        params = "" if getattr(sys, "frozen", False) else subprocess.list2cmdline([os.path.abspath(__file__)])
        if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32:
            return 0
        print("Please run as Administrator.")
        return 1
    try:
        import psutil, pydivert  # noqa: F401
    except ImportError:
        print("Missing packages. Run: py -m pip install psutil pydivert")
        return 2
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NetQuota.App")
    except Exception:
        pass
    root = tk.Tk()
    root.report_callback_exception = lambda *a: log("".join(traceback.format_exception(*a)))
    NetQuotaApp(root)
    root.mainloop()
    return 0


def main():
    try:
        log(f"NetQuota {__version__} starting (frozen={getattr(sys, 'frozen', False)}, admin={is_admin()}, "
            f"python={sys.version.split()[0]})")
        return _main()
    except BaseException:
        tb = traceback.format_exc()
        log(tb)
        print(tb)
        try:
            r = tk.Tk(); r.withdraw()
            messagebox.showerror(APP, "NetQuota crashed:\n\n" + tb[-1500:])
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
