"""Tkinter GUI for the VMware CIS / EOL / patch auditor."""
from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from . import report, lifecycle
from .models import ScanOptions, STATUSES
from .scanner import run_scan

TAG_COLORS = {"FAIL": "#fde0e0", "WARN": "#fff3cd", "PASS": "#e2f5e6", "ERROR": "#ead9fb",
              "MANUAL": "#eceff1", "INFO": "#dcebff"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VMware vCenter / ESXi - CIS, EOL & Patch Auditor")
        self.geometry("1280x780")
        self.minsize(1000, 600)
        self._set_icon()
        self.q = queue.Queue()
        self.results, self.meta = [], {}
        self.cancel = threading.Event()
        self.worker = None
        self._build()
        self.after(100, self._pump)

    def _set_icon(self):
        assets = Path(__file__).resolve().parent.parent / "assets"
        try:
            self._icon = tk.PhotoImage(file=str(assets / "icon_64.png"))
            self.iconphoto(True, self._icon)
            if sys.platform == "win32":
                self.iconbitmap(str(assets / "icon.ico"))
        except Exception:
            pass  # icon is cosmetic

    # ---------------------------------------------------------------- layout
    def _build(self):
        menu = tk.Menu(self)
        data = tk.Menu(menu, tearoff=0)
        data.add_command(label="Fetch EOL dates online (endoflife.date)", command=self.fetch_eol)
        data.add_command(label="Import builds.json / eol.json...", command=self.import_data)
        menu.add_cascade(label="Data", menu=data)
        exp = tk.Menu(menu, tearoff=0)
        for lbl, fn in (("HTML report...", "html"), ("CSV...", "csv"), ("JSON...", "json")):
            exp.add_command(label=lbl, command=lambda f=fn: self.export(f))
        menu.add_cascade(label="Export", menu=exp)
        self.config(menu=menu)

        conn = ttk.LabelFrame(self, text="Target (vCenter Server or standalone ESXi host)")
        conn.pack(fill="x", padx=8, pady=6)
        self.v_host, self.v_user, self.v_port = tk.StringVar(), tk.StringVar(value="administrator@vsphere.local"), tk.StringVar(value="443")
        self.v_pw = tk.StringVar()
        for i, (lbl, var, show, w) in enumerate((("Host / FQDN", self.v_host, "", 30), ("User", self.v_user, "", 30),
                                                 ("Password", self.v_pw, "*", 22), ("Port", self.v_port, "", 6))):
            ttk.Label(conn, text=lbl).grid(row=0, column=2 * i, padx=(8, 2), pady=6, sticky="e")
            ttk.Entry(conn, textvariable=var, show=show, width=w).grid(row=0, column=2 * i + 1, padx=(0, 6))

        opt = ttk.LabelFrame(self, text="Scope")
        opt.pack(fill="x", padx=8)
        self.o = {k: tk.BooleanVar(value=v) for k, v in (("hosts", True), ("vms", True), ("vcenter", True),
                                                          ("appliance", True), ("network", True), ("tls", False))}
        for i, (k, lbl) in enumerate((("hosts", "ESXi hosts"), ("vms", "Virtual machines"), ("vcenter", "vCenter settings"),
                                      ("appliance", "VCSA appliance (REST)"), ("network", "Distributed switches"),
                                      ("tls", "Verify TLS certificate"))):
            ttk.Checkbutton(opt, text=lbl, variable=self.o[k]).grid(row=0, column=i, padx=8, pady=4)
        ttk.Label(opt, text="Snapshot max age (days)").grid(row=0, column=6, padx=(16, 2))
        self.v_snap = tk.StringVar(value="3")
        ttk.Spinbox(opt, from_=1, to=60, width=4, textvariable=self.v_snap).grid(row=0, column=7)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=6)
        self.btn_scan = ttk.Button(bar, text="Run audit", command=self.start)
        self.btn_scan.pack(side="left")
        self.btn_cancel = ttk.Button(bar, text="Cancel", command=self.cancel.set, state="disabled")
        self.btn_cancel.pack(side="left", padx=6)
        self.pb = ttk.Progressbar(bar, mode="indeterminate", length=220)
        self.pb.pack(side="left", padx=10)
        self.v_status = tk.StringVar(value="Ready. Credentials are used for this session only and never saved.")
        ttk.Label(bar, textvariable=self.v_status).pack(side="left", padx=8)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.nb = nb

        # Summary
        self.f_sum = ttk.Frame(nb)
        nb.add(self.f_sum, text="Summary")
        self.t_sum = tk.Text(self.f_sum, font=("Consolas", 11), state="disabled", wrap="word")
        self.t_sum.pack(fill="both", expand=True)

        # Results (CIS / all) + lifecycle tabs share one builder
        self.tree_all = self._results_tab(nb, "All findings", None)
        self.tree_cis = self._results_tab(nb, "CIS hardening", "CIS")
        self.tree_eol = self._results_tab(nb, "EOL", "EOL")
        self.tree_patch = self._results_tab(nb, "Patches", "PATCH")

        # Log
        f_log = ttk.Frame(nb)
        nb.add(f_log, text="Log")
        self.t_log = tk.Text(f_log, state="disabled", font=("Consolas", 10))
        self.t_log.pack(fill="both", expand=True)

    def _results_tab(self, nb, title, category):
        frame = ttk.Frame(nb)
        nb.add(frame, text=title)
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=4)
        status_var = tk.StringVar(value="ALL")
        ttk.Label(top, text="Status:").pack(side="left", padx=(4, 2))
        cb = ttk.Combobox(top, textvariable=status_var, values=("ALL",) + STATUSES, width=9, state="readonly")
        cb.pack(side="left")
        ttk.Label(top, text="Search:").pack(side="left", padx=(12, 2))
        search = tk.StringVar()
        ttk.Entry(top, textvariable=search, width=35).pack(side="left")
        cols = ("status", "area", "id", "title", "target", "actual")
        pane = ttk.PanedWindow(frame, orient="vertical")
        pane.pack(fill="both", expand=True)
        tf = ttk.Frame(pane)
        tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (70, 100, 110, 380, 170, 380)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for s, col in TAG_COLORS.items():
            tree.tag_configure(s, background=col)
        detail = tk.Text(pane, height=8, wrap="word", state="disabled", font=("Segoe UI", 10))
        pane.add(tf, weight=4)
        pane.add(detail, weight=1)
        tree.category, tree.status_var, tree.search_var, tree.detail, tree.items = category, status_var, search, detail, {}
        refresh = lambda *_: self._fill(tree)
        cb.bind("<<ComboboxSelected>>", refresh)
        search.trace_add("write", refresh)
        tree.bind("<<TreeviewSelect>>", lambda e, t=tree: self._detail(t))
        return tree

    # ----------------------------------------------------------------- views
    def _fill(self, tree):
        tree.delete(*tree.get_children())
        tree.items.clear()
        st, q = tree.status_var.get(), tree.search_var.get().lower()
        order = {s: i for i, s in enumerate(STATUSES)}
        for r in sorted(self.results, key=lambda x: (order.get(x.status, 9), x.check_id)):
            if tree.category and r.category != tree.category:
                continue
            if st != "ALL" and r.status != st:
                continue
            if q and q not in f"{r.title} {r.target} {r.actual} {r.check_id} {r.area}".lower():
                continue
            iid = tree.insert("", "end", values=(r.status, r.area, r.check_id, r.title, r.target, str(r.actual)[:200]), tags=(r.status,))
            tree.items[iid] = r

    def _detail(self, tree):
        sel = tree.selection()
        if not sel:
            return
        r = tree.items[sel[0]]
        txt = (f"{r.check_id}  [{r.status}]  {r.title}\nTarget: {r.target}   Profile: {r.level or '-'}   Ref: {r.reference or '-'}\n"
               f"Actual:   {r.actual}\nExpected: {r.expected}\n\nRemediation:\n{r.remediation or '(none required)'}")
        tree.detail.config(state="normal")
        tree.detail.delete("1.0", "end")
        tree.detail.insert("end", txt)
        tree.detail.config(state="disabled")

    def _summary(self):
        c, score = report.summarize(self.results)
        m = self.meta
        lines = [f"Target : {m.get('target')}  ({m.get('type')})", f"Product: {m.get('product')}", f"Build  : {m.get('build')}", "",
                 f"Compliance score: {score}%   (PASS / PASS+FAIL+WARN)", ""]
        lines += [f"  {s:<7} {c.get(s, 0)}" for s in STATUSES]
        for cat in ("CIS", "EOL", "PATCH"):
            sub = [r for r in self.results if r.category == cat]
            lines.append(f"\n{cat}: {len(sub)} checks, {sum(1 for r in sub if r.status == 'FAIL')} failed")
        crit = [r for r in self.results if r.category in ("EOL", "PATCH") and r.status in ("FAIL", "WARN")]
        if crit:
            lines.append("\nLifecycle attention items:")
            lines += [f"  - [{r.status}] {r.target}: {r.title} -> {r.actual}" for r in crit[:25]]
        self._set(self.t_sum, "\n".join(lines))

    @staticmethod
    def _set(widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def log(self, msg):
        self.q.put(("log", msg))

    # ------------------------------------------------------------- scanning
    def start(self):
        if self.worker and self.worker.is_alive():
            return
        host, user, pw = self.v_host.get().strip(), self.v_user.get().strip(), self.v_pw.get()
        if not host or not user or not pw:
            messagebox.showwarning("Missing input", "Enter host, user and password.")
            return
        try:
            port = int(self.v_port.get())
            snap = int(self.v_snap.get())
        except ValueError:
            messagebox.showwarning("Invalid input", "Port and snapshot age must be numbers.")
            return
        opts = ScanOptions(self.o["hosts"].get(), self.o["vms"].get(), self.o["vcenter"].get(), self.o["appliance"].get(),
                           self.o["network"].get(), snap, self.o["tls"].get())
        self.cancel.clear()
        self.btn_scan.config(state="disabled")
        self.btn_cancel.config(state="normal")
        self.pb.start(12)
        self.v_status.set("Scanning ...")

        def work():
            try:
                res, meta = run_scan(host, user, pw, port, opts, self.log, lambda d, t: None, self.cancel.is_set)
                self.q.put(("done", (res, meta)))
            except Exception as e:
                self.q.put(("error", f"{type(e).__name__}: {e}"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.t_log.config(state="normal")
                    self.t_log.insert("end", payload + "\n")
                    self.t_log.see("end")
                    self.t_log.config(state="disabled")
                elif kind == "done":
                    self.results, self.meta = payload
                    self._finish("Done: %d checks" % len(self.results))
                    for t in (self.tree_all, self.tree_cis, self.tree_eol, self.tree_patch):
                        self._fill(t)
                    self._summary()
                    self.nb.select(0)
                elif kind == "error":
                    self._finish("Failed")
                    messagebox.showerror("Scan failed", payload)
                    self.log(payload)
                elif kind == "info":
                    messagebox.showinfo("Info", payload)
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _finish(self, status):
        self.pb.stop()
        self.btn_scan.config(state="normal")
        self.btn_cancel.config(state="disabled")
        self.v_status.set(status)
        self.v_pw.set("")  # do not keep the password in memory longer than needed

    # ----------------------------------------------------------------- data
    def fetch_eol(self):
        def work():
            try:
                n = lifecycle.fetch_eol_online(self.log)
                self.q.put(("info", f"EOL data refreshed ({n} date changes). Saved to {lifecycle.USER_DIR}"))
            except Exception as e:
                self.q.put(("error", f"EOL fetch failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def import_data(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if p:
            try:
                name = lifecycle.import_json_file(p, self.log)
                messagebox.showinfo("Imported", f"Installed as {name} in {lifecycle.USER_DIR}")
            except Exception as e:
                messagebox.showerror("Import failed", str(e))

    def export(self, kind):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run an audit first.")
            return
        p = filedialog.asksaveasfilename(defaultextension="." + kind, filetypes=[(kind.upper(), "*." + kind)])
        if not p:
            return
        if kind == "html":
            report.to_html(self.results, self.meta, p)
        elif kind == "csv":
            report.to_csv(self.results, p)
        else:
            report.to_json(self.results, self.meta, p)
        self.v_status.set(f"Exported {p}")


def main():
    App().mainloop()
