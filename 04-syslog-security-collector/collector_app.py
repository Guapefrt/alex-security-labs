import json
import os
import queue
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from collector import (
    AUDIT_FILE,
    HOST,
    PORT,
    SyslogSecurityEngine,
    create_udp_server,
    send_test_burst,
)


class SyslogCollectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Syslog Security Collector V2 — Real-Time SIEM & Threat Telemetry")
        self.geometry("1260x820")
        self.minsize(1020, 680)

        self.engine = SyslogSecurityEngine(brute_force_threshold=3, window_seconds=60)
        self.event_queue: queue.Queue = queue.Queue()
        self.server = None
        self.is_listening = False
        self.all_events: list[dict] = []
        self.event_map: dict[str, dict] = {}

        self.card_vars: dict[str, tk.StringVar] = {}
        self.card_labels: dict[str, ttk.Label] = {}

        self._configure_styles()
        self._build_ui()

        self.start_listener()
        self.after(80, self._poll_event_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#5f6368", font=("Sans", 9, "bold"))
        style.configure("CardBlue.TLabel", background="#ffffff", foreground="#1a73e8", font=("Sans", 18, "bold"))
        style.configure("CardGreen.TLabel", background="#ffffff", foreground="#137333", font=("Sans", 18, "bold"))
        style.configure("CardAmber.TLabel", background="#ffffff", foreground="#b06000", font=("Sans", 18, "bold"))
        style.configure("CardRed.TLabel", background="#ffffff", foreground="#c5221f", font=("Sans", 18, "bold"))
        style.configure("CardGray.TLabel", background="#ffffff", foreground="#5f6368", font=("Sans", 18, "bold"))
        style.configure("Treeview", rowheight=26, font=("Monospace", 9))
        style.configure("Treeview.Heading", font=("Sans", 9, "bold"))

    def _build_ui(self):
        toolbar = ttk.Frame(self, padding=(12, 10))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Bind Host:", font=("Sans", 9, "bold")).pack(side="left", padx=(0, 4))
        self.host_var = tk.StringVar(value=HOST)
        self.host_entry = ttk.Entry(toolbar, textvariable=self.host_var, width=14)
        self.host_entry.pack(side="left", padx=(0, 10))

        ttk.Label(toolbar, text="UDP Port:", font=("Sans", 9, "bold")).pack(side="left", padx=(0, 4))
        self.port_var = tk.StringVar(value=str(PORT))
        self.port_entry = ttk.Entry(toolbar, textvariable=self.port_var, width=7)
        self.port_entry.pack(side="left", padx=(0, 12))

        self.toggle_btn = ttk.Button(toolbar, text="Stop Listener", command=self.toggle_listener)
        self.toggle_btn.pack(side="left", padx=(0, 8))

        self.sim_btn = ttk.Button(toolbar, text="Simulate Attack Burst", command=self.run_simulation)
        self.sim_btn.pack(side="left", padx=(0, 14))

        ttk.Label(toolbar, text="Filter Severity:", font=("Sans", 9, "bold")).pack(side="left", padx=(0, 4))
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_combo = ttk.Combobox(
            toolbar,
            textvariable=self.filter_var,
            values=["ALL", "CRITICAL", "ALERT", "WARN", "INFO"],
            width=11,
            state="readonly",
        )
        self.filter_combo.pack(side="left", padx=(0, 10))
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_treeview())

        self.export_btn = ttk.Button(toolbar, text="Export Report (.md)", command=self.export_report)
        self.export_btn.pack(side="right", padx=(6, 0))

        self.load_btn = ttk.Button(toolbar, text="Load Audit Log", command=self.load_audit_log)
        self.load_btn.pack(side="right", padx=(6, 0))

        self.clear_btn = ttk.Button(toolbar, text="Clear Feed", command=self.clear_feed)
        self.clear_btn.pack(side="right")

        cards_frame = ttk.Frame(self, padding=(12, 4, 12, 10))
        cards_frame.pack(fill="x")

        card_specs = [
            ("Total Events", "0", "CardBlue.TLabel"),
            ("Critical (Brute-Force)", "0", "CardGreen.TLabel"),
            ("Security Alerts", "0", "CardGreen.TLabel"),
            ("Warnings", "0", "CardBlue.TLabel"),
            ("Unique Sources", "0", "CardBlue.TLabel"),
            ("Listener Status", "ACTIVE", "CardGreen.TLabel"),
        ]

        for idx, (title, init_val, style_name) in enumerate(card_specs):
            cards_frame.columnconfigure(idx, weight=1, uniform="kpi")
            card = ttk.Frame(cards_frame, style="Card.TFrame", padding=(10, 8))
            card.grid(row=0, column=idx, sticky="nsew", padx=4)

            ttk.Label(card, text=title.upper(), style="CardTitle.TLabel").pack(anchor="w")
            var = tk.StringVar(value=init_val)
            self.card_vars[title] = var
            val_lbl = ttk.Label(card, textvariable=var, style=style_name)
            val_lbl.pack(anchor="w", pady=(4, 0))
            self.card_labels[title] = val_lbl

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        feed_frame = ttk.Frame(paned)
        paned.add(feed_frame, weight=3)

        columns = ("id", "time", "level", "host", "app", "actor", "rule", "message")
        self.tree = ttk.Treeview(feed_frame, columns=columns, show="headings", selectmode="browse")

        col_defs = {
            "id": ("#", 50, "center"),
            "time": ("Timestamp", 150, "center"),
            "level": ("Severity", 95, "center"),
            "host": ("Hostname", 110, "w"),
            "app": ("App / Process", 105, "w"),
            "actor": ("Source / Actor IP", 135, "w"),
            "rule": ("Detection Rule", 230, "w"),
            "message": ("Parsed Message", 340, "w"),
        }

        for col, (heading, width, anchor) in col_defs.items():
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=width, anchor=anchor)

        self.tree.tag_configure("CRITICAL", background="#fce8e6", foreground="#a50e0e")
        self.tree.tag_configure("ALERT", background="#fef7e0", foreground="#b06000")
        self.tree.tag_configure("WARN", background="#fff8e1", foreground="#7a5900")
        self.tree.tag_configure("INFO", background="#ffffff", foreground="#202124")

        vsb = ttk.Scrollbar(feed_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(feed_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        feed_frame.rowconfigure(0, weight=1)
        feed_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_event_select)

        inspector_frame = ttk.LabelFrame(paned, text="Selected Event & RFC 5424 Telemetry Inspector", padding=6)
        paned.add(inspector_frame, weight=2)

        self.inspector_text = scrolledtext.ScrolledText(
            inspector_frame, wrap="word", font=("Monospace", 10), height=9, state="disabled"
        )
        self.inspector_text.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Ready.")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(10, 4))
        status_bar.pack(fill="x", side="bottom")

    def toggle_listener(self):
        if self.is_listening:
            self.stop_listener()
        else:
            self.start_listener()

    def start_listener(self):
        if self.is_listening:
            return
        host = self.host_var.get().strip() or HOST
        try:
            port = int(self.port_var.get().strip())
            if port < 1024 or port > 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter an unprivileged UDP port between 1024 and 65535.")
            return

        try:
            self.server = create_udp_server(
                host, port, self.engine, on_event_callback=self.event_queue.put
            )
        except OSError as exc:
            messagebox.showerror("Socket Bind Error", f"Could not bind to {host}:{port}\n{exc}")
            return

        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.is_listening = True
        self.toggle_btn.configure(text="Stop Listener")
        self.host_entry.configure(state="disabled")
        self.port_entry.configure(state="disabled")
        self.card_vars["Listener Status"].set("ACTIVE")
        self.card_labels["Listener Status"].configure(style="CardGreen.TLabel")
        self.status_var.set(f"Listening for UDP Syslog telemetry on {host}:{port}")

    def stop_listener(self):
        if not self.is_listening or not self.server:
            return
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.is_listening = False
        self.toggle_btn.configure(text="Start Listener")
        self.host_entry.configure(state="normal")
        self.port_entry.configure(state="normal")
        self.card_vars["Listener Status"].set("STOPPED")
        self.card_labels["Listener Status"].configure(style="CardGray.TLabel")
        self.status_var.set("Listener stopped.")

    def run_simulation(self):
        if not self.is_listening:
            self.start_listener()
        host = self.host_var.get().strip() or HOST
        port = int(self.port_var.get().strip())

        try:
            sent = send_test_burst(host, port)
            self.status_var.set(f"Sent {sent} simulated syslog datagrams to {host}:{port}.")
        except Exception as exc:
            messagebox.showerror("Simulation Error", f"Failed to send UDP datagrams:\n{exc}")

    def _poll_event_queue(self):
        updated = False
        try:
            while not self.event_queue.empty():
                ev = self.event_queue.get_nowait()
                key = f"ev_{ev['id']}"
                self.all_events.append(ev)
                self.event_map[key] = ev
                self._insert_event_row(ev)
                updated = True

            if updated:
                self._update_kpis()
        except Exception as exc:
            self.status_var.set(f"UI refresh warning: {exc}")
        finally:
            self.after(80, self._poll_event_queue)

    def _insert_event_row(self, ev: dict):
        active_filter = self.filter_var.get()
        if active_filter != "ALL" and ev["level"] != active_filter:
            return

        iid = f"ev_{ev['id']}"
        self.tree.insert(
            "",
            0,
            iid=iid,
            values=(
                ev["id"],
                ev["timestamp"],
                ev["level"],
                ev["hostname"],
                ev["app_name"],
                ev["actor_ip"],
                ev["rule"],
                ev["message"],
            ),
            tags=(ev["level"],),
        )
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        self.on_event_select()

    def _refresh_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for ev in self.all_events:
            self._insert_event_row(ev)

    def _update_kpis(self):
        stats = self.engine.get_summary()
        self.card_vars["Total Events"].set(f"{stats['total']:,}")

        crit = stats["CRITICAL"]
        self.card_vars["Critical (Brute-Force)"].set(f"{crit:,}")
        self.card_labels["Critical (Brute-Force)"].configure(
            style="CardRed.TLabel" if crit > 0 else "CardGreen.TLabel"
        )

        alerts = stats["ALERT"]
        self.card_vars["Security Alerts"].set(f"{alerts:,}")
        self.card_labels["Security Alerts"].configure(
            style="CardAmber.TLabel" if alerts > 0 else "CardGreen.TLabel"
        )

        self.card_vars["Warnings"].set(f"{stats['WARN']:,}")
        self.card_vars["Unique Sources"].set(f"{stats['unique_sources']:,}")

    def on_event_select(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        ev = self.event_map.get(str(selected[0]))
        if not ev:
            return

        detail = (
            f"================================================================================\n"
            f"EVENT #{ev['id']} | SEVERITY: {ev['level']} | RULE: {ev['rule']}\n"
            f"--------------------------------------------------------------------------------\n"
            f"Received Timestamp:  {ev['timestamp']}\n"
            f"Source / Actor IP:   {ev['actor_ip']} (UDP Transport: {ev['transport_ip']})\n"
            f"Syslog Format:       {ev['format']} (PRI: {ev.get('pri', 'N/A')}, Facility: {ev['facility']}, Syslog Sev: {ev['syslog_severity']})\n"
            f"Endpoint Hostname:   {ev['hostname']}\n"
            f"Application / Proc:  {ev['app_name']}\n"
            f"Structured Data:     {ev['structured_data']}\n"
            f"Brute-Force Window:  {ev['bf_attempts_in_window']} failed attempt(s) in last 60s\n"
            f"--------------------------------------------------------------------------------\n"
            f"Parsed Message:\n"
            f"  {ev['message']}\n\n"
            f"Raw Syslog Datagram:\n"
            f"  {ev['raw']}\n"
        )

        self.inspector_text.configure(state="normal")
        self.inspector_text.delete("1.0", "end")
        self.inspector_text.insert("1.0", detail)
        self.inspector_text.configure(state="disabled")

    def load_audit_log(self):
        if not os.path.isfile(AUDIT_FILE):
            messagebox.showinfo("No Audit File", "No saved audit log found yet at logs/security_audit.jsonl.")
            return
        self.clear_feed()
        loaded = 0
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                raw = data.get("raw") or data.get("message", "")
                rec = self.engine.process_raw_message(raw, data.get("transport_ip", "127.0.0.1"), persist=False)
                self.all_events.append(rec)
                self.event_map[f"ev_{rec['id']}"] = rec
                self._insert_event_row(rec)
                loaded += 1
        self._update_kpis()
        self.status_var.set(f"Replayed {loaded} event(s) from logs/security_audit.jsonl")

    def clear_feed(self):
        self.engine.reset()
        self.all_events.clear()
        self.event_map.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.inspector_text.configure(state="normal")
        self.inspector_text.delete("1.0", "end")
        self.inspector_text.configure(state="disabled")
        self._update_kpis()
        self.status_var.set("Event feed cleared.")

    def export_report(self):
        default_name = f"syslog_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        path = filedialog.asksaveasfilename(
            title="Export Incident Report",
            initialfile=default_name,
            defaultextension=".md",
            filetypes=[("Markdown Report", "*.md"), ("All Files", "*.*")],
        )
        if not path:
            return
        self.engine.export_markdown(path)
        self.status_var.set(f"Exported Markdown report to {os.path.basename(path)}")
        messagebox.showinfo("Report Exported", f"Incident report saved to:\n{path}")

    def _on_close(self):
        self.stop_listener()
        self.destroy()


if __name__ == "__main__":
    app = SyslogCollectorApp()
    app.mainloop()
