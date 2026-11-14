import os
import re
import subprocess
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from pcap_explainer import build_tab_reports


class PcapExplainerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Explainer V6 — Network Telemetry & Security Context")
        self.geometry("1220x820")
        self.minsize(980, 680)

        self.captures_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")
        os.makedirs(self.captures_dir, exist_ok=True)

        self.current_pcap: str | None = None
        self.is_capturing = False
        self.stream_cache: dict[str, str] = {}
        self.card_vars: dict[str, tk.StringVar] = {}
        self.card_value_labels: dict[str, ttk.Label] = {}

        self._configure_styles()
        self._build_ui()
        self._populate_interfaces()

    def _configure_styles(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("CardTitle.TLabel", background="#ffffff", foreground="#5f6368", font=("Sans", 9, "bold"))
        style.configure("CardValue.TLabel", background="#ffffff", foreground="#1a73e8", font=("Sans", 18, "bold"))
        style.configure("CardSafe.TLabel", background="#ffffff", foreground="#137333", font=("Sans", 18, "bold"))
        style.configure("CardWarn.TLabel", background="#ffffff", foreground="#c5221f", font=("Sans", 18, "bold"))
        style.configure("Treeview", rowheight=26, font=("Monospace", 9))
        style.configure("Treeview.Heading", font=("Sans", 9, "bold"))

    def _build_ui(self):
        # Top Control Toolbar
        toolbar = ttk.Frame(self, padding=(12, 10))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Interface:", font=("Sans", 9, "bold")).pack(side="left", padx=(0, 5))
        self.iface_var = tk.StringVar(value="wlp42s0")
        self.iface_combo = ttk.Combobox(toolbar, textvariable=self.iface_var, width=16, state="readonly")
        self.iface_combo.pack(side="left", padx=(0, 12))

        ttk.Label(toolbar, text="Duration (s):", font=("Sans", 9, "bold")).pack(side="left", padx=(0, 5))
        self.duration_var = tk.StringVar(value="15")
        self.duration_spin = ttk.Spinbox(toolbar, from_=5, to=3600, textvariable=self.duration_var, width=7)
        self.duration_spin.pack(side="left", padx=(0, 14))

        self.capture_btn = ttk.Button(toolbar, text="Start Capture", command=self.start_capture)
        self.capture_btn.pack(side="left", padx=(0, 8))

        self.open_btn = ttk.Button(toolbar, text="Open PCAP", command=self.open_pcap_dialog)
        self.open_btn.pack(side="left", padx=(0, 8))

        self.wireshark_btn = ttk.Button(
            toolbar, text="Open in Wireshark", command=self.open_in_wireshark, state="disabled"
        )
        self.wireshark_btn.pack(side="right")

        # V6 KPI Summary Cards Row
        cards_frame = ttk.Frame(self, padding=(12, 4, 12, 10))
        cards_frame.pack(fill="x")

        card_titles = [
            "Total Packets",
            "Unique DNS Names",
            "TCP Conversations",
            "Complete Handshakes",
            "Encrypted Packets",
            "HTTP Packets",
        ]

        for idx, title in enumerate(card_titles):
            cards_frame.columnconfigure(idx, weight=1, uniform="cards")
            card = ttk.Frame(cards_frame, style="Card.TFrame", padding=(10, 8))
            card.grid(row=0, column=idx, sticky="nsew", padx=4)

            lbl_title = ttk.Label(card, text=title.upper(), style="CardTitle.TLabel")
            lbl_title.pack(anchor="w")

            var = tk.StringVar(value="0")
            self.card_vars[title] = var
            lbl_val = ttk.Label(card, textvariable=var, style="CardValue.TLabel")
            lbl_val.pack(anchor="w", pady=(4, 0))
            self.card_value_labels[title] = lbl_val

        # Main Notebook Tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Tab 1: Summary
        summary_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(summary_tab, text="Summary")
        self.summary_text = scrolledtext.ScrolledText(summary_tab, wrap="word", font=("Monospace", 10), state="disabled")
        self.summary_text.pack(fill="both", expand=True)

        # Tab 2: DNS
        dns_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(dns_tab, text="DNS")
        self.dns_text = scrolledtext.ScrolledText(dns_tab, wrap="word", font=("Monospace", 10), state="disabled")
        self.dns_text.pack(fill="both", expand=True)

        # Tab 3: TCP Connections (Interactive Treeview + Stream Inspector)
        tcp_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tcp_tab, text="TCP Connections")

        paned = ttk.PanedWindow(tcp_tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        tree_container = ttk.Frame(paned)
        paned.add(tree_container, weight=3)

        columns = ("stream", "src", "dst", "service", "packets", "bytes", "handshake")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="browse")

        headings = {
            "stream": ("Stream", 75, "center"),
            "src": ("Endpoint A (Source)", 260, "w"),
            "dst": ("Endpoint B (Destination)", 260, "w"),
            "service": ("Likely Service", 120, "center"),
            "packets": ("Packets", 90, "e"),
            "bytes": ("Bytes", 110, "e"),
            "handshake": ("3-Way Handshake", 140, "center"),
        }

        for col, (text, width, anchor) in headings.items():
            self.tree.heading(col, text=text, command=lambda c=col: self._sort_treeview(c, False))
            self.tree.column(col, width=width, anchor=anchor)

        # Row color tags
        self.tree.tag_configure("complete", background="#e6f4ea", foreground="#137333")
        self.tree.tag_configure("http", background="#fef7e0", foreground="#b06000")
        self.tree.tag_configure("incomplete", background="#f8f9fa", foreground="#3c4043")

        tree_vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        tree_hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_vsb.set, xscrollcommand=tree_hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_vsb.grid(row=0, column=1, sticky="ns")
        tree_hsb.grid(row=1, column=0, sticky="ew")
        tree_container.rowconfigure(0, weight=1)
        tree_container.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_tcp_select)

        inspector_frame = ttk.LabelFrame(paned, text="Selected TCP Stream Inspector", padding=6)
        paned.add(inspector_frame, weight=2)

        self.tcp_detail_text = scrolledtext.ScrolledText(
            inspector_frame, wrap="word", font=("Monospace", 10), height=10, state="disabled"
        )
        self.tcp_detail_text.pack(fill="both", expand=True)

        # Tab 4: Security
        sec_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(sec_tab, text="Security")
        self.security_text = scrolledtext.ScrolledText(sec_tab, wrap="word", font=("Monospace", 10), state="disabled")
        self.security_text.pack(fill="both", expand=True)

        # Bottom Status Bar
        self.status_var = tk.StringVar(value="Ready. Select an interface to capture or open an existing PCAP/PCAPNG file.")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(10, 4))
        status_bar.pack(fill="x", side="bottom")

    def _populate_interfaces(self):
        interfaces = []
        try:
            proc = subprocess.run(["dumpcap", "-D"], capture_output=True, text=True, check=False)
            for line in proc.stdout.splitlines():
                match = re.match(r"^\d+\.\s+([^\s(]+)", line.strip())
                if match:
                    interfaces.append(match.group(1))
        except Exception:
            pass

        if not interfaces:
            interfaces = ["wlp42s0", "tailscale0", "enp43s0", "lo"]

        self.iface_combo["values"] = interfaces
        if "wlp42s0" in interfaces:
            self.iface_var.set("wlp42s0")
        else:
            self.iface_var.set(interfaces[0])

    def _set_text_widget(self, widget: scrolledtext.ScrolledText, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def start_capture(self):
        if self.is_capturing:
            return

        iface = self.iface_var.get().strip()
        try:
            duration = int(self.duration_var.get().strip())
            if duration < 1 or duration > 3600:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Duration", "Please enter a capture duration between 1 and 3600 seconds.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(self.captures_dir, f"capture_{iface}_{timestamp}.pcapng")

        self.is_capturing = True
        self.capture_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        self.status_var.set(f"Capturing on {iface} for {duration}s...")

        def worker():
            cmd = ["dumpcap", "-i", iface, "-a", f"duration:{duration}", "-w", out_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.after(0, lambda: self._on_capture_finished(proc.returncode, proc.stderr, out_path))

        threading.Thread(target=worker, daemon=True).start()

    def _on_capture_finished(self, returncode: int, stderr: str, out_path: str):
        self.is_capturing = False
        self.capture_btn.configure(state="normal")
        self.open_btn.configure(state="normal")

        if returncode != 0 or not os.path.isfile(out_path):
            self.status_var.set("Capture failed.")
            messagebox.showerror("Capture Error", stderr.strip() or "dumpcap failed to capture packets.")
            return

        self.load_pcap(out_path)

    def open_pcap_dialog(self):
        path = filedialog.askopenfilename(
            title="Select PCAP / PCAPNG File",
            initialdir=self.captures_dir,
            filetypes=[("Packet Captures", "*.pcapng *.pcap"), ("All Files", "*.*")],
        )
        if path:
            self.load_pcap(path)

    def load_pcap(self, pcap_path: str):
        self.current_pcap = pcap_path
        self.status_var.set(f"Analyzing {os.path.basename(pcap_path)}...")

        def worker():
            try:
                reports = build_tab_reports(pcap_path)
                self.after(0, lambda: self.display_tab_reports(reports))
            except Exception as exc:
                self.after(0, lambda: self._on_analysis_error(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_analysis_error(self, err: str):
        self.status_var.set("Analysis error.")
        messagebox.showerror("Analysis Error", err)

    def display_tab_reports(self, reports: dict):
        metrics = reports.get("summary_metrics", {})

        self.card_vars["Total Packets"].set(f"{metrics.get('total_packets', 0):,}")
        self.card_vars["Unique DNS Names"].set(f"{metrics.get('unique_dns', 0):,}")
        self.card_vars["TCP Conversations"].set(f"{metrics.get('tcp_conversations', 0):,}")
        self.card_vars["Complete Handshakes"].set(f"{metrics.get('complete_handshakes', 0):,}")
        self.card_vars["Encrypted Packets"].set(f"{metrics.get('encrypted_packets', 0):,}")

        http_count = metrics.get("http_packets", 0)
        self.card_vars["HTTP Packets"].set(f"{http_count:,}")
        if http_count == 0:
            self.card_value_labels["HTTP Packets"].configure(style="CardSafe.TLabel")
        else:
            self.card_value_labels["HTTP Packets"].configure(style="CardWarn.TLabel")

        self._set_text_widget(self.summary_text, reports.get("summary", ""))
        self._set_text_widget(self.dns_text, reports.get("dns", ""))
        self._set_text_widget(self.security_text, reports.get("security", ""))

        # Populate TCP Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.stream_cache.clear()

        tcp_streams = reports.get("tcp_streams", [])
        for stream in tcp_streams:
            sid = str(stream["stream_id"])
            hs_complete = stream.get("handshake_complete", False)
            service = stream.get("service", "Unknown / App")
            hs_label = "Complete" if hs_complete else "Partial"

            if service == "HTTP":
                tag = "http"
            elif hs_complete:
                tag = "complete"
            else:
                tag = "incomplete"

            self.stream_cache[sid] = stream.get("details", "")
            self.tree.insert(
                "",
                "end",
                iid=sid,
                values=(
                    sid,
                    stream.get("src", ""),
                    stream.get("dst", ""),
                    service,
                    stream.get("packets", 0),
                    stream.get("bytes", 0),
                    hs_label,
                ),
                tags=(tag,),
            )

        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])
            self.on_tcp_select()
        else:
            self._set_text_widget(self.tcp_detail_text, "No TCP streams observed in this capture.")

        self.wireshark_btn.configure(state="normal")
        self.status_var.set(
            f"Loaded: {os.path.basename(self.current_pcap)} | "
            f"{metrics.get('total_packets', 0):,} packets | "
            f"{metrics.get('tcp_conversations', 0)} TCP streams"
        )

    def on_tcp_select(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        sid = selected[0]
        detail_text = self.stream_cache.get(sid, "No details available for this stream.")
        self._set_text_widget(self.tcp_detail_text, detail_text)

    def _sort_treeview(self, col: str, reverse: bool):
        numeric_cols = {"stream", "packets", "bytes"}
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]

        if col in numeric_cols:
            rows.sort(key=lambda t: int(str(t[0]).replace(",", "")), reverse=reverse)
        else:
            rows.sort(key=lambda t: str(t[0]).lower(), reverse=reverse)

        for idx, (_, k) in enumerate(rows):
            self.tree.move(k, "", idx)

        self.tree.heading(col, command=lambda: self._sort_treeview(col, not reverse))

    def open_in_wireshark(self):
        if not self.current_pcap or not os.path.isfile(self.current_pcap):
            messagebox.showwarning("No Capture", "Please capture or open a PCAP file first.")
            return
        try:
            subprocess.Popen(["wireshark", self.current_pcap])
        except FileNotFoundError:
            messagebox.showerror("Wireshark Not Found", "Could not find the 'wireshark' executable in PATH.")


if __name__ == "__main__":
    app = PcapExplainerApp()
    app.mainloop()
