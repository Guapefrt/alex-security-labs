import subprocess
import threading
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime
from io import StringIO
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from pcap_explainer import (
    print_dns_activity,
    print_security_summary,
    print_tcp_conversations,
    read_dns_activity,
    read_protocols,
    read_tcp_conversations,
)


BASE_DIRECTORY = Path(__file__).resolve().parent
CAPTURE_DIRECTORY = BASE_DIRECTORY / "captures"


def get_capture_interfaces():
    """Return the local interfaces available through dumpcap."""

    result = subprocess.run(
        ["dumpcap", "-D"],
        capture_output=True,
        text=True,
        check=True,
    )

    interfaces = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line or ". " not in line:
            continue

        _, interface_description = line.split(". ", 1)
        interface_name = interface_description.split()[0]

        interfaces.append(
            {
                "name": interface_name,
                "description": interface_description,
            }
        )

    return interfaces


def format_endpoint(ip_address, port):
    """Format IPv4 and IPv6 endpoints clearly."""

    if ":" in ip_address:
        return f"[{ip_address}]:{port}"

    return f"{ip_address}:{port}"


def build_tab_reports(capture_file):
    """Build one report for each V5 tab."""

    protocols = read_protocols(capture_file)
    dns_activity = read_dns_activity(capture_file)
    tcp_conversations = read_tcp_conversations(capture_file)

    protocol_counts = Counter(protocols)

    encrypted_packets = (
        protocol_counts.get("TLS", 0)
        + protocol_counts.get("TLSv1.2", 0)
        + protocol_counts.get("TLSv1.3", 0)
        + protocol_counts.get("SSL", 0)
        + protocol_counts.get("SSH", 0)
    )

    http_packets = protocol_counts.get("HTTP", 0)

    complete_handshakes = sum(
        1
        for conversation in tcp_conversations
        if (
            conversation["syn"]
            and conversation["syn_ack"]
            and conversation["final_ack"]
        )
    )

    service_counts = Counter()

    for conversation in tcp_conversations:
        port_a = conversation["endpoint_a_port"]
        port_b = conversation["endpoint_b_port"]

        if 443 in (port_a, port_b):
            service_counts["HTTPS"] += 1
        elif 80 in (port_a, port_b):
            service_counts["HTTP"] += 1
        elif 22 in (port_a, port_b):
            service_counts["SSH"] += 1
        else:
            service_counts["Other TCP"] += 1

    summary = StringIO()

    with redirect_stdout(summary):
        print("PCAP EXPLAINER V5")
        print("=" * 64)
        print()
        print(f"Capture: {capture_file.name}")
        print(f"Packets analyzed: {len(protocols)}")
        print()
        print("CAPTURE OVERVIEW")
        print("-" * 64)
        print(f"{'Metric':<34} {'Value':>10}")
        print("-" * 64)
        print(f"{'Total packets':<34} {len(protocols):>10}")
        print(f"{'Unique DNS names':<34} {len(dns_activity):>10}")
        print(f"{'TCP conversations':<34} {len(tcp_conversations):>10}")
        print(f"{'Complete TCP handshakes':<34} {complete_handshakes:>10}")
        print(f"{'Encrypted-protocol packets':<34} {encrypted_packets:>10}")
        print(f"{'HTTP packets':<34} {http_packets:>10}")

        print()
        print("PROTOCOL COUNTS")
        print("-" * 64)

        for protocol, count in protocol_counts.most_common():
            print(f"{protocol:<34} {count:>10}")

        print()
        print("LIKELY TCP SERVICES")
        print("-" * 64)

        if service_counts:
            for service, count in service_counts.most_common():
                print(f"{service:<34} {count:>10}")
        else:
            print("No TCP services were identified.")

    dns = StringIO()

    with redirect_stdout(dns):
        print_dns_activity(dns_activity)

    tcp = StringIO()

    with redirect_stdout(tcp):
        print("=== TCP CONNECTIONS ===")

        if not tcp_conversations:
            print()
            print("No TCP conversations were found.")

        for conversation in tcp_conversations[:20]:
            port_a = conversation["endpoint_a_port"]
            port_b = conversation["endpoint_b_port"]

            if 443 in (port_a, port_b):
                service = "HTTPS"
            elif 80 in (port_a, port_b):
                service = "HTTP"
            elif 22 in (port_a, port_b):
                service = "SSH"
            else:
                service = "Unknown or application-specific"

            handshake_complete = (
                conversation["syn"]
                and conversation["syn_ack"]
                and conversation["final_ack"]
            )

            print()
            print("=" * 72)
            print(
                f"TCP Stream {conversation['stream_id']} | "
                f"Likely service: {service}"
            )
            print("-" * 72)

            print(
                "Endpoint A: "
                + format_endpoint(
                    conversation["endpoint_a_ip"],
                    conversation["endpoint_a_port"],
                )
            )

            print(
                "Endpoint B: "
                + format_endpoint(
                    conversation["endpoint_b_ip"],
                    conversation["endpoint_b_port"],
                )
            )

            print()
            print(f"Packets captured: {conversation['packets']}")
            print(f"Captured bytes: {conversation['bytes']}")
            print(f"TCP payload bytes: {conversation['payload_bytes']}")

            print()
            print("Handshake evidence:")
            print(
                "  SYN:     "
                + (
                    "detected"
                    if conversation["syn"]
                    else "not observed"
                )
            )
            print(
                "  SYN/ACK: "
                + (
                    "detected"
                    if conversation["syn_ack"]
                    else "not observed"
                )
            )
            print(
                "  ACK:     "
                + (
                    "detected"
                    if conversation["final_ack"]
                    else "not observed"
                )
            )

            print()

            if handshake_complete:
                print(
                    "Result: TCP connection establishment "
                    "was observed successfully."
                )
            else:
                print(
                    "Result: The complete handshake was not visible."
                )
                print(
                    "The connection may have existed before "
                    "the capture started."
                )

            print()

            if service == "HTTPS":
                print(
                    "Security context: encrypted web traffic is likely."
                )
                print(
                    "IP addresses, ports, timing, and traffic volume "
                    "remain visible."
                )

            elif service == "HTTP":
                print(
                    "Security context: HTTP does not provide TLS "
                    "encryption."
                )
                print(
                    "Application content may be visible in the capture."
                )

            elif service == "SSH":
                print(
                    "Security context: encrypted remote administration "
                    "traffic is likely."
                )

    security = StringIO()

    with redirect_stdout(security):
        print_security_summary(
            protocol_counts,
            dns_activity,
        )

        print()
        print("V5 SECURITY OBSERVATIONS")
        print("-" * 64)

        if encrypted_packets:
            print(
                "[OK] Encrypted traffic was detected: "
                f"{encrypted_packets} packets."
            )
        else:
            print(
                "[INFO] No packets were classified as TLS, SSL, or SSH."
            )

        if dns_activity:
            print(
                "[INFO] DNS visibility exposed "
                f"{len(dns_activity)} unique requested names."
            )

        if complete_handshakes:
            print(
                "[OK] Complete TCP connection establishment was "
                f"observed for {complete_handshakes} conversations."
            )

        if http_packets:
            print(
                "[WARNING] Unencrypted HTTP traffic was observed: "
                f"{http_packets} packets."
            )
            print(
                "HTTP application content may be visible "
                "to a network observer."
            )
        else:
            print(
                "[OK] No traffic was classified as plaintext HTTP."
            )

        print()
        print(
            "Important: these are evidence-based observations, "
            "not proof of malicious activity."
        )

    return {
        "summary": summary.getvalue(),
        "dns": dns.getvalue(),
        "tcp": tcp.getvalue(),
        "security": security.getvalue(),
    }


class PcapExplainerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Explainer")
        self.root.geometry("1000x720")
        self.root.minsize(760, 560)

        self.interfaces = []
        self.capture_running = False

        CAPTURE_DIRECTORY.mkdir(exist_ok=True)

        self.create_widgets()
        self.load_interfaces()

    def create_widgets(self):
        main_frame = ttk.Frame(
            self.root,
            padding=16,
        )
        main_frame.pack(
            fill="both",
            expand=True,
        )

        title_label = ttk.Label(
            main_frame,
            text="PCAP Explainer",
            font=("Sans", 20, "bold"),
        )
        title_label.pack(anchor="w")

        subtitle_label = ttk.Label(
            main_frame,
            text=(
                "Capture traffic from a selected interface and translate "
                "packet data into a human-readable security report."
            ),
        )
        subtitle_label.pack(
            anchor="w",
            pady=(0, 18),
        )

        settings_frame = ttk.LabelFrame(
            main_frame,
            text="Capture settings",
            padding=12,
        )
        settings_frame.pack(fill="x")

        interface_label = ttk.Label(
            settings_frame,
            text="Network interface:",
        )
        interface_label.grid(
            row=0,
            column=0,
            sticky="w",
            padx=(0, 10),
            pady=6,
        )

        self.interface_variable = tk.StringVar()

        self.interface_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.interface_variable,
            state="readonly",
            width=45,
        )
        self.interface_combo.grid(
            row=0,
            column=1,
            sticky="ew",
            pady=6,
        )

        refresh_button = ttk.Button(
            settings_frame,
            text="Refresh",
            command=self.load_interfaces,
        )
        refresh_button.grid(
            row=0,
            column=2,
            padx=(10, 0),
            pady=6,
        )

        duration_label = ttk.Label(
            settings_frame,
            text="Duration:",
        )
        duration_label.grid(
            row=1,
            column=0,
            sticky="w",
            padx=(0, 10),
            pady=6,
        )

        self.duration_variable = tk.IntVar(value=30)

        self.duration_spinbox = ttk.Spinbox(
            settings_frame,
            from_=5,
            to=3600,
            increment=5,
            textvariable=self.duration_variable,
            width=10,
        )
        self.duration_spinbox.grid(
            row=1,
            column=1,
            sticky="w",
            pady=6,
        )

        seconds_label = ttk.Label(
            settings_frame,
            text="seconds (5 to 3600)",
        )
        seconds_label.grid(
            row=1,
            column=1,
            sticky="w",
            padx=(90, 0),
            pady=6,
        )

        settings_frame.columnconfigure(
            1,
            weight=1,
        )

        controls_frame = ttk.Frame(main_frame)
        controls_frame.pack(
            fill="x",
            pady=14,
        )

        self.start_button = ttk.Button(
            controls_frame,
            text="Start Capture",
            command=self.start_capture,
        )
        self.start_button.pack(side="left")

        clear_button = ttk.Button(
            controls_frame,
            text="Clear Reports",
            command=self.clear_reports,
        )
        clear_button.pack(
            side="left",
            padx=(10, 0),
        )

        open_folder_button = ttk.Button(
            controls_frame,
            text="Open Captures Folder",
            command=self.open_capture_folder,
        )
        open_folder_button.pack(
            side="left",
            padx=(10, 0),
        )

        self.progress_bar = ttk.Progressbar(
            controls_frame,
            mode="indeterminate",
            length=180,
        )
        self.progress_bar.pack(side="right")

        self.status_variable = tk.StringVar(
            value="Ready. Select an interface and capture duration."
        )

        status_label = ttk.Label(
            main_frame,
            textvariable=self.status_variable,
        )
        status_label.pack(
            anchor="w",
            pady=(0, 8),
        )

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(
            fill="both",
            expand=True,
        )

        self.summary_tab = ttk.Frame(
            self.notebook,
            padding=10,
        )
        self.dns_tab = ttk.Frame(
            self.notebook,
            padding=10,
        )
        self.tcp_tab = ttk.Frame(
            self.notebook,
            padding=10,
        )
        self.security_tab = ttk.Frame(
            self.notebook,
            padding=10,
        )

        self.notebook.add(
            self.summary_tab,
            text="Summary",
        )
        self.notebook.add(
            self.dns_tab,
            text="DNS",
        )
        self.notebook.add(
            self.tcp_tab,
            text="TCP Connections",
        )
        self.notebook.add(
            self.security_tab,
            text="Security",
        )

        self.summary_text = self.create_scrolled_text(
            self.summary_tab
        )
        self.dns_text = self.create_scrolled_text(
            self.dns_tab
        )
        self.tcp_text = self.create_scrolled_text(
            self.tcp_tab
        )
        self.security_text = self.create_scrolled_text(
            self.security_tab
        )

        self.summary_text.insert(
            tk.END,
            (
                "PCAP EXPLAINER V5\n\n"
                "Select a network interface and duration, "
                "then press Start Capture.\n\n"
                "Suggested interfaces:\n"
                "- wlp42s0: normal Wi-Fi traffic\n"
                "- tailscale0: Tailscale and SSH traffic\n"
                "- lo: local laptop traffic\n"
            ),
        )

    def create_scrolled_text(self, parent):
        """Create a text area with a vertical scrollbar."""

        container = ttk.Frame(parent)
        container.pack(
            fill="both",
            expand=True,
        )

        text_widget = tk.Text(
            container,
            wrap="word",
            font=("Monospace", 10),
            padx=10,
            pady=10,
        )

        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=text_widget.yview,
        )

        text_widget.configure(
            yscrollcommand=scrollbar.set
        )

        text_widget.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        return text_widget

    def load_interfaces(self):
        try:
            self.interfaces = get_capture_interfaces()

        except FileNotFoundError:
            messagebox.showerror(
                "dumpcap not found",
                "dumpcap is not installed or is not available in PATH.",
            )
            return

        except subprocess.CalledProcessError as error:
            messagebox.showerror(
                "Interface error",
                f"Could not list capture interfaces.\n\n{error.stderr}",
            )
            return

        descriptions = [
            interface["description"]
            for interface in self.interfaces
        ]

        self.interface_combo["values"] = descriptions

        preferred_interfaces = [
            "wlp42s0",
            "tailscale0",
            "enp43s0",
            "any",
        ]

        selected_index = 0

        for preferred_name in preferred_interfaces:
            match_found = False

            for index, interface in enumerate(self.interfaces):
                if interface["name"] == preferred_name:
                    selected_index = index
                    match_found = True
                    break

            if match_found:
                break

        if descriptions:
            self.interface_combo.current(selected_index)
            self.status_variable.set(
                f"Found {len(descriptions)} capture interfaces."
            )
        else:
            self.status_variable.set(
                "No capture interfaces were found."
            )

    def get_selected_interface(self):
        selected_description = self.interface_variable.get()

        for interface in self.interfaces:
            if interface["description"] == selected_description:
                return interface["name"]

        return None

    def validate_duration(self):
        try:
            duration = int(self.duration_variable.get())

        except (ValueError, tk.TclError):
            raise ValueError(
                "Capture duration must be a whole number."
            )

        if duration < 5 or duration > 3600:
            raise ValueError(
                "Capture duration must be between 5 and 3600 seconds."
            )

        return duration

    def start_capture(self):
        if self.capture_running:
            return

        interface = self.get_selected_interface()

        if not interface:
            messagebox.showwarning(
                "No interface",
                "Select a capture interface first.",
            )
            return

        try:
            duration = self.validate_duration()

        except ValueError as error:
            messagebox.showwarning(
                "Invalid duration",
                str(error),
            )
            return

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        capture_file = (
            CAPTURE_DIRECTORY
            / f"capture_{interface}_{timestamp}.pcapng"
        )

        self.capture_running = True
        self.start_button.configure(state="disabled")
        self.interface_combo.configure(state="disabled")
        self.duration_spinbox.configure(state="disabled")
        self.progress_bar.start(10)

        self.status_variable.set(
            f"Capturing {interface} for {duration} seconds..."
        )

        self.clear_reports()

        self.summary_text.insert(
            tk.END,
            (
                "Capture started.\n\n"
                f"Interface: {interface}\n"
                f"Duration: {duration} seconds\n"
                f"Output: {capture_file}\n\n"
                "Generate traffic while capture is running.\n"
            ),
        )

        worker = threading.Thread(
            target=self.capture_and_analyze,
            args=(
                interface,
                duration,
                capture_file,
            ),
            daemon=True,
        )
        worker.start()

    def capture_and_analyze(
        self,
        interface,
        duration,
        capture_file,
    ):
        command = [
            "dumpcap",
            "-i",
            interface,
            "-a",
            f"duration:{duration}",
            "-w",
            str(capture_file),
        ]

        try:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
            )

            reports = build_tab_reports(capture_file)

            self.root.after(
                0,
                self.capture_finished,
                capture_file,
                reports,
            )

        except FileNotFoundError:
            self.root.after(
                0,
                self.capture_failed,
                "dumpcap is not installed or unavailable in PATH.",
            )

        except subprocess.CalledProcessError as error:
            error_message = (
                error.stderr.strip()
                or error.stdout.strip()
                or "dumpcap returned an unknown error."
            )

            self.root.after(
                0,
                self.capture_failed,
                error_message,
            )

        except Exception as error:
            self.root.after(
                0,
                self.capture_failed,
                str(error),
            )

    def capture_finished(
        self,
        capture_file,
        reports,
    ):
        self.capture_running = False
        self.start_button.configure(state="normal")
        self.interface_combo.configure(state="readonly")
        self.duration_spinbox.configure(state="normal")
        self.progress_bar.stop()

        self.display_tab_reports(reports)

        self.status_variable.set(
            f"Capture and analysis complete: {capture_file.name}"
        )

        messagebox.showinfo(
            "Analysis complete",
            f"Capture saved to:\n{capture_file}",
        )

    def capture_failed(self, error_message):
        self.capture_running = False
        self.start_button.configure(state="normal")
        self.interface_combo.configure(state="readonly")
        self.duration_spinbox.configure(state="normal")
        self.progress_bar.stop()

        self.status_variable.set("Capture failed.")

        messagebox.showerror(
            "Capture failed",
            error_message,
        )

    def display_tab_reports(self, reports):
        """Display the four V5 reports."""

        text_widgets = {
            "summary": self.summary_text,
            "dns": self.dns_text,
            "tcp": self.tcp_text,
            "security": self.security_text,
        }

        for report_name, widget in text_widgets.items():
            widget.delete(
                "1.0",
                tk.END,
            )
            widget.insert(
                tk.END,
                reports.get(report_name, ""),
            )
            widget.see("1.0")

        self.notebook.select(self.summary_tab)

    def clear_reports(self):
        """Clear all report tabs."""

        for widget in (
            self.summary_text,
            self.dns_text,
            self.tcp_text,
            self.security_text,
        ):
            widget.delete(
                "1.0",
                tk.END,
            )

    def open_capture_folder(self):
        subprocess.Popen(
            [
                "xdg-open",
                str(CAPTURE_DIRECTORY),
            ]
        )


def main():
    root = tk.Tk()
    PcapExplainerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()