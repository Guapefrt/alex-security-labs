# PCAP Explainer

A Python desktop application that captures live network traffic, parses packet telemetry via `dumpcap` and `tshark`, reconstructs DNS and TCP activity, validates 3-way handshakes, and translates raw packet data into human-readable security context.

Built as part of an active home lab portfolio on **Arch Linux**, focusing on network visibility, endpoint vs. network telemetry analysis, and technical sales engineering demonstrations.

## Architecture & Workflow

    [ Network Interface ]
             ↓ (dumpcap)
      .pcapng Capture
             ↓ (tshark)
      Parsed Telemetry
             ↓ (Python Parser)
    Human-Readable Report
             ↓
      [ GUI (Tkinter) ]
       ├── Summary (Overview, Protocol Counts & Likely Services)
       ├── DNS (Queries, Responses, IPv4/IPv6 Answers & CNAME Aliases)
       ├── TCP Connections (Stream Reconstitution & 3-Way Handshake Validation)
       └── Security (Evidence-Based Observations & Cleartext Detection)

## Key Features

- **Live Capture Control:** Select active network interfaces (`wlp42s0`, `tailscale0`, `enp43s0`, `lo`), configure capture duration (5–3600 seconds), and run `dumpcap` in a background thread so the UI stays responsive.
- **TCP Stream Reconstitution:** Tracks IPv4 and `[IPv6]:port` endpoints, calculates packet/byte/payload volume, identifies likely services (HTTPS, HTTP, SSH, DNS), and verifies `SYN` → `SYN/ACK` → `ACK` handshakes.
- **DNS Visibility:** Parses `A`, `AAAA`, `CNAME`, `PTR`, `MX`, `TXT`, `SRV`, and `HTTPS` records, mapping requested domains to resolved IP addresses.
- **Evidence-Based Security Context:** Highlights encrypted traffic vs. plaintext HTTP risks without making automated malware verdicts, keeping observations grounded in packet evidence.

## Tech Stack & Environment

- **OS:** Arch Linux (Linux Zen Kernel, KDE Plasma)
- **Language:** Python 3 (`tkinter`, `subprocess`, `threading`)
- **Packet Capture & Analysis:** Wireshark CLI (`dumpcap`, `tshark`)
- **Version Control:** Git & GitHub CLI (`gh`)

## Getting Started

### Prerequisites

Install `wireshark-cli` (which provides `dumpcap` and `tshark`) and add your user to the `wireshark` group to allow non-root packet capture:

    sudo pacman -S wireshark-cli
    sudo usermod -aG wireshark $USER

### Running the Application

    git clone https://github.com/Guapefrt/alex-security-labs.git
    cd alex-security-labs/03-pcap-explainer
    python pcap_app.py

## Purpose & Career Goal

This project bridges the gap between raw low-level network telemetry and clear technical communication—demonstrating practical skills in Linux networking, Python automation, and technical presales / solutions engineering.

## License

This project is available under the [MIT License](LICENSE).
