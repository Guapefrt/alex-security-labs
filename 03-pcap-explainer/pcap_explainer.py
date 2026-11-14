import os
import re
import subprocess
from collections import defaultdict


DNS_TYPE_MAP = {
    "1": ("A", "The endpoint asked for an IPv4 address."),
    "2": ("NS", "The endpoint asked for authoritative name server records."),
    "5": ("CNAME", "The endpoint asked for a canonical domain alias."),
    "12": ("PTR", "The endpoint asked for a reverse DNS hostname lookup."),
    "15": ("MX", "The endpoint asked for mail exchange server records."),
    "16": ("TXT", "The endpoint asked for text metadata records."),
    "28": ("AAAA", "The endpoint asked for an IPv6 address."),
    "33": ("SRV", "The endpoint asked for service location records."),
    "65": ("HTTPS", "The endpoint asked for HTTPS service-binding information."),
}


def _split_values(raw_val: str) -> list[str]:
    if not raw_val:
        return []
    return [item.strip() for item in raw_val.split(",") if item.strip()]


def _format_endpoint(ipv4: str, ipv6: str, port: str) -> str:
    if ipv4:
        return f"{ipv4}:{port}" if port else ipv4
    if ipv6:
        return f"[{ipv6}]:{port}" if port else f"[{ipv6}]"
    return f"unknown:{port}" if port else "unknown"


def _classify_service(ports: set[str], protocols: set[str]) -> str:
    upper_protos = {p.upper() for p in protocols}
    if "HTTP" in upper_protos or "80" in ports or "8080" in ports:
        return "HTTP"
    if "TLS" in upper_protos or "SSL" in upper_protos or "443" in ports or "8443" in ports:
        return "HTTPS"
    if "SSH" in upper_protos or "22" in ports:
        return "SSH"
    if "DNS" in upper_protos or "53" in ports:
        return "DNS"
    return "Unknown / App"


def build_tab_reports(pcap_path: str) -> dict:
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    fields = [
        "frame.number",
        "frame.len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.len",
        "dns.qry.name",
        "dns.qry.type",
        "dns.flags.response",
        "dns.a",
        "dns.aaaa",
        "dns.cname",
        "dns.ptr.domain_name",
    ]

    cmd = [
        "tshark",
        "-r",
        pcap_path,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
    ]
    for field in fields:
        cmd.extend(["-e", field])

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        err_msg = proc.stderr.strip() or "tshark failed to read the capture file."
        raise RuntimeError(err_msg)

    total_packets = 0
    encrypted_packets = 0
    http_packets = 0
    local_discovery_packets = 0
    nat_traversal_packets = 0
    protocol_counts = defaultdict(int)

    dns_records = defaultdict(
        lambda: {
            "types": set(),
            "queries": 0,
            "responses": 0,
            "ipv4": set(),
            "ipv6": set(),
            "aliases": set(),
        }
    )

    streams = {}

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        while len(cols) < len(fields):
            cols.append("")

        (
            _frame_num,
            frame_len_raw,
            protocols_raw,
            ip_src,
            ip_dst,
            ipv6_src,
            ipv6_dst,
            tcp_stream_raw,
            tcp_srcport,
            tcp_dstport,
            syn_raw,
            ack_raw,
            tcp_len_raw,
            dns_qry_name,
            dns_qry_type,
            dns_resp_flag,
            dns_a,
            dns_aaaa,
            dns_cname,
            dns_ptr,
        ) = cols[: len(fields)]

        total_packets += 1
        frame_len = int(frame_len_raw) if frame_len_raw.isdigit() else 0

        proto_chain = [p.lower() for p in protocols_raw.split(":") if p]
        proto_set = set(proto_chain)

        if proto_chain:
            top_proto = proto_chain[-1].upper()
            protocol_counts[top_proto] += 1

        if {"tls", "ssl", "ssh", "wg", "quic"} & proto_set:
            encrypted_packets += 1
        if "http" in proto_set and "tls" not in proto_set:
            http_packets += 1
        if {"arp", "ssdp", "mdns", "llmnr", "nbns"} & proto_set:
            local_discovery_packets += 1
        if {"stun", "turn"} & proto_set:
            nat_traversal_packets += 1

        # DNS parsing
        q_names = _split_values(dns_qry_name)
        q_types = _split_values(dns_qry_type)
        is_response = dns_resp_flag.lower() in ("1", "true")

        if q_names:
            for idx, domain in enumerate(q_names):
                entry = dns_records[domain]
                if is_response:
                    entry["responses"] += 1
                else:
                    entry["queries"] += 1

                q_code = q_types[idx] if idx < len(q_types) else (q_types[0] if q_types else "")
                if q_code:
                    q_label, _ = DNS_TYPE_MAP.get(q_code, (f"TYPE-{q_code}", ""))
                    entry["types"].add((q_code, q_label))

                for v4 in _split_values(dns_a):
                    entry["ipv4"].add(v4)
                for v6 in _split_values(dns_aaaa):
                    entry["ipv6"].add(v6)
                for cname in _split_values(dns_cname):
                    entry["aliases"].add(cname)
                for ptr in _split_values(dns_ptr):
                    entry["aliases"].add(ptr)

        # TCP stream parsing
        if tcp_stream_raw != "":
            for s_id_str in _split_values(tcp_stream_raw):
                if not s_id_str.isdigit():
                    continue
                sid = int(s_id_str)
                src_ep = _format_endpoint(
                    _split_values(ip_src)[0] if ip_src else "",
                    _split_values(ipv6_src)[0] if ipv6_src else "",
                    _split_values(tcp_srcport)[0] if tcp_srcport else "",
                )
                dst_ep = _format_endpoint(
                    _split_values(ip_dst)[0] if ip_dst else "",
                    _split_values(ipv6_dst)[0] if ipv6_dst else "",
                    _split_values(tcp_dstport)[0] if tcp_dstport else "",
                )

                if sid not in streams:
                    streams[sid] = {
                        "stream_id": sid,
                        "src": src_ep,
                        "dst": dst_ep,
                        "ports": set(),
                        "protocols": set(),
                        "packets": 0,
                        "bytes": 0,
                        "payload_bytes": 0,
                        "syn": False,
                        "syn_ack": False,
                        "ack": False,
                    }

                st = streams[sid]
                st["packets"] += 1
                st["bytes"] += frame_len
                if tcp_len_raw.isdigit():
                    st["payload_bytes"] += int(tcp_len_raw)
                if tcp_srcport:
                    st["ports"].add(_split_values(tcp_srcport)[0])
                if tcp_dstport:
                    st["ports"].add(_split_values(tcp_dstport)[0])
                st["protocols"].update(proto_set)

                syn_on = syn_raw.lower() in ("1", "true")
                ack_on = ack_raw.lower() in ("1", "true")
                if syn_on and not ack_on:
                    st["syn"] = True
                elif syn_on and ack_on:
                    st["syn_ack"] = True
                elif not syn_on and ack_on:
                    st["ack"] = True

    # Build structured TCP stream objects sorted by packet volume
    tcp_streams_list = []
    tcp_text_blocks = []
    complete_handshakes = 0

    for sid, st in sorted(streams.items(), key=lambda item: item[1]["packets"], reverse=True):
        hs_complete = st["syn"] and st["syn_ack"] and st["ack"]
        if hs_complete:
            complete_handshakes += 1

        service = _classify_service(st["ports"], st["protocols"])
        syn_txt = "detected" if st["syn"] else "not observed"
        synack_txt = "detected" if st["syn_ack"] else "not observed"
        ack_txt = "detected" if st["ack"] else "not observed"

        if hs_complete:
            hs_result = "TCP connection establishment was observed successfully."
        else:
            hs_result = (
                "The complete handshake was not visible.\n"
                "The connection may have existed before the capture started."
            )

        sec_note = ""
        if service == "HTTPS":
            sec_note = (
                "\nSecurity context: encrypted web traffic is likely.\n"
                "IP addresses, ports, timing, and traffic volume remain visible."
            )
        elif service == "HTTP":
            sec_note = (
                "\nSecurity context: unencrypted HTTP traffic detected.\n"
                "URLs, headers, and payload data may be observable in cleartext."
            )
        elif service == "SSH":
            sec_note = (
                "\nSecurity context: encrypted remote administration session (SSH).\n"
                "Session metadata and packet timing remain observable."
            )

        detail_block = (
            f"========================================================================\n"
            f"TCP Stream {sid} | Likely service: {service}\n"
            f"------------------------------------------------------------------------\n"
            f"Endpoint A: {st['src']}\n"
            f"Endpoint B: {st['dst']}\n\n"
            f"Packets captured: {st['packets']}\n"
            f"Captured bytes: {st['bytes']}\n"
            f"TCP payload bytes: {st['payload_bytes']}\n\n"
            f"Handshake evidence:\n"
            f"  SYN:     {syn_txt}\n"
            f"  SYN/ACK: {synack_txt}\n"
            f"  ACK:     {ack_txt}\n\n"
            f"Result: {hs_result}\n"
            f"{sec_note}"
        ).strip()

        tcp_streams_list.append(
            {
                "stream_id": sid,
                "src": st["src"],
                "dst": st["dst"],
                "service": service,
                "packets": st["packets"],
                "bytes": st["bytes"],
                "payload_bytes": st["payload_bytes"],
                "handshake_complete": hs_complete,
                "details": detail_block,
            }
        )
        tcp_text_blocks.append(detail_block)

    # Build DNS report text
    dns_lines = ["=== DNS ACTIVITY ===", ""]
    if not dns_records:
        dns_lines.append("No DNS queries or responses were observed in this capture.")
    else:
        for domain in sorted(dns_records.keys()):
            info = dns_records[domain]
            sorted_types = sorted(info["types"], key=lambda t: int(t[0]) if t[0].isdigit() else 999)
            type_names = ", ".join(t[1] for t in sorted_types) if sorted_types else "Unknown"
            dns_lines.append(f"Domain: {domain}")
            dns_lines.append(f"Query type(s): {type_names}")
            for _, label in sorted_types:
                for code, (lbl, desc) in DNS_TYPE_MAP.items():
                    if lbl == label and desc:
                        dns_lines.append(f"  - {lbl}: {desc}")
                        break
            dns_lines.append(f"Queries observed: {info['queries']}")
            dns_lines.append(f"Responses observed: {info['responses']}")
            if info["aliases"]:
                dns_lines.append("Aliases returned:")
                for alias in sorted(info["aliases"]):
                    dns_lines.append(f"  {domain} -> {alias}")
            if info["ipv4"]:
                dns_lines.append("IPv4 answer(s):")
                for v4 in sorted(info["ipv4"]):
                    dns_lines.append(f"  {domain} -> {v4}")
            if info["ipv6"]:
                dns_lines.append("IPv6 answer(s):")
                for v6 in sorted(info["ipv6"]):
                    dns_lines.append(f"  {domain} -> {v6}")
            dns_lines.append("")

    # Build Summary report text
    filename = os.path.basename(pcap_path)
    summary_lines = [
        "PCAP EXPLAINER V6",
        "================================================================",
        f"Capture: {filename}",
        f"Packets analyzed: {total_packets}",
        "",
        "CAPTURE OVERVIEW",
        "----------------------------------------------------------------",
        f"{'Metric':<40} {'Value':>12}",
        "----------------------------------------------------------------",
        f"{'Total packets':<40} {total_packets:>12}",
        f"{'Unique DNS names':<40} {len(dns_records):>12}",
        f"{'TCP conversations':<40} {len(streams):>12}",
        f"{'Complete TCP handshakes':<40} {complete_handshakes:>12}",
        f"{'Encrypted-protocol packets':<40} {encrypted_packets:>12}",
        f"{'HTTP packets':<40} {http_packets:>12}",
        "----------------------------------------------------------------",
        "",
        "TOP OBSERVED PROTOCOLS",
        "----------------------------------------------------------------",
    ]
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:12]:
        summary_lines.append(f"  {proto:<20} {cnt:>10} packets")

    # Build Security report text
    sec_lines = [
        "=== SECURITY SUMMARY ===",
        "",
        f"Unique DNS names observed: {len(dns_records)}",
        f"Encrypted-protocol packets observed: {encrypted_packets}",
        f"Local discovery packets observed: {local_discovery_packets}",
        f"NAT-traversal-related packets observed: {nat_traversal_packets}",
        "",
        "Evidence-Based Observations:",
    ]
    if encrypted_packets > 0:
        sec_lines.append(
            f"[OK] Encrypted traffic was detected ({encrypted_packets} packets). "
            "Application payloads are protected, while IPs, ports, timing, and volume remain visible."
        )
    if len(dns_records) > 0:
        sec_lines.append(
            f"[INFO] DNS visibility exposed {len(dns_records)} unique requested domain name(s)."
        )
    if complete_handshakes > 0:
        sec_lines.append(
            f"[OK] Complete TCP 3-way handshake establishment was observed for {complete_handshakes} conversation(s)."
        )
    if http_packets == 0:
        sec_lines.append("[OK] No traffic was classified as plaintext HTTP.")
    else:
        sec_lines.append(
            f"[WARN] Cleartext HTTP traffic detected ({http_packets} packets). "
            "Inspect affected TCP streams for unencrypted data exposure."
        )
    if local_discovery_packets > 0:
        sec_lines.append(
            f"[INFO] Local-network discovery activity observed ({local_discovery_packets} ARP/mDNS/SSDP packets)."
        )
    sec_lines.extend(
        [
            "",
            "Important: these are evidence-based observations, not proof of malicious activity.",
        ]
    )

    return {
        "summary_metrics": {
            "total_packets": total_packets,
            "unique_dns": len(dns_records),
            "tcp_conversations": len(streams),
            "complete_handshakes": complete_handshakes,
            "encrypted_packets": encrypted_packets,
            "http_packets": http_packets,
        },
        "tcp_streams": tcp_streams_list,
        "summary": "\n".join(summary_lines),
        "dns": "\n".join(dns_lines),
        "tcp": "\n\n".join(tcp_text_blocks) if tcp_text_blocks else "No TCP streams observed.",
        "security": "\n".join(sec_lines),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        res = build_tab_reports(sys.argv[1])
        print(res["summary"])
        print()
        print(res["security"])
