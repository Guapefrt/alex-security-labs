import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROTOCOL_EXPLANATIONS = {
    "ARP": (
        "ARP maps a local IPv4 address to a MAC address. "
        "Devices use ARP when communicating on the same local network."
    ),
    "DNS": (
        "DNS translates domain names such as github.com into IP addresses."
    ),
    "TCP": (
        "TCP provides reliable, connection-oriented transport using "
        "sequence numbers, acknowledgements, and retransmissions."
    ),
    "UDP": (
        "UDP sends datagrams without establishing a TCP-style connection. "
        "DNS, discovery, and real-time applications commonly use UDP."
    ),
    "SSH": (
        "SSH provides encrypted remote administration, normally over TCP port 22."
    ),
    "TLS": (
        "TLS encrypts application traffic such as HTTPS."
    ),
    "TLSv1.2": (
        "TLS 1.2 encrypted application traffic was detected. "
        "The network can observe connection metadata, but not simply read "
        "the encrypted application content."
    ),
    "TLSv1.3": (
        "TLS 1.3 encrypted traffic was detected. TLS 1.3 uses a simplified "
        "handshake and modern cryptography."
    ),
    "SSL": (
        "Wireshark classified this traffic using its SSL/TLS dissector. "
        "Modern secure applications normally use TLS rather than obsolete SSL."
    ),
    "ICMP": (
        "ICMP provides network control and diagnostic messages. "
        "Ping uses ICMP Echo Request and Echo Reply."
    ),
    "ICMPv6": (
        "ICMPv6 provides diagnostics and essential control functions for IPv6."
    ),
    "STUN": (
        "STUN helps applications discover how their connection appears through NAT. "
        "It is often associated with WebRTC and peer-to-peer communication."
    ),
    "SSDP": (
        "SSDP is a local service-discovery protocol commonly associated with UPnP."
    ),
    "NAT-PMP": (
        "NAT-PMP allows a device to request port mappings from a NAT gateway."
    ),
    "PCP v2": (
        "PCP allows devices to request and manage mappings through NAT devices "
        "and firewalls."
    ),
    "HTTP": (
    "HTTP carries web application traffic without TLS encryption. "
    "Unlike HTTPS, HTTP content can potentially be visible in a packet capture."
    ),
}


DNS_TYPE_NAMES = {
    "1": "A",
    "5": "CNAME",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "65": "HTTPS",
}

SERVICE_NAMES = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP server",
    68: "DHCP client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP submission",
    636: "LDAPS",
    853: "DNS over TLS",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
}


def run_tshark(command):
    """Run tshark and return its standard output."""

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def read_protocols(capture_file):
    """Return the protocol shown by Wireshark for every packet."""

    command = [
        "tshark",
        "-r",
        str(capture_file),
        "-T",
        "fields",
        "-e",
        "_ws.col.Protocol",
    ]

    output = run_tshark(command)

    protocols = []

    for line in output.splitlines():
        protocol = line.strip()

        if protocol:
            protocols.append(protocol)

    return protocols


def split_values(value):
    """Split comma-separated tshark values and remove empty entries."""

    if not value:
        return []

    return [
        item.strip().rstrip(".")
        for item in value.split(",")
        if item.strip()
    ]


def read_dns_activity(capture_file):
    """Extract DNS questions and answers from the capture."""

    command = [
        "tshark",
        "-r",
        str(capture_file),
        "-Y",
        "dns",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
        "-e",
        "dns.flags.response",
        "-e",
        "dns.qry.name",
        "-e",
        "dns.qry.type",
        "-e",
        "dns.a",
        "-e",
        "dns.aaaa",
        "-e",
        "dns.cname",
    ]

    output = run_tshark(command)

    activity = defaultdict(
        lambda: {
            "query_types": set(),
            "ipv4": set(),
            "ipv6": set(),
            "cnames": set(),
            "queries": 0,
            "responses": 0,
        }
    )

    for line in output.splitlines():
        fields = line.split("\t")

        while len(fields) < 6:
            fields.append("")

        (
            response_flag,
            query_names,
            query_types,
            ipv4_answers,
            ipv6_answers,
            cname_answers,
        ) = fields[:6]

        names = split_values(query_names)
        types = split_values(query_types)
        ipv4 = split_values(ipv4_answers)
        ipv6 = split_values(ipv6_answers)
        cnames = split_values(cname_answers)

        if not names:
            continue

        # tshark on this system returns True/False.
        # We also support 1/0 for compatibility.
        response_value = response_flag.strip().lower()

        for name in names:
            entry = activity[name]

            if response_value in ("0", "false"):
                entry["queries"] += 1

            elif response_value in ("1", "true"):
                entry["responses"] += 1

            for query_type in types:
                entry["query_types"].add(
                    DNS_TYPE_NAMES.get(
                        query_type,
                        f"TYPE {query_type}",
                    )
                )

            entry["ipv4"].update(ipv4)
            entry["ipv6"].update(ipv6)
            entry["cnames"].update(cnames)

    return activity

def read_tcp_conversations(capture_file):
    """Extract TCP streams and determine whether a handshake was observed."""

    command = [
        "tshark",
        "-r",
        str(capture_file),
        "-Y",
        "tcp",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "ipv6.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "frame.len",
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.ack",
        "-e",
        "tcp.len",
    ]

    output = run_tshark(command)
    conversations = {}

    for line in output.splitlines():
        fields = line.split("\t")

        while len(fields) < 11:
            fields.append("")

        (
            stream_id,
            ipv4_source,
            ipv6_source,
            source_port,
            ipv4_destination,
            ipv6_destination,
            destination_port,
            frame_length,
            syn_flag,
            ack_flag,
            tcp_payload_length,
        ) = fields[:11]

        if not stream_id or not source_port or not destination_port:
            continue

        source_ip = ipv4_source or ipv6_source
        destination_ip = ipv4_destination or ipv6_destination

        if not source_ip or not destination_ip:
            continue

        source_port_number = int(source_port)
        destination_port_number = int(destination_port)

        if stream_id not in conversations:
            conversations[stream_id] = {
                "stream_id": int(stream_id),
                "endpoint_a_ip": source_ip,
                "endpoint_a_port": source_port_number,
                "endpoint_b_ip": destination_ip,
                "endpoint_b_port": destination_port_number,
                "packets": 0,
                "bytes": 0,
                "payload_bytes": 0,
                "syn": False,
                "syn_ack": False,
                "final_ack": False,
            }

        conversation = conversations[stream_id]

        conversation["packets"] += 1

        if frame_length:
            conversation["bytes"] += int(frame_length)

        if tcp_payload_length:
            conversation["payload_bytes"] += int(tcp_payload_length)

        # tshark on this system returns True/False.
        # Also accepting 1/0 makes the parser portable.
        syn_is_set = syn_flag.strip().lower() in ("1", "true")
        ack_is_set = ack_flag.strip().lower() in ("1", "true")

        if syn_is_set and not ack_is_set:
            conversation["syn"] = True

        elif syn_is_set and ack_is_set:
            conversation["syn_ack"] = True

        elif ack_is_set and not syn_is_set:
            conversation["final_ack"] = True

    return sorted(
        conversations.values(),
        key=lambda conversation: conversation["bytes"],
        reverse=True,
    )



def explain_protocol(protocol):
    """Return a simple explanation for a protocol."""

    return PROTOCOL_EXPLANATIONS.get(
        protocol,
        "No simple explanation has been added for this protocol yet.",
    )


def explain_dns_type(query_type):
    """Return a simple explanation for a DNS query type."""

    explanations = {
        "A": "The endpoint asked for an IPv4 address.",
        "AAAA": "The endpoint asked for an IPv6 address.",
        "CNAME": "The endpoint asked about a canonical-name alias.",
        "PTR": "The endpoint asked for a reverse DNS name.",
        "MX": "The endpoint asked for mail-server information.",
        "TXT": "The endpoint asked for a DNS text record.",
        "SRV": "The endpoint asked where a particular service is available.",
        "HTTPS": "The endpoint asked for HTTPS service-binding information.",
    }

    return explanations.get(
        query_type,
        "The endpoint requested this DNS record type.",
    )


def print_protocol_summary(protocols):
    """Print protocol counts and explanations."""

    counts = Counter(protocols)

    print("=== PROTOCOL SUMMARY ===")
    print()

    for protocol, count in counts.most_common():
        print(f"{protocol:12} {count}")

    print()
    print("=== WHAT THE PROTOCOLS MEAN ===")

    for protocol, count in counts.most_common():
        print()
        print(f"{protocol} ({count} packets)")
        print(explain_protocol(protocol))

    return counts


def print_dns_activity(activity):
    """Print human-readable DNS questions and answers."""

    print()
    print("=== DNS ACTIVITY ===")

    if not activity:
        print()
        print("No DNS activity was found in this capture.")
        return

    for domain in sorted(activity):
        entry = activity[domain]

        print()
        print(f"Domain: {domain}")

        if entry["query_types"]:
            types = ", ".join(sorted(entry["query_types"]))
            print(f"Query type(s): {types}")

            for query_type in sorted(entry["query_types"]):
                print(f"  - {query_type}: {explain_dns_type(query_type)}")

        print(f"Queries observed: {entry['queries']}")
        print(f"Responses observed: {entry['responses']}")

        if entry["cnames"]:
            print("Aliases returned:")

            for cname in sorted(entry["cnames"]):
                print(f"  {domain} -> {cname}")

        if entry["ipv4"]:
            print("IPv4 answer(s):")

            for address in sorted(entry["ipv4"]):
                print(f"  {domain} -> {address}")

        if entry["ipv6"]:
            print("IPv6 answer(s):")

            for address in sorted(entry["ipv6"]):
                print(f"  {domain} -> {address}")

        if not entry["ipv4"] and not entry["ipv6"] and not entry["cnames"]:
            print("No address answer was visible in the captured DNS packets.")


def print_security_summary(protocol_counts, dns_activity):
    """Print a cautious summary based only on observed evidence."""

    encrypted_packets = (
        protocol_counts.get("TLS", 0)
        + protocol_counts.get("TLSv1.2", 0)
        + protocol_counts.get("TLSv1.3", 0)
        + protocol_counts.get("SSL", 0)
        + protocol_counts.get("SSH", 0)
    )

    discovery_packets = (
        protocol_counts.get("ARP", 0)
        + protocol_counts.get("SSDP", 0)
    )

    nat_traversal_packets = (
        protocol_counts.get("STUN", 0)
        + protocol_counts.get("NAT-PMP", 0)
        + protocol_counts.get("PCP v2", 0)
    )

    print()
    print("=== SECURITY SUMMARY ===")
    print()

    print(f"Unique DNS names observed: {len(dns_activity)}")
    print(f"Encrypted-protocol packets observed: {encrypted_packets}")
    print(f"Local discovery packets observed: {discovery_packets}")
    print(f"NAT-traversal-related packets observed: {nat_traversal_packets}")

    print()
    print("Observations:")

    if encrypted_packets:
        print(
            "- Encrypted traffic was present. IP addresses, ports, timing, "
            "and packet sizes remain observable, while application content "
            "is protected."
        )

    if dns_activity:
        print(
            "- DNS activity exposed the domain names requested by the endpoint "
            "and, where captured, the returned IP addresses."
        )

    if discovery_packets:
        print(
            "- Local-network discovery activity was present through protocols "
            "such as ARP or SSDP."
        )

    if nat_traversal_packets:
        print(
            "- NAT traversal or mapping-related activity was present. "
            "This can be normal for real-time, peer-to-peer, or "
            "device-connectivity applications."
        )

    print()
    print(
        "Important: these are observations, not proof of malicious activity."
    )

def guess_service(port_a, port_b):
    """Guess the application service from a known TCP port."""

    if port_a in SERVICE_NAMES:
        return SERVICE_NAMES[port_a], port_a

    if port_b in SERVICE_NAMES:
        return SERVICE_NAMES[port_b], port_b

    return "Unknown or application-specific", None


def format_bytes(byte_count):
    """Convert bytes into a readable value."""

    if byte_count >= 1_000_000:
        return f"{byte_count / 1_000_000:.2f} MB"

    if byte_count >= 1_000:
        return f"{byte_count / 1_000:.2f} KB"

    return f"{byte_count} bytes"


def print_tcp_conversations(conversations, limit=10):
    """Explain the largest observed TCP conversations."""

    print()
    print("=== TCP CONVERSATIONS ===")

    if not conversations:
        print()
        print("No TCP conversations were found.")
        return

    print()
    print(
        f"Showing the {min(limit, len(conversations))} "
        "largest TCP conversations."
    )

    for conversation in conversations[:limit]:

        service_name, service_port = guess_service(
            conversation["endpoint_a_port"],
            conversation["endpoint_b_port"],
        )

        handshake_complete = (
            conversation["syn"]
            and conversation["syn_ack"]
            and conversation["final_ack"]
        )

        print()
        print("=" * 60)

        print(f"TCP Stream {conversation['stream_id']}")

        print()
        print(
            f"Endpoint A: "
            f"{conversation['endpoint_a_ip']}:"
            f"{conversation['endpoint_a_port']}"
        )

        print(
            f"Endpoint B: "
            f"{conversation['endpoint_b_ip']}:"
            f"{conversation['endpoint_b_port']}"
        )

        print()
        print(f"Likely service: {service_name}")

        if service_port is not None:
            print(f"Recognized server port: TCP/{service_port}")

        print(f"Packets captured: {conversation['packets']}")

        print(
            f"Captured traffic: "
            f"{format_bytes(conversation['bytes'])}"
        )

        print(
            f"TCP payload: "
            f"{format_bytes(conversation['payload_bytes'])}"
        )

        print()
        print("TCP handshake:")

        print(
            "  SYN      : "
            + (
                "detected"
                if conversation["syn"]
                else "not observed"
            )
        )

        print(
            "  SYN/ACK  : "
            + (
                "detected"
                if conversation["syn_ack"]
                else "not observed"
            )
        )

        print(
            "  ACK      : "
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
                "Result: The complete TCP handshake was "
                "not visible in this capture."
            )
            print(
                "The capture may have started after the "
                "connection was already established."
            )

        print()

        if service_name == "HTTPS":
            print(
                "Explanation: This is likely encrypted web traffic."
            )
            print(
                "IP addresses, ports, timing, and traffic volume "
                "remain visible even though the application "
                "content is protected by TLS."
            )

        elif service_name == "SSH":
            print(
                "Explanation: This is likely an encrypted "
                "remote administration session."
            )

        elif service_name == "HTTP":
            print(
                "Explanation: This appears to be HTTP traffic."
            )
            print(
                "Unlike HTTPS, HTTP application content may "
                "be visible in a packet capture."
            )

        elif service_name == "DNS over TLS":
            print(
                "Explanation: DNS traffic may be transported "
                "inside an encrypted TLS connection."
            )


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python pcap_explainer.py <capture.pcapng>")
        sys.exit(1)

    capture_file = Path(sys.argv[1])

    if not capture_file.exists():
        print(f"Error: {capture_file} does not exist.")
        sys.exit(1)

    try:
        protocols = read_protocols(capture_file)
        dns_activity = read_dns_activity(capture_file)
        tcp_conversations = read_tcp_conversations(capture_file)

    except FileNotFoundError:
        print("Error: tshark is not installed or is not available in PATH.")
        sys.exit(1)

    except subprocess.CalledProcessError as error:
        print("Error: tshark could not read the capture.")
        print(error.stderr)
        sys.exit(1)

    print()
    print("=== PCAP EXPLAINER V4 ===")
    print()
    print(f"Capture: {capture_file.name}")
    print(f"Packets analyzed: {len(protocols)}")
    print()

    protocol_counts = print_protocol_summary(protocols)

    print_dns_activity(dns_activity)

    print_tcp_conversations(tcp_conversations)

    print_security_summary(
    protocol_counts,
    dns_activity,
)


if __name__ == "__main__":
    main()