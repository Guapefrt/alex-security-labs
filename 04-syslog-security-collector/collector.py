import datetime
import json
import os
import re
import socket
import socketserver
import threading
import time
from collections import defaultdict, deque

HOST, PORT = "127.0.0.1", 5140
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
AUDIT_FILE = os.path.join(LOGS_DIR, "security_audit.jsonl")

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    10: "authpriv", 16: "local0", 17: "local1", 18: "local2",
}

SEVERITY_NAMES = {
    0: "Emergency", 1: "Alert", 2: "Critical", 3: "Error",
    4: "Warning", 5: "Notice", 6: "Informational", 7: "Debug",
}

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_syslog_packet(raw_message: str) -> dict:
    """Decodare determinista pentru antete RFC 5424 si mesaje syslog standard."""
    text = raw_message.strip()
    if text.startswith("<") and ">" in text:
        pri_end = text.find(">")
        pri_str = text[1:pri_end]
        if pri_str.isdigit():
            pri = int(pri_str)
            facility_code = pri >> 3
            severity_code = pri & 7
            facility = FACILITY_NAMES.get(facility_code, f"facility-{facility_code}")
            sev_name = SEVERITY_NAMES.get(severity_code, str(severity_code))
            rest = text[pri_end + 1:].strip()

            # Format RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            if rest.startswith("1 "):
                parts = rest.split(None, 6)
                if len(parts) >= 7:
                    _, ts_hdr, host, app, proc_id, msg_id, sd_and_msg = parts
                    structured_data = "-"
                    clean_msg = sd_and_msg

                    if sd_and_msg.startswith("- "):
                        structured_data = "-"
                        clean_msg = sd_and_msg[2:].strip()
                    elif sd_and_msg.startswith("["):
                        close_idx = sd_and_msg.rfind("]")
                        if close_idx != -1:
                            structured_data = sd_and_msg[: close_idx + 1]
                            clean_msg = sd_and_msg[close_idx + 1 :].strip()

                    return {
                        "format": "RFC 5424",
                        "pri": pri,
                        "facility": facility,
                        "syslog_severity": sev_name,
                        "version": "1",
                        "header_timestamp": ts_hdr,
                        "hostname": host,
                        "app_name": app,
                        "proc_id": proc_id,
                        "msg_id": msg_id,
                        "structured_data": structured_data,
                        "message": clean_msg,
                    }

    return {
        "format": "Plain / Raw",
        "pri": None,
        "facility": "unknown",
        "syslog_severity": "Notice",
        "version": "-",
        "header_timestamp": "-",
        "hostname": "local-endpoint",
        "app_name": "syslog",
        "proc_id": "-",
        "msg_id": "-",
        "structured_data": "-",
        "message": text,
    }


class SyslogSecurityEngine:
    def __init__(self, brute_force_threshold: int = 3, window_seconds: int = 60):
        self.threshold = brute_force_threshold
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self.events: list[dict] = []
        self.failed_tracker: dict[str, deque] = defaultdict(deque)
        self.level_counts: dict[str, int] = defaultdict(int)
        self.source_counts: dict[str, int] = defaultdict(int)

    def reset(self):
        with self._lock:
            self.events.clear()
            self.failed_tracker.clear()
            self.level_counts.clear()
            self.source_counts.clear()

    def process_raw_message(self, raw_message: str, transport_ip: str, persist: bool = True) -> dict:
        now = datetime.datetime.now()
        ts_str = now.strftime("%Y-%m-%d %H:%M:%S")
        parsed = parse_syslog_packet(raw_message)
        clean_msg = parsed["message"]
        msg_lower = clean_msg.lower()

        ip_match = IPV4_REGEX.search(clean_msg)
        actor_ip = ip_match.group(0) if ip_match else transport_ip

        level = "INFO"
        rule_name = "Normal Telemetry"
        bf_count = 0

        with self._lock:
            is_auth_fail = any(
                sig in msg_lower
                for sig in ("failed password", "authentication failure", "invalid user", "failed publickey")
            )

            if is_auth_fail:
                attempts = self.failed_tracker[actor_ip]
                attempts.append(now)
                cutoff = now - datetime.timedelta(seconds=self.window_seconds)
                while attempts and attempts[0] < cutoff:
                    attempts.popleft()

                bf_count = len(attempts)
                if bf_count >= self.threshold:
                    level = "CRITICAL"
                    rule_name = f"Brute-Force Pattern ({bf_count} failures in {self.window_seconds}s)"
                else:
                    level = "ALERT"
                    rule_name = f"Authentication Failure ({bf_count}/{self.threshold} in window)"

            elif "sudo" in msg_lower and ("session opened" in msg_lower or "command=" in msg_lower):
                level = "WARN"
                rule_name = "Privilege Escalation (sudo)"
            elif any(fw in msg_lower for fw in ("nftables", "iptables", "ufw block", "packet dropped")):
                level = "WARN"
                rule_name = "Firewall Drop / Block"
            elif any(err in msg_lower for err in ("error", "fail", "denied", "segfault")):
                level = "WARN"
                rule_name = "Service / System Error"

            event_id = len(self.events) + 1
            event_record = {
                "id": event_id,
                "timestamp": ts_str,
                "level": level,
                "rule": rule_name,
                "actor_ip": actor_ip,
                "transport_ip": transport_ip,
                "hostname": parsed["hostname"],
                "app_name": parsed["app_name"],
                "pri": parsed["pri"],
                "format": parsed["format"],
                "facility": parsed["facility"],
                "syslog_severity": parsed["syslog_severity"],
                "structured_data": parsed["structured_data"],
                "bf_attempts_in_window": bf_count,
                "message": clean_msg,
                "raw": raw_message,
            }

            self.events.append(event_record)
            self.level_counts[level] += 1
            self.source_counts[actor_ip] += 1

        if persist:
            self._persist_jsonl(event_record)
        return event_record

    def _persist_jsonl(self, event_record: dict):
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record) + "\n")

    def get_summary(self) -> dict:
        with self._lock:
            top_sources = sorted(self.source_counts.items(), key=lambda x: x[1], reverse=True)
            return {
                "total": len(self.events),
                "CRITICAL": self.level_counts.get("CRITICAL", 0),
                "ALERT": self.level_counts.get("ALERT", 0),
                "WARN": self.level_counts.get("WARN", 0),
                "INFO": self.level_counts.get("INFO", 0),
                "unique_sources": len(self.source_counts),
                "top_sources": top_sources,
            }

    def export_markdown(self, output_path: str):
        stats = self.get_summary()
        with self._lock:
            high_priority = [e for e in self.events if e["level"] in ("CRITICAL", "ALERT", "WARN")]

        lines = [
            "# Syslog Security Collector — Incident & Telemetry Report",
            "",
            f"- **Generated at:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Total Events Analyzed:** {stats['total']}",
            f"- **Critical (Brute-Force):** {stats['CRITICAL']}",
            f"- **Security Alerts:** {stats['ALERT']}",
            f"- **Warnings:** {stats['WARN']}",
            f"- **Informational:** {stats['INFO']}",
            f"- **Unique Source IPs:** {stats['unique_sources']}",
            "",
            "## Top Observed Source IPs",
            "",
        ]
        if stats["top_sources"]:
            for ip, count in stats["top_sources"][:10]:
                lines.append(f"- `{ip}`: {count} event(s)")
        else:
            lines.append("- No source traffic recorded.")

        lines.extend(["", "## High-Priority Security Events (CRITICAL / ALERT / WARN)", ""])
        if high_priority:
            for ev in high_priority:
                lines.append(
                    f"- **[{ev['level']}]** `{ev['timestamp']}` | Source: `{ev['actor_ip']}` | "
                    f"Rule: *{ev['rule']}* — `{ev['message']}`"
                )
        else:
            lines.append("- No security alerts or warnings detected.")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


class SimpleUDPServer(socketserver.UDPServer):
    allow_reuse_address = True


def create_udp_server(host: str, port: int, engine: SyslogSecurityEngine, on_event_callback=None):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            raw = self.request[0].strip().decode("utf-8", errors="ignore")
            if not raw:
                return
            client_ip = self.client_address[0]
            record = engine.process_raw_message(raw, client_ip)
            if on_event_callback:
                on_event_callback(record)

    return SimpleUDPServer((host, port), Handler)


def send_test_burst(host: str = HOST, port: int = PORT) -> int:
    hostname = socket.gethostname()
    now_iso = datetime.datetime.now().astimezone().isoformat()
    sample_logs = [
        f"<38>1 {now_iso} {hostname} sshd 4102 - - Failed password for invalid user admin from 192.168.1.50 port 51244 ssh2",
        f"<38>1 {now_iso} {hostname} sshd 4103 - - Failed password for invalid user root from 192.168.1.50 port 51248 ssh2",
        f"<38>1 {now_iso} {hostname} sshd 4104 - - Failed password for user alex from 192.168.1.50 port 51251 ssh2",
        f"<86>1 {now_iso} {hostname} sudo 4110 - - pam_unix(sudo:session): session opened for user root by alex(uid=1000)",
        f"<30>1 {now_iso} {hostname} systemd 1 - - Started Daily Network Telemetry Sync.",
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for msg in sample_logs:
            sock.sendto(msg.encode("utf-8"), (host, port))
            sent += 1
            time.sleep(0.03)
    finally:
        sock.close()
    return sent
