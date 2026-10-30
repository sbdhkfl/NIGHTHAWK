"""Conservative TCP service exposure checks for an explicitly authorized private host.

This module only connects to a short, fixed list of common TCP ports on RFC1918
private IPv4/IPv6 addresses. It does not exploit services, fingerprint versions,
scan public addresses, or attempt authentication.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

COMMON_PORTS: tuple[tuple[int, str, str], ...] = (
    (21, "FTP", "plaintext file-transfer protocol; prefer encrypted alternatives"),
    (22, "SSH", "remote administration; keep patched and restrict access"),
    (23, "Telnet", "plaintext remote administration; disable if not required"),
    (25, "SMTP", "mail transfer service; verify it is intentionally exposed"),
    (53, "DNS", "DNS service; verify recursion is not exposed unintentionally"),
    (80, "HTTP", "unencrypted web service; redirect sensitive traffic to HTTPS"),
    (110, "POP3", "plaintext mail retrieval; prefer POP3S or IMAPS"),
    (139, "NetBIOS", "legacy Windows file-sharing service"),
    (143, "IMAP", "mail retrieval; prefer encrypted IMAPS"),
    (443, "HTTPS", "encrypted web service"),
    (445, "SMB", "file sharing; restrict to trusted local devices"),
    (3306, "MySQL", "database service; should not be broadly reachable"),
    (3389, "RDP", "remote desktop; restrict to trusted devices"),
    (5432, "PostgreSQL", "database service; should not be broadly reachable"),
    (5900, "VNC", "remote desktop; restrict and secure access"),
    (8080, "HTTP-alt", "alternate web or administration interface"),
    (8443, "HTTPS-alt", "alternate encrypted web or administration interface"),
)

SENSITIVE_PORTS = {21, 23, 110, 139, 445, 3306, 3389, 5432, 5900}


def run(target: str, session=None) -> list[dict[str, Any]]:
    """Check fixed common TCP ports on one private address only."""
    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError("enter one private IP address; CIDR ranges are not accepted") from exc

    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError(
            "ip-ports only accepts a private LAN address (not public, loopback, or link-local)"
        )

    opened: list[dict[str, Any]] = []
    checked = 0
    for port, service, advice in COMMON_PORTS:
        checked += 1
        sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            result = sock.connect_ex((str(address), port))
            if result == 0:
                opened.append({
                    "port": port,
                    "protocol": "tcp",
                    "service": service,
                    "exposure_note": advice,
                    "attention": "review" if port in SENSITIVE_PORTS else "informational",
                })
        finally:
            sock.close()

    return [{
        "module": "ip_ports",
        "target": str(address),
        "result_data": {
            "checked_tcp_ports": checked,
            "open_tcp_ports": opened,
            "open_count": len(opened),
            "scope": "fixed common-port check on one private LAN address",
            "limitations": (
                "An open port is not proof of a vulnerability. No version detection, "
                "authentication, exploit testing, or public-IP scanning is performed."
            ),
        },
        "source": None,
        "confidence": "high",
    }]


__all__ = ["run", "COMMON_PORTS"]
