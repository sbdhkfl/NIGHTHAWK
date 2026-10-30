"""Read the local operating-system neighbor table; do not probe the network."""
from __future__ import annotations

import platform
import re
import subprocess
from typing import Any


def run(target: str = "local-neighbor-table", session=None) -> list[dict[str, Any]]:
    """Report devices already visible in the local ARP/NDP neighbor cache."""
    system = platform.system().lower()
    if system != "linux":
        raise RuntimeError("lan-devices currently supports Linux (Kali) only")

    try:
        completed = subprocess.run(
            ["ip", "neigh", "show"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"unable to read local neighbor table: {exc}") from exc

    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "ip neigh command failed")

    devices: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        entry: dict[str, str] = {"ip": parts[0], "state": parts[-1]}
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                entry["mac"] = parts[idx + 1]
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                entry["interface"] = parts[idx + 1]
        devices.append(entry)

    return [{
        "module": "lan_devices",
        "target": target,
        "result_data": {
            "devices": devices,
            "device_count": len(devices),
            "source": "local Linux ARP/NDP neighbor cache",
            "limitations": (
                "Only devices already present in the neighbor cache appear. "
                "This is not a complete router client list and does not identify people."
            ),
        },
        "source": None,
        "confidence": "medium",
    }]


__all__ = ["run"]
