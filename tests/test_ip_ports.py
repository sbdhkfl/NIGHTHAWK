"""Safety and behavior tests for local network inventory modules."""
import socket
from unittest.mock import Mock

import pytest

from nighthawk.modules.ip_ports import run as ip_ports_run


def test_ip_ports_rejects_public_targets():
    with pytest.raises(ValueError, match="RFC1918"):
        ip_ports_run("8.8.8.8")


def test_ip_ports_only_reports_open_common_ports(monkeypatch):
    fake = Mock()
    fake.connect_ex.side_effect = lambda address: 0 if address[1] == 23 else 1
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: fake)

    findings = ip_ports_run("192.168.1.1")
    result = findings[0]["result_data"]
    assert result["checked_tcp_ports"] > 0
    assert result["open_count"] == 1
    assert result["open_tcp_ports"][0]["port"] == 23
    assert result["open_tcp_ports"][0]["attention"] == "review"
    assert "not proof of a vulnerability" in result["limitations"]
