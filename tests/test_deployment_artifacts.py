from pathlib import Path


def test_deployment_artifacts_present():
    root = Path(__file__).resolve().parents[1]
    assert (root / "install.sh").is_file()
    assert (root / "packaging" / "systemd" / "nemos.service").is_file()
    assert (root / "packaging" / "systemd" / "nemos.env.example").is_file()


def test_systemd_service_points_at_installed_app():
    root = Path(__file__).resolve().parents[1]
    service = (root / "packaging" / "systemd" / "nemos.service").read_text()
    assert "ExecStart=/opt/nemos/.venv/bin/python /opt/nemos/main.py" in service
    assert "User=nemos" in service
    assert "CapabilityBoundingSet=CAP_NET_RAW" in service
    # Scapy uses Linux packet sockets and netlink for interface discovery.
    # The sandbox must allow both families or capture fails with errno 97.
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET" in service
    assert "NoNewPrivileges=true" in service


def test_installer_is_executable_and_idempotent_contract():
    root = Path(__file__).resolve().parents[1]
    installer = root / "install.sh"
    assert installer.stat().st_mode & 0o111
    text = installer.read_text()
    assert "python3 -m venv" in text
    assert "systemctl enable nemos" in text
    assert "systemctl restart nemos" in text
    assert "node --check nemos/static/app.js" in (root / "scripts" / "verify-kali.sh").read_text()
    assert "NEMOS_API_TOKEN" not in text
