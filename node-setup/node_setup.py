#!/usr/bin/env python3
"""Standalone VLESS-over-WebSocket node setup with Cloudflare Quick Tunnel.

Intentionally excludes InstaBox API access, machine leases, keepalive scheduling,
and account credential handling. Use only on hosts where proxy services are allowed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid
from urllib.parse import quote

SB_VERSION = "1.14.2"
SB_ARCHIVE = f"sing-box-{SB_VERSION}-linux-amd64.tar.gz"
SB_URL = f"https://github.com/SagerNet/sing-box/releases/download/v{SB_VERSION}/{SB_ARCHIVE}"
SB_SHA256 = "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6"
CF_VERSION = "2026.10.1"
CF_URL = f"https://github.com/cloudflare/cloudflared/releases/download/{CF_VERSION}/cloudflared-linux-amd64"
CF_SHA256 = "3bfc539f45d2620c71debb7a86be0efa737ed5ccbad9eb85c787116900e5c586"
MARKER = "# Managed-by: InstaBox node setup"
MAX_DOWNLOAD = 200 * 1024 * 1024
APP_REL = Path(".local/share/ibt-node")


class SetupError(RuntimeError):
    """Expected setup/preflight failure with a safe user-facing message."""


def validate_port(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise SetupError("Port must be an integer from 1024 to 65535.") from None
    if str(value) != str(port) or not 1024 <= port <= 65535:
        raise SetupError("Port must be an integer from 1024 to 65535.")
    return port


def build_config(node_uuid: str, port: int, ws_path: str) -> dict:
    try:
        canonical_uuid = str(uuid.UUID(node_uuid))
    except (ValueError, AttributeError, TypeError):
        raise SetupError("Invalid node UUID.") from None
    if canonical_uuid != node_uuid.lower():
        raise SetupError("Node UUID must be canonical.")
    port = validate_port(port)
    if not re.fullmatch(r"/ws-[0-9a-f]{36}", ws_path):
        raise SetupError("Invalid WebSocket path.")
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "vless", "tag": "vless-ws", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"name": "private", "uuid": canonical_uuid}],
            "transport": {"type": "ws", "path": ws_path},
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }


def make_vless_link(node_uuid: str, host: str, ws_path: str, name: str = "Node") -> str:
    try:
        canonical_uuid = str(uuid.UUID(node_uuid))
    except (ValueError, AttributeError, TypeError):
        raise SetupError("Invalid node UUID.") from None
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+trycloudflare\.com", host, re.IGNORECASE):
        raise SetupError("Invalid Quick Tunnel hostname.")
    if not re.fullmatch(r"/ws-[0-9a-f]{36}", ws_path):
        raise SetupError("Invalid WebSocket path.")
    return (f"vless://{canonical_uuid}@{host}:443?encryption=none&security=tls"
            f"&sni={host}&type=ws&host={host}&path={quote(ws_path, safe='')}#{quote(name, safe='')}")


def node_unit_text() -> str:
    command = "%h/.local/share/ibt-node/bin/sing-box run -c %h/.local/share/ibt-node/config.json"
    return (f"{MARKER}\n[Unit]\nDescription=Standalone VLESS WebSocket node\n"
            "Wants=network-online.target\nAfter=network-online.target\n[Service]\n"
            "Type=simple\nUMask=0077\n"
            f"ExecStart={command}\nRestart=always\nRestartSec=5\nNoNewPrivileges=yes\n"
            "[Install]\nWantedBy=default.target\n")


def tunnel_unit_text() -> str:
    return (f"{MARKER}\n[Unit]\nDescription=Standalone Cloudflare Quick Tunnel\n"
            "Wants=network-online.target ibt-node.service\nAfter=network-online.target ibt-node.service\n"
            "[Service]\nType=simple\nUMask=0077\n"
            "ExecStart=%h/.local/share/ibt-node/bin/start-tunnel\n"
            "Restart=always\nRestartSec=5\nNoNewPrivileges=yes\n"
            "[Install]\nWantedBy=default.target\n")


def ensure_private_dir(path: Path, *, tighten_existing: bool = True) -> None:
    created = not path.exists() and not path.is_symlink()
    if not created:
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid():
            raise SetupError(f"Unsafe directory; refusing to use {path}.")
        if path.stat().st_mode & 0o022:
            raise SetupError(f"Directory is writable by other users; refusing to use {path}.")
    else:
        path.mkdir(mode=0o700, parents=True)
    if created or tighten_existing:
        os.chmod(path, 0o700)


def write_private_atomic(path: Path, data: bytes, mode: int = 0o600, *, parent_private: bool = True) -> None:
    ensure_private_dir(path.parent, tighten_existing=parent_private)
    if path.is_symlink():
        raise SetupError(f"Refusing to replace a symbolic link: {path}.")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        os.chmod(path, mode)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def run_checked(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupError(f"Command failed: {Path(args[0]).name}.") from exc


def download_verified(url: str, expected_sha256: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise SetupError("Downloads must use HTTPS.")
    ensure_private_dir(dest.parent)
    request = urllib.request.Request(url, headers={"User-Agent": "ibt-node-setup/1"})
    digest = hashlib.sha256()
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", dir=dest.parent)
    tmp = Path(tmp_name)
    total = 0
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(
            request, context=ssl.create_default_context(), timeout=30
        ) as response:
            if not response.geturl().startswith("https://"):
                raise SetupError("Release download redirected away from HTTPS.")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise SetupError("Release file exceeded the download size limit.")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if digest.hexdigest() != expected_sha256:
            raise SetupError(f"SHA-256 verification failed for {dest.name}.")
        os.chmod(tmp, 0o700 if dest.name == "cloudflared" else 0o600)
        os.replace(tmp, dest)
    except BaseException:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def install_singbox(app_dir: Path, port: int, node_uuid: str, ws_path: str) -> None:
    bins = app_dir / "bin"
    ensure_private_dir(bins)
    archive = app_dir / SB_ARCHIVE
    download_verified(SB_URL, SB_SHA256, archive)
    binary = bins / "sing-box"
    tmp_name: str | None = None
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = [m for m in tar.getmembers() if Path(m.name).name == "sing-box"]
            member = next((m for m in members if m.isfile()), None)
            if member is None or member.size > MAX_DOWNLOAD:
                raise SetupError("Release archive has no safe sing-box executable.")
            source = tar.extractfile(member)
            if source is None:
                raise SetupError("Could not read sing-box executable from archive.")
            fd, tmp_name = tempfile.mkstemp(prefix=".sing-box.", dir=bins)
            with os.fdopen(fd, "wb") as out, source:
                shutil.copyfileobj(source, out, length=1024 * 1024)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(tmp_name, 0o700)
            os.replace(tmp_name, binary)
            tmp_name = None
    finally:
        archive.unlink(missing_ok=True)
        if tmp_name:
            Path(tmp_name).unlink(missing_ok=True)
    config = build_config(node_uuid, port, ws_path)
    config_path = app_dir / "config.json"
    write_private_atomic(config_path, (json.dumps(config, indent=2) + "\n").encode())
    run_checked([str(binary), "check", "-c", str(config_path)])


def install_cloudflared(app_dir: Path) -> None:
    binary = app_dir / "bin" / "cloudflared"
    download_verified(CF_URL, CF_SHA256, binary)
    os.chmod(binary, 0o700)


def install_unit(unit_dir: Path, name: str, content: str) -> None:
    ensure_private_dir(unit_dir, tighten_existing=False)
    path = unit_dir / name
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or MARKER not in path.read_text(errors="replace"):
            raise SetupError(f"Service file already exists and is not managed by this installer: {name}.")
    write_private_atomic(path, content.encode(), parent_private=False)


def write_tunnel_launcher(app_dir: Path, port: int) -> None:
    script = ("#!/usr/bin/env bash\nset -Eeuo pipefail\numask 077\n"
              'base="$HOME/.local/share/ibt-node"\n'
              ': > "$base/tunnel.log"\n'
              'exec env -u TUNNEL_TOKEN -u TUNNEL_ORIGIN_CERT -u TUNNEL_CONFIG '
              '"$base/bin/cloudflared" tunnel --config "$base/quick-config.yml" '
              f'--no-autoupdate --url "http://127.0.0.1:{port}" '
              '>> "$base/tunnel.log" 2>&1\n')
    write_private_atomic(app_dir / "bin" / "start-tunnel", script.encode(), 0o700)
    write_private_atomic(app_dir / "quick-config.yml", b"{}\n")
    write_private_atomic(app_dir / "tunnel.log", b"")


def find_quick_host(log_path: Path) -> str | None:
    try:
        text = log_path.read_text(errors="replace")[-1_000_000:]
    except OSError:
        return None
    matches = re.findall(r"https://([A-Za-z0-9-]+\.trycloudflare\.com)", text)
    return matches[-1] if matches else None


def wait_for_tunnel(log_path: Path, timeout: int = 60) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        host = find_quick_host(log_path)
        if host:
            return host
        time.sleep(1)
    raise SetupError("Quick Tunnel did not publish a hostname within 60 seconds; check the tunnel service logs.")


def check_unit_conflicts(unit_dir: Path) -> None:
    for name in ("ibt-node.service", "ibt-tunnel.service"):
        path = unit_dir / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or MARKER not in path.read_text(errors="replace"):
                raise SetupError(f"Service file already exists and is not managed by this installer: {name}.")


def get_saved_link(app_dir: Path) -> str:
    state_path = app_dir / "state.json"
    try:
        state = json.loads(state_path.read_text())
        host = find_quick_host(app_dir / "tunnel.log")
        if not isinstance(state, dict) or not host:
            raise ValueError
        return make_vless_link(state["uuid"], host, state["path"], "VLESS-WS")
    except (OSError, ValueError, KeyError, TypeError, SetupError):
        raise SetupError("No current node link is available; check the systemd service and tunnel log.") from None


def install(port: int) -> str:
    if sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64"):
        raise SetupError("This extracted installer supports Linux x86_64 only.")
    if os.geteuid() == 0:
        raise SetupError("Run as a regular user, not root or sudo.")
    if shutil.which("systemctl") is None:
        raise SetupError("Required command is missing: systemctl.")
    try:
        subprocess.run(["systemctl", "--user", "show-environment"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        raise SetupError("A working user-level systemd session is required.") from None

    home = Path.home()
    app_dir = home / APP_REL
    unit_dir = home / ".config/systemd/user"
    ensure_private_dir(app_dir)
    ensure_private_dir(app_dir / "bin")
    if (app_dir / "state.json").exists():
        raise SetupError("A node setup already exists; use --show to display its current link.")
    unmanaged = [app_dir / rel for rel in (
        "config.json", "bin/sing-box", "bin/cloudflared", "bin/start-tunnel",
        "quick-config.yml", "tunnel.log",
    ) if (app_dir / rel).exists() or (app_dir / rel).is_symlink()]
    if unmanaged:
        raise SetupError("Existing node files are present without setup state; refusing to overwrite them.")
    check_unit_conflicts(unit_dir)
    if shutil.which("ss"):
        result = subprocess.run(["ss", "-ltnH"], check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4 and re.search(rf":{port}$", fields[3]):
                raise SetupError(f"Local port {port} is already in use.")

    node_uuid = str(uuid.uuid4())
    ws_path = "/ws-" + secrets.token_hex(18)
    install_singbox(app_dir, port, node_uuid, ws_path)
    install_cloudflared(app_dir)
    write_tunnel_launcher(app_dir, port)
    install_unit(unit_dir, "ibt-node.service", node_unit_text())
    install_unit(unit_dir, "ibt-tunnel.service", tunnel_unit_text())
    run_checked(["systemctl", "--user", "daemon-reload"])
    for service in ("ibt-node.service", "ibt-tunnel.service"):
        run_checked(["systemctl", "--user", "enable", "--now", service])
        run_checked(["systemctl", "--user", "is-active", "--quiet", service])
    host = wait_for_tunnel(app_dir / "tunnel.log")
    state = {"port": port, "uuid": node_uuid, "path": ws_path}
    write_private_atomic(app_dir / "state.json", (json.dumps(state) + "\n").encode())
    return make_vless_link(node_uuid, host, ws_path, "VLESS-WS")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install a standalone VLESS+WebSocket node and Cloudflare Quick Tunnel.")
    parser.add_argument("command", nargs="?", choices=("install", "show"), default="install")
    parser.add_argument("--port", default=os.environ.get("IBT_PORT", "20000"),
                        help="local listening port (default: 20000)")
    args = parser.parse_args(argv)
    try:
        app_dir = Path.home() / APP_REL
        if args.command == "show":
            link = get_saved_link(app_dir)
        else:
            link = install(validate_port(args.port))
    except SetupError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    print("Node is running. Import this private link into your client:")
    print(link)
    print("The Quick Tunnel hostname is temporary and changes if Cloudflare rebuilds it.")
    print("This installer does not configure InstaBox API leases or any keepalive scheduler.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
