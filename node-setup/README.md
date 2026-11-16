# Standalone node setup

This folder contains the extracted node-installation portion of InstaBox-Tool, separated from the InstaBox account and machine-management code.

It installs a VLESS over WebSocket node using sing-box and exposes it through a Cloudflare Quick Tunnel. It does not read or request an InstaBox API key, create InstaBox activity leases for the host, or install the original machine manager. The tunnel hostname is temporary; if Cloudflare rebuilds the tunnel, retrieve a fresh link with `show` and re-import it in your client.

## Requirements

- Linux x86_64, a regular (non-root) user, Python 3, `tar`, and a working user-level systemd session.
- Outbound HTTPS access to the pinned sing-box and cloudflared release downloads, and Cloudflare Quick Tunnel service.
- A host and plan where running a proxy service is permitted. Check the provider’s current terms before deploying; this installer does not override provider restrictions.

## Install

From this directory, run:

```sh
python3 node_setup.py install
```

Optional local port (default `20000`):

```sh
python3 node_setup.py install --port 20001
```

It downloads pinned upstream release assets and verifies their SHA-256 digests before installation. It creates a dedicated `~/.local/share/ibt-node/` tree and two user services (`ibt-node.service`, `ibt-tunnel.service`). Existing unrelated files or conflicting service definitions are not overwritten. The generated VLESS URI contains the node UUID and should be treated as a secret; do not post it publicly.

The services are enabled for the user systemd manager. Keeping them running after logout or reboot may require user lingering, according to the host’s systemd policy; this tool does not change that setting.

Show the current link after a tunnel restart:

```sh
python3 node_setup.py show
```

## Scope and limitations

This is an extraction, not a complete migration or an unattended deployment. It does not set up InstaBox machine keepalive, enforce a daily runtime limit, install a fixed domain, or guarantee Cloudflare tunnel availability. The installer was not run against a live target machine as part of this branch work.
