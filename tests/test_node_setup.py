from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import uuid

MODULE_PATH = Path(__file__).resolve().parents[1] / "node-setup" / "node_setup.py"
spec = importlib.util.spec_from_file_location("node_setup", MODULE_PATH)
assert spec and spec.loader
node_setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node_setup)


class NodeSetupTests(unittest.TestCase):
    def test_port_bounds_and_format(self):
        self.assertEqual(node_setup.validate_port("20000"), 20000)
        for invalid in ("80", "65536", "02000", "1.5", "abc", " 20000"):
            with self.subTest(invalid=invalid), self.assertRaises(node_setup.SetupError):
                node_setup.validate_port(invalid)

    def test_config_binds_only_loopback_and_validated_path(self):
        user = str(uuid.uuid4())
        path = "/ws-" + "a" * 36
        config = node_setup.build_config(user, 20000, path)
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["listen_port"], 20000)
        self.assertEqual(inbound["users"][0]["uuid"], user)
        self.assertEqual(inbound["transport"]["path"], path)
        with self.assertRaises(node_setup.SetupError):
            node_setup.build_config(user, 20000, "/not-a-random-path")

    def test_uri_encodes_path_and_label(self):
        user = str(uuid.uuid4())
        link = node_setup.make_vless_link(user, "abc.trycloudflare.com", "/ws-" + "b" * 36, "private node")
        self.assertIn("@abc.trycloudflare.com:443?", link)
        self.assertIn("path=%2Fws-", link)
        self.assertTrue(link.endswith("#private%20node"))
        for host in ("bad/host", "a..trycloudflare.com", "example.com"):
            with self.subTest(host=host), self.assertRaises(node_setup.SetupError):
                node_setup.make_vless_link(user, host, "/ws-" + "b" * 36)

    def test_units_are_user_scoped_and_restart_services(self):
        node = node_setup.node_unit_text()
        tunnel = node_setup.tunnel_unit_text()
        for text in (node, tunnel):
            self.assertIn("NoNewPrivileges=yes", text)
            self.assertIn("Restart=always", text)
            self.assertIn(node_setup.MARKER, text)
        self.assertIn("%h/.local/share/ibt-node/bin/sing-box", node)
        self.assertIn("ibt-node.service", tunnel)

    def test_tunnel_launcher_uses_isolated_quick_tunnel_and_clears_old_log(self):
        with tempfile.TemporaryDirectory() as td:
            app = Path(td) / "app"
            (app / "bin").mkdir(parents=True)
            node_setup.write_tunnel_launcher(app, 20000)
            text = (app / "bin/start-tunnel").read_text()
            self.assertIn(": > \"$base/tunnel.log\"", text)
            self.assertIn("--config \"$base/quick-config.yml\"", text)
            self.assertIn("--url \"http://127.0.0.1:20000\"", text)
            self.assertIn("-u TUNNEL_TOKEN", text)
            self.assertEqual((app / "quick-config.yml").read_text(), "{}\n")
            self.assertEqual((app / "bin/start-tunnel").stat().st_mode & 0o777, 0o700)

    def test_private_atomic_write_and_refuse_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "private" / "state.json"
            node_setup.write_private_atomic(path, b'{"ok": true}\n')
            self.assertEqual(path.read_bytes(), b'{"ok": true}\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = path.parent / "link"
            link.symlink_to(path)
            with self.assertRaises(node_setup.SetupError):
                node_setup.write_private_atomic(link, b"replacement")
            self.assertEqual(path.read_bytes(), b'{"ok": true}\n')

    def test_quick_host_parser_uses_latest_valid_hostname(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "tunnel.log"
            log.write_text("first https://old.trycloudflare.com\nfailed\nhttps://new-host.trycloudflare.com\n")
            self.assertEqual(node_setup.find_quick_host(log), "new-host.trycloudflare.com")

    def test_node_app_scope_does_not_reference_instabox_api_or_keepalive(self):
        source = MODULE_PATH.read_text()
        self.assertNotIn("api.instabox.sh", source)
        self.assertNotIn("heartbeat.py", source)
        self.assertNotIn("machines:write", source)
        self.assertEqual(node_setup.APP_REL, Path(".local/share/ibt-node"))

    def test_installer_pinned_assets_use_https_and_sha256(self):
        self.assertTrue(node_setup.SB_URL.startswith("https://"))
        self.assertTrue(node_setup.CF_URL.startswith("https://"))
        self.assertRegex(node_setup.SB_SHA256, r"^[0-9a-f]{64}$")
        self.assertRegex(node_setup.CF_SHA256, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
