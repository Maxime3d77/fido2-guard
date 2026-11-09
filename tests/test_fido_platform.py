"""Hardware-free smoke tests for portable FIDO2 Guard desktop capabilities."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location(
    "fido_platform", Path(__file__).resolve().parents[1] / "fido-platform.py")
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)


def completed(output, status=0):
    return SimpleNamespace(stdout=output, returncode=status)


class DesktopCapabilitiesTests(unittest.TestCase):
    def test_login_session_finds_active_local_x11(self):
        def fake_command(*args):
            if args[:2] == ("loginctl", "list-sessions"):
                return completed("c1 1000 maxime seat0 tty2\nc2 1000 maxime seat0 tty3\n")
            if args[:2] == ("loginctl", "show-session") and args[2] == "c1":
                return completed("Type=tty\nActive=no\nRemote=no\n")
            return completed("Type=x11\nActive=yes\nRemote=no\n")
        with patch.object(platform, "command", side_effect=fake_command):
            self.assertEqual(platform.login_session(1000), {"type": "x11", "id": "c2"})

    def test_plasma_versions(self):
        with patch.object(platform.shutil, "which", return_value="/usr/bin/plasmashell"):
            with patch.object(platform, "command", return_value=completed("plasmashell 5.27.12")):
                self.assertEqual(platform.plasma_version(), {"major": 5, "version": "5.27.12"})
            with patch.object(platform, "command", return_value=completed("plasmashell 6.8.2")):
                self.assertEqual(platform.plasma_version(), {"major": 6, "version": "6.8.2"})

    def test_login_manager_systemd(self):
        with patch.object(platform, "command", return_value=completed("Id=lightdm.service\n")):
            self.assertEqual(platform.desktop_manager(), "lightdm")

    def test_ecryptfs_fs_detection(self):
        with patch.object(platform, "command", return_value=completed("ecryptfs\n")):
            self.assertEqual(platform.home_filesystem("/home/example"), "ecryptfs")

    def test_no_rule_in_comments(self):
        with patch.object(Path, "read_text", return_value=(
            "# auth sufficient pam_u2f.so\nauth include common-auth\n")):
            self.assertEqual(platform.active_pam_rules("/etc/pam.d/kde"),
                             ["auth include common-auth"])


if __name__ == "__main__":
    unittest.main()
