"""Hardware-free verification of the Linux distro adapter (no package installs)."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPAT = ROOT / "fido-linux-compat.sh"


def probe(os_release):
    with tempfile.TemporaryDirectory(prefix="fido2-distro-test-") as tmp:
        fixture = Path(tmp) / "os-release"
        fixture.write_text(os_release, encoding="utf-8")
        script = (
            'source "$1"; fido_linux_detect "$2"; '
            'printf "%s\\n" "$FIDO_OS_ID" "$FIDO_OS_PACKAGE_MANAGER"; '
            'fido_linux_packages core'
        )
        result = subprocess.run(
            ["bash", "-c", script, "fido-test", str(COMPAT), str(fixture)],
            capture_output=True, text=True, timeout=5, check=False
        )
        return result.returncode, result.stdout.splitlines(), result.stderr


class LinuxCompatibilityTests(unittest.TestCase):
    def test_debian_family(self):
        code, rows, _ = probe('ID=linuxmint\nID_LIKE="ubuntu debian"\n')
        self.assertEqual(code, 0)
        self.assertEqual(rows[1], "apt")
        self.assertIn("libpam-u2f", rows[2])
        self.assertIn("pamu2fcfg", rows[2])

    def test_fedora_family(self):
        code, rows, _ = probe('ID=rocky\nID_LIKE="rhel centos fedora"\n')
        self.assertEqual(code, 0)
        self.assertEqual(rows[1], "dnf")
        self.assertIn("pam-u2f", rows[2])
        self.assertIn("python3-pyudev", rows[2])

    def test_arch_package_contains_pamu2fcfg_and_fido2_token(self):
        code, rows, _ = probe('ID=arch\n')
        self.assertEqual(code, 0)
        self.assertEqual(rows[1], "pacman")
        self.assertIn("pam-u2f", rows[2])
        self.assertIn("libfido2", rows[2])
        self.assertNotIn("fido2-tools", rows[2])

    def test_suse_uses_underscore_name(self):
        code, rows, _ = probe('ID=opensuse-tumbleweed\nID_LIKE="suse opensuse"\n')
        self.assertEqual(code, 0)
        self.assertEqual(rows[1], "zypper")
        self.assertIn("pam_u2f", rows[2])

    def test_unknown_distro_fails_closed(self):
        code, rows, _ = probe('ID=not-a-linux-family\n')
        self.assertNotEqual(code, 0)
        self.assertEqual(rows[1], "unsupported")

    def test_package_inspection_has_no_side_effects(self):
        source = COMPAT.read_text(encoding="utf-8")
        self.assertIn("BASH_SOURCE[0]", source)
        self.assertIn("--packages)", source)
        self.assertIn("--check)", source)
        self.assertIn("FIDO_OS_IMMUTABLE", source)
        self.assertNotIn("pacman -Sy", source)

    def test_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(COMPAT)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
