"""Hardware-free tests for the safe, per-user screen-lock trace."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location(
    "fido_lock_trace", Path(__file__).resolve().parents[1] / "fido-lock-trace.py")
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)


def completed(output, status=0):
    return SimpleNamespace(stdout=output, returncode=status)


class LockTraceTests(unittest.TestCase):
    def test_xrandr_monitor_count(self):
        sample = ("Monitors: 3\n"
                  " 0: +*eDP 1920/302x1200/189+1920+0  eDP\n"
                  " 1: +HDMI-A-0 1920/521x1080/293+0+60  HDMI-A-0\n"
                  " 2: +DisplayPort-1 1920/521x1080/293+3840+60  DisplayPort-1\n")
        self.assertEqual(trace.parse_monitors(sample), 3)
        with patch.dict(trace.os.environ, {"DISPLAY": ":0", "XDG_SESSION_TYPE": "x11"}):
            with patch.object(trace.shutil, "which", return_value="/usr/bin/xrandr"):
                with patch.object(trace, "run", return_value=completed(sample)):
                    self.assertEqual(trace.screen_layout(), {
                        "count": 3,
                        "names": ["eDP", "HDMI-A-0", "DisplayPort-1"],
                        "source": "xrandr",
                    })

    def test_wayland_does_not_use_xwayland_monitor_count(self):
        with patch.dict(trace.os.environ, {"DISPLAY": ":1", "XDG_SESSION_TYPE": "wayland"}):
            result = trace.screen_layout()
        self.assertEqual(result["count"], None)
        self.assertEqual(result["source"], "wayland-not-probed")

    def test_only_own_screenlocker_processes_recorded(self):
        sample = ("100 1000 kscreenlocker_g\n"
                  "101 1000 kwin_x11\n"
                  "102 1000 plasmashell\n"
                  "103 0 kscreenlocker_g\n"
                  "104 1000 unrelated-program\n")
        with patch.object(trace, "run", return_value=completed(sample)):
            self.assertEqual(trace.desktop_processes(1000),
                             {"kscreenlocker_g": [100],
                              "kwin_x11": [101],
                              "plasmashell": [102]})

    def test_lockedhint_is_reporting_only(self):
        with patch.object(trace, "run", return_value=completed(
                "Type=x11\nActive=yes\nLockedHint=no\n")):
            result = trace.session_state("c2")
        self.assertEqual(result["locked_hint"], "no")
        self.assertEqual(result["type"], "x11")


if __name__ == "__main__":
    unittest.main()
