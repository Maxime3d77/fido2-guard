#!/usr/bin/env python3
"""FIDO2 Guard: read-only hotplug diagnostics for Linux USB FIDO authenticators.

Supports systemd Linux distributions with libfido2 (fido2-token) and pyudev.
This observer NEVER modifies PAM, unlocks, or claims that a detected USB device
is an enrolled credential. For interactive KDE login switching, a greeter-side
PAM integration is required; this standalone watcher cannot provide it.
"""
import argparse
import datetime as dt
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

try:
    import pyudev
except ImportError:
    sys.exit("python3-pyudev is missing. Install dependencies from FIDO2 Guard.")

@dataclass(frozen=True)
class Token:
    sys_path: str
    device: str
    description: str

def enumerate_tokens(ctx):
    binary = shutil.which("fido2-token")
    if binary is None:
        raise RuntimeError("fido2-token not installed (fido2-tools/libfido2)")
    result = subprocess.run([binary, "-L"], capture_output=True, text=True,
                            timeout=12, check=False)
    if result.returncode:
        raise RuntimeError("fido2-token -L failed: " + (result.stderr.strip() or str(result.returncode)))
    tokens = {}
    for line in result.stdout.splitlines():
        device_path, sep, description = line.partition(": ")
        if not sep or not device_path.startswith("/dev/hidraw"):
            continue
        try:
            device = pyudev.Devices.from_device_file(ctx, device_path)
            parent = device.find_parent("usb", "usb_device")
            if parent:
                tokens[parent.sys_path] = Token(parent.sys_path, device_path, description.strip())
        except (OSError, ValueError, pyudev.DeviceNotFoundError):
            continue
    return tokens

def timestamp():
    return dt.datetime.now().astimezone().strftime("%H:%M:%S")

def announce(snapshot, previous=None):
    if previous is None:
        print(f"[{timestamp()}] FIDO2 devices: {len(snapshot)}", flush=True)
        for token in snapshot.values():
            print(f"  PRESENT   {token.device}: {token.description}", flush=True)
        return
    for key in previous.keys() - snapshot.keys():
        t = previous[key]
        print(f"[{timestamp()}] REMOVED   {t.device}: {t.description}", flush=True)
    for key in snapshot.keys() - previous.keys():
        t = snapshot[key]
        print(f"[{timestamp()}] INSERTED  {t.device}: {t.description}", flush=True)

def watch(ctx, previous):
    monitor = pyudev.Monitor.from_netlink(ctx)
    monitor.filter_by(subsystem="usb")
    monitor.start()
    print("Monitoring USB FIDO2 insertions/removals. Ctrl+C to exit.", flush=True)
    print("NOTE: This does not restart KDE PAM authentication or unlock screens.", flush=True)
    last_scan = 0.0
    try:
        while True:
            event = monitor.poll(timeout=0.6)
            if event is None or event.device_type != "usb_device" or event.action not in ("add", "remove"):
                continue
            # Let udev publish hidraw interfaces before re-enumerating.
            time.sleep(0.8)
            current = None
            for attempt in range(3):
                try:
                    current = enumerate_tokens(ctx)
                    break
                except RuntimeError as error:
                    if attempt == 2:
                        print(f"[{timestamp()}] ERROR: {error}", file=sys.stderr, flush=True)
                    time.sleep(0.5)
            if current is not None:
                announce(current, previous)
                previous = current
            last_scan = time.monotonic()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)

def main():
    parser = argparse.ArgumentParser(description="Read-only live FIDO2 USB hotplug diagnostics")
    parser.add_argument("--watch", action="store_true", help="Watch USB insertions/removals")
    args = parser.parse_args()
    context = pyudev.Context()
    try:
        current = enumerate_tokens(context)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(2, str(error) + "\n")
    announce(current)
    if args.watch:
        watch(context, current)

if __name__ == "__main__":
    main()
