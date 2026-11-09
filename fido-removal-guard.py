#!/usr/bin/env python3
"""FIDO2 Guard v2.7: USB removal monitor, LOCK ONLY.

Tracks USB physical device identity by sysfs path. A successful FIDO
cryptographic assertion is NOT implied by USB detection. The daemon
never unlocks, never edits PAM and never authenticates users.
"""
import logging
import pwd
import subprocess
import sys
import time
from pathlib import Path

try:
    import pyudev
except ImportError:
    sys.exit('python3-pyudev is required (install from menu 01)')

logging.basicConfig(level=logging.INFO, format='%(asctime)s [FIDO-GUARD] %(message)s')
USER = sys.argv[1] if len(sys.argv) == 2 else ''
try:
    UID = pwd.getpwnam(USER).pw_uid
except KeyError:
    sys.exit('Invalid account')

CTX = pyudev.Context()

def command(argv, timeout=10):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logging.warning('Command %s failed: %s', argv[0], exc)
        return None

def usb_parent(hidraw_path):
    try:
        device = pyudev.Devices.from_device_file(CTX, hidraw_path)
        parent = device.find_parent('usb', 'usb_device')
        return parent.sys_path if parent else None
    except (OSError, pyudev.DeviceNotFoundError, ValueError):
        return None

def known_token_usb_paths():
    """Discover existing USB FIDO authenticators without VID/PID allowlisting.

    Only called at startup and after USB insertion, never in the lock path.
    """
    result = command(['/usr/bin/fido2-token', '-L'], timeout=12)
    if result is None or result.returncode != 0:
        logging.warning('FIDO discovery failed; existing token set unchanged')
        return None
    recognized = set()
    for line in result.stdout.splitlines():
        path = line.partition(':')[0].strip()
        if not path.startswith('/dev/hidraw'):
            continue
        parent = usb_parent(path)
        if parent:
            recognized.add(parent)
    return recognized

def graphical_session():
    found = command(['loginctl', 'list-sessions', '--no-legend', '--no-pager'])
    if found is None or found.returncode:
        return None
    for line in found.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != str(UID):
            continue
        sid = parts[0]
        details = command(['loginctl', 'show-session', sid, '-p', 'Type', '-p', 'Active',
                           '-p', 'Remote', '-p', 'Class', '-p', 'Name'])
        if details is None or details.returncode:
            continue
        props = dict(entry.split('=', 1) for entry in details.stdout.splitlines()
                     if '=' in entry)
        if (props.get('Name') == USER and props.get('Type') in ('x11', 'wayland')
                and props.get('Active') == 'yes' and props.get('Remote') == 'no'
                and props.get('Class') == 'user'):
            return sid
    return None

def lock():
    sid = graphical_session()
    if not sid:
        logging.info('No local active GUI session; no action')
        return
    result = command(['loginctl', 'lock-session', sid])
    logging.info('Lock session %s: %s', sid,
                 'OK' if result is not None and result.returncode == 0 else 'FAILED')

def main():
    known = known_token_usb_paths()
    if known is None:
        logging.warning('No reliable initial enumeration; deferring until USB insertion')
        known = set()
    logging.info('Started for %s: %d USB FIDO token(s), LOCK ONLY', USER, len(known))
    monitor = pyudev.Monitor.from_netlink(CTX)
    monitor.filter_by(subsystem='usb')
    monitor.start()
    last_lock = 0.0
    while True:
        event = monitor.poll(timeout=1)
        if event is None or event.device_type != 'usb_device':
            continue
        path = event.sys_path
        if event.action == 'remove':
            if path in known:
                known.discard(path)
                # Deduplicate bursts from a multi-interface token.
                now = time.monotonic()
                if now - last_lock >= 1.5:
                    logging.info('Known USB FIDO authenticator removed: %s', path)
                    lock()
                    last_lock = now
        elif event.action == 'add':
            # Never unlock when a token arrives.
            time.sleep(0.7)
            refreshed = known_token_usb_paths()
            if refreshed is not None:
                known = refreshed
                logging.info('USB insertion: %d FIDO token(s) detected; no unlock', len(known))

if __name__ == '__main__':
    main()
