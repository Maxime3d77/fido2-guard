# FIDO2 Guard — v2.9

A Linux **FIDO2/U2F security key manager** with PAM authentication for KDE Plasma and **optional automatic screen locking when a USB FIDO2 key is removed**.

> **Experimental, not security-audited.** Intermittent KScreenLocker issues (black screens and unexpected behavior) have been observed during testing on Linux Mint KDE. Test on a non-critical computer, keep a working password and an administrator recovery console available, and do not deploy directly to production.

## KDE key insertion and screen unlock (v2.8)

**Important limitation:** Inserting a FIDO2 key while KScreenLocker is already waiting for a password does **not** reliably switch the existing PAM conversation to a touch prompt. This depends on KDE's lock-screen implementation; it cannot safely be fixed by a systemd USB watcher or by reloading PAM files. The v2.8 manager therefore **does not claim to automatically switch the locked screen UI**.

Menu **16 — KDE / FIDO2 state diagnostics** checks for detected FIDO devices, registered key count, and whether the KDE PAM profile has a touch-required U2F rule. It is read-only and does not authenticate, unlock, or send keystrokes. This is a diagnostic step toward a future KDE integration rather than the final adaptive UI.

If PAM is already prompting for a touch, touch the key; otherwise use the regular password. The existing password fallback remains available. A true automatic UI transition requires validated changes to KScreenLocker/Plasma that can restart PAM authentication safely when a key arrives, including correct behavior across X11 and Wayland.

## v2.9 — KDE X11 hotplug monitoring (safety update)

**Safety change (November 2026):** A previous experimental watcher sent a synthetic **Enter** key event to KScreenLocker on USB insertion. On a password screen, it can submit an empty password and count as a failed PAM attempt. Users also reported black-screen behavior after FIDO2 unlock (causality not yet determined). **Automatic keyboard injection is now suspended**. The watcher only observes USB insertion/removal and logs the KDE lock state; it does not press keys, restart PAM, or unlock the session.

**Important:** To stop a previously installed copy, run:

```bash
systemctl --user disable --now fido2-kde-retry.service
```

A **Git pull alone does not replace** the installed script in `/usr/local/libexec`. To deploy the updated passive watcher instead of the older injected-key version:

```bash
cd ~/Documents/git/fido2-guard
git pull --ff-only
sudo install -m 755 fido-kde-x11-retry.py /usr/local/libexec/fido2-kde-x11-retry.py
systemctl --user restart fido2-kde-retry.service
```

Or choose **18 — Enable KDE X11 insertion monitor (safe mode)** in the manager. **Option 19** disables it. Option 07 prepares the component without enabling it and does not require reenrolling keys when updating. The watcher does not need `xdotool` in safe monitoring mode.

**KDE limitation:** While locked, a late-inserted FIDO2 token may not automatically restart an already-running PAM password conversation. On affected KDE builds, unlock using **a blank password field → Enter → physical FIDO2 touch**, or the normal Linux password. Automatic switching requires a native, tested KScreenLocker integration; a USB watcher alone cannot provide it. **Never weaken the KDE greeter's ptrace protections or disable the password fallback to force this feature.**

### Isolating a black screen after FIDO2 authentication

1. Disable the experimental service as shown above.
2. Lock with the token already plugged in and unlock by touching it. Compare against normal password unlock. Do **not** test after suspend or a display-mode switch at the same time.
3. If the black screen persists **even with the watcher off**, examine the KDE/X11 and PAM logs; do not edit PAM blindly.

```bash
journalctl -b --since "15 minutes ago" --no-pager |
  grep -Ei 'kscreenlocker|pam_u2f|pam_kwallet|pam_ecryptfs|kwin_x11|plasmashell|sddm|xorg' |
  tail -100
```

The reported screen behavior has not yet been reproduced or attributed to a specific component. No automatic greeter or display-manager restart is attempted.

## Features

- Manage multiple Thetis, YubiKey, and other FIDO2 authenticators.
- Register, list, import, and revoke security keys, with confirmations and backups.
- Authenticate through `pam_u2f` with **physical touch required** (`userpresence=1`).
- Keep your **Linux account password** as a fallback.
- Enable or disable **automatic locking on USB key removal** from the menu (**options 14 / 15**).
- **Never unlock automatically**: the monitoring daemon does **not** call `loginctl unlock-session`.
- KDE PAM diagnostics, service logs, PAM rollback, and confirmed full removal.
- Detect mainstream distribution families using **apt**, **dnf**, or **pacman**.

## Get the latest version

Install Git if it is not already available:

```bash
# Debian / Ubuntu / Linux Mint
sudo apt update && sudo apt install -y git

# Fedora (run instead on Fedora)
# sudo dnf install -y git

# Arch / Manjaro (run instead on Arch-based systems)
# sudo pacman -S --needed git
```

Clone the repository and launch the manager:

```bash
git clone https://github.com/Maxime3d77/fido2-guard.git
cd fido2-guard
sudo bash fido2-guard.sh
```

The tool requires **systemd**, a terminal, and administrator privileges. On supported distributions, select **01 — Dependencies** to install the relevant packages, including `pam-u2f`, `pamu2fcfg`, `fido2-tools`, and `pyudev`.

## Setup

1. Select **02 — Add a key**. Unplug other authenticators and touch the key when prompted.
2. Select **03 — List keys** to confirm registration.
3. Select **07 — Integrated installation**. This checks FIDO2 touch authentication, KDE PAM, and the fallback password path.
4. **Test the actual KDE unlock screen** using both a key touch and your regular password.
5. Only once both methods work, select **14 — Enable lock on removal**, if desired.

Option **07 installs the monitoring daemon but leaves lock-on-removal disabled by default**. This avoids automatically locking a session before its unlock methods have been validated. Option **15** disables removal monitoring without removing the keys or changing PAM.

### Menu reference

| Option | Action |
| --- | --- |
| 01 | Install dependencies |
| 02 / 03 / 04 | Add, list, and revoke keys |
| 05 | Import existing keys |
| 06 | Prepare a FIDO2 PAM touch test |
| 07 | Integrated setup |
| 09 | Restore previous KDE PAM configuration |
| 10 / 13 | Service logs / PAM diagnostics |
| 11 | Remove the monitoring service only |
| 12 | Full removal with explicit confirmation and backup |
| 14 / 15 | Enable / disable lock on removal |
| 16 | Read-only KDE key/PAM state diagnostics |
| 17 | Live USB FIDO2 insertion/removal diagnostics |
| 18 / 19 | Enable / disable passive KDE X11 USB watcher |

*The current terminal interface may display some menu text in French.*

## Automatic dependencies and English interface

The administration dashboard and fallback menu are now in **English**. The package manager's **Install dependencies** action installs the Linux FIDO2/PAM packages and the Python prerequisites for the Textual UI. On Debian, Ubuntu and Linux Mint, this includes `python3-venv` and `python3-pip`.

The first interactive launch also offers to install **Textual inside a dedicated virtual environment**, `/opt/fido2-guard/ui-venv`, using `pip` (requires internet access and Python 3.9+). Confirm with **`y`**. Textual is not installed system-wide. If the virtual environment cannot be created, the manager falls back to the basic menu. Installing prerequisites does not overwrite key registrations or PAM profiles.

Dependency support varies by distribution; in particular, package availability on Arch-based systems may require manual resolution. Verify the actual versions and installed commands before proceeding.

### Key insertion while KDE is already locked

**Re-running Integrated setup (option 7) will not enable automatic switching from a password prompt to the FIDO2 touch prompt.** That feature is **not implemented**. The current daemon monitors USB insertion/removal for lock behavior only, and KDE's lock screen owns the active PAM conversation.

If the key is inserted *after* KDE started a password-only conversation, KDE may not recognize it until authentication is restarted by the lock screen itself. Do not attempt to force `loginctl unlock-session`, inject an OTP, or kill/restart `kscreenlocker` as an automated workaround. Keep password unlock available. A native, version-aware KDE lock-screen integration is required to implement an automatic prompt transition correctly.

To diagnose your current setup without changing PAM:

```bash
sudo bash fido2-guard.sh
# Select "Connected key and KDE status" (option 16).
# Verify the real KDE login and lock screens separately.
```

## Live USB FIDO2 hotplug diagnostics

Use **menu option 17 — Live FIDO2 USB hotplug diagnostics** to observe actual insertion and removal events on Linux, without modifying PAM or the lock screen. This is a useful first check when testing Thetis and YubiKey devices across supported Linux distributions.

Direct command (from your Git clone):

```bash
sudo /usr/bin/python3 fido-hotplug.py --watch
```

Unplug and reinsert your security key. The output should include `REMOVED` and `INSERTED` for recognized USB FIDO2 devices. Press Ctrl+C to stop. The tool uses `fido2-token` and `python3-pyudev`, not a distribution-specific USB polling loop. NFC authenticators are not included.

**This is a diagnostic watcher, not an automatic KDE authenticator.** USB detection proves only that a FIDO2 device is connected, not that it matches a registered PAM credential. The watcher cannot terminate or restart an existing PAM conversation in KScreenLocker, and it never unlocks a session.

The KDE 5.27 lock screen does not provide an independently validated external API for safely replacing an already-active password prompt with an FIDO2 prompt. Delivering this specific UX requires a separately developed and tested KScreenLocker integration, with version-specific handling for Plasma 5 and 6. **Do not run the integrated setup repeatedly to fix this behavior.**

## Configuration health dashboard (v2.9)

The top of the full-screen terminal UI now displays a **read-only health overview**:

- **Packages** — presence of core PAM, FIDO2, and Python-udev tools.
- **Keys** — number of credentials registered for the current user (not proof that a physical key is plugged in or working).
- **KDE PAM** — presence of a touch-required FIDO2 rule and a recognizable password fallback (configuration check, not a live unlock test).
- **Removal lock** — systemd status of the optional lock-on-removal service.
- **Insertion monitor** — user-systemd status of the passive KDE X11 watcher (does **not** restart PAM).

Statuses are `READY`, `CONFIGURED`, `ACTIVE`, `DISABLED`, `MISSING`, or `ERROR`. **Disabled optional functions are not treated as setup errors.** The dashboard shows recommended menu actions when anything is missing. Press **F5** to refresh, or wait for its periodic refresh (15 seconds). Starting the interface does not modify PAM, register keys, or toggle services.

**Important:** A status of `CONFIGURED` means the relevant files and services appear correctly set up, **not** that FIDO2 unlocking has been successfully tested on the current device. Verify the real KDE lock screen with both touch and password.

## Modern terminal dashboard

The manager now includes a **full-screen Textual TUI**, with a live action search field, scrollable selection list, detail panel, and status header. It runs in a **dedicated Python virtual environment** under `/opt/fido2-guard/ui-venv`, without installing Python packages into the system interpreter.

On first launch, the script can offer to install Textual. On Debian, Ubuntu, or Linux Mint, if virtual environment creation is unavailable, first run:

```bash
sudo apt install -y python3-venv
```

Then launch again:

```bash
git pull --ff-only
sudo bash fido2-guard.sh
```

When prompted, choose `y` to install the terminal UI. This requires Python 3.9+ and network access to PyPI. Textual is optional; if installation fails, the existing fallback menu remains available. The terminal UI is only an administrative interface and never modifies PAM or unlocks sessions by itself.

## Navigating the menu

In the Textual UI, use the **Up/Down arrow keys** to scroll through the options, **Enter** to select, and **Esc** to exit. Use `/` to focus the search input and `F5` to clear the filter. A basic dialog or plain-text fallback remains available if Textual is missing.

**Updating from v2.7 to v2.8:** Running `git pull --ff-only` and launching `sudo bash fido2-guard.sh` is sufficient to use the updated menu and diagnostic option 16. **Do not rerun option 7** merely to update the menu: integrated installation re-tests PAM and related services and should only be used when setting up or repairing that integration. Existing key mappings and installed service configuration remain unchanged after a Git pull.

## Update from Git

From the cloned repository directory:

```bash
git pull --ff-only
sudo bash fido2-guard.sh
```

When upgrading from an earlier v1.x or v2.x build, **do not purge first**: existing key mappings in `/etc/thetis-auth/u2f_keys` can be reused. Disable the previous monitoring service while testing:

```bash
sudo systemctl disable --now thetis-guard.service
```

Then use option **07** to update the installed component, followed by option **14** if you want to explicitly enable lock-on-removal.

## Service management and troubleshooting

```bash
# Inspect the service
sudo systemctl status thetis-guard.service

# View recent service logs
sudo journalctl -u thetis-guard.service -n 80 --no-pager

# Disable lock-on-removal immediately
sudo systemctl disable --now thetis-guard.service
```

Stopping the daemon does **not** remove registered keys or KDE PAM authentication. If KDE unlock stops working as expected, use **option 09** to restore the prior PAM configuration. Do **not** manually delete `/etc/pam.d/kde`.

To inspect KScreenLocker-related logs:

```bash
journalctl --user -b --no-pager | grep -Ei 'kscreenlocker|kwin|plasmashell|sddm' | tail -80
sudo journalctl -b --no-pager | grep -Ei 'pam_u2f|pam_unix\(kde:auth\)|kscreenlocker' | tail -80
```

If touching a YubiKey types a long string into the password field, that is the keyboard-emulating **OTP interface**, **not** successful FIDO2 authentication.

## Compatibility and security limitations

The installer recognizes `apt`, `dnf`, and `pacman` distributions, but **PAM integration is not guaranteed across all Linux configurations**. KDE's actual PAM service name can depend on how it was built and packaged. Immutable distributions, GNOME, and SELinux-enforcing environments require separate evaluation. On Arch-based systems, `pamtester` might not be available through the default `pacman` repositories.

USB removal detection monitors **recognized FIDO devices**, not exclusively individually registered keys. Therefore an unregistered device may trigger locking, and removing one key may lock the session even when another key remains connected. NFC authenticators are not monitored. The monitoring service itself **does not cryptographically authenticate the key**: that happens through PAM when unlocking.

This project has **not undergone a security audit** and is not a replacement for full-disk encryption or endpoint protection.

## Repository layout

```text
fido2-guard/
├── README.md
├── fido2-guard.sh           # Terminal administration and setup menu
├── fido-removal-guard.py    # USB removal monitor; locks only
├── fido-hotplug.py         # Read-only event diagnostics
├── fido-kde-x11-retry.py   # Passive KDE X11 USB insertion monitor (no key injection)
└── fido-tui.py             # Modern Textual TUI
```

**Version:** 2.9. **License:** No redistribution license has been explicitly granted until a LICENSE file is added.
