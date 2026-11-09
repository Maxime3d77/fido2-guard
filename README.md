# FIDO2 Guard — v2.7

A Linux **FIDO2/U2F security key manager** with PAM authentication for KDE Plasma and **optional automatic screen locking when a USB FIDO2 key is removed**.

> **Experimental, not security-audited.** Intermittent KScreenLocker issues (black screens and unexpected behavior) have been observed during testing on Linux Mint KDE. Test on a non-critical computer, keep a working password and an administrator recovery console available, and do not deploy directly to production.

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

*The current terminal interface may display some menu text in French.*

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
└── fido-removal-guard.py    # USB removal monitor; locks only
```

**Version:** 2.7. **License:** No redistribution license has been explicitly granted until a LICENSE file is added.
