# FIDO2 Guard — v2.7

Gestionnaire Linux de clés **FIDO2/U2F** avec authentification PAM pour KDE Plasma et verrouillage **facultatif** lors du retrait physique d'une clé USB FIDO2.

> **Version pilote, non auditée.** Des anomalies intermittentes de KScreenLocker (écran noir ou comportement inattendu) ont été observées sur Linux Mint KDE. Tester sur une machine non critique et conserver un mot de passe et une console de secours. Ne pas déployer directement en production.

## Fonctionnalités

- Gestion de plusieurs clés Thetis, YubiKey ou autres authentificateurs FIDO2.
- Ajout, liste, import, révocation avec confirmation et sauvegardes.
- Authentification `pam_u2f` avec **toucher requis** (`userpresence=1`).
- Conservation du **mot de passe Linux** comme solution de secours.
- Verrouillage au retrait USB activable et désactivable dans le menu (**14 / 15**).
- **Jamais de déverrouillage automatique** : le démon ne lance pas `loginctl unlock-session`.
- Diagnostic PAM KDE, journaux, restauration PAM et purge complète avec confirmations.
- Détection des distributions classiques utilisant **apt**, **dnf** et **pacman**.

## Installer la dernière version

Installer Git si nécessaire :

```bash
# Debian / Ubuntu / Linux Mint
sudo apt update && sudo apt install -y git

# Fedora
# sudo dnf install -y git

# Arch / Manjaro
# sudo pacman -S --needed git
```

Cloner le dépôt et lancer le menu :

```bash
git clone https://github.com/Maxime3d77/fido2-guard.git
cd fido2-guard
sudo bash fido2-guard.sh
```

Le script nécessite **systemd**, un terminal et des droits administrateur. Sur les distributions compatibles, choisir **01 — Dépendances** pour installer les outils `pam-u2f`, `pamu2fcfg`, `fido2-tools`, `pyudev`, etc.

## Installation / mise en route

1. **02 — Ajouter une clé** ; débrancher les autres authentificateurs et toucher la clé demandée.
2. **03 — Lister les clés** pour vérifier l'enregistrement.
3. **07 — Installation intégrée** : vérifie FIDO2 avec toucher, PAM KDE, puis la méthode de secours.
4. Tester réellement le déverrouillage KDE par **toucher** et **mot de passe**.
5. **14 — Activer le verrouillage au retrait** uniquement après les tests.

L'option **07 installe le démon mais laisse la surveillance du retrait désactivée par défaut** ; ce choix évite de verrouiller automatiquement une session dont le déverrouillage n'a pas encore été éprouvé. L'option **15** désactive la surveillance sans toucher aux clés ou à PAM.

### Principales options du menu

| Option | Action |
| --- | --- |
| 01 | Dépendances |
| 02 / 03 / 04 | Ajouter, lister et révoquer les clés |
| 05 | Importer des clés existantes |
| 06 | Préparer un test PAM FIDO2 |
| 07 | Installation intégrée |
| 09 | Restaurer PAM KDE |
| 10 / 13 | Journaux / diagnostic |
| 11 | Supprimer le service uniquement |
| 12 | Purge complète avec confirmation et sauvegarde |
| 14 / 15 | Activer / désactiver le verrouillage au retrait |

## Mettre à jour depuis Git

Dans le dossier du clone :

```bash
git pull --ff-only
sudo bash fido2-guard.sh
```

Depuis une ancienne v1.x ou v2.x, **ne pas purger d'abord** : les autorisations sont conservées dans `/etc/thetis-auth/u2f_keys`. Durant les tests, désactiver le service précédent :

```bash
sudo systemctl disable --now thetis-guard.service
```

Utiliser ensuite l'option 07 pour mettre à jour le composant, et l'option 14 pour activer volontairement le retrait.

## Gestion du service et diagnostic

```bash
sudo systemctl status thetis-guard.service
sudo journalctl -u thetis-guard.service -n 80 --no-pager
sudo systemctl disable --now thetis-guard.service
```

L'arrêt du service n'enlève ni les autorisations ni PAM KDE. Si le verrouillage KDE pose problème, utiliser l'option **09** pour revenir à l'ancienne configuration PAM. Ne pas supprimer `/etc/pam.d/kde` manuellement.

Journaux KScreenLocker :

```bash
journalctl --user -b --no-pager | grep -Ei 'kscreenlocker|kwin|plasmashell|sddm' | tail -80
sudo journalctl -b --no-pager | grep -Ei 'pam_u2f|pam_unix\(kde:auth\)|kscreenlocker' | tail -80
```

Si une YubiKey écrit un long code dans le champ mot de passe, il s'agit de son interface **OTP clavier**, pas d'une authentification FIDO2.

## Compatibilité et limites

Le script détecte les distributions `apt`, `dnf` et `pacman`, mais l'intégration PAM **n'est pas garantie pour tous les environnements**. Le service PAM utilisé par KDE dépend de sa compilation et de la distribution. Les distributions immuables, GNOME et les environnements SELinux enforcing demandent une validation séparée. Sur Arch, `pamtester` peut ne pas être installé par `pacman` sans dépôt tiers.

Le retrait USB détecte des **périphériques FIDO**, pas exclusivement les clés enregistrées : une clé inconnue peut aussi provoquer un verrouillage, et le retrait d'une clé peut verrouiller alors qu'une autre est encore connectée. Les authentificateurs NFC ne sont pas surveillés. Le démon ne prouve **pas** la possession de la clé ; l'authentification cryptographique intervient dans PAM au déverrouillage. Ceci n'est pas une solution de sécurité auditée et ne remplace pas le chiffrement du disque.

## Structure

```text
fido2-guard/
├── README.md
├── fido2-guard.sh           # gestionnaire terminal / installation
└── fido-removal-guard.py    # service de verrouillage USB uniquement
```

**Version : 2.7.** Aucune licence de réutilisation n'est explicitement accordée tant qu'un fichier LICENSE n'est pas ajouté.
