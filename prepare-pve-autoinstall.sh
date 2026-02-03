#!/usr/bin/env bash
set -euo pipefail

# Подготовка машины Ubuntu и базы для сборки ISO Proxmox VE с pve-autoinstall.
# Запускать один раз: ставит пакеты, скачивает официальный ISO, распаковывает
# в extract/ и pve-base.squashfs в squashfs-root/, вшивает pve-autoinstall (roadmap п.2).

PVE_AUTOINSTALL_ISO_ROOT="${PVE_AUTOINSTALL_ISO_ROOT:-$HOME/proxmox_iso_pve_autoinstall}"
PROXMOX_ISO_URL="${PROXMOX_ISO_URL:-https://enterprise.proxmox.com/iso/proxmox-ve_9.1-1.iso}"
ISO_FILE="$PVE_AUTOINSTALL_ISO_ROOT/proxmox-ve.iso"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[prepare-pve-autoinstall] root: $PVE_AUTOINSTALL_ISO_ROOT"

# Пакеты
sudo apt-get update
sudo apt-get install -y xorriso squashfs-tools rsync wget

# Каталоги (без binaries/ — в этом образе только pve-autoinstall)
mkdir -p "$PVE_AUTOINSTALL_ISO_ROOT"/{mnt,extract,squashfs-root}
cd "$PVE_AUTOINSTALL_ISO_ROOT"

# Скачать ISO (если ещё нет)
if [[ ! -f "$ISO_FILE" ]]; then
  wget -O "$ISO_FILE" "$PROXMOX_ISO_URL"
fi
ls -lh "$ISO_FILE"

# Распаковать ISO в extract/
sudo mount -o loop "$ISO_FILE" "$PVE_AUTOINSTALL_ISO_ROOT/mnt"
sudo rsync -a "$PVE_AUTOINSTALL_ISO_ROOT/mnt/" "$PVE_AUTOINSTALL_ISO_ROOT/extract/"
sudo umount "$PVE_AUTOINSTALL_ISO_ROOT/mnt"

# Распаковать pve-base.squashfs в squashfs-root
sudo rm -rf "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root"
sudo unsquashfs -d "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root" "$PVE_AUTOINSTALL_ISO_ROOT/extract/pve-base.squashfs"

# Встраивание pve-autoinstall в squashfs (roadmap п.2)
sudo mkdir -p "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/usr/local/sbin"
sudo cp "$SCRIPT_DIR/pve-autoinstall.sh" "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/usr/local/sbin/pve-autoinstall.sh"
sudo chmod 0755 "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/usr/local/sbin/pve-autoinstall.sh"

sudo mkdir -p "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/etc/systemd/system"
sudo cp "$SCRIPT_DIR/pve-autoinstall.service" "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/etc/systemd/system/pve-autoinstall.service"
sudo chmod 0755 "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/etc/systemd/system/pve-autoinstall.service"

sudo mkdir -p "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/etc/systemd/system/multi-user.target.wants"
sudo ln -sf ../pve-autoinstall.service "$PVE_AUTOINSTALL_ISO_ROOT/squashfs-root/etc/systemd/system/multi-user.target.wants/pve-autoinstall.service"

echo "[prepare-pve-autoinstall] done. Run build-pve-autoinstall.sh to build ISO."
