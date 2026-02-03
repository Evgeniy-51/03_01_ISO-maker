#!/usr/bin/env bash
set -euo pipefail

# Подготовка базы для ISO Proxmox VE с test-pve-autoinstall.
# Отдельный корень сборки, чтобы не пересекаться с боевым ISO.

PVE_AUTOINSTALL_TEST_ISO_ROOT="${PVE_AUTOINSTALL_TEST_ISO_ROOT:-$HOME/proxmox_iso_pve_autoinstall_test}"
PROXMOX_ISO_URL="${PROXMOX_ISO_URL:-https://enterprise.proxmox.com/iso/proxmox-ve_9.1-1.iso}"
ISO_FILE="$PVE_AUTOINSTALL_TEST_ISO_ROOT/proxmox-ve.iso"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[prepare-test-pve-autoinstall] root: $PVE_AUTOINSTALL_TEST_ISO_ROOT"

# Пакеты
sudo apt-get update
sudo apt-get install -y xorriso squashfs-tools rsync wget

# Каталоги (без binaries/)
mkdir -p "$PVE_AUTOINSTALL_TEST_ISO_ROOT"/{mnt,extract,squashfs-root}
cd "$PVE_AUTOINSTALL_TEST_ISO_ROOT"

# Скачать ISO (если ещё нет)
if [[ ! -f "$ISO_FILE" ]]; then
  wget -O "$ISO_FILE" "$PROXMOX_ISO_URL"
fi
ls -lh "$ISO_FILE"

# Распаковать ISO в extract/
sudo mount -o loop "$ISO_FILE" "$PVE_AUTOINSTALL_TEST_ISO_ROOT/mnt"
sudo rsync -a "$PVE_AUTOINSTALL_TEST_ISO_ROOT/mnt/" "$PVE_AUTOINSTALL_TEST_ISO_ROOT/extract/"
sudo umount "$PVE_AUTOINSTALL_TEST_ISO_ROOT/mnt"

# Распаковать pve-base.squashfs в squashfs-root
sudo rm -rf "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root"
sudo unsquashfs -d "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root" "$PVE_AUTOINSTALL_TEST_ISO_ROOT/extract/pve-base.squashfs"

# Встраивание test-pve-autoinstall в squashfs
sudo mkdir -p "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/usr/local/sbin"
sudo cp "$SCRIPT_DIR/test-pve-autoinstall.sh" \
  "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/usr/local/sbin/test-pve-autoinstall.sh"
sudo chmod 0755 "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/usr/local/sbin/test-pve-autoinstall.sh"

sudo mkdir -p "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/etc/systemd/system"
sudo cp "$SCRIPT_DIR/test-pve-autoinstall.service" \
  "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/etc/systemd/system/test-pve-autoinstall.service"
sudo chmod 0755 "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/etc/systemd/system/test-pve-autoinstall.service"

sudo mkdir -p "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/etc/systemd/system/multi-user.target.wants"
sudo ln -sf ../test-pve-autoinstall.service \
  "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root/etc/systemd/system/multi-user.target.wants/test-pve-autoinstall.service"

echo "[prepare-test-pve-autoinstall] done. Run build-test-pve-autoinstall.sh to build TEST ISO."

