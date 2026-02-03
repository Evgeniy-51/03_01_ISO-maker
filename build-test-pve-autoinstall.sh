#!/usr/bin/env bash
set -euo pipefail

# Сборка TEST ISO Proxmox VE с test-pve-autoinstall.
# Требует предварительного запуска prepare-test-pve-autoinstall.sh.
#
# Переменные:
#   PVE_AUTOINSTALL_TEST_ISO_ROOT — корень сборки
#   DIST_DIR                     — каталог вывода
#   ISO_NAME                     — имя файла (по умолчанию proxmox-test-pve-autoinstall.iso)

PVE_AUTOINSTALL_TEST_ISO_ROOT="${PVE_AUTOINSTALL_TEST_ISO_ROOT:-$HOME/proxmox_iso_pve_autoinstall_test}"
DIST_DIR="${DIST_DIR:-$PVE_AUTOINSTALL_TEST_ISO_ROOT/dist}"
ISO_NAME="${ISO_NAME:-proxmox-test-pve-autoinstall.iso}"
SQUASHFS_OPTS="-comp xz -noappend -no-xattrs -b 1M"
ISO_VOLUME_ID="PVE"

if [[ ! -d "$PVE_AUTOINSTALL_TEST_ISO_ROOT/squashfs-root" ]] || [[ ! -d "$PVE_AUTOINSTALL_TEST_ISO_ROOT/extract" ]]; then
  echo "[build-test-pve-autoinstall] error: run prepare-test-pve-autoinstall.sh first (squashfs-root or extract missing)"
  exit 1
fi

mkdir -p "$DIST_DIR"
DIST_DIR="$(cd "$DIST_DIR" && pwd)"
ISO_OUT="$DIST_DIR/$ISO_NAME"

echo "[build-test-pve-autoinstall] building $ISO_NAME"

cd "$PVE_AUTOINSTALL_TEST_ISO_ROOT"
sudo mksquashfs squashfs-root extract/pve-base.squashfs $SQUASHFS_OPTS

cd "$PVE_AUTOINSTALL_TEST_ISO_ROOT/extract"
sudo xorriso -as mkisofs \
  -o "$ISO_OUT" \
  -R -J -V "$ISO_VOLUME_ID" \
  -b boot/grub/i386-pc/eltorito.img \
  -no-emul-boot -boot-load-size 4 -boot-info-table \
  --grub2-boot-info \
  -eltorito-alt-boot \
  -e efi.img \
  -no-emul-boot \
  -isohybrid-gpt-basdat \
  .

echo "[build-test-pve-autoinstall] done: $ISO_OUT"

