#!/usr/bin/env bash
set -euo pipefail

MARKER="/var/lib/pve-autoinstall/done"
LOG_TAG="pve-autoinstall"
NET_FILE="/etc/network/interfaces"

mkdir -p "$(dirname "$MARKER")"

log() { echo "[$(date -Is)] $*" | systemd-cat -t "$LOG_TAG"; }

if [[ -f "$MARKER" ]]; then
  log "Already done (marker exists: $MARKER). Exiting."
  exit 0
fi

log "Starting Proxmox autoinstall..."

# --- Wait services ---
log "Waiting for pve-cluster..."
for i in {1..60}; do
  if systemctl is-active --quiet pve-cluster; then break; fi
  sleep 2
done
systemctl is-active --quiet pve-cluster || { log "ERROR: pve-cluster not ready"; exit 1; }
log "pve-cluster ready."

log "Waiting for network-online..."
for i in {1..60}; do
  if systemctl is-active --quiet network-online.target; then break; fi
  sleep 2
done
log "network-online target reached (or timed out)."

# --- Time sync (avoid "not valid yet" / unsigned repo issues) ---
log "Ensuring NTP time sync on PVE host (fail-fast)..."
timedatectl set-ntp true 2>/dev/null || true
systemctl restart systemd-timesyncd 2>/dev/null || true
for i in {1..12}; do
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx "yes"; then
    break
  fi
  sleep 5
done
if ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx "yes"; then
  log "ERROR: NTP not synchronized on PVE host. Check UDP/123 access or systemd-timesyncd."
  exit 1
fi
log "PVE time OK: $(date -Is)"

# --- Post-install repo policies and updates ---
DISABLE_ENTERPRISE_REPO=1
ENABLE_NO_SUBSCRIPTION_REPO=1
ADD_CEPH_NO_SUBSCRIPTION_REPO=1
ADD_PVETEST_DISABLED=1
DISABLE_SUBSCRIPTION_NAG=1
DISABLE_HA_ON_SINGLE_NODE=1
DO_DIST_UPGRADE=1
APT_PROXY=""

get_pve_version() {
  pveversion 2>/dev/null | awk -F'/' '{print $2}' | awk -F'-' '{print $1}'
}

pve_major_minor() {
  local ver="$1"
  local major minor
  IFS='.' read -r major minor _ <<<"$ver"
  echo "$major" "$minor"
}

component_exists_in_sources() {
  local component="$1"
  grep -h -E "^[^#]*Components:[^#]*\b${component}\b" /etc/apt/sources.list.d/*.sources 2>/dev/null | grep -q .
}

ensure_deb822_trixie_sources() {
  log "Ensuring deb822 sources for Debian (trixie)..."

  mkdir -p /etc/apt/sources.list.d
  cat >/etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie
Components: main contrib
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main contrib
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie-updates
Components: main contrib
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
}

ensure_legacy_bookworm_sources() {
  log "Ensuring legacy sources for Debian (bookworm)..."

  cat >/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib
deb http://deb.debian.org/debian bookworm-updates main contrib
deb http://security.debian.org/debian-security bookworm-security main contrib
EOF
  echo 'APT::Get::Update::SourceListWarnings::NonFreeFirmware "false";' >/etc/apt/apt.conf.d/no-bookworm-firmware.conf
}

disable_enterprise_repo_legacy() {
  log "Disabling pve-enterprise (legacy)..."
  cat >/etc/apt/sources.list.d/pve-enterprise.list <<'EOF'
# deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise
EOF
}

add_enterprise_repo_deb822_disabled() {
  :
}

disable_enterprise_repo_deb822() {
  log "Disabling pve-enterprise (deb822) if present..."
  for file in /etc/apt/sources.list.d/*.sources; do
    [[ -f "$file" ]] || continue
    if grep -q "Components:.*pve-enterprise" "$file"; then
      if grep -q "^Enabled:" "$file"; then
        sed -i 's/^Enabled:.*/Enabled: false/' "$file"
      else
        echo "Enabled: false" >>"$file"
      fi
    fi
  done
}

enable_no_subscription_repo_legacy() {
  log "Enabling pve-no-subscription (legacy)..."
  cat >/etc/apt/sources.list.d/pve-install-repo.list <<'EOF'
deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription
EOF
}

enable_no_subscription_repo_deb822() {
  log "Enabling pve-no-subscription (deb822)..."
  cat >/etc/apt/sources.list.d/proxmox.sources <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
}

add_ceph_repo_deb822_optional() {
  log "Adding Ceph repo (deb822, no-subscription)..."
  cat >/etc/apt/sources.list.d/ceph.sources <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/ceph-squid
Suites: trixie
Components: no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
}

add_pvetest_repo_deb822_disabled_optional() {
  log "Adding pve-test repo (deb822, disabled)..."
  cat >/etc/apt/sources.list.d/pve-test.sources <<'EOF'
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-test
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
Enabled: false
EOF
}

install_disable_nag() {
  log "Installing subscription nag patch (auto re-apply after apt)..."

  mkdir -p /usr/local/bin
  cat >/usr/local/bin/pve-remove-nag.sh <<'EOF'
#!/bin/sh
WEB_JS=/usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js
if [ -s "$WEB_JS" ] && ! grep -q NoMoreNagging "$WEB_JS"; then
  sed -i -e "/data\.status/ s/!//" -e "/data\.status/ s/active/NoMoreNagging/" "$WEB_JS"
fi
EOF
  chmod 755 /usr/local/bin/pve-remove-nag.sh

  cat >/etc/apt/apt.conf.d/no-nag-script <<'EOF'
DPkg::Post-Invoke { "/usr/local/bin/pve-remove-nag.sh"; };
EOF
  chmod 644 /etc/apt/apt.conf.d/no-nag-script

  DEBIAN_FRONTEND=noninteractive apt-get -y --reinstall install proxmox-widget-toolkit >/dev/null 2>&1 || true
}

disable_ha_services_if_single_node() {
  log "Disabling HA services (single node policy)..."
  systemctl disable -q --now pve-ha-lrm 2>/dev/null || true
  systemctl disable -q --now pve-ha-crm 2>/dev/null || true
  systemctl disable -q --now corosync   2>/dev/null || true
}

wait_for_apt() {
  local max_wait=300
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock >/dev/null 2>&1; do
    [[ $waited -ge $max_wait ]] && { log "ERROR: apt lock timeout"; return 1; }
    log "Waiting for apt lock to be released..."
    sleep 10
    (( waited += 10 )) || true
  done
  return 0
}

do_updates() {
  wait_for_apt || return 1
  log "Running apt update..."
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  if [[ "$DO_DIST_UPGRADE" -eq 1 ]]; then
    log "Running dist-upgrade..."
    DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade
  fi
}

postinstall_auto() {
  local ver major minor
  ver="$(get_pve_version)"
  read -r major minor <<<"$(pve_major_minor "$ver")"

  log "Detected Proxmox version: $ver (major=$major minor=$minor)"

  if [[ "$major" == "9" ]]; then
    ensure_deb822_trixie_sources

    if [[ "$DISABLE_ENTERPRISE_REPO" -eq 1 ]]; then
      disable_enterprise_repo_deb822
    fi

    if [[ "$ENABLE_NO_SUBSCRIPTION_REPO" -eq 1 ]]; then
      enable_no_subscription_repo_deb822
    fi

    if [[ "$ADD_CEPH_NO_SUBSCRIPTION_REPO" -eq 1 ]]; then
      add_ceph_repo_deb822_optional
    fi

    if [[ "$ADD_PVETEST_DISABLED" -eq 1 ]]; then
      add_pvetest_repo_deb822_disabled_optional
    fi

  elif [[ "$major" == "8" ]]; then
    ensure_legacy_bookworm_sources

    if [[ "$DISABLE_ENTERPRISE_REPO" -eq 1 ]]; then
      disable_enterprise_repo_legacy
    fi

    if [[ "$ENABLE_NO_SUBSCRIPTION_REPO" -eq 1 ]]; then
      enable_no_subscription_repo_legacy
    fi
  else
    log "ERROR: Unsupported Proxmox major version: $major"
    exit 1
  fi

  if [[ "$DISABLE_SUBSCRIPTION_NAG" -eq 1 ]]; then
    install_disable_nag
  else
    rm -f /etc/apt/apt.conf.d/no-nag-script 2>/dev/null || true
  fi

  if [[ "$DISABLE_HA_ON_SINGLE_NODE" -eq 1 ]]; then
    disable_ha_services_if_single_node
  fi

  do_updates

  log "Post-install auto completed."
}

postinstall_auto

# --- Detect uplink (default route interface) ---
UPLINK_IF="$(ip -o route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' || true)"
if [[ -n "${UPLINK_IF}" ]]; then
  log "Detected uplink interface: ${UPLINK_IF}"
else
  log "WARN: Could not detect uplink interface (no default route). Continuing anyway."
fi

# --- Detect node IP address ---
NODE_IP=""
if [[ -n "${UPLINK_IF}" ]]; then
  NODE_IP="$(ip -4 -o addr show dev "${UPLINK_IF}" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
fi
if [[ -z "${NODE_IP}" ]]; then
  NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
fi
if [[ -n "${NODE_IP}" ]]; then
  log "Detected node IP: ${NODE_IP}"
else
  log "WARN: Could not detect node IP address."
fi

write_pve_node_ip_env() {
  local target_dir="$1"
  if [[ -z "${NODE_IP}" ]]; then
    log "WARN: Node IP not detected. Skipping .env write in ${target_dir}."
    return 0
  fi
  if [[ -d "${target_dir}" ]]; then
    echo "PVE_NODE_IP=${NODE_IP}" > "${target_dir}/.env"
    log "Wrote PVE_NODE_IP to ${target_dir}/.env"
  else
    log "WARN: ${target_dir} not found. Skipping .env write."
  fi
}

ensure_nat_persistence() {
  local LISTEN_IP="$1"
  local WIREGUARD_IP="192.168.10.10"
  local STACK_IP="192.168.10.3"

  if [[ -z "${LISTEN_IP}" ]]; then
    log "WARN: Node IP not detected. Skipping NAT persistence in ${NET_FILE}."
    return 0
  fi

  local IFACE_NAME=""
  if grep -qE "^\s*iface\s+vmbr0\s+inet\b" "$NET_FILE"; then
    IFACE_NAME="vmbr0"
  elif [[ -n "${UPLINK_IF}" ]] && grep -qE "^\s*iface\s+${UPLINK_IF}\s+inet\b" "$NET_FILE"; then
    IFACE_NAME="${UPLINK_IF}"
  fi

  if [[ -z "${IFACE_NAME}" ]]; then
    log "WARN: Could not find vmbr0 or uplink iface stanza in ${NET_FILE}. Skipping NAT persistence."
    return 0
  fi

  log "Ensuring NAT persistence (post-up/post-down, iptables) in ${NET_FILE} for ${IFACE_NAME}..."
  local tmpfile
  tmpfile="$(mktemp /tmp/pve-autoinstall-interfaces.XXXXXX)"
  awk -v iface="$IFACE_NAME" -v node_ip="$LISTEN_IP" -v wg_ip="$WIREGUARD_IP" -v st_ip="$STACK_IP" '
    /pve-autoinstall nat rules/ { next }
    /^[[:space:]]+post-up iptables / { next }
    /^[[:space:]]+post-down iptables / { next }
    /^[[:space:]]+post-up echo 1 > \/proc\/sys\/net\/ipv4\/ip_forward/ { next }
    /^[[:space:]]+post-up iptables -t nat -A POSTROUTING -s 192\.168\.10\.0\/24 -o vmbr0 -j MASQUERADE/ { next }
    /^[[:space:]]+post-down iptables -t nat -D POSTROUTING -s 192\.168\.10\.0\/24 -o vmbr0 -j MASQUERADE/ { next }
    $0 ~ "^[[:space:]]*iface[[:space:]]+" iface "[[:space:]]+inet" {
      print
      print "        # pve-autoinstall nat rules (iptables)"
      print "        post-up iptables -t nat -A PREROUTING -p tcp -d " node_ip " --dport 50442 -j DNAT --to-destination " wg_ip ":50442"
      print "        post-up iptables -t nat -A OUTPUT -p tcp -d " node_ip " --dport 50442 -j DNAT --to-destination " wg_ip ":50442"
      print "        post-up iptables -A FORWARD -p tcp -d " wg_ip " --dport 50442 -j ACCEPT"
      print "        post-up iptables -t nat -A POSTROUTING -p tcp -d " wg_ip " --dport 50442 -j MASQUERADE"
      print "        post-up iptables -t nat -A PREROUTING -p tcp -d " node_ip " --dport 3002 -j DNAT --to-destination " st_ip ":3002"
      print "        post-up iptables -t nat -A OUTPUT -p tcp -d " node_ip " --dport 3002 -j DNAT --to-destination " st_ip ":3002"
      print "        post-up iptables -A FORWARD -p tcp -d " st_ip " --dport 3002 -j ACCEPT"
      print "        post-up iptables -t nat -A POSTROUTING -p tcp -d " st_ip " --dport 3002 -j MASQUERADE"
      print "        post-down iptables -t nat -D PREROUTING -p tcp -d " node_ip " --dport 50442 -j DNAT --to-destination " wg_ip ":50442"
      print "        post-down iptables -t nat -D OUTPUT -p tcp -d " node_ip " --dport 50442 -j DNAT --to-destination " wg_ip ":50442"
      print "        post-down iptables -D FORWARD -p tcp -d " wg_ip " --dport 50442 -j ACCEPT"
      print "        post-down iptables -t nat -D POSTROUTING -p tcp -d " wg_ip " --dport 50442 -j MASQUERADE"
      print "        post-down iptables -t nat -D PREROUTING -p tcp -d " node_ip " --dport 3002 -j DNAT --to-destination " st_ip ":3002"
      print "        post-down iptables -t nat -D OUTPUT -p tcp -d " node_ip " --dport 3002 -j DNAT --to-destination " st_ip ":3002"
      print "        post-down iptables -D FORWARD -p tcp -d " st_ip " --dport 3002 -j ACCEPT"
      print "        post-down iptables -t nat -D POSTROUTING -p tcp -d " st_ip " --dport 3002 -j MASQUERADE"
      print "        post-up echo 1 > /proc/sys/net/ipv4/ip_forward"
      print "        post-up iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o vmbr0 -j MASQUERADE"
      print "        post-down iptables -t nat -D POSTROUTING -s 192.168.10.0/24 -o vmbr0 -j MASQUERADE"
      next
    }
    { print }
  ' "$NET_FILE" >"$tmpfile"
  mv "$tmpfile" "$NET_FILE"
}

# --- Ensure local-lvm uses all free space in VG pve (if any) ---
# Proxmox default: VG=pve, LV=data (thin pool). We'll extend LV if VG has FREE extents.
if command -v vgs >/dev/null 2>&1 && command -v lvs >/dev/null 2>&1; then
  if vgs pve >/dev/null 2>&1 && lvs pve/data >/dev/null 2>&1; then
    FREE_BYTES="$(vgs --noheadings --units b -o vg_free --nosuffix pve | awk '{gsub(/ /,""); print $1}' || echo "0")"
    FREE_BYTES="${FREE_BYTES:-0}"
    if [[ "$FREE_BYTES" =~ ^[0-9]+$ ]] && (( FREE_BYTES > 0 )); then
      log "VG 'pve' has free space: ${FREE_BYTES} bytes. Extending pve/data to 100%FREE..."
      lvextend -l +100%FREE -y pve/data || { log "ERROR: lvextend failed"; exit 1; }
      log "local-lvm (pve/data) extended."
    else
      log "VG 'pve' has no free space. Skipping lvextend."
    fi
  else
    log "WARN: VG/LV (pve / pve/data) not found. Skipping lvextend."
  fi
else
  log "WARN: LVM tools not found. Skipping lvextend."
fi

# --- Network bridges definitions ---
# Internal bridges (bridge-ports none)
declare -a BRIDGES=(
"vmbrlab0|192.168.10.1/24"
"vmbrlab1|192.168.101.1/24"
"vmbrlab2|192.168.102.1/24"
"vmbrlab3|192.168.103.1/24"
"vmbrlab4|192.168.104.1/24"
)

add_bridge_if_missing() {
  local br="$1"
  local addr="$2"

  if grep -qE "^\s*auto\s+${br}\b" "$NET_FILE" || grep -qE "^\s*iface\s+${br}\b" "$NET_FILE"; then
    log "Bridge ${br} already present in ${NET_FILE}, skipping."
    return 0
  fi

  log "Adding bridge ${br} (${addr}) to ${NET_FILE}"
  cat >> "$NET_FILE" <<EOF

auto ${br}
iface ${br} inet static
        address ${addr}
        bridge-ports none
        bridge-stp off
        bridge-fd 0
EOF
}

for item in "${BRIDGES[@]}"; do
  br="${item%%|*}"
  addr="${item##*|}"
  add_bridge_if_missing "$br" "$addr"
done

# Apply network changes
log "Applying network config (ifreload -a)..."
if command -v ifreload >/dev/null 2>&1; then
  ifreload -a || { log "WARN: ifreload -a failed, attempting ifup for new bridges..."; }
else
  log "WARN: ifreload not found. Trying ifup for bridges..."
fi

for item in "${BRIDGES[@]}"; do
  br="${item%%|*}"
  # bring up quietly; ignore if already up
  ifup "$br" 2>/dev/null || true
done

# --- Ensure Ubuntu 24.04 template exists ---
# We'll pick the newest available ubuntu-24.04 standard template and download if missing.
log "Ensuring Ubuntu 24.04 Noble template is present on 'local'..."
pveam update >/dev/null 2>&1 || true

TPL_NAME="$(pveam available --section system 2>/dev/null | awk '{print $2}' | grep -E '^ubuntu-24\.04-standard_.*_amd64\.tar\.(zst|gz)$' | sort -V | tail -n1 || true)"
if [[ -z "$TPL_NAME" ]]; then
  log "ERROR: Could not find ubuntu-24.04 template in pveam available output."
  exit 1
fi

if ! pveam list local 2>/dev/null | awk '{print $1}' | grep -q "^${TPL_NAME}$"; then
  log "Downloading template: ${TPL_NAME}"
  pveam download local "$TPL_NAME"
else
  log "Template already downloaded: ${TPL_NAME}"
fi

TEMPLATE_REF="local:vztmpl/${TPL_NAME}"

# --- Create containers ---
create_or_skip_ct() {
  local CTID="$1"
  local HOSTNAME="$2"
  local CORES="$3"
  local MEM_GB="$4"
  local ROOTFS="$5"
  local BRIDGE="$6"
  local IP_CIDR="$7"
  local GW="$8"
  local ONBOOT="$9"

  if pct status "$CTID" &>/dev/null; then
    log "CT ${CTID} already exists, skipping create."
    return 0
  fi

  local MEM_MB=$(( MEM_GB * 1024 ))

  log "Creating CT ${CTID} (${HOSTNAME})..."
  pct create "$CTID" "$TEMPLATE_REF" \
    --hostname "$HOSTNAME" \
    --cores "$CORES" \
    --memory "$MEM_MB" \
    --swap 0 \
    --rootfs "$ROOTFS" \
    --net0 "name=eth0,bridge=${BRIDGE},ip=${IP_CIDR},gw=${GW}" \
    --onboot "$ONBOOT" \
    --unprivileged 1 \
    --features nesting=1,keyctl=1

  log "CT ${CTID} created."
}

# --- Wireguard CT networks ---
apply_wireguard_networks() {
  local CTID="$1"

  if ! pct status "$CTID" &>/dev/null; then
    log "WARN: CT ${CTID} not found. Skipping Wireguard network setup."
    return 0
  fi

  log "Configuring Wireguard networks for CT ${CTID}..."
  pct set "$CTID" \
    --net0 "name=eth0,bridge=vmbrlab0,ip=192.168.10.10/24,gw=192.168.10.1" \
    --net1 "name=eth1,bridge=vmbrlab1,ip=192.168.101.10/24" \
    --net2 "name=eth2,bridge=vmbrlab2,ip=192.168.102.10/24" \
    --net3 "name=eth3,bridge=vmbrlab3,ip=192.168.103.10/24" \
    --net4 "name=eth4,bridge=vmbrlab4,ip=192.168.104.10/24" \
    || { log "ERROR: Failed to configure Wireguard networks for CT ${CTID}"; exit 1; }
  log "Wireguard networks configured for CT ${CTID}."
}

set_ct_password() {
  local CTID="$1"
  local PASS="$2"

  if ! pct status "$CTID" &>/dev/null; then
    log "WARN: CT ${CTID} not found. Skipping password set."
    return 0
  fi

  if ! pct status "$CTID" 2>/dev/null | grep -q "status: running"; then
    log "CT ${CTID} not running. Starting for password set..."
    pct start "$CTID" >/dev/null 2>&1 || true
  fi

  log "Setting password for CT ${CTID} (chpasswd)..."
  pct exec "$CTID" -- bash -lc "echo \"root:${PASS}\" | chpasswd" \
    || { log "ERROR: Failed to set password for CT ${CTID} via chpasswd"; exit 1; }
  log "Password set for CT ${CTID}."
}

# CT 103 Wireguard
create_or_skip_ct 103 "Wireguard" 2 2 "local-lvm:15" "vmbrlab0" "192.168.10.10/24" "192.168.10.1" 1
apply_wireguard_networks 103

# CT 104 Stack
create_or_skip_ct 104 "Stack" 16 32 "local-lvm:100" "vmbrlab0" "192.168.10.3/24" "192.168.10.1" 1

# Set container passwords
set_ct_password 103 "Qazxc7823"
set_ct_password 104 "Qazxc7823"

ensure_nat_persistence "${NODE_IP}"
log "Reloading network to apply NAT rules..."
if command -v ifreload >/dev/null 2>&1; then
  ifreload -a || { log "WARN: ifreload -a failed after NAT update."; }
else
  systemctl restart networking >/dev/null 2>&1 || log "WARN: networking restart failed."
fi

# --- Start and verify containers ---
start_and_verify_ct() {
  local CTID="$1"
  local EXPECT_IP="$2"  # without /mask

  log "Starting CT ${CTID}..."
  pct start "$CTID" >/dev/null 2>&1 || true

  log "Waiting CT ${CTID} to become running..."
  for i in {1..30}; do
    if pct status "$CTID" 2>/dev/null | grep -q "status: running"; then
      break
    fi
    sleep 1
  done

  if ! pct status "$CTID" 2>/dev/null | grep -q "status: running"; then
    log "ERROR: CT ${CTID} did not start."
    return 1
  fi

  # Basic network checks inside container (no ping dependency)
  log "Verifying network inside CT ${CTID}..."
  if ! pct exec "$CTID" -- ip -4 addr show dev eth0 >/dev/null 2>&1; then
    log "ERROR: CT ${CTID}: eth0 not found or ip tool missing."
    return 1
  fi

  IP_LINE="$(pct exec "$CTID" -- ip -4 -o addr show dev eth0 2>/dev/null | awk '{print $4}' | head -n1 || true)"
  if [[ -z "$IP_LINE" ]]; then
    log "ERROR: CT ${CTID}: no IPv4 address on eth0."
    return 1
  fi

  if [[ "$IP_LINE" != "${EXPECT_IP}/"* ]]; then
    log "ERROR: CT ${CTID}: expected IP ${EXPECT_IP} on eth0, got ${IP_LINE}"
    return 1
  fi

  if ! pct exec "$CTID" -- ip route show default >/dev/null 2>&1; then
    log "ERROR: CT ${CTID}: default route missing."
    return 1
  fi

  log "CT ${CTID} OK: running, eth0 has ${IP_LINE}, default route present."
  return 0
}

start_and_verify_ct 103 "192.168.10.10"
start_and_verify_ct 104 "192.168.10.3"

# --- Ensure time sync inside CTs ---
ensure_ct_timesync() {
  local CTID="$1"
  log "Ensuring NTP time sync in CT ${CTID}..."
  pct exec "$CTID" -- bash -lc 'timedatectl set-ntp true 2>/dev/null || true; systemctl restart systemd-timesyncd 2>/dev/null || true; for i in {1..12}; do if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then break; fi; sleep 5; done; date -Is' \
    || { log "WARN: Failed to ensure time sync in CT ${CTID} (continuing)"; }
  if ! pct exec "$CTID" -- bash -lc 'timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes'; then
    log "WARN: CT ${CTID} time not synchronized (often normal in LXC). Ensure PVE host time is synced."
  fi
}

ensure_ct_timesync 103
ensure_ct_timesync 104

# --- Deploy stack payload and run installer ---
STACK_SRC_DIR="/mnt/stack"
STACK_DST_DIR="/opt/stack"

if [[ -d "$STACK_SRC_DIR" ]]; then
  write_pve_node_ip_env "${STACK_SRC_DIR}/Auto-start-wireguard-ui"
  log "Copying ${STACK_SRC_DIR} to CT 104:${STACK_DST_DIR}..."
  pct exec 104 -- mkdir -p "${STACK_DST_DIR}" || { log "ERROR: Failed to create ${STACK_DST_DIR} in CT 104"; exit 1; }
  set +e
  tar -C "$(dirname "$STACK_SRC_DIR")" --warning=no-timestamp --clamp-mtime --mtime='@0' -cf - "$(basename "$STACK_SRC_DIR")" \
    | pct exec 104 -- tar -C "$(dirname "$STACK_DST_DIR")" --warning=no-timestamp --clamp-mtime --mtime='@0' -xf -
  TAR_STATUS=$?
  set -e
  if [[ "$TAR_STATUS" -gt 1 ]]; then
    log "ERROR: Failed to copy ${STACK_SRC_DIR} to CT 104"
    exit 1
  fi
  if [[ -n "${NODE_IP}" ]]; then
    pct exec 104 -- bash -lc "if [ -d '${STACK_DST_DIR}/Auto-start-wireguard-ui' ]; then echo 'PVE_NODE_IP=${NODE_IP}' > '${STACK_DST_DIR}/Auto-start-wireguard-ui/.env'; fi" \
      || log "WARN: Failed to write PVE_NODE_IP to ${STACK_DST_DIR}/Auto-start-wireguard-ui/.env in CT 104"
  fi
  log "Running stack installer in CT 104..."
  pct exec 104 -- bash -lc "source /etc/profile >/dev/null 2>&1 || true; source /root/.bashrc >/dev/null 2>&1 || true; if [ -s /root/.nvm/nvm.sh ]; then . /root/.nvm/nvm.sh; fi; cd '${STACK_DST_DIR}' && chmod +x './install' && APT_PROXY='${APT_PROXY}' './install'" \
    || { log "ERROR: Stack installer failed in CT 104"; exit 1; }
else
  log "WARN: ${STACK_SRC_DIR} not found. Skipping stack deploy."
fi

# --- Finish ---
touch "$MARKER"
log "Autoinstall completed successfully. Marker created: $MARKER"

# Disable itself (optional; comment if you want it to stay enabled)
systemctl disable --now pve-autoinstall.service >/dev/null 2>&1 || true
log "Service disabled."
