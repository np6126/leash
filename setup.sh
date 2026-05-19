#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: run as root (sudo ./setup.sh)" >&2
        exit 1
    fi
}

need_root

echo "==> installing packages"
apt-get update -qq
apt-get install -y -qq podman git iptables-persistent

echo "==> enabling IP forwarding for agent network routing"
WAN_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -z "$WAN_IF" ]]; then
    echo "error: could not detect default network interface" >&2
    exit 1
fi
echo "    outbound interface: $WAN_IF"

echo "==> creating data directories"
mkdir -p /var/lib/leash/mitmproxy
mkdir -p /var/lib/leash/logs
mkdir -p /etc/leash

# ── One-shot migration: legacy /etc/leash/allowlist*.yaml → new layout ───────
# Detect the old single-file deployment and split it into mode + agents.yaml +
# enforce.yaml. The legacy local override (deployed by the old
# deploy-allowlist-local.sh) is converted to config/enforce.local.yaml so the
# subsequent base+local merge preserves user data even on `git pull && setup.sh`
# upgrades that haven't run the new deploy script first. Idempotent.
_LEGACY="/etc/leash/allowlist.yaml"
_LEGACY_LOCAL="/etc/leash/allowlist.local.yaml"
if [[ -f "$_LEGACY" && ! -f "/etc/leash/enforce.yaml" ]]; then
    echo "==> migrating legacy allowlist.yaml → new layout"
    LEGACY="$_LEGACY" python3 <<'PYEOF'
import os, yaml
src = yaml.safe_load(open(os.environ['LEGACY'])) or {}

agents = {'agent_networks': src.get('agent_networks') or []}
with open('/etc/leash/agents.yaml', 'w') as f:
    yaml.dump(agents, f, default_flow_style=False, allow_unicode=True)

allow = src.get('allowed_destinations') or []
with open('/etc/leash/enforce.yaml', 'w') as f:
    if not allow:
        f.write('allow: []\n')
    else:
        yaml.dump({'allow': allow}, f, default_flow_style=False, allow_unicode=True)

with open('/etc/leash/blocklist.yaml', 'w') as f:
    f.write('block: []\n')

with open('/etc/leash/mode', 'w') as f:
    f.write('enforce\n')

print("    agents.yaml, enforce.yaml, blocklist.yaml, mode written")
PYEOF
    mv "$_LEGACY" "${_LEGACY}.bak"
    echo "    legacy file kept at ${_LEGACY}.bak (safe to delete)"
fi

# Convert legacy /etc/leash/allowlist.local.yaml → repo-side enforce.local.yaml
# (so the subsequent merge picks it up). Only runs if the new local file is
# absent — never clobbers a fresh deploy-policy.sh upload.
if [[ -f "$_LEGACY_LOCAL" && ! -f "$REPO_DIR/config/enforce.local.yaml" ]]; then
    echo "==> migrating legacy allowlist.local.yaml → config/enforce.local.yaml"
    SRC="$_LEGACY_LOCAL" DST="$REPO_DIR/config/enforce.local.yaml" python3 <<'PYEOF'
import os, yaml
src = yaml.safe_load(open(os.environ['SRC'])) or {}
allow = src.get('allowed_destinations') or []
with open(os.environ['DST'], 'w') as f:
    if not allow:
        f.write('allow: []\n')
    else:
        yaml.dump({'allow': allow}, f, default_flow_style=False, allow_unicode=True)
PYEOF
fi
# Rename orphaned legacy local file (idempotent — only runs once).
if [[ -f "$_LEGACY_LOCAL" ]]; then
    mv "$_LEGACY_LOCAL" "${_LEGACY_LOCAL}.bak"
fi

# ── Merge base + local fragments for each policy file ────────────────────────
_merge() {
    local base="$1" local_file="$2" dest="$3" top_key="$4"
    if [[ -f "$local_file" ]]; then
        BASE="$base" LOCAL="$local_file" DEST="$dest" KEY="$top_key" python3 <<'PYEOF'
import os, yaml
base  = yaml.safe_load(open(os.environ['BASE']))  or {}
local = yaml.safe_load(open(os.environ['LOCAL'])) or {}
key   = os.environ['KEY']
items = list(base.get(key) or [])
def _host(e):
    return e if isinstance(e, str) else e.get('host')
seen = {_host(e) for e in items}
for e in (local.get(key) or []):
    if _host(e) not in seen:
        items.append(e)
        seen.add(_host(e))
out = {key: items}
with open(os.environ['DEST'], 'w') as f:
    if not items:
        f.write(f"{key}: []\n")
    else:
        yaml.dump(out, f, default_flow_style=False, allow_unicode=True)
PYEOF
        echo "    $(basename "$dest") merged (base + local)"
    else
        cp "$base" "$dest"
        echo "    $(basename "$dest") copied from base"
    fi
}

echo "==> building runtime policy under /etc/leash/"
_merge "$REPO_DIR/config/agents.yaml"    "$REPO_DIR/config/agents.local.yaml"    /etc/leash/agents.yaml    agent_networks
_merge "$REPO_DIR/config/enforce.yaml"   "$REPO_DIR/config/enforce.local.yaml"   /etc/leash/enforce.yaml   allow
_merge "$REPO_DIR/config/blocklist.yaml" "$REPO_DIR/config/blocklist.local.yaml" /etc/leash/blocklist.yaml block

# Ensure mode file exists with safe default (enforce). Never overwrite an
# existing mode — operator may have flipped to audit/blocklist intentionally.
if [[ ! -f /etc/leash/mode ]]; then
    echo "enforce" > /etc/leash/mode
    echo "    mode initialised → enforce"
else
    echo "    mode preserved → $(cat /etc/leash/mode)"
fi

# Validate every YAML file we produced
for f in agents.yaml enforce.yaml blocklist.yaml; do
    if ! python3 -c "import yaml; yaml.safe_load(open('/etc/leash/$f'))" 2>/dev/null; then
        echo "error: /etc/leash/$f is not valid YAML" >&2
        exit 1
    fi
done

# ── NAT masquerade for the agent network ─────────────────────────────────────
AGENT_SUBNET="$(AGENTS=/etc/leash/agents.yaml python3 -c "
import yaml, os
data = yaml.safe_load(open(os.environ['AGENTS'])) or {}
nets = data.get('agent_networks') or []
print(nets[0] if nets else '', end='')
")"
if [[ -z "$AGENT_SUBNET" ]]; then
    echo "" >&2
    echo "WARNING: agent_networks is empty in agents.yaml" >&2
    echo "         Without it, agents can reach /api/policy/* and whitelist" >&2
    echo "         themselves. Set agent_networks before going live." >&2
    echo "         NAT masquerade rule will not be configured." >&2
    echo "" >&2
else
    echo "    agent subnet: $AGENT_SUBNET"
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-leash-forward.conf
    sysctl -q -p /etc/sysctl.d/99-leash-forward.conf
    if ! iptables -t nat -C POSTROUTING -s "$AGENT_SUBNET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$AGENT_SUBNET" -o "$WAN_IF" -j MASQUERADE
    fi
fi

netfilter-persistent save

echo "==> building container images"
podman build --no-cache -t localhost/leash:latest "$REPO_DIR"
podman build --no-cache -t localhost/logviewer:latest "$REPO_DIR/logviewer"

echo "==> installing systemd container units"
mkdir -p /etc/containers/systemd
cp "$REPO_DIR/etc/containers/systemd/leash.container"     /etc/containers/systemd/
cp "$REPO_DIR/etc/containers/systemd/logviewer.container" /etc/containers/systemd/

echo "==> installing leashctl"
install -m 755 "$REPO_DIR/leashctl" /usr/local/bin/leashctl

echo "==> enabling and starting services"
mkdir -p /etc/systemd/system/multi-user.target.d
cat > /etc/systemd/system/multi-user.target.d/leash.conf <<'EOF'
[Unit]
Wants=leash.service logviewer.service
EOF
systemctl daemon-reload
systemctl restart leash.service logviewer.service
podman network reload leash logviewer 2>/dev/null || true

_clean_dnat() {
    local port="$1" current_ip="$2"
    iptables -t nat -L NETAVARK-DN-1D8721804F16F -n --line-numbers 2>/dev/null \
        | awk -v port="$port" -v ip="$current_ip" '
            /DNAT/ && $0 ~ "dpt:"port && $0 !~ ip { print $1 }
          ' \
        | sort -rn \
        | xargs -r -I{} iptables -t nat -D NETAVARK-DN-1D8721804F16F {} 2>/dev/null || true
}
_clean_dnat 8080 "$(podman inspect leash     --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"
_clean_dnat 8090 "$(podman inspect logviewer --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"

echo ""
echo "==> done. status:"
systemctl status leash.service logviewer.service --no-pager -l

echo ""
echo "CA certificate (distribute to agent VMs):"
echo "  podman exec leash cat /root/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
VM_IP="$(ip -4 addr show "$WAN_IF" | awk '/inet / {print $2}' | cut -d/ -f1)"
echo "Log viewer:  http://$VM_IP:8090"
echo "Raw logs:    tail -f /var/lib/leash/logs/egress.jsonl"
echo "Current mode: $(cat /etc/leash/mode)"
echo ""
echo "CA key backup (run once; needed to survive host rebuilds):"
echo "  cp /var/lib/leash/mitmproxy/mitmproxy-ca.p12 <safe-location>"
