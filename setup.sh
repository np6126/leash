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
AGENT_SUBNET="$(ALLOWLIST="$REPO_DIR/config/allowlist.yaml" python3 -c "
import yaml, os
data = yaml.safe_load(open(os.environ['ALLOWLIST'])) or {}
nets = data.get('agent_networks') or []
print(nets[0] if nets else '', end='')
")"
if [[ -z "$AGENT_SUBNET" ]]; then
    echo "" >&2
    echo "WARNING: agent_networks is not set in config/allowlist.yaml" >&2
    echo "         Without it, agents can reach /api/allowlist/add and whitelist" >&2
    echo "         any destination for themselves. Set agent_networks before going live." >&2
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

echo "==> creating data directories"
mkdir -p /var/lib/leash/mitmproxy
mkdir -p /var/lib/leash/logs
mkdir -p /etc/leash

_BASE="$REPO_DIR/config/allowlist.yaml"
_LOCAL="/etc/leash/allowlist.local.yaml"
_DEST="/etc/leash/allowlist.yaml"

if [[ -f "$_LOCAL" ]]; then
    BASE="$_BASE" LOCAL="$_LOCAL" DEST="$_DEST" python3 <<'PYEOF'
import yaml, os
base  = yaml.safe_load(open(os.environ['BASE']))  or {}
local = yaml.safe_load(open(os.environ['LOCAL'])) or {}
dests = list(base.get('allowed_destinations') or [])
seen  = {e.get('host') for e in dests}
for e in (local.get('allowed_destinations') or []):
    if e.get('host') not in seen:
        dests.append(e)
        seen.add(e.get('host'))
base['allowed_destinations'] = dests
yaml.dump(base, open(os.environ['DEST'], 'w'), default_flow_style=False, allow_unicode=True)
PYEOF
    echo "    allowlist merged (allowlist.yaml + allowlist.local.yaml) → $_DEST"
else
    cp "$_BASE" "$_DEST"
    echo "    allowlist copied to $_DEST"
fi
if ! python3 -c "import yaml; yaml.safe_load(open('$_DEST'))" 2>/dev/null; then
    echo "error: allowlist is not valid YAML — check config/allowlist.yaml and config/allowlist.local.yaml" >&2
    exit 1
fi
echo "==> building container images"
podman build --no-cache -t localhost/leash:latest "$REPO_DIR"
podman build --no-cache -t localhost/logviewer:latest "$REPO_DIR/logviewer"

echo "==> installing systemd container units"
mkdir -p /etc/containers/systemd
cp "$REPO_DIR/etc/containers/systemd/leash.container"     /etc/containers/systemd/
cp "$REPO_DIR/etc/containers/systemd/logviewer.container" /etc/containers/systemd/

echo "==> enabling and starting services"
# Quadlet-generated units live in /run/systemd/generator/ and cannot be
# enabled with systemctl enable. Instead, pull them into multi-user.target
# via a persistent drop-in so they start automatically on every boot.
mkdir -p /etc/systemd/system/multi-user.target.d
cat > /etc/systemd/system/multi-user.target.d/leash.conf <<'EOF'
[Unit]
Wants=leash.service logviewer.service
EOF
systemctl daemon-reload
systemctl restart leash.service logviewer.service
# Podman assigns new IPs on every container restart but leaves stale DNAT
# entries in iptables. Reload rewrites the rules to match current IPs.
podman network reload leash logviewer 2>/dev/null || true
# Drop any remaining stale DNAT entries (same port, different destination).
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
echo ""
echo "CA key backup (run once; needed to survive host rebuilds):"
echo "  cp /var/lib/leash/mitmproxy/mitmproxy-ca.p12 <safe-location>"
