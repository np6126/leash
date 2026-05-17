#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root (sudo ./purge.sh)" >&2
    exit 1
fi

systemctl stop leash.service logviewer.service 2>/dev/null || true
systemctl disable leash.service logviewer.service 2>/dev/null || true

rm -f /etc/containers/systemd/leash.container
rm -f /etc/containers/systemd/logviewer.container
systemctl daemon-reload

podman rm -f leash logviewer 2>/dev/null || true
podman rmi localhost/leash:latest localhost/logviewer:latest 2>/dev/null || true

rm -rf /var/lib/leash
rm -rf /etc/leash

WAN_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -n "$WAN_IF" ]]; then
    iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
    netfilter-persistent save
fi
rm -f /etc/sysctl.d/99-leash-forward.conf
sysctl -q net.ipv4.ip_forward=0
