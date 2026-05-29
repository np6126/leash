# Proxmox VE Setup

A step-by-step walkthrough for provisioning the leash VM on a Proxmox host —
from cloud image to a running proxy with the log viewer reachable. For
non-Proxmox deployments, see [Deployment](deployment.md).

## Prerequisites

- A Proxmox VE host with two bridges already configured: `vmbr0` (LAN) and
  `vmbr1` (the isolated agent network). The walkthrough references both but
  does not create `vmbr1`.
- A storage pool named `local-lvm` for the VM disk and cloud-init drive (used
  throughout step 2). Adjust the commands if your pool is named differently.
- Shell access to the Proxmox host.
- An SSH keypair to inject into the new VM via cloud-init.

## 1. Download the Ubuntu 24.04 Cloud Image

Run on the Proxmox host:

```bash
wget -P /var/lib/vz/images/ \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
```

## 2. Create the VM

The leash VM needs two network interfaces:
- `net0` on `vmbr0`: LAN access for SSH and outbound internet (NAT source)
- `net1` on `vmbr1`: isolated agent network — leash acts as gateway at `10.10.10.1`

```bash
qm create <VMID> \
  --name leash \
  --memory 1024 \
  --cores 1 \
  --net0 virtio,bridge=vmbr0 \
  --net1 virtio,bridge=vmbr1 \
  --ostype l26

qm importdisk <VMID> \
  /var/lib/vz/images/noble-server-cloudimg-amd64.img \
  local-lvm

qm set <VMID> \
  --scsihw virtio-scsi-pci \
  --scsi0 local-lvm:vm-<VMID>-disk-0 \
  --ide2 local-lvm:cloudinit \
  --boot c --bootdisk scsi0 \
  --serial0 socket --vga serial0 \
  --agent enabled=1

qm resize <VMID> scsi0 10G
```

## 3. Configure Cloud-Init

Create a vendor cloud-init snippet to install the QEMU guest agent and `git`
(needed in step 5 to clone the repo) on first boot:

```bash
mkdir -p /var/lib/vz/snippets
cat > /var/lib/vz/snippets/leash-vendor.yaml << 'EOF'
#cloud-config
packages:
  - qemu-guest-agent
  - git
write_files:
  # Optional: control-plane host whose agent traffic gets its real source IP
  # stamped into the X-Agent-Source header (the host behind a NAT that would
  # otherwise collapse every agent to one client IP). Set to your own host;
  # omit this file entirely to leave the feature off.
  - path: /etc/leash/identity.env
    content: |
      LEASH_IDENTITY_HOST=beacon.example.com
runcmd:
  - systemctl enable --now qemu-guest-agent
EOF
```

`identity.env` is read by the leash container (`EnvironmentFile=` in
`leash.container`). Set `LEASH_IDENTITY_HOST` to the host this leash instance
fronts, or omit the file to leave source-IP stamping off.

Then configure the VM. In the Proxmox UI, select the VM → **Cloud-Init** tab:

| Field | Value |
|---|---|
| User | `root` (or your preferred username) |
| SSH public key | paste your `~/.ssh/id_ed25519.pub` |
| IP Config | static IP or DHCP depending on your network |
| DNS domain / servers | as needed |

Or via CLI:

```bash
qm set <VMID> \
  --ciuser root \
  --sshkeys ~/.ssh/id_ed25519.pub \
  --ipconfig0 ip=<vm-ip>/24,gw=<your-gateway> \
  --ipconfig1 ip=10.10.10.1/24 \
  --nameserver 9.9.9.9
qm set <VMID> --cicustom "vendor=local:snippets/leash-vendor.yaml"
```

`ipconfig1` has no gateway — leash is the gateway for that network, not a client of it.

## 4. Start the VM

```bash
qm start <VMID>
```

## 5. Run the Setup Script

SSH into the VM, then clone the repo and run the setup script:

```bash
ssh root@<vm-ip>
git clone https://github.com/np6126/leash.git
cd leash
sudo ./setup.sh
```

**Private policy entries (optional):** If you need deployment-specific
destinations that should not be committed to the repository, drop them into
`config/*.local.yaml` files next to `setup.sh` before running it:

```bash
cat > /root/leash/config/enforce.local.yaml <<'EOF'
allow:
  - host: registry.internal.example.com
    ports: [443]
EOF

cat > /root/leash/config/blocklist.local.yaml <<'EOF'
block:
  - pastebin.com
EOF
```

`setup.sh` merges each base file with its `.local.yaml` counterpart on every
run, deduplicating by host. The files are git-ignored and never leave the VM.

## 6. Extract the CA Certificate

After setup, extract the mitmproxy CA certificate and distribute it to all agent VMs:

```bash
podman exec leash cat /root/.mitmproxy/mitmproxy-ca-cert.pem > mitmproxy-ca-cert.pem
```

With [tank-agent-os](https://github.com/np6126/tank-agent-os), inject it as a Podman secret named `proxy_ca_cert`.

## 7. Open the Log Viewer

After setup, the audit log viewer is available at:

```text
http://<vm-ip>:8090
```

It shows all proxy requests with timestamp, client, method, URL, port, status
code, and response size — one row per request. Clicking a row expands the
request/response headers and body.

Key features:

- `[Enforce | Audit | Blocklist]` mode switcher in the header
- Free-text search and a client IP filter
- **Internet only** toggle (hides LAN/RFC 1918 traffic)
- **Would block in enforce** toggle in non-enforce modes
- Dark/light mode and copy-to-clipboard on body blocks
- **Clear logs** button
- **Manage Access** in the detail panel — add or remove rules in either the
  enforce list or the blocklist without editing YAML

## Firewall

| Port | Purpose | Reachable from |
|---|---|---|
| 8080 | Proxy (agents connect here) | Agent VMs only (`10.10.10.0/24`) |
| 8090 | Log viewer | Management network only — **never from `10.10.10.0/24`** |
| 22 | SSH | Management network only |

The log viewer's policy-mutation endpoints (`PUT /api/mode`, `POST /api/policy/*`)
are blocked at the application level for any client IP listed under
`agent_networks` in `/etc/leash/agents.yaml`. The default config ships with
`10.10.10.0/24` there, so agent VMs cannot flip the mode or modify their own
restrictions out of the box.

For additional hardening, also restrict port 8090 at the network level:

```text
allow in  tcp dport 8080 from 10.10.10.0/24  # proxy — agents only
allow in  tcp dport 8090 from <mgmt-network>  # log viewer — management only
allow in  tcp dport 22   from <mgmt-network>  # SSH — management only
drop      all
```

> [!WARNING]
> **Why port 8090 must not be reachable from `10.10.10.0/24`:** An agent that
> can reach the log viewer could call `PUT /api/mode` to disable enforcement
> or `POST /api/policy/enforce/add` to whitelist any destination for itself.
> The `agent_networks` key in `agents.yaml` is the primary control; a firewall
> rule is defence in depth.

## Next steps

The proxy is now running and enforcing policy. To author allow and block
rules, see [Policy files](policy.md#policy-files); to understand the three
modes, see [Modes](policy.md#modes).
