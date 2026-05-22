# Deployment

Installing and operating leash. For the policy model — the three modes, the
rule files, the audit log format — see [Policy](policy.md). For a full Proxmox
VE walkthrough, see [Proxmox VE Setup](proxmox-setup.md). For an overview of
the project, see the [README](../README.md).

## Installing with setup.sh

`setup.sh` is the recommended way to deploy. Re-run it whenever the proxy
code, policy files, or container configuration changes.

> [!NOTE]
> `setup.sh` targets **Debian and Ubuntu** — it uses `apt-get` and
> `netfilter-persistent`. On other distributions, install `podman`, `git`,
> PyYAML, and an iptables persistence mechanism with your own package manager,
> then deploy the containers by hand (see [Manual run](#manual-run-for-developmenttesting)).

On the proxy host:

```bash
git clone https://github.com/np6126/leash.git
cd leash
sudo ./setup.sh
```

### What setup.sh does

1. Installs `podman`, `git`, `python3-yaml`, `iptables-persistent`
2. Enables IP forwarding and sets up NAT masquerade for the agent subnet (read from `/etc/leash/agents.yaml`)
3. Materialises the runtime policy under `/etc/leash/` by merging each base file with its optional `*.local.yaml` counterpart (see [Policy files](policy.md#policy-files))
4. Creates `/etc/leash/mode` with `enforce` if not already present (existing mode is preserved across re-runs)
5. Migrates legacy `/etc/leash/allowlist.yaml` deployments to the new layout in place, one-shot
6. Builds `localhost/leash:latest` and `localhost/logviewer:latest`
7. Copies Quadlet unit files to `/etc/containers/systemd/`
8. Installs `leashctl` to `/usr/local/bin/`
9. Writes `/etc/systemd/system/multi-user.target.d/leash.conf` so both services start automatically on boot

> [!NOTE]
> **Why the drop-in?** Podman Quadlet generates systemd units at runtime into
> `/run/systemd/generator/`, which systemd marks as generated. `systemctl enable`
> refuses to create symlinks for generated units. The `multi-user.target.d` drop-in
> is the correct way to make Quadlet services autostart persistently.

### Manual run (for development/testing)

Build the images and run the containers directly — for development, or on a
host where `setup.sh` does not apply. Create the data directories and a
minimal policy first:

```bash
mkdir -p /var/lib/leash/{mitmproxy,logs} /etc/leash
cp config/agents.yaml    /etc/leash/agents.yaml
cp config/enforce.yaml   /etc/leash/enforce.yaml
cp config/blocklist.yaml /etc/leash/blocklist.yaml
echo enforce > /etc/leash/mode
```

Build the proxy image and start it:

```bash
podman build -t localhost/leash:latest .

podman run -d \
  --name leash \
  -p 0.0.0.0:8080:8080 \
  -v /var/lib/leash/mitmproxy:/root/.mitmproxy:Z \
  -v /var/lib/leash/logs:/logs:Z \
  -v /etc/leash:/etc/leash:Z \
  -e LEASH_DIR=/etc/leash \
  -e LOG_PATH=/logs/egress.jsonl \
  localhost/leash:latest
```

The log viewer is a second image, built from the `logviewer/` subdirectory:

```bash
podman build -t localhost/logviewer:latest logviewer/

podman run -d \
  --name logviewer \
  -p 0.0.0.0:8090:8090 \
  -v /var/lib/leash/logs:/logs:Z \
  -v /etc/leash:/etc/leash:Z \
  -e LOG_PATH=/logs/egress.jsonl \
  -e LEASH_DIR=/etc/leash \
  -e PORT=8090 \
  localhost/logviewer:latest
```

This is NAT-only equivalent to `setup.sh` minus the host firewall and
IP-forwarding setup — for the agent network to route through the proxy you
still need IP forwarding and a NAT masquerade rule on the host.

## Extract the CA Certificate

mitmproxy generates a CA key and certificate on first start and stores them in
the persistent volume. Extract the certificate after the container is running:

```bash
podman exec leash cat /root/.mitmproxy/mitmproxy-ca-cert.pem > mitmproxy-ca-cert.pem
```

This certificate must be distributed to every agent VM that will use this
proxy so that TLS interception succeeds. With tank-agent-os, inject it as a
Podman secret named `proxy_ca_cert`.

The CA key never leaves the volume. Back up `/var/lib/leash/mitmproxy/mitmproxy-ca.p12`
if you need to preserve it across host rebuilds.

**CA key rotation:** If the CA key is compromised or you need to rotate it,
delete `/var/lib/leash/mitmproxy/` and restart the container — mitmproxy will
generate a new key pair on next start. You must then re-extract the new
certificate and redistribute it to every agent VM (or Podman secret); until
you do, TLS interception will fail for those agents.

## Enforcing the Restriction

leash only constrains traffic that is routed through it. For the proxy to be
the *only* path to the internet, the agent must be both pointed at the proxy
and prevented from reaching the internet any other way.

### Configuring an agent

Any agent — containerised or not — needs three things:

1. **Proxy environment variables.** Set `HTTP_PROXY` and `HTTPS_PROXY` (and
   their lowercase variants) to `http://<proxy-host>:8080` in the agent's
   environment, so its HTTP client sends every request through leash.
2. **Trust the CA certificate.** Install the extracted `mitmproxy-ca-cert.pem`
   (see [Extract the CA Certificate](#extract-the-ca-certificate)) into the
   agent's trust store, or TLS interception fails with certificate errors. The
   exact mechanism depends on the agent's runtime — the system trust store,
   `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and so on.
3. **Restrict the network.** The agent must not be able to reach external
   hosts directly — only the proxy. Enforce this at the OS or container level
   (a dedicated bridge network, firewall rules, routing) so that bypassing the
   proxy is impossible, not merely discouraged.

Without step 3 the proxy environment variables are advisory: an agent process
can override them and connect to the internet directly.

### Worked example: tank-agent-os

With [tank-agent-os](https://github.com/np6126/tank-agent-os) the three steps
are handled by the platform: the agent container sits on a dedicated Podman
bridge network with no default route to the internet, nftables rules on the
host permit it to reach only leash, and the CA certificate is injected as a
Podman secret named `proxy_ca_cert`. See [Proxmox VE Setup](proxmox-setup.md)
for the host firewall rules.

## Environment Variables

**Proxy (`leash`):**

| Variable | Default | Description |
|---|---|---|
| `LEASH_DIR` | `/etc/leash` | Directory holding `mode`, `enforce.yaml`, `blocklist.yaml`, `agents.yaml` |
| `LOG_PATH` | `/logs/egress.jsonl` | Path for the NDJSON log |
| `BODY_LIMIT_KB` | `1024` | Maximum captured body size in KB for text responses; larger bodies are truncated |

**Log viewer (`logviewer`):**

| Variable | Default | Description |
|---|---|---|
| `LOG_PATH` | `/logs/egress.jsonl` | Path to the NDJSON log file |
| `LEASH_DIR` | `/etc/leash` | Directory holding the policy files (mutated by the UI) |
| `PORT` | `8090` | HTTP port the log viewer listens on |

## Log Rotation

The log file grows unboundedly. For long-running deployments, configure logrotate to cap its size:

```text
/var/lib/leash/logs/egress.jsonl {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

`copytruncate` truncates the live file in place rather than moving it. The
proxy addon also revalidates its log file descriptor on every write, so
move-then-create rotation works too.

## Memory Safety

Large binary responses (container image blobs, archives, firmware files) are
proxied in streaming mode without buffering the body in RAM. The `bytes` field
in the log will reflect the `Content-Length` header for streamed responses; if
the header is absent the field is omitted.

SSE (`text/event-stream`) responses are also streamed so that the proxy does
not block the agent's real-time token feed.

Text responses (JSON, plain text, XML, form data) up to `BODY_LIMIT_KB` KB
(default 1024 KB) are captured and stored in the log; larger text responses are
truncated. LLM API requests with large system prompts and tool definitions can
easily exceed 64 KB, so the default is set high enough to capture the full
payload in most cases.
</content>
</invoke>
