# leash

An auditing egress proxy for AI agent deployments. It sits between the agent
VM and the public internet, intercepts all outbound HTTPS, applies one of three
operation modes (strict allowlist · pure audit · blocklist) to every request,
and writes a structured log of every event to a persistent volume outside the
agent environment.

Designed to run alongside [tank-agent-os](https://github.com/np6126/tank-agent-os)
but works with any setup where you can point an HTTP proxy at this service.

## Why This Exists

AI agents that can reach the public internet without restriction create two
problems. First, they can exfiltrate data by calling arbitrary external services
directly rather than through the application's authorised API layer. Second,
there is no record of what they contacted, making post-incident analysis
difficult or impossible.

This proxy addresses both. The allowlist makes unauthorised destinations
technically unreachable. The log gives you a complete record of everything the
agent tried to reach, including blocked attempts. Because the log lives outside
the agent VM, the agent cannot alter or delete it — it survives VM compromise
or destruction. The log is not cryptographically signed; an operator with shell
access to the proxy host could modify it.

TLS interception means HTTPS traffic is logged in plaintext. This is intentional:
an audit log that only records hostnames and ports is far less useful than one
that records full URLs and request methods.

## Architecture

```
agent container
    │  HTTP_PROXY / HTTPS_PROXY
    ▼
leash (mitmproxy, explicit proxy mode, port 8080)
    │  TLS interception with self-signed CA
    │  policy check per request (enforce | audit | blocklist)
    │  JSON log → /logs/egress.jsonl
    ▼
permitted external destinations only
```

The proxy runs in explicit proxy mode. The agent sets `HTTP_PROXY` and
`HTTPS_PROXY` in its environment. For HTTPS the agent sends a `CONNECT` tunnel
request; mitmproxy intercepts the tunnel, applies the active policy to the
destination before the TLS handshake begins, and either rejects it with HTTP
403 or intercepts and re-encrypts the traffic using its own CA certificate.

Mode and both policy files are reloaded from disk on every request, so you can
flip modes and edit allow/block rules without restarting the proxy.

## Modes

Three operation modes, selected by the single-line file `/etc/leash/mode`:

| Mode        | What passes                                            | What's blocked                | Use case                     |
|-------------|--------------------------------------------------------|-------------------------------|------------------------------|
| `enforce`   | Only hosts listed in `enforce.yaml`                    | Everything else (HTTP 403)    | Production, strict           |
| `audit`     | Everything                                             | Nothing                       | Discovery / policy authoring |
| `blocklist` | Everything except hosts listed in `blocklist.yaml`     | Hosts in `blocklist.yaml`     | Defence-in-depth on trusted agents |

Switching modes is one click in the log viewer header, or on the proxy host:

```bash
leashctl mode                    # show current mode
leashctl mode audit              # flip (hot-reload, no restart)
leashctl edit                    # open the active policy file in $EDITOR
leashctl edit blocklist          # edit a specific file by name
```

The proxy picks up the change on the next request, no restart required.

In `audit` and `blocklist` modes, every passing request is also matched against
the enforce rules; rows that *would have been blocked in enforce* are tagged
with `audit: "would_block_in_enforce"` in the JSON log and rendered with an
amber chip + row tint in the viewer. Use this to stage an allowlist against
real agent traffic, then flip to enforce when the rules look right.

> **Audit and blocklist are degraded-security postures.** The log viewer shows
> a persistent amber banner whenever mode is not `enforce`. Don't leave
> production deployments in audit unless you intend to.

## Enforcing the Restriction

The proxy is not advisory. For it to be the only path to the internet, the
agent's network access must be restricted at the OS or container level so it
cannot reach external hosts directly. With tank-agent-os this is done through
a combination of a dedicated Podman bridge network and nftables rules on the host.

## Log Viewer

A web UI for browsing the audit log is available at port 8090 after running `setup.sh`.

![Log viewer in enforce mode (dark theme)](docs/logviewer.png)

![Log viewer in audit mode (light theme) — banner + WOULD-BLOCK chips](docs/logviewer-light.png)

Requests are shown newest-first with timestamp, client IP, method, URL, port, HTTP status, and response size. Each HTTPS request appears as a single row — the intermediate CONNECT tunnel event is suppressed in the viewer (it is still written to the log file).

Header and filter bar:
- **Mode switcher** — segmented control showing `[Enforce | Audit | Blocklist]`. Click to flip mode; a confirm dialog appears when switching to a permissive mode.
- **Mode banner** — an amber strip below the header in `audit` and `blocklist` modes, with the active rule summary.
- **Search** — free-text across all fields (URL, host, method, status, client, …)
- **Client IP** — narrow down by source IP
- **Internet only** — hides requests to private/LAN addresses (RFC 1918, `.local`, `.lan`, etc.)
- **Would block in enforce** — visible in non-enforce modes; narrows the view to rows tagged with `audit: "would_block_in_enforce"`, i.e. the actionable backlog for hardening the allowlist.
- **Copy button** — hover over any request or response body block to reveal a clipboard icon; click to copy the content.
- **Clear logs** — truncates the log file.
- **Dark/light mode toggle** — preference is saved in `localStorage`.

Rows are colour-tinted by event class: red for `blocked`, orange for `error`,
amber for `allowed + would_block_in_enforce`. A `WOULD BLOCK` chip appears
in the event column next to the `allowed` dot for those rows.

The log file size and total entry count are shown in the header.

The log viewer runs as a separate container (`localhost/logviewer:latest`) serving a Python HTTP backend with static assets in `logviewer/static/` and an HTML template in `logviewer/templates/`. It mounts the log volume read-write so it can truncate the file.

Clicking any row opens a detail panel with request and response headers and body. A **Manage Access** button opens a dialog that shows the host's status in **both** lists simultaneously — enforce list and blocklist — with a green "active in current mode" marker on whichever list the proxy is currently consulting. Add or remove rules in either list from any mode; one click writes to the appropriate file (`enforce.yaml` or `blocklist.yaml`) and the proxy picks the change up on the next request without a restart.

> **Security:** The mode-switch endpoint (`PUT /api/mode`) and the policy-mutation endpoints (`POST /api/policy/*`) are blocked for any client IP that falls within a network listed under `agent_networks` in `agents.yaml`. **This is the only application-level control preventing agents from changing the mode or whitelisting themselves.** If `agent_networks` is missing or covers the wrong subnet, agents can call `/api/mode` and `/api/policy/enforce/add` to free themselves. The network-level firewall rule (block port 8090 from `10.10.10.0/24`) is defence-in-depth, not a substitute. Configure `agent_networks` before exposing the logviewer. See `docs/proxmox-setup.md` for firewall rules.

## Deployment

The recommended way to deploy is `setup.sh`, which handles everything in one step:
building both container images, merging the allowlist, installing the Podman Quadlet
systemd units, configuring autostart, and starting the services.

```bash
git clone https://github.com/np6126/leash.git
cd leash
sudo ./setup.sh
```

`setup.sh` must be re-run whenever the proxy code, policy files, or container
configuration changes.

### What setup.sh does

1. Installs `podman`, `git`, `iptables-persistent`
2. Enables IP forwarding and sets up NAT masquerade for the agent subnet (read from `/etc/leash/agents.yaml`)
3. Materialises the runtime policy under `/etc/leash/` by merging each base file with its optional `*.local.yaml` counterpart (see [Policy files](#policy-files))
4. Creates `/etc/leash/mode` with `enforce` if not already present (existing mode is preserved across re-runs)
5. Migrates legacy `/etc/leash/allowlist.yaml` deployments to the new layout in place, one-shot
6. Builds `localhost/leash:latest` and `localhost/logviewer:latest`
7. Copies Quadlet unit files to `/etc/containers/systemd/`
8. Writes `/etc/systemd/system/multi-user.target.d/leash.conf` so both services start automatically on boot

> **Why the drop-in?** Podman Quadlet generates systemd units at runtime into
> `/run/systemd/generator/`, which systemd marks as generated. `systemctl enable`
> refuses to create symlinks for generated units. The `multi-user.target.d` drop-in
> is the correct way to make Quadlet services autostart persistently.

### Manual run (for development/testing)

```bash
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

Create the directories and a minimal policy before first run:

```bash
mkdir -p /var/lib/leash/{mitmproxy,logs} /etc/leash
cp config/agents.yaml    /etc/leash/agents.yaml
cp config/enforce.yaml   /etc/leash/enforce.yaml
cp config/blocklist.yaml /etc/leash/blocklist.yaml
echo enforce > /etc/leash/mode
```

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

## Policy files

The deployed policy lives under `/etc/leash/`. Each file has one job:

```
/etc/leash/
├── mode              # one line: "enforce" | "audit" | "blocklist"
├── agents.yaml       # who counts as an agent (cross-mode topology)
├── enforce.yaml      # allow rules — active when mode == "enforce"
└── blocklist.yaml    # deny rules — active when mode == "blocklist"
```

Changes to any of these files are picked up on the next request — no restart.

### `enforce.yaml`

```yaml
allow:
  - host: api.anthropic.com
    ports: [443]
  - host: github.com         # parent-domain fallback: matches api.github.com, gist.github.com, …
    ports: [443]
```

Multiple ports per host are supported: `ports: [11434, 5555]`. Omitting `paths`
allows all methods and paths on the listed ports. To restrict by path, add a
`paths` list:

```yaml
allow:
  - host: quay.io
    ports: [443]
    paths:
      - { method: GET,  prefix: /v2/ }
      - { method: HEAD, prefix: /v2/ }
```

Each path rule matches when the request method equals `method`
(case-insensitive; empty string matches any method) **and** the URL path
starts with `prefix`. A request that matches the host and port but no path
rule is blocked with reason `path_not_allowed`. CONNECT tunnel requests
(before the TLS handshake) are checked against host and port only; path rules
apply to the subsequent HTTP request.

Blocked destinations receive an HTTP 403 before any TLS handshake completes.

### `blocklist.yaml`

Pattern-native, documentation-rich:

```yaml
block:
  # bare strings — equivalent to {host: "...", ports: [443]}
  - pastebin.com
  - hastebin.com
  - "*.doubleclick.net"

  # object form for port or path specificity
  - host: github.com
    paths:
      - { prefix: /raw/ }
    reason: "no raw-file fetches"
```

Parent-domain fallback applies here too: `doubleclick.net` also blocks any
subdomain. A `host` entry without `paths` blocks the whole host on the listed
ports (default `[443]`).

### `agents.yaml`

```yaml
agent_networks:
  - 10.10.10.0/24
```

Lists the source networks the log viewer treats as agents. Policy-mutation
endpoints (`/api/mode`, `/api/policy/*`) refuse traffic from these networks —
this is the only application-level control preventing an agent from
whitelisting (or unblocking) itself. Set this before exposing port 8090.

### Hostname matching

All three files use the same matcher: exact host first, then parent-domain
fallback. `github.com` matches every subdomain. The `*.foo.com` prefix in
the blocklist is purely informational; the underlying match is the same.

### Fail-safe behaviour

On startup the proxy starts with empty rule sets. `mode` defaults to
`enforce` if the file is missing or contains an invalid value, so a fresh
container with no policy fails closed — every request is rejected as
`not_in_allowlist` until the files appear.

Once a file has been loaded, its in-memory copy is kept even if the file is
later deleted or becomes unreadable; requests continue against the
last-known-good state and an error is logged. If a file exists but contains
invalid YAML, the reload is skipped and the previous state is retained.
This means:

- **No files at startup → fail-closed** (everything blocked until they appear).
- **A file disappears after startup → fail-open** (last loaded state preserved).
- **An invalid edit → fail-open** (the broken edit is skipped; previous state stays live).

Keep the policy files accessible and syntactically valid. `setup.sh` validates
each YAML file before deploying.

### Private overlay

If you need deployment-specific rules that should not be part of the
repository (internal hosts, corporate services), drop `*.local.yaml` files
into your local `config/`:

```yaml
# config/enforce.local.yaml
allow:
  - host: registry.internal.example.com
    ports: [443]
```

```yaml
# config/blocklist.local.yaml
block:
  - pastebin.com
```

These files are git-ignored. `setup.sh` merges each base file with its
`.local.yaml` counterpart on every run, deduplicating by host (base entries
win on collision).

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

## Log Format

Logs are written as NDJSON to the configured `LOG_PATH`. Each line is one event:

```json
{"ts": 1746900000.123, "event": "allowed", "client": "10.88.0.2", "host": "api.anthropic.com", "port": 443, "method": "POST", "url": "https://api.anthropic.com/v1/messages", "status": 200, "bytes": 4821}
{"ts": 1746900001.456, "event": "blocked", "client": "10.88.0.2", "host": "raw.githubusercontent.com", "port": 443, "reason": "not_in_allowlist"}
```

| Field | Description |
|---|---|
| `ts` | Unix timestamp (float) |
| `event` | `allowed`, `blocked`, `connect_allowed`, or `error` |
| `client` | Source IP of the agent |
| `host` | Target hostname |
| `port` | Target port |
| `method` | HTTP method (on `allowed` and `blocked` requests) |
| `url` | Full URL (on `allowed` and `blocked` requests) |
| `status` | HTTP response status code (on `allowed` requests) |
| `bytes` | Response body size in bytes. For buffered (text) responses this is the actual body size captured. For streamed responses (binary, SSE) this is taken from the `Content-Length` response header and omitted if the header is absent — it may not reflect the true transfer size. |
| `audit` | `would_block_in_enforce` — only on `allowed` events in non-enforce modes when the request would have been blocked in enforce mode. Drives the amber row tint and `WOULD BLOCK` chip in the viewer. |
| `reason` | Reason for block (`not_in_allowlist`, `path_not_allowed`, or `in_blocklist`), or error message |
| `req_headers` / `res_headers` | Captured headers as `[[name, value], …]` |
| `req_body` / `res_body` | Captured body text (up to `BODY_LIMIT_KB` KB; omitted for binary and streamed responses) |
| `req_truncated` / `res_truncated` | `true` if the body was cut at the `BODY_LIMIT_KB` limit |

`connect_allowed` is written to the log when an HTTPS CONNECT tunnel is
established but is **not shown** in the log viewer UI — each HTTPS request
appears as a single `allowed` or `blocked` row. `blocked` at the CONNECT stage
means the destination was rejected before TLS began. `error` covers TLS
failures and connection resets.

## Log Rotation

The log file grows unboundedly. For long-running deployments, configure logrotate to cap its size:

```
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
