# Policy

How leash decides what passes, and what it records. For installing and
operating leash, see [Deployment](deployment.md); for an overview of the
project, see the [README](../README.md).

## Modes

Three operation modes, selected by the single-line file `/etc/leash/mode`:

| Mode        | What passes                                            | What's blocked                | Use case                     |
|-------------|--------------------------------------------------------|-------------------------------|------------------------------|
| `enforce`   | Only hosts listed in `enforce.yaml`                    | Everything else (HTTP 403)    | Production, strict           |
| `audit`     | Everything                                             | Nothing                       | Discovery / policy authoring |
| `blocklist` | Everything except hosts listed in `blocklist.yaml`     | Hosts in `blocklist.yaml`     | Defence-in-depth on trusted agents |

Switch modes from the log viewer header, or on the proxy host with `leashctl`
(installed to `/usr/local/bin/` by `setup.sh`):

```bash
leashctl mode                    # show current mode
leashctl mode audit              # flip (hot-reload, no restart)
leashctl edit                    # open the active policy file in $EDITOR
leashctl edit blocklist          # edit a specific file by name
```

In `audit` and `blocklist` modes, every passing request is also matched against
the enforce rules; rows that *would have been blocked in enforce* are tagged
with `audit: "would_block_in_enforce"` in the JSON log and rendered with an
amber chip + row tint in the viewer. Use this to stage an allowlist against
real agent traffic, then flip to enforce when the rules look right.

> [!WARNING]
> Audit and blocklist are degraded-security postures. The log viewer shows
> a persistent amber banner whenever mode is not `enforce`. Don't leave
> production deployments in audit unless you intend to.

## Policy Files

The deployed policy lives under `/etc/leash/`. Each file has one job:

```text
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
</content>
