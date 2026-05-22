<p align="center">
  <img src="docs/banner.svg" alt="leash — an auditing egress proxy for AI agent deployments" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python 3.12">
</p>

> Know — and control — every outbound request your AI agents make.

An auditing egress proxy for AI agent deployments. It sits between the agent
VM and the public internet and, for every outbound request, applies one of
three operation modes (strict allowlist · pure audit · blocklist) and writes a
structured event to an audit log on a persistent volume outside the agent
environment.

Designed to run alongside [tank-agent-os](https://github.com/np6126/tank-agent-os)
but works with any setup where you can point an HTTP proxy at this service.

It is built for the people who run AI-agent infrastructure — platform,
DevOps, and security engineers who need a defensible record of agent network
activity and a hard limit on where agents can reach.

## What You Get

- **Three policy modes** — strict allowlist, pure audit, or blocklist,
  switchable without a restart.
- **Full-fidelity audit log** — structured NDJSON with URLs, methods,
  status codes, and bodies, stored outside the agent VM.
- **Hot-reloadable policy** — edit allow/block rules and flip modes; changes
  apply on the next request.
- **Web log viewer** — browse, search, and filter egress; manage allow/block
  rules from the UI.
- **Fail-closed startup** — the proxy starts in `enforce` mode with empty rule
  sets, so a container that comes up before its policy files are present rejects
  every request until the policy is in place.
- **Staged hardening** — audit mode flags requests that *would* be blocked in
  enforce, so you can build an allowlist against real traffic.

## Why This Exists

An AI agent with unrestricted internet access is an unaudited, unbounded
egress path. That creates two concrete problems. First, the agent can
exfiltrate data by calling arbitrary external services directly rather than
through the application's authorised API layer. Second, there is no record of
what it contacted, making post-incident analysis difficult or impossible.

This proxy addresses both. The allowlist makes unauthorised destinations
technically unreachable. The log gives you a complete record of everything the
agent tried to reach, including blocked attempts. Because the log lives outside
the agent VM, the agent cannot alter or delete it — it survives VM compromise
or destruction. The log is not cryptographically signed; an operator with shell
access to the proxy host could modify it.

TLS interception means HTTPS traffic is logged in plaintext, so the log
records full URLs and request methods rather than only hostnames and ports.

## Documentation

- **[Deployment](docs/deployment.md)** — installing leash, extracting the CA
  certificate, restricting the agent, and operational reference (environment
  variables, log rotation, memory safety).
- **[Policy](docs/policy.md)** — the three modes, the policy files, hostname
  matching, fail-safe behaviour, and the audit log format.
- **[Proxmox VE Setup](docs/proxmox-setup.md)** — a full VM walkthrough, from
  cloud image to a running proxy.

## Architecture

```text
┌──────────────────────────────────────────────────┐
│ agent container                                  │
└──────────────────────────────────────────────────┘
        │  HTTP_PROXY / HTTPS_PROXY
        ▼
┌──────────────────────────────────────────────────┐
│ leash                                            │
│ mitmproxy · explicit proxy mode · port 8080      │
│                                                  │
│  • TLS interception with self-signed CA          │
│  • policy check per request                      │
│    (enforce | audit | blocklist)                 │
│  • JSON log → /logs/egress.jsonl                 │
└──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────┐
│ permitted external destinations only             │
└──────────────────────────────────────────────────┘
```

The proxy runs in explicit proxy mode. The agent sets `HTTP_PROXY` and
`HTTPS_PROXY` in its environment. For HTTPS the agent sends a `CONNECT` tunnel
request; mitmproxy intercepts the tunnel, applies the active policy to the
destination before the TLS handshake begins, and either rejects it with HTTP
403 or intercepts and re-encrypts the traffic using its own CA certificate.

Mode and both policy files are reloaded from disk on every request, so you can
flip modes and edit allow/block rules without restarting the proxy.

## Quickstart

`setup.sh` targets Debian/Ubuntu. On the proxy host:

```bash
git clone https://github.com/np6126/leash.git
cd leash
sudo ./setup.sh
```

`setup.sh` builds both container images, materialises the runtime policy under
`/etc/leash/`, installs the Podman Quadlet systemd units, and starts the
services. See [Deployment](docs/deployment.md) for a step-by-step breakdown and
the path for non-Debian hosts, and [Proxmox VE Setup](docs/proxmox-setup.md)
for a full VM walkthrough.

## Modes

leash runs in one of three modes, selected by the single-line file
`/etc/leash/mode`:

| Mode        | What passes                                            | What's blocked                | Use case                     |
|-------------|--------------------------------------------------------|-------------------------------|------------------------------|
| `enforce`   | Only hosts listed in `enforce.yaml`                    | Everything else (HTTP 403)    | Production, strict           |
| `audit`     | Everything                                             | Nothing                       | Discovery / policy authoring |
| `blocklist` | Everything except hosts listed in `blocklist.yaml`     | Hosts in `blocklist.yaml`     | Defence-in-depth on trusted agents |

Switch modes from the log viewer header or with `leashctl` on the proxy host.
Audit and blocklist are degraded-security postures — see [Policy](docs/policy.md)
for the full detail on modes, the policy files, and the audit log format.

## Log Viewer

leash ships with a web UI for browsing the audit log and managing policy
without touching YAML. It is available at port 8090 after running `setup.sh`.

![leash log viewer, enforce mode, dark theme](docs/logviewer.png)

*Log viewer in `enforce` mode (dark theme).*

![leash log viewer, audit mode, light theme, showing the amber banner and WOULD-BLOCK chips](docs/logviewer-light.png)

*Log viewer in `audit` mode (light theme) — note the amber mode banner and `WOULD BLOCK` chips.*

Requests are listed newest-first with timestamp, client IP, method, URL, port,
HTTP status, and response size — one row per request. Rows are colour-tinted by
event class (red for blocked, amber for would-block-in-enforce). Clicking a row
opens a detail panel with the request and response headers and body.

- **Mode switcher** — flip between enforce, audit, and blocklist from the header.
- **Search and filters** — free-text search, a client-IP filter, an *Internet
  only* toggle, and a *Would block in enforce* filter for the hardening backlog.
- **Manage Access** — from the detail panel, add or remove a host in the
  enforce list or the blocklist; the change applies on the next request.
- **Mode and health banners** — an amber strip in non-enforce modes, and a
  warning strip when the policy is misconfigured.
- **Redact toggle** — masks sensitive header values (API keys, cookies).

> [!CAUTION]
> The mode-switch and policy-mutation endpoints (`PUT /api/mode`,
> `POST /api/policy/*`) are refused for any client IP within a network listed
> under `agent_networks` in `agents.yaml` — **the only application-level
> control preventing agents from changing the mode or whitelisting
> themselves.** Configure `agent_networks` before exposing the log viewer. A
> network firewall rule (block port 8090 from the agent subnet) is
> defence-in-depth, not a substitute.

See [Deployment](docs/deployment.md) for operating leash, and
[Policy](docs/policy.md) for the rule files behind the *Manage Access* dialog.

## License

leash is released under the [MIT License](LICENSE).
</content>
