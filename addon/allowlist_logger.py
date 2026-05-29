"""
mitmproxy addon: three-mode policy enforcement + structured JSON logging.

Modes (selected by /etc/leash/mode, single-line plain text):

    enforce    — only hosts in enforce.yaml may pass. Rest is 403.
    audit      — everything passes. Nothing is blocked.
    blocklist  — everything passes except hosts in blocklist.yaml (403).

The policy is hot-reloaded: every connection re-checks file mtimes and reloads
whichever file changed. Mode flips, allow-rule edits, and blocklist edits all
take effect on the next request — no restart needed.

In `audit` and `blocklist` modes, when a request passes through, the addon
additionally evaluates the enforce rules and writes an informational
`audit: "would_block_in_enforce"` field on rows that would NOT have passed
in enforce mode. The log viewer renders those rows amber so an operator can
stage an allowlist against real traffic before flipping to enforce.
"""

import json
import os
import time

import yaml
from mitmproxy import ctx, http

BODY_LIMIT = int(os.environ.get("BODY_LIMIT_KB", "1024")) * 1024
LEASH_DIR = os.environ.get("LEASH_DIR", "/etc/leash")

_VALID_MODES = ("enforce", "audit", "blocklist")
_DEFAULT_PORTS = (443,)


class AllowlistLogger:
    def __init__(self) -> None:
        self.mode_path      = os.path.join(LEASH_DIR, "mode")
        self.enforce_path   = os.path.join(LEASH_DIR, "enforce.yaml")
        self.blocklist_path = os.path.join(LEASH_DIR, "blocklist.yaml")
        self.log_path = os.environ.get("LOG_PATH", "/logs/leash.jsonl")

        # Host whose requests get their real client IP stamped into
        # X-Agent-Source (see request()). Empty = feature off.
        self._identity_host = os.environ.get("LEASH_IDENTITY_HOST", "").strip()

        self._mode: str = "enforce"
        self._enforce: dict[str, dict] = {}
        self._block: dict[str, dict] = {}
        self._mtimes: dict[str, float] = {}
        self._log_fh = None

    @staticmethod
    def _client_ip(flow: http.HTTPFlow) -> str | None:
        return flow.client_conn.peername[0] if flow.client_conn.peername else None

    # ------------------------------------------------------------------
    # Policy loading
    # ------------------------------------------------------------------

    def _reload_if_changed(self) -> None:
        loaders = (
            ("mode",      self.mode_path,      self._load_mode),
            ("enforce",   self.enforce_path,   self._load_enforce),
            ("blocklist", self.blocklist_path, self._load_blocklist),
        )
        for key, path, loader in loaders:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if mtime == self._mtimes.get(key):
                continue
            try:
                loader(path)
                self._mtimes[key] = mtime
            except Exception as exc:
                ctx.log.error(f"leash: {key} reload failed: {exc}")

    def _load_mode(self, path: str) -> None:
        with open(path) as fh:
            value = fh.read().strip()
        if value not in _VALID_MODES:
            ctx.log.warn(f"leash: invalid mode {value!r}, defaulting to enforce")
            value = "enforce"
        if value != self._mode:
            previous = self._mode
            ctx.log.info(f"leash: mode → {value}")
            self._mode = value
            self._log_mode_change(previous, value)
        else:
            self._mode = value

    def _load_enforce(self, path: str) -> None:
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}
        rules = self._parse_rules(raw.get("allow") or [], allow_bare_string=False, file_label="enforce.yaml")
        self._enforce = rules
        ctx.log.info(f"leash: enforce.yaml loaded — {len(rules)} host(s)")

    def _load_blocklist(self, path: str) -> None:
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}
        rules = self._parse_rules(raw.get("block") or [], allow_bare_string=True, file_label="blocklist.yaml")
        self._block = rules
        ctx.log.info(f"leash: blocklist.yaml loaded — {len(rules)} host(s)")

    @staticmethod
    def _normalize_host(host: str) -> str:
        host = host.strip()
        if host.startswith("*."):
            host = host[2:]
        return host

    def _parse_rules(self, entries, *, allow_bare_string: bool, file_label: str = "") -> dict[str, dict]:
        rules: dict[str, dict] = {}
        for entry in entries:
            if isinstance(entry, str):
                if not allow_bare_string:
                    ctx.log.warn(
                        f"leash: {file_label}: bare-string entry {entry!r} ignored "
                        f"(this list requires `{{host: ..., ports: [...]}}` form)"
                    )
                    continue
                host = self._normalize_host(entry)
                if host:
                    rules[host] = {"ports": set(_DEFAULT_PORTS), "paths": None}
                continue
            if not isinstance(entry, dict):
                continue
            host = self._normalize_host(str(entry.get("host", "")))
            if not host:
                continue
            raw_paths = entry.get("paths")
            path_rules: list[dict] | None = None
            if raw_paths:
                path_rules = [
                    {
                        "method": str(r.get("method", "")).upper(),
                        "prefix": str(r.get("prefix", "/")),
                    }
                    for r in raw_paths
                    if isinstance(r, dict) and r.get("prefix")
                ] or None
            rules[host] = {
                "ports": set(entry.get("ports") or _DEFAULT_PORTS),
                "paths": path_rules,
            }
        return rules

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    @staticmethod
    def _find_entry(rules: dict, host: str):
        """Exact match first, then parent-domain wildcard (api.github.com → github.com)."""
        entry = rules.get(host)
        if entry is not None:
            return entry
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            entry = rules.get(".".join(labels[i:]))
            if entry is not None:
                return entry
        return None

    def _match(
        self, rules: dict, host: str, port: int, method: str = "", path: str = ""
    ) -> tuple[bool, str]:
        """
        Returns (matched, mismatch_kind).
        mismatch_kind is "host" (host or port missing) or "path" (host+port ok,
        path rejected). Empty when matched.
        """
        entry = self._find_entry(rules, host)
        if entry is None or port not in entry["ports"]:
            return False, "host"
        path_rules = entry["paths"]
        if path_rules is None or not method or not path:
            return True, ""
        for rule in path_rules:
            if (not rule["method"] or rule["method"] == method.upper()) and path.startswith(rule["prefix"]):
                return True, ""
        return False, "path"

    def _decide(
        self, host: str, port: int, method: str = "", path: str = ""
    ) -> tuple[str, str, str]:
        """
        Returns (action, reason, audit_decision).

          action          — "pass" | "block"
          reason          — non-empty only when action == "block"
                            ("in_blocklist" | "not_in_allowlist" | "path_not_allowed")
          audit_decision  — non-empty only on pass in non-enforce modes when
                            the request would have been blocked by enforce rules
                            ("would_block_in_enforce")
        """
        self._reload_if_changed()

        if self._mode == "audit":
            enforce_matched, _ = self._match(self._enforce, host, port, method, path)
            return "pass", "", ("" if enforce_matched else "would_block_in_enforce")

        if self._mode == "blocklist":
            block_matched, _ = self._match(self._block, host, port, method, path)
            if block_matched:
                return "block", "in_blocklist", ""
            enforce_matched, _ = self._match(self._enforce, host, port, method, path)
            return "pass", "", ("" if enforce_matched else "would_block_in_enforce")

        # enforce
        matched, reason = self._match(self._enforce, host, port, method, path)
        if matched:
            return "pass", "", ""
        return "block", ("path_not_allowed" if reason == "path" else "not_in_allowlist"), ""

    # ------------------------------------------------------------------
    # Capture helpers
    # ------------------------------------------------------------------

    def _is_text_response(self, flow: http.HTTPFlow) -> bool:
        if not flow.response:
            return False
        ct = flow.response.headers.get("content-type", "").split(";")[0].strip().lower()
        return ct.startswith("text/") or ct in (
            "application/json",
            "application/xml",
            "application/yaml",
            "application/x-www-form-urlencoded",
        )

    def _capture_headers(self, headers) -> list:
        return [[k, v] for k, v in headers.items()]

    def _capture_body(self, content: bytes) -> tuple:
        if not content:
            return None, False
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return f"[binary, {len(content)} bytes]", False
        if len(text) > BODY_LIMIT:
            return text[:BODY_LIMIT], True
        return text, False

    # ------------------------------------------------------------------
    # JSON logging
    # ------------------------------------------------------------------

    def _ensure_log_fh(self) -> None:
        # If something external rotated/deleted the file (logrotate, manual rm,
        # logviewer clear-logs creating a fresh inode), the cached fd points at
        # an orphaned inode and writes are silently lost. Reopen when inode
        # diverges from the on-disk path.
        if self._log_fh is not None and not self._log_fh.closed:
            try:
                if os.fstat(self._log_fh.fileno()).st_ino == os.stat(self.log_path).st_ino:
                    return
            except OSError:
                pass
            try:
                self._log_fh.close()
            except OSError:
                pass
        self._log_fh = open(self.log_path, "a")

    def _log(
        self,
        event: str,
        host: str,
        port: int,
        client_ip: str | None,
        *,
        method: str = "",
        url: str = "",
        reason: str = "",
        status: int = 0,
        size: int = 0,
        audit: str = "",
        req_headers: list | None = None,
        req_body: str | None = None,
        req_truncated: bool = False,
        res_headers: list | None = None,
        res_body: str | None = None,
        res_truncated: bool = False,
    ) -> None:
        record: dict = {
            "ts": time.time(),
            "event": event,
            "client": client_ip,
            "host": host,
            "port": port,
        }
        if method:
            record["method"] = method
        if url:
            record["url"] = url
        if reason:
            record["reason"] = reason
        if status:
            record["status"] = status
        if size:
            record["bytes"] = size
        if audit:
            record["audit"] = audit
        if req_headers is not None:
            record["req_headers"] = req_headers
        if req_body is not None:
            record["req_body"] = req_body
        if req_truncated:
            record["req_truncated"] = True
        if res_headers is not None:
            record["res_headers"] = res_headers
        if res_body is not None:
            record["res_body"] = res_body
        if res_truncated:
            record["res_truncated"] = True
        try:
            self._ensure_log_fh()
            self._log_fh.write(json.dumps(record) + "\n")
            self._log_fh.flush()
        except OSError as exc:
            self._log_fh = None
            ctx.log.error(f"leash: log write failed: {exc}")

    def _log_mode_change(self, previous: str, current: str) -> None:
        """Append a structured mode_change event so the JSONL log carries the audit trail."""
        record = {
            "ts": time.time(),
            "event": "mode_change",
            "previous": previous,
            "mode": current,
        }
        try:
            self._ensure_log_fh()
            self._log_fh.write(json.dumps(record) + "\n")
            self._log_fh.flush()
        except OSError as exc:
            self._log_fh = None
            ctx.log.error(f"leash: mode_change log write failed: {exc}")

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """
        Intercept HTTPS CONNECT tunnels before TLS handshake.
        Path rules are not checked here (path is unknown before TLS);
        they are enforced in request() after interception.
        """
        host = flow.request.host
        port = flow.request.port
        client_ip = self._client_ip(flow)
        action, reason, _ = self._decide(host, port)
        if action == "block":
            self._log("blocked", host, port, client_ip, reason=reason)
            flow.response = http.Response.make(
                403,
                f"leash: {host}:{port} blocked ({reason})\n",
                {"Content-Type": "text/plain"},
            )
            return
        self._log("connect_allowed", host, port, client_ip)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept plaintext HTTP and already-tunneled HTTPS requests.
        Enforces host:port and path-level rules.
        """
        host = flow.request.host
        port = flow.request.port
        client_ip = self._client_ip(flow)
        # Stamp the real agent IP for the control plane behind this host.
        # Rootless-Docker port-publish NATs every agent to one bridge gateway,
        # collapsing their source IPs into a single identity. This L7 header
        # survives the L4 NAT; overwrite it so a (prompt-injected) agent can't
        # forge another's identity.
        if client_ip and self._identity_host and host == self._identity_host:
            flow.request.headers["X-Agent-Source"] = client_ip
        action, reason, audit_decision = self._decide(
            host, port, flow.request.method, flow.request.path
        )
        req_body, req_truncated = self._capture_body(flow.request.content or b"")
        if action == "block":
            self._log(
                "blocked", host, port, client_ip,
                method=flow.request.method,
                url=flow.request.pretty_url,
                reason=reason,
                req_headers=self._capture_headers(flow.request.headers),
                req_body=req_body,
                req_truncated=req_truncated,
            )
            flow.response = http.Response.make(
                403,
                f"leash: {host}:{port}{flow.request.path} blocked ({reason})\n",
                {"Content-Type": "text/plain"},
            )
            return
        flow.metadata["log_allowed"] = True
        flow.metadata["log_client"] = client_ip
        flow.metadata["log_audit"] = audit_decision
        flow.metadata["log_req_headers"] = self._capture_headers(flow.request.headers)
        flow.metadata["log_req_body"] = req_body
        flow.metadata["log_req_truncated"] = req_truncated

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if not flow.metadata.get("log_allowed") or not flow.response:
            return
        ct = flow.response.headers.get("content-type", "")
        if "event-stream" in ct or not self._is_text_response(flow):
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.metadata.get("log_allowed"):
            return
        size = 0
        res_headers = None
        res_body = None
        res_truncated = False
        if flow.response:
            res_headers = self._capture_headers(flow.response.headers)
            if flow.response.stream:
                try:
                    size = int(flow.response.headers.get("content-length", 0))
                except (ValueError, TypeError):
                    size = 0
            else:
                try:
                    size = len(flow.response.raw_content or b"")
                except Exception:
                    size = 0
                try:
                    res_body, res_truncated = self._capture_body(flow.response.content or b"")
                except Exception:
                    pass
        self._log(
            "allowed",
            flow.request.host,
            flow.request.port,
            flow.metadata.get("log_client"),
            method=flow.request.method,
            url=flow.request.pretty_url,
            status=flow.response.status_code if flow.response else 0,
            size=size,
            audit=flow.metadata.get("log_audit") or "",
            req_headers=flow.metadata.get("log_req_headers"),
            req_body=flow.metadata.get("log_req_body"),
            req_truncated=flow.metadata.get("log_req_truncated", False),
            res_headers=res_headers,
            res_body=res_body,
            res_truncated=res_truncated,
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """
        Log TLS failures, connection resets, and other post-CONNECT errors.
        Skip flows intentionally blocked (already logged as 'blocked').
        """
        if not flow.error:
            return
        if flow.response and flow.response.status_code == 403:
            return
        try:
            host = flow.request.host
            port = flow.request.port
        except Exception:
            return
        client_ip = self._client_ip(flow)
        method = ""
        url = ""
        try:
            method = flow.request.method or ""
            url = flow.request.pretty_url
        except Exception:
            pass
        self._log(
            "error",
            host,
            port,
            client_ip,
            method=method,
            url=url,
            reason=str(flow.error.msg),
        )

    def _log_tls_failure(self, data, label: str, default_msg: str) -> None:
        try:
            tls_ctx = data.context
            host = tls_ctx.server.address[0] if tls_ctx.server.address else "unknown"
            port = int(tls_ctx.server.address[1]) if tls_ctx.server.address else 0
            client_ip: str | None = (
                tls_ctx.client.peername[0] if tls_ctx.client.peername else None
            )
            err = str(data.conn.error or default_msg)
        except Exception as exc:
            ctx.log.warn(f"leash: could not parse TLS context in {label}: {exc}")
            return
        self._log("error", host, port, client_ip, reason=f"{label}: {err}")

    def tls_failed_client(self, data) -> None:
        """Client ↔ proxy TLS handshake failed — agent rejected mitmproxy's certificate."""
        self._log_tls_failure(data, "tls_client", "TLS client handshake failed")

    def tls_failed_server(self, data) -> None:
        """Proxy ↔ server TLS handshake failed — destination rejected our connection."""
        self._log_tls_failure(data, "tls_server", "TLS server handshake failed")


addons = [AllowlistLogger()]
