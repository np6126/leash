"""
mitmproxy addon: allowlist enforcement + structured JSON logging.

Blocks connections not in the allowlist before the TLS handshake (HTTPS CONNECT)
and at the HTTP request stage for plaintext traffic. The allowlist file is
re-read on every connection so changes take effect without restarting the proxy.

Each allowlist entry may include an optional `paths` list to restrict which
HTTP methods and path prefixes are permitted on that host. Entries without
`paths` allow all paths on the matching host:port.
"""

import json
import os
import time

import yaml
from mitmproxy import ctx, http

BODY_LIMIT = int(os.environ.get("BODY_LIMIT_KB", "1024")) * 1024


class AllowlistLogger:
    def __init__(self) -> None:
        self.allowlist_path = os.environ.get(
            "ALLOWLIST_PATH", "/etc/leash/allowlist.yaml"
        )
        self.log_path = os.environ.get("LOG_PATH", "/logs/leash.jsonl")
        self._allowed: dict[str, dict] = {}
        self._mtime: float = 0.0
        self._log_fh = None

    @staticmethod
    def _client_ip(flow: http.HTTPFlow) -> str | None:
        return flow.client_conn.peername[0] if flow.client_conn.peername else None

    # ------------------------------------------------------------------
    # Allowlist loading
    # ------------------------------------------------------------------

    def _reload_if_changed(self) -> None:
        try:
            mtime = os.path.getmtime(self.allowlist_path)
        except OSError:
            return
        if mtime == self._mtime:
            return
        try:
            with open(self.allowlist_path) as fh:
                raw = yaml.safe_load(fh) or {}
            allowed: dict[str, dict] = {}
            for entry in raw.get("allowed_destinations", []):
                host = str(entry.get("host", "")).strip()
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
                        if r.get("prefix")
                    ] or None
                allowed[host] = {
                    "ports": set(entry.get("ports", [443])),
                    "paths": path_rules,
                }
            self._allowed = allowed
            self._mtime = mtime
            ctx.log.info(
                f"leash: allowlist loaded — {len(allowed)} host(s) permitted"
            )
        except Exception as exc:
            ctx.log.error(f"leash: allowlist reload failed: {exc}")

    def _find_entry(self, host: str):
        """Exact match first, then parent-domain wildcard (e.g. api.github.com → github.com)."""
        entry = self._allowed.get(host)
        if entry is not None:
            return entry
        labels = host.split(".")
        for i in range(1, len(labels) - 1):
            entry = self._allowed.get(".".join(labels[i:]))
            if entry is not None:
                return entry
        return None

    def _is_allowed(
        self, host: str, port: int, method: str = "", path: str = ""
    ) -> tuple[bool, str]:
        """
        Return (allowed, reason). reason is non-empty only when blocked.

        If method and path are empty (called from http_connect before TLS),
        only host:port is checked — path rules are enforced later in request().
        """
        self._reload_if_changed()
        entry = self._find_entry(host)
        if entry is None or port not in entry["ports"]:
            return False, "not_in_allowlist"
        path_rules = entry["paths"]
        if path_rules is None or not method or not path:
            return True, ""
        for rule in path_rules:
            rule_method = rule["method"]
            rule_prefix = rule["prefix"]
            if (not rule_method or rule_method == method.upper()) and path.startswith(
                rule_prefix
            ):
                return True, ""
        return False, "path_not_allowed"

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
            if self._log_fh is None or self._log_fh.closed:
                self._log_fh = open(self.log_path, "a")
            self._log_fh.write(json.dumps(record) + "\n")
            self._log_fh.flush()
        except OSError as exc:
            self._log_fh = None
            ctx.log.error(f"leash: log write failed: {exc}")

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """
        Intercept HTTPS CONNECT tunnels before TLS handshake.
        Blocking here prevents mitmproxy from ever negotiating TLS with the
        destination, so no bytes reach a disallowed host.
        Path rules are not checked here (path is unknown before TLS);
        they are enforced in request() after interception.
        """
        host = flow.request.host
        port = flow.request.port
        client_ip = self._client_ip(flow)
        allowed, reason = self._is_allowed(host, port)
        if not allowed:
            self._log("blocked", host, port, client_ip, reason=reason)
            flow.response = http.Response.make(
                403,
                f"leash: {host}:{port} not in allowlist\n",
                {"Content-Type": "text/plain"},
            )
            return
        self._log("connect_allowed", host, port, client_ip)

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept plaintext HTTP requests (and already-tunneled HTTPS requests
        after TLS interception by mitmproxy). Enforces both host:port and
        path-level rules.
        """
        host = flow.request.host
        port = flow.request.port
        client_ip = self._client_ip(flow)
        allowed, reason = self._is_allowed(
            host, port, flow.request.method, flow.request.path
        )
        req_body, req_truncated = self._capture_body(flow.request.content or b"")
        if not allowed:
            self._log(
                "blocked",
                host,
                port,
                client_ip,
                method=flow.request.method,
                url=flow.request.pretty_url,
                reason=reason,
                req_headers=self._capture_headers(flow.request.headers),
                req_body=req_body,
                req_truncated=req_truncated,
            )
            flow.response = http.Response.make(
                403,
                f"leash: {host}:{port}{flow.request.path} blocked\n",
                {"Content-Type": "text/plain"},
            )
            return
        flow.metadata["log_allowed"] = True
        flow.metadata["log_client"] = client_ip
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
        These are currently invisible — the CONNECT gets logged as
        connect_allowed but the subsequent failure is silently dropped.
        Skip flows we intentionally blocked (already logged as 'blocked').
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
