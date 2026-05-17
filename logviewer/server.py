#!/usr/bin/env python3
"""
Logviewer: serves the leash audit log as a filterable web UI.
PyYAML is required for allowlist management (added to container image).
"""

import ipaddress
import json
import mmap
import os
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

LOG_PATH = os.environ.get("LOG_PATH", "/logs/leash.jsonl")
PORT = int(os.environ.get("PORT", "8090"))
ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "/etc/leash/allowlist.yaml")
BODY_LIMIT_KB = int(os.environ.get("BODY_LIMIT_KB", "1024"))
_LOGVIEWER_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_LOGVIEWER_DIR, "static")
_TEMPLATES_DIR = os.path.join(_LOGVIEWER_DIR, "templates")

_INVALID_FIELD_RE = re.compile(r'[\r\n\x00]')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, content_type: str) -> None:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            self.send_json(404, {"error": "not found"})
            return
        with _static_lock:
            cached = _static_cache.get(path)
            if cached is not None and cached[0] == mtime:
                body = cached[1]
            else:
                body = None
        if body is None:
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_json(404, {"error": "not found"})
                return
            with _static_lock:
                _static_cache[path] = (mtime, body)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self._send_file(os.path.join(_TEMPLATES_DIR, "index.html"), "text/html; charset=utf-8")

        elif parsed.path == "/static/style.css":
            self._send_file(os.path.join(_STATIC_DIR, "style.css"), "text/css; charset=utf-8")

        elif parsed.path == "/static/app.js":
            self._send_file(os.path.join(_STATIC_DIR, "app.js"), "application/javascript; charset=utf-8")

        elif parsed.path == "/logo.svg":
            self._send_file(os.path.join(_LOGVIEWER_DIR, "logo.svg"), "image/svg+xml")

        elif parsed.path == "/api/logs":
            qs = parse_qs(parsed.query)
            q = (qs.get("q", [""])[0] or "").strip().lower()
            client_f = (qs.get("client", [""])[0] or "").strip().lower()
            limit = min(int(qs.get("limit", ["500"])[0]), 2000)
            internet_only = qs.get("internet_only", [""])[0] == "1"
            self.send_json(200, _read_logs(q, client_f, limit, internet_only))

        elif parsed.path == "/api/meta":
            try:
                stat = os.stat(LOG_PATH)
                size_mb = round(stat.st_size / 1_048_576, 3)
                total_lines = _count_lines()
            except OSError:
                size_mb = 0.0
                total_lines = 0
            self.send_json(200, {"size_mb": size_mb, "total_lines": total_lines, "body_limit_kb": BODY_LIMIT_KB})

        elif parsed.path == "/api/allowlist":
            if _is_agent_source(self.client_address[0]):
                self.send_json(403, {"error": "not available from agent network"})
                return
            self.send_json(200, _load_allowlist())

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/logs/clear":
            try:
                with open(LOG_PATH, "w"):
                    pass
                self.send_json(200, {"ok": True})
            except OSError as e:
                self.send_json(500, {"error": str(e)})

        elif self.path in ("/api/allowlist/add", "/api/allowlist/remove"):
            if _is_agent_source(self.client_address[0]):
                self.send_json(403, {"error": "not available from agent network"})
                return
            try:
                fn = _allowlist_add if self.path.endswith("/add") else _allowlist_remove
                self.send_json(200, fn(self._read_body()))
            except Exception as e:
                self.send_json(500, {"error": str(e)})

        else:
            self.send_json(404, {"error": "not found"})


# ── Static file cache (mtime-keyed; invalidated automatically on disk change) ──

_static_lock: threading.Lock = threading.Lock()
_static_cache: dict[str, tuple[float, bytes]] = {}  # path → (mtime, content)

# ── Allowlist helpers ─────────────────────────────────────────────────────────

def _is_agent_source(client_ip: str) -> bool:
    """True if client_ip is in any network listed under agent_networks in the allowlist."""
    networks = _load_allowlist().get("agent_networks") or []
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)
    except ValueError:
        return False


_allowlist_cache: tuple[float, dict] = (0.0, {})
_allowlist_lock: threading.Lock = threading.Lock()
# Serialises the read→modify→write cycle in _allowlist_add/_allowlist_remove.
# Without this, two concurrent POST requests could each load the same state and
# silently overwrite each other's changes.
_allowlist_mgmt_lock: threading.Lock = threading.Lock()


def _load_allowlist() -> dict:
    global _allowlist_cache
    try:
        mtime = os.path.getmtime(ALLOWLIST_PATH)
        with _allowlist_lock:
            if mtime == _allowlist_cache[0]:
                return _allowlist_cache[1]
        with open(ALLOWLIST_PATH) as fh:
            data = yaml.safe_load(fh) or {}
        data["allowed_destinations"] = data.get("allowed_destinations") or []
        data["agent_networks"] = data.get("agent_networks") or []
        with _allowlist_lock:
            _allowlist_cache = (mtime, data)
        return data
    except OSError:
        return {"allowed_destinations": [], "agent_networks": []}


def _save_allowlist(data: dict) -> None:
    global _allowlist_cache
    lines: list[str] = []

    # Preserve agent_networks — dropping this would disable the security block
    # that prevents agent VMs from calling the allowlist management endpoints.
    networks = data.get("agent_networks") or []
    if networks:
        lines.append("agent_networks:\n")
        for net in networks:
            lines.append(f"  - {net}\n")
        lines.append("\n")

    entries = data.get("allowed_destinations") or []
    # Write "allowed_destinations: []" explicitly when empty so YAML doesn't
    # parse the key-with-no-value back as None on the next load.
    if not entries:
        lines.append("allowed_destinations: []\n")
    else:
        lines.append("allowed_destinations:\n")
    for entry in entries:
        host = entry.get("host", "")
        ports = entry.get("ports", [443])
        lines.append(f"  - host: {json.dumps(host)}\n")
        lines.append(f"    ports: [{', '.join(str(p) for p in ports)}]\n")
        paths = entry.get("paths")
        if paths:
            lines.append("    paths:\n")
            for rule in paths:
                lines.append(f"      - method: {json.dumps(rule.get('method', ''))}\n")
                lines.append(f"        prefix: {json.dumps(rule.get('prefix', '/'))}\n")
    # Atomic write: write to temp file then rename to avoid partial reads by the proxy addon
    dir_path = os.path.dirname(os.path.abspath(ALLOWLIST_PATH))
    os.makedirs(dir_path, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=dir_path, delete=False, suffix=".tmp") as tmp:
        tmp.writelines(lines)
        tmp_path = tmp.name
    os.replace(tmp_path, ALLOWLIST_PATH)
    with _allowlist_lock:
        _allowlist_cache = (0.0, {})


def _validate_fields(host: str, method: str, prefix: str) -> str | None:
    """Return an error string if any value contains characters that would break YAML output."""
    for val, name in ((host, "host"), (method, "method"), (prefix, "prefix")):
        if _INVALID_FIELD_RE.search(val):
            return f"{name} contains invalid characters"
    return None


def _allowlist_add(body: dict) -> dict:
    host = str(body.get("host", "")).strip()
    if not host:
        return {"ok": False, "error": "host required"}
    port   = int(body.get("port", 443))
    scope  = str(body.get("scope", "host"))
    method = str(body.get("method", "")).upper()
    prefix = str(body.get("prefix", "/"))

    err = _validate_fields(host, method, prefix)
    if err:
        return {"ok": False, "error": err}

    with _allowlist_mgmt_lock:
        data  = _load_allowlist()
        dests = data["allowed_destinations"]
        entry = next((e for e in dests if e.get("host") == host), None)

        if scope == "host":
            if entry is None:
                dests.append({"host": host, "ports": [port]})
            else:
                if port not in entry.get("ports", []):
                    entry.setdefault("ports", []).append(port)
                entry.pop("paths", None)
        else:
            if entry is None:
                entry = {"host": host, "ports": [port], "paths": []}
                dests.append(entry)
            else:
                if port not in entry.get("ports", []):
                    entry.setdefault("ports", []).append(port)
                entry.setdefault("paths", [])
            paths = entry["paths"]
            if not any(p.get("method") == method and p.get("prefix") == prefix for p in paths):
                paths.append({"method": method, "prefix": prefix})

        _save_allowlist(data)
        return {"ok": True, "allowlist": data}


def _allowlist_remove(body: dict) -> dict:
    host = str(body.get("host", "")).strip()
    if not host:
        return {"ok": False, "error": "host required"}
    scope  = str(body.get("scope", "host"))
    method = str(body.get("method", "")).upper()
    prefix = str(body.get("prefix", "/"))

    err = _validate_fields(host, method, prefix)
    if err:
        return {"ok": False, "error": err}

    with _allowlist_mgmt_lock:
        data  = _load_allowlist()
        dests = data["allowed_destinations"]

        if scope == "host":
            data["allowed_destinations"] = [e for e in dests if e.get("host") != host]
        else:
            entry = next((e for e in dests if e.get("host") == host), None)
            if entry and entry.get("paths"):
                entry["paths"] = [
                    p for p in entry["paths"]
                    if not (p.get("method") == method and p.get("prefix") == prefix)
                ]
                if not entry["paths"]:
                    del entry["paths"]

        _save_allowlist(data)
        return {"ok": True, "allowlist": data}


# ── Log reading helpers ───────────────────────────────────────────────────────

_LAN_NAMES = {"localhost", "local", "lan", "internal", "home", "fritz.box"}


def _is_lan(host: str) -> bool:
    """True if host is a private/loopback IP or a known local hostname."""
    if not host:
        return False
    # Try the bare value first (handles plain IPv6 like "::1"), then strip a
    # trailing ":port" suffix (handles "host:port" and "[::1]:port" notation).
    for candidate in (host.strip("[]"), host.rsplit(":", 1)[0].strip("[]")):
        try:
            addr = ipaddress.ip_address(candidate)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            continue
    h_lower = host.rsplit(":", 1)[0].strip("[]").lower()
    return (h_lower in _LAN_NAMES
            or h_lower.endswith(".local")
            or h_lower.endswith(".lan")
            or h_lower.endswith(".internal")
            or h_lower.endswith(".home")
            or h_lower.endswith(".fritz.box"))


_count_cache: tuple[float, int] = (0.0, 0)  # (mtime, count)
_count_lock: threading.Lock = threading.Lock()

# Cannot appear inside a JSON string value because interior quotes are backslash-escaped.
_CONNECT_MARKER = b'"event": "connect_allowed"'


def _count_lines() -> int:
    global _count_cache
    try:
        mtime = os.path.getmtime(LOG_PATH)
        with _count_lock:
            if mtime == _count_cache[0]:
                return _count_cache[1]
        with open(LOG_PATH, "rb") as f:
            data = f.read()
        count = sum(1 for ln in data.splitlines() if ln.strip() and _CONNECT_MARKER not in ln)
        with _count_lock:
            _count_cache = (mtime, count)
        return count
    except OSError:
        return 0


def _record_matches(record: dict, q: str, client_f: str, internet_only: bool) -> bool:
    if record.get("event") == "connect_allowed":
        return False
    if internet_only and _is_lan(record.get("host") or record.get("url") or ""):
        return False
    if client_f and client_f not in (record.get("client") or "").lower():
        return False
    if q:
        haystack = " ".join(str(v) for v in record.values()).lower()
        return q in haystack
    return True


def _read_logs(q: str, client_f: str, limit: int, internet_only: bool = False) -> list:
    # The proxy addon appends to this file concurrently. POSIX append semantics
    # prevent torn writes, but a line being written exactly as the mmap is built
    # may appear truncated and will be silently skipped by json.JSONDecodeError.
    results = []
    try:
        with open(LOG_PATH, "rb") as f:
            mm = None
            try:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                pos = mm.size()
                while pos > 0 and len(results) < limit:
                    prev = mm.rfind(b"\n", 0, pos - 1)
                    line = mm[max(prev + 1, 0):pos].strip()
                    pos = prev if prev >= 0 else 0
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not _record_matches(record, q, client_f, internet_only):
                        continue
                    results.append(record)
            except ValueError:
                pass  # empty file
            finally:
                if mm is not None:
                    mm.close()
    except OSError:
        pass
    return results


if __name__ == "__main__":
    print(f"logviewer listening on :{PORT} (HTTP — do not expose publicly without a firewall)", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
