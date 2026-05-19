#!/usr/bin/env python3
"""
Logviewer: serves the leash audit log + policy management as a web UI.

Policy files live under LEASH_DIR (default /etc/leash):
    mode              — single-line: "enforce" | "audit" | "blocklist"
    agents.yaml       — { agent_networks: [...] } (gate /api/policy mutations)
    enforce.yaml      — { allow:    [{host, ports, paths?}, ...] }
    blocklist.yaml    — { block:    [{host, ports, paths?} | "host", ...] }

Mode and both policy files are hot-reloaded by the addon. The logviewer's
own cache is also mtime-keyed and refreshes on edit.
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
LEASH_DIR = os.environ.get("LEASH_DIR", "/etc/leash")
MODE_PATH      = os.path.join(LEASH_DIR, "mode")
AGENTS_PATH    = os.path.join(LEASH_DIR, "agents.yaml")
ENFORCE_PATH   = os.path.join(LEASH_DIR, "enforce.yaml")
BLOCKLIST_PATH = os.path.join(LEASH_DIR, "blocklist.yaml")
BODY_LIMIT_KB = int(os.environ.get("BODY_LIMIT_KB", "1024"))

_LOGVIEWER_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_LOGVIEWER_DIR, "static")
_TEMPLATES_DIR = os.path.join(_LOGVIEWER_DIR, "templates")

_VALID_MODES = ("enforce", "audit", "blocklist")
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

    def _gate_agent_source(self) -> bool:
        """Return True (and send 403) if the request is from an agent network."""
        if _is_agent_source(self.client_address[0]):
            self.send_json(403, {"error": "not available from agent network"})
            return True
        return False

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
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"[")
            sep = b""
            for record in _iter_logs(q, client_f, limit, internet_only):
                self.wfile.write(sep + json.dumps(record).encode())
                sep = b","
            self.wfile.write(b"]")

        elif parsed.path == "/api/meta":
            try:
                stat = os.stat(LOG_PATH)
                size_mb = round(stat.st_size / 1_048_576, 3)
                total_lines = _count_lines()
            except OSError:
                size_mb = 0.0
                total_lines = 0
            self.send_json(200, {"size_mb": size_mb, "total_lines": total_lines, "body_limit_kb": BODY_LIMIT_KB})

        elif parsed.path == "/api/mode":
            self.send_json(200, {"mode": _load_mode()})

        elif parsed.path == "/api/health":
            self.send_json(200, _health_snapshot())

        elif parsed.path == "/api/policy":
            if self._gate_agent_source():
                return
            self.send_json(200, _policy_snapshot())

        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/logs/clear":
            try:
                _clear_log()
                self.send_json(200, {"ok": True})
            except OSError as e:
                self.send_json(500, {"error": str(e)})
            return

        if self.path in ("/api/policy/enforce/add", "/api/policy/enforce/remove",
                         "/api/policy/blocklist/add", "/api/policy/blocklist/remove"):
            if self._gate_agent_source():
                return
            parts = self.path.split("/")        # ['', 'api', 'policy', '<list>', '<verb>']
            list_name = parts[3]
            verb = parts[4]
            try:
                fn = _policy_add if verb == "add" else _policy_remove
                self.send_json(200, fn(list_name, self._read_body()))
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            return

        if self.path == "/api/mode":
            if self._gate_agent_source():
                return
            try:
                body = self._read_body()
                mode = str(body.get("mode", "")).strip()
                if mode not in _VALID_MODES:
                    self.send_json(400, {"error": f"mode must be one of {_VALID_MODES}"})
                    return
                _save_mode(mode)
                self.send_json(200, {"ok": True, "mode": mode})
            except Exception as e:
                self.send_json(500, {"error": str(e)})
            return

        self.send_json(404, {"error": "not found"})

    def do_PUT(self):
        # Alias for POST /api/mode — semantically a PUT is a better fit for
        # "set mode" but we keep POST working too for clients that can't PUT.
        if self.path == "/api/mode":
            self.do_POST()
            return
        self.send_json(404, {"error": "not found"})


# ── Static file cache (mtime-keyed; invalidated automatically on disk change) ──

_static_lock: threading.Lock = threading.Lock()
_static_cache: dict[str, tuple[float, bytes]] = {}

# ── Policy helpers ────────────────────────────────────────────────────────────

# Maps API list name → (file path, yaml top-level key).
# Resolved lazily on each call so tests can monkeypatch the module-level paths.
def _policy_meta(name: str) -> tuple[str, str]:
    if name == "enforce":
        return ENFORCE_PATH, "allow"
    if name == "blocklist":
        return BLOCKLIST_PATH, "block"
    raise ValueError(f"unknown policy list: {name}")


_policy_lock: threading.Lock = threading.Lock()
# name → (mtime, normalized list of entries)
_policy_cache: dict[str, tuple[float, list]] = {}
# Serialises read→modify→write cycles per list.
_policy_mgmt_lock: threading.Lock = threading.Lock()


def _normalize_host(host: str) -> str:
    host = host.strip()
    if host.startswith("*."):
        host = host[2:]
    return host


def _normalize_entry(entry, *, allow_bare_string: bool) -> dict | None:
    """Return a {host, ports, paths?} dict, or None to skip the entry."""
    if isinstance(entry, str):
        if not allow_bare_string:
            return None
        host = _normalize_host(entry)
        if not host:
            return None
        return {"host": host, "ports": [443]}
    if not isinstance(entry, dict):
        return None
    host = _normalize_host(str(entry.get("host", "")))
    if not host:
        return None
    out: dict = {"host": host, "ports": list(entry.get("ports") or [443])}
    paths = entry.get("paths")
    if paths:
        norm_paths = []
        for r in paths:
            if isinstance(r, dict) and r.get("prefix"):
                norm_paths.append({
                    "method": str(r.get("method", "")).upper(),
                    "prefix": str(r.get("prefix", "/")),
                })
        if norm_paths:
            out["paths"] = norm_paths
    return out


def _load_policy(name: str) -> list:
    """Load and normalize a policy list. Returns a list of {host, ports, paths?} dicts."""
    path, key = _policy_meta(name)
    allow_bare = (name == "blocklist")
    try:
        mtime = os.path.getmtime(path)
        with _policy_lock:
            cached = _policy_cache.get(name)
            if cached and cached[0] == mtime:
                return cached[1]
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        raw_entries = data.get(key) or []
        normalized = []
        for entry in raw_entries:
            norm = _normalize_entry(entry, allow_bare_string=allow_bare)
            if norm is not None:
                normalized.append(norm)
        with _policy_lock:
            _policy_cache[name] = (mtime, normalized)
        return normalized
    except OSError:
        return []


def _save_policy(name: str, entries: list) -> None:
    path, key = _policy_meta(name)
    lines: list[str] = []
    if not entries:
        lines.append(f"{key}: []\n")
    else:
        lines.append(f"{key}:\n")
        for entry in entries:
            host = entry.get("host", "")
            ports = entry.get("ports") or [443]
            lines.append(f"  - host: {json.dumps(host)}\n")
            lines.append(f"    ports: [{', '.join(str(p) for p in ports)}]\n")
            paths = entry.get("paths")
            if paths:
                lines.append("    paths:\n")
                for rule in paths:
                    lines.append(f"      - method: {json.dumps(rule.get('method', ''))}\n")
                    lines.append(f"        prefix: {json.dumps(rule.get('prefix', '/'))}\n")
    dir_path = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_path, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=dir_path, delete=False, suffix=".tmp") as tmp:
        tmp.writelines(lines)
        tmp_path = tmp.name
    os.replace(tmp_path, path)
    with _policy_lock:
        _policy_cache.pop(name, None)


def _load_agents() -> list[str]:
    try:
        with open(AGENTS_PATH) as fh:
            data = yaml.safe_load(fh) or {}
        return list(data.get("agent_networks") or [])
    except OSError:
        return []


def _load_mode() -> str:
    try:
        with open(MODE_PATH) as fh:
            value = fh.read().strip()
        return value if value in _VALID_MODES else "enforce"
    except OSError:
        return "enforce"


def _save_mode(mode: str) -> None:
    if mode not in _VALID_MODES:
        raise ValueError(f"invalid mode: {mode}")
    dir_path = os.path.dirname(os.path.abspath(MODE_PATH))
    os.makedirs(dir_path, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=dir_path, delete=False, suffix=".tmp") as tmp:
        tmp.write(mode + "\n")
        tmp_path = tmp.name
    os.replace(tmp_path, MODE_PATH)


def _policy_snapshot() -> dict:
    return {
        "mode": _load_mode(),
        "enforce": _load_policy("enforce"),
        "blocklist": _load_policy("blocklist"),
    }


def _health_snapshot() -> dict:
    """Active mode + per-list counts + warnings on misconfigurations the operator
    would otherwise only notice after a confusing 403 stream or a security hole."""
    mode = _load_mode()
    enforce = _load_policy("enforce")
    blocklist = _load_policy("blocklist")
    agents = _load_agents()
    warnings: list[str] = []
    if not agents:
        warnings.append(
            "agents.yaml has no networks — the policy-mutation API is reachable from any client IP"
        )
    if mode == "enforce" and not enforce:
        warnings.append(
            "enforce mode is active but enforce.yaml is empty — every request will be blocked"
        )
    if mode == "blocklist" and not blocklist:
        warnings.append(
            "blocklist mode is active but blocklist.yaml is empty — nothing will be blocked"
        )
    return {
        "mode": mode,
        "enforce_entries": len(enforce),
        "blocklist_entries": len(blocklist),
        "agents_entries": len(agents),
        "warnings": warnings,
    }


def _is_agent_source(client_ip: str) -> bool:
    """True if client_ip is in any network listed under agent_networks."""
    networks = _load_agents()
    try:
        addr = ipaddress.ip_address(client_ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in networks)
    except ValueError:
        return False


def _validate_fields(host: str, method: str, prefix: str) -> str | None:
    # Guards untrusted HTTP body before it reaches the YAML writer. The addon
    # trusts what it loads because the only paths into the file are this
    # function (POST /api/policy/*) and operator hand-edits.
    for val, name in ((host, "host"), (method, "method"), (prefix, "prefix")):
        if _INVALID_FIELD_RE.search(val):
            return f"{name} contains invalid characters"
    return None


def _policy_add(list_name: str, body: dict) -> dict:
    host = str(body.get("host", "")).strip()
    if not host:
        return {"ok": False, "error": "host required"}
    port = int(body.get("port", 443))
    scope = str(body.get("scope", "host"))
    method = str(body.get("method", "")).upper()
    prefix = str(body.get("prefix", "/"))

    err = _validate_fields(host, method, prefix)
    if err:
        return {"ok": False, "error": err}

    with _policy_mgmt_lock:
        entries = _load_policy(list_name)
        entry = next((e for e in entries if e.get("host") == host), None)

        if scope == "host":
            if entry is None:
                entries.append({"host": host, "ports": [port]})
            else:
                if port not in entry.get("ports", []):
                    entry.setdefault("ports", []).append(port)
                entry.pop("paths", None)
        else:
            if entry is None:
                entry = {"host": host, "ports": [port], "paths": []}
                entries.append(entry)
            else:
                if port not in entry.get("ports", []):
                    entry.setdefault("ports", []).append(port)
                entry.setdefault("paths", [])
            paths = entry["paths"]
            if not any(p.get("method") == method and p.get("prefix") == prefix for p in paths):
                paths.append({"method": method, "prefix": prefix})

        _save_policy(list_name, entries)
        return {"ok": True, "policy": _policy_snapshot()}


def _policy_remove(list_name: str, body: dict) -> dict:
    host = str(body.get("host", "")).strip()
    if not host:
        return {"ok": False, "error": "host required"}
    scope = str(body.get("scope", "host"))
    method = str(body.get("method", "")).upper()
    prefix = str(body.get("prefix", "/"))

    err = _validate_fields(host, method, prefix)
    if err:
        return {"ok": False, "error": err}

    with _policy_mgmt_lock:
        entries = _load_policy(list_name)

        if scope == "host":
            entries = [e for e in entries if e.get("host") != host]
        else:
            entry = next((e for e in entries if e.get("host") == host), None)
            if entry and entry.get("paths"):
                entry["paths"] = [
                    p for p in entry["paths"]
                    if not (p.get("method") == method and p.get("prefix") == prefix)
                ]
                if not entry["paths"]:
                    del entry["paths"]

        _save_policy(list_name, entries)
        return {"ok": True, "policy": _policy_snapshot()}


# ── Log reading helpers ───────────────────────────────────────────────────────

_LAN_NAMES = {"localhost", "local", "lan", "internal", "home", "fritz.box"}


def _is_lan(host: str) -> bool:
    """True if host is a private/loopback IP or a known local hostname."""
    if not host:
        return False
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


_count_cache: tuple[float, int] = (0.0, 0)
_count_lock: threading.Lock = threading.Lock()
_CONNECT_MARKER = b'"event": "connect_allowed"'


def _clear_log() -> None:
    # Truncate in place rather than open("w"): the latter creates a fresh
    # inode if the file is missing, which orphans any append-mode fd the
    # proxy addon may be holding. r+ requires the file to exist; if it
    # doesn't, there's nothing to clear and we exit silently.
    try:
        with open(LOG_PATH, "r+b") as f:
            f.truncate(0)
    except FileNotFoundError:
        pass


def _count_lines() -> int:
    global _count_cache
    try:
        mtime = os.path.getmtime(LOG_PATH)
        with _count_lock:
            if mtime == _count_cache[0]:
                return _count_cache[1]
        count = 0
        with open(LOG_PATH, "rb") as f:
            for ln in f:
                if ln.strip() and _CONNECT_MARKER not in ln:
                    count += 1
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


def _iter_logs(q: str, client_f: str, limit: int, internet_only: bool = False):
    try:
        f = open(LOG_PATH, "rb")
    except OSError:
        return
    try:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            return
        try:
            pos = mm.size()
            yielded = 0
            while pos > 0 and yielded < limit:
                prev = mm.rfind(b"\n", 0, pos - 1)
                line = mm[prev + 1:pos].strip()
                pos = prev if prev >= 0 else 0
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not _record_matches(record, q, client_f, internet_only):
                    continue
                yield record
                yielded += 1
        finally:
            mm.close()
    finally:
        f.close()


if __name__ == "__main__":
    print(f"logviewer listening on :{PORT} (HTTP — do not expose publicly without a firewall)", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
