"""
Unit tests for logviewer/server.py.

The module uses module-level globals (LOG_PATH, ALLOWLIST_PATH) which are
patched per-test via monkeypatch.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "logviewer"))
import server as srv  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_log(tmp_path, records):
    p = tmp_path / "leash.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def _write_allowlist(tmp_path, content):
    p = tmp_path / "allowlist.yaml"
    p.write_text(content)
    return str(p)


def _setup_allowlist(tmp_path, monkeypatch, destinations=None):
    path = str(tmp_path / "allowlist.yaml")
    monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
    srv._save_allowlist({"allowed_destinations": destinations if destinations is not None else []})
    return path


# ── _is_lan ───────────────────────────────────────────────────────────────────

class TestIsLan:
    def test_private_class_a(self):
        assert srv._is_lan("10.0.0.1")

    def test_private_class_b(self):
        assert srv._is_lan("172.16.0.1")

    def test_private_class_c(self):
        assert srv._is_lan("192.168.1.100")

    def test_loopback_v4(self):
        assert srv._is_lan("127.0.0.1")

    def test_loopback_v6(self):
        assert srv._is_lan("::1")  # bare IPv6 loopback

    def test_public_ip(self):
        assert not srv._is_lan("8.8.8.8")
        assert not srv._is_lan("1.1.1.1")

    def test_known_local_hostnames(self):
        assert srv._is_lan("localhost")
        assert srv._is_lan("fritz.box")

    def test_dot_local(self):
        assert srv._is_lan("mydevice.local")

    def test_dot_lan(self):
        assert srv._is_lan("rainkingstation.lan")

    def test_dot_internal(self):
        assert srv._is_lan("service.internal")

    def test_public_hostname(self):
        assert not srv._is_lan("github.com")
        assert not srv._is_lan("api.anthropic.com")

    def test_empty_string(self):
        assert not srv._is_lan("")


# ── _read_logs ────────────────────────────────────────────────────────────────

class TestReadLogs:
    def test_basic_read(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "a.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        assert len(list(srv._iter_logs("", "", 500))) == 1

    def test_connect_allowed_suppressed(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "connect_allowed", "host": "a.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed",         "host": "a.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "", 500))
        assert len(result) == 1 and result[0]["event"] == "allowed"

    def test_newest_first(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "a.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed", "host": "b.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "", 500))
        assert result[0]["ts"] == 2.0 and result[1]["ts"] == 1.0

    def test_query_filter(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "target.example.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed", "host": "other.example.com",  "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("target", "", 500))
        assert len(result) == 1 and result[0]["host"] == "target.example.com"

    def test_client_filter(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "a.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed", "host": "a.com", "client": "10.0.0.2"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "10.0.0.1", 500))
        assert len(result) == 1 and result[0]["client"] == "10.0.0.1"

    def test_internet_only_excludes_lan(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "192.168.1.1", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed", "host": "api.example.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "", 500, internet_only=True))
        assert len(result) == 1 and result[0]["host"] == "api.example.com"

    def test_limit_respected(self, tmp_path, monkeypatch):
        records = [
            {"ts": float(i), "event": "allowed", "host": "a.com", "client": "10.0.0.1"}
            for i in range(10)
        ]
        path = _write_log(tmp_path, records)
        monkeypatch.setattr(srv, "LOG_PATH", path)
        assert len(list(srv._iter_logs("", "", 3))) == 3

    def test_malformed_lines_skipped(self, tmp_path, monkeypatch):
        p = tmp_path / "leash.jsonl"
        p.write_text('not json\n{"ts":1.0,"event":"allowed","host":"a.com","client":"10.0.0.1"}\n')
        monkeypatch.setattr(srv, "LOG_PATH", str(p))
        result = list(srv._iter_logs("", "", 500))
        assert len(result) == 1

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(srv, "LOG_PATH", str(tmp_path / "nonexistent.jsonl"))
        assert list(srv._iter_logs("", "", 500)) == []


# ── _load_allowlist / _save_allowlist ─────────────────────────────────────────

class TestAllowlistRoundtrip:
    def test_load_basic(self, tmp_path, monkeypatch):
        path = _write_allowlist(tmp_path,
            "allowed_destinations:\n  - host: api.example.com\n    ports: [443]\n"
        )
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
        data = srv._load_allowlist()
        hosts = [e["host"] for e in data["allowed_destinations"]]
        assert "api.example.com" in hosts

    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", str(tmp_path / "nope.yaml"))
        data = srv._load_allowlist()
        assert data["allowed_destinations"] == []

    def test_roundtrip_preserves_agent_networks(self, tmp_path, monkeypatch):
        path = str(tmp_path / "allowlist.yaml")
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
        original = {
            "agent_networks": ["10.0.0.0/8"],
            "allowed_destinations": [{"host": "a.com", "ports": [443]}],
        }
        srv._save_allowlist(original)
        loaded = srv._load_allowlist()
        assert loaded["agent_networks"] == ["10.0.0.0/8"]

    def test_roundtrip_preserves_path_rules(self, tmp_path, monkeypatch):
        path = str(tmp_path / "allowlist.yaml")
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
        original = {
            "allowed_destinations": [{
                "host": "api.example.com",
                "ports": [443],
                "paths": [{"method": "GET", "prefix": "/v1/"}],
            }],
        }
        srv._save_allowlist(original)
        loaded = srv._load_allowlist()
        entry = loaded["allowed_destinations"][0]
        assert entry["paths"][0]["prefix"] == "/v1/"

    def test_save_is_atomic(self, tmp_path, monkeypatch):
        path = str(tmp_path / "allowlist.yaml")
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
        srv._save_allowlist({"allowed_destinations": []})
        # No .tmp file should be left behind
        assert not list(tmp_path.glob("*.tmp"))

    def test_ipv6_host_quoted(self, tmp_path, monkeypatch):
        # IPv6 brackets must be YAML-quoted, otherwise [::1] is parsed as a list
        path = str(tmp_path / "allowlist.yaml")
        monkeypatch.setattr(srv, "ALLOWLIST_PATH", path)
        srv._save_allowlist({"allowed_destinations": [{"host": "[::1]", "ports": [80]}]})
        loaded = srv._load_allowlist()
        assert loaded["allowed_destinations"][0]["host"] == "[::1]"


# ── _count_lines ─────────────────────────────────────────────────────────────

class TestCountLines:
    def test_excludes_connect_allowed(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "connect_allowed", "host": "a.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed",         "host": "a.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        assert srv._count_lines() == 1

    def test_counts_all_other_events(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "a.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "blocked", "host": "b.com", "client": "10.0.0.1"},
            {"ts": 3.0, "event": "error",   "host": "c.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        assert srv._count_lines() == 3

    def test_missing_file_returns_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(srv, "LOG_PATH", str(tmp_path / "none.jsonl"))
        assert srv._count_lines() == 0


# ── _allowlist_add ────────────────────────────────────────────────────────────

class TestAllowlistAdd:
    def test_add_new_host(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({"host": "new.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
        hosts = [e["host"] for e in result["allowlist"]["allowed_destinations"]]
        assert "new.example.com" in hosts

    def test_add_path_rule(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({
            "host": "api.example.com", "port": 443,
            "scope": "path", "method": "GET", "prefix": "/v1/",
        })
        assert result["ok"]
        entry = result["allowlist"]["allowed_destinations"][0]
        assert entry["paths"][0]["prefix"] == "/v1/"

    def test_add_host_clears_path_restrictions(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch, [
            {"host": "api.example.com", "ports": [443], "paths": [{"method": "GET", "prefix": "/v1/"}]},
        ])
        result = srv._allowlist_add({"host": "api.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
        entry = result["allowlist"]["allowed_destinations"][0]
        assert "paths" not in entry

    def test_no_duplicate_path_rules(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        srv._allowlist_add({"host": "a.com", "port": 443, "scope": "path", "method": "GET", "prefix": "/v1/"})
        result = srv._allowlist_add({"host": "a.com", "port": 443, "scope": "path", "method": "GET", "prefix": "/v1/"})
        entry = result["allowlist"]["allowed_destinations"][0]
        assert len(entry["paths"]) == 1

    def test_missing_host_returns_error(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({"host": "", "port": 443, "scope": "host"})
        assert not result["ok"]


# ── _allowlist_remove ─────────────────────────────────────────────────────────

class TestAllowlistRemove:
    def test_remove_host(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch, [{"host": "a.com", "ports": [443]}])
        result = srv._allowlist_remove({"host": "a.com", "scope": "host"})
        assert result["ok"] and result["allowlist"]["allowed_destinations"] == []

    def test_remove_one_path_rule(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch, [{
            "host": "api.example.com", "ports": [443],
            "paths": [
                {"method": "GET",  "prefix": "/v1/"},
                {"method": "POST", "prefix": "/v1/"},
            ],
        }])
        result = srv._allowlist_remove({
            "host": "api.example.com", "scope": "path",
            "method": "GET", "prefix": "/v1/",
        })
        assert result["ok"]
        entry = result["allowlist"]["allowed_destinations"][0]
        assert len(entry["paths"]) == 1 and entry["paths"][0]["method"] == "POST"

    def test_remove_nonexistent_host_is_noop(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch, [{"host": "a.com", "ports": [443]}])
        result = srv._allowlist_remove({"host": "z.com", "scope": "host"})
        assert result["ok"] and len(result["allowlist"]["allowed_destinations"]) == 1

    def test_missing_host_returns_error(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_remove({"host": "", "scope": "host"})
        assert not result["ok"]


# ── Input validation (_validate_fields) ──────────────────────────────────────

class TestInputValidation:
    def test_add_host_with_newline_rejected(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({"host": "evil.com\ninjected:", "port": 443, "scope": "host"})
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_add_prefix_with_newline_rejected(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({
            "host": "api.example.com", "port": 443, "scope": "path",
            "method": "GET", "prefix": "/v1/\nmalicious:",
        })
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_add_method_with_null_byte_rejected(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({
            "host": "api.example.com", "port": 443, "scope": "path",
            "method": "GET\x00", "prefix": "/v1/",
        })
        assert not result["ok"]

    def test_remove_host_with_newline_rejected(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_remove({"host": "evil.com\ninjected:", "scope": "host"})
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_valid_inputs_still_work(self, tmp_path, monkeypatch):
        _setup_allowlist(tmp_path, monkeypatch)
        result = srv._allowlist_add({"host": "api.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
