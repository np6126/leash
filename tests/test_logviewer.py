"""
Unit tests for logviewer/server.py.

The module uses module-level globals for file paths; tests patch them per-test
via monkeypatch.
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


@pytest.fixture
def policy_dir(tmp_path, monkeypatch):
    """Point all four module-level policy paths into a tmp dir."""
    monkeypatch.setattr(srv, "MODE_PATH",      str(tmp_path / "mode"))
    monkeypatch.setattr(srv, "AGENTS_PATH",    str(tmp_path / "agents.yaml"))
    monkeypatch.setattr(srv, "ENFORCE_PATH",   str(tmp_path / "enforce.yaml"))
    monkeypatch.setattr(srv, "BLOCKLIST_PATH", str(tmp_path / "blocklist.yaml"))
    # Reset the policy cache so prior tests don't leak state across modules
    with srv._policy_lock:
        srv._policy_cache.clear()
    return tmp_path


def _seed_policy(policy_dir, *, mode="enforce", enforce=None, blocklist=None, agents=None):
    if mode is not None:
        (policy_dir / "mode").write_text(mode + "\n")
    if enforce is not None:
        srv._save_policy("enforce", enforce)
    if blocklist is not None:
        srv._save_policy("blocklist", blocklist)
    if agents is not None:
        (policy_dir / "agents.yaml").write_text("agent_networks:\n" + "".join(f"  - {n}\n" for n in agents))


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
        assert srv._is_lan("::1")

    def test_public_ip(self):
        assert not srv._is_lan("8.8.8.8")
        assert not srv._is_lan("1.1.1.1")

    def test_known_local_hostnames(self):
        assert srv._is_lan("localhost")
        assert srv._is_lan("fritz.box")

    def test_dot_local(self):
        assert srv._is_lan("mydevice.local")

    def test_dot_internal(self):
        assert srv._is_lan("service.internal")

    def test_public_hostname(self):
        assert not srv._is_lan("github.com")
        assert not srv._is_lan("api.anthropic.com")

    def test_empty_string(self):
        assert not srv._is_lan("")


# ── _iter_logs ────────────────────────────────────────────────────────────────

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

    def test_exclude_hosts(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "noisy.example.com", "client": "10.0.0.1"},
            {"ts": 2.0, "event": "allowed", "host": "api.example.com",   "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "", 500, exclude_hosts={"noisy.example.com"}))
        assert len(result) == 1 and result[0]["host"] == "api.example.com"

    def test_exclude_hosts_case_insensitive(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "allowed", "host": "Noisy.Example.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        assert list(srv._iter_logs("", "", 500, exclude_hosts={"noisy.example.com"})) == []

    def test_exclude_hosts_keeps_mode_change(self, tmp_path, monkeypatch):
        path = _write_log(tmp_path, [
            {"ts": 1.0, "event": "mode_change", "previous": "enforce", "mode": "audit"},
            {"ts": 2.0, "event": "allowed", "host": "noisy.example.com", "client": "10.0.0.1"},
        ])
        monkeypatch.setattr(srv, "LOG_PATH", path)
        result = list(srv._iter_logs("", "", 500, exclude_hosts={"noisy.example.com"}))
        assert len(result) == 1 and result[0]["event"] == "mode_change"

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


class TestClearLog:
    """_clear_log must truncate in place so the proxy addon's open log fd
    keeps pointing at the live inode. open(path, 'w') was wrong because
    when the file is missing it creates a fresh inode, orphaning any
    append-mode fd held by the writer."""

    def test_truncates_existing_file_in_place(self, tmp_path, monkeypatch):
        path = tmp_path / "leash.jsonl"
        path.write_text('{"event":"x"}\n{"event":"y"}\n')
        original_inode = path.stat().st_ino
        monkeypatch.setattr(srv, "LOG_PATH", str(path))
        srv._clear_log()
        assert path.stat().st_size == 0
        assert path.stat().st_ino == original_inode

    def test_missing_file_is_silent(self, tmp_path, monkeypatch):
        path = tmp_path / "none.jsonl"
        monkeypatch.setattr(srv, "LOG_PATH", str(path))
        srv._clear_log()
        # Did not create a file
        assert not path.exists()


# ── Mode load / save ─────────────────────────────────────────────────────────

class TestMode:
    def test_default_enforce_on_missing_file(self, policy_dir):
        assert srv._load_mode() == "enforce"

    def test_save_and_load_roundtrip(self, policy_dir):
        srv._save_mode("audit")
        assert srv._load_mode() == "audit"
        srv._save_mode("blocklist")
        assert srv._load_mode() == "blocklist"
        srv._save_mode("enforce")
        assert srv._load_mode() == "enforce"

    def test_save_rejects_invalid_mode(self, policy_dir):
        with pytest.raises(ValueError):
            srv._save_mode("not_a_mode")

    def test_load_returns_enforce_on_garbage(self, policy_dir):
        (policy_dir / "mode").write_text("garbage\n")
        assert srv._load_mode() == "enforce"


# ── Policy load / save ──────────────────────────────────────────────────────

class TestPolicyRoundtrip:
    def test_load_empty_when_missing(self, policy_dir):
        assert srv._load_policy("enforce") == []
        assert srv._load_policy("blocklist") == []

    def test_enforce_roundtrip(self, policy_dir):
        srv._save_policy("enforce", [
            {"host": "api.example.com", "ports": [443], "paths": [{"method": "GET", "prefix": "/v1/"}]},
        ])
        entries = srv._load_policy("enforce")
        assert entries[0]["host"] == "api.example.com"
        assert entries[0]["paths"][0]["prefix"] == "/v1/"

    def test_blocklist_roundtrip(self, policy_dir):
        srv._save_policy("blocklist", [{"host": "pastebin.com", "ports": [443]}])
        entries = srv._load_policy("blocklist")
        assert entries[0]["host"] == "pastebin.com"

    def test_blocklist_loads_bare_strings(self, policy_dir):
        (policy_dir / "blocklist.yaml").write_text("block:\n  - pastebin.com\n  - hastebin.com\n")
        entries = srv._load_policy("blocklist")
        hosts = [e["host"] for e in entries]
        assert "pastebin.com" in hosts and "hastebin.com" in hosts

    def test_blocklist_strips_star_prefix(self, policy_dir):
        (policy_dir / "blocklist.yaml").write_text('block:\n  - "*.doubleclick.net"\n')
        entries = srv._load_policy("blocklist")
        assert entries[0]["host"] == "doubleclick.net"

    def test_save_is_atomic(self, policy_dir):
        srv._save_policy("enforce", [])
        # No .tmp file should be left behind
        assert not list(policy_dir.glob("*.tmp"))

    def test_unknown_list_name_raises(self, policy_dir):
        with pytest.raises(ValueError):
            srv._load_policy("nonsense")


# ── _policy_snapshot ────────────────────────────────────────────────────────

class TestPolicySnapshot:
    def test_returns_mode_and_both_lists(self, policy_dir):
        _seed_policy(policy_dir, mode="audit",
                     enforce=[{"host": "a.com", "ports": [443]}],
                     blocklist=[{"host": "bad.com", "ports": [443]}])
        snap = srv._policy_snapshot()
        assert snap["mode"] == "audit"
        assert snap["enforce"][0]["host"] == "a.com"
        assert snap["blocklist"][0]["host"] == "bad.com"


# ── _health_snapshot ────────────────────────────────────────────────────────

class TestHealth:
    def test_healthy_state_no_warnings(self, policy_dir):
        _seed_policy(policy_dir, mode="enforce", agents=["10.10.10.0/24"],
                     enforce=[{"host": "a.com", "ports": [443]}],
                     blocklist=[])
        h = srv._health_snapshot()
        assert h["mode"] == "enforce"
        assert h["enforce_entries"] == 1
        assert h["agents_entries"] == 1
        assert h["warnings"] == []

    def test_enforce_with_empty_list_warns(self, policy_dir):
        _seed_policy(policy_dir, mode="enforce", agents=["10.10.10.0/24"],
                     enforce=[], blocklist=[])
        h = srv._health_snapshot()
        assert any("enforce mode" in w and "empty" in w for w in h["warnings"])

    def test_blocklist_with_empty_list_warns(self, policy_dir):
        _seed_policy(policy_dir, mode="blocklist", agents=["10.10.10.0/24"],
                     enforce=[], blocklist=[])
        h = srv._health_snapshot()
        assert any("blocklist mode" in w and "empty" in w for w in h["warnings"])

    def test_audit_with_empty_lists_no_warning(self, policy_dir):
        # audit mode doesn't depend on either list — no list-empty warning
        _seed_policy(policy_dir, mode="audit", agents=["10.10.10.0/24"],
                     enforce=[], blocklist=[])
        h = srv._health_snapshot()
        # only the agents warning could fire; agents is set here → no warnings
        assert h["warnings"] == []

    def test_missing_agents_warns(self, policy_dir):
        _seed_policy(policy_dir, mode="enforce",
                     enforce=[{"host": "a.com", "ports": [443]}],
                     blocklist=[])
        h = srv._health_snapshot()
        assert any("agents.yaml" in w for w in h["warnings"])


# ── _is_agent_source (agents.yaml integration) ──────────────────────────────

class TestIsAgentSource:
    def test_agent_in_network(self, policy_dir):
        _seed_policy(policy_dir, agents=["10.10.10.0/24"])
        assert srv._is_agent_source("10.10.10.42")

    def test_agent_outside_network(self, policy_dir):
        _seed_policy(policy_dir, agents=["10.10.10.0/24"])
        assert not srv._is_agent_source("192.168.1.1")

    def test_no_agents_file(self, policy_dir):
        # Without agents.yaml, no one is treated as an agent
        assert not srv._is_agent_source("10.10.10.42")

    def test_invalid_client_ip(self, policy_dir):
        _seed_policy(policy_dir, agents=["10.10.10.0/24"])
        assert not srv._is_agent_source("not-an-ip")


# ── _policy_add ──────────────────────────────────────────────────────────────

class TestPolicyAdd:
    def test_add_host_to_enforce(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {"host": "new.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
        hosts = [e["host"] for e in result["policy"]["enforce"]]
        assert "new.example.com" in hosts

    def test_add_host_to_blocklist(self, policy_dir):
        srv._save_policy("blocklist", [])
        result = srv._policy_add("blocklist", {"host": "bad.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
        hosts = [e["host"] for e in result["policy"]["blocklist"]]
        assert "bad.example.com" in hosts

    def test_add_path_rule(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {
            "host": "api.example.com", "port": 443,
            "scope": "path", "method": "GET", "prefix": "/v1/",
        })
        assert result["ok"]
        entry = result["policy"]["enforce"][0]
        assert entry["paths"][0]["prefix"] == "/v1/"

    def test_add_host_clears_path_restrictions(self, policy_dir):
        srv._save_policy("enforce", [
            {"host": "api.example.com", "ports": [443], "paths": [{"method": "GET", "prefix": "/v1/"}]},
        ])
        result = srv._policy_add("enforce", {"host": "api.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
        entry = result["policy"]["enforce"][0]
        assert "paths" not in entry

    def test_no_duplicate_path_rules(self, policy_dir):
        srv._save_policy("enforce", [])
        srv._policy_add("enforce", {"host": "a.com", "port": 443, "scope": "path", "method": "GET", "prefix": "/v1/"})
        result = srv._policy_add("enforce", {"host": "a.com", "port": 443, "scope": "path", "method": "GET", "prefix": "/v1/"})
        entry = result["policy"]["enforce"][0]
        assert len(entry["paths"]) == 1

    def test_missing_host_returns_error(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {"host": "", "port": 443, "scope": "host"})
        assert not result["ok"]


# ── _policy_remove ───────────────────────────────────────────────────────────

class TestPolicyRemove:
    def test_remove_host_from_enforce(self, policy_dir):
        srv._save_policy("enforce", [{"host": "a.com", "ports": [443]}])
        result = srv._policy_remove("enforce", {"host": "a.com", "scope": "host"})
        assert result["ok"] and result["policy"]["enforce"] == []

    def test_remove_host_from_blocklist(self, policy_dir):
        srv._save_policy("blocklist", [{"host": "bad.com", "ports": [443]}])
        result = srv._policy_remove("blocklist", {"host": "bad.com", "scope": "host"})
        assert result["ok"] and result["policy"]["blocklist"] == []

    def test_remove_one_path_rule(self, policy_dir):
        srv._save_policy("enforce", [{
            "host": "api.example.com", "ports": [443],
            "paths": [
                {"method": "GET",  "prefix": "/v1/"},
                {"method": "POST", "prefix": "/v1/"},
            ],
        }])
        result = srv._policy_remove("enforce", {
            "host": "api.example.com", "scope": "path",
            "method": "GET", "prefix": "/v1/",
        })
        assert result["ok"]
        entry = result["policy"]["enforce"][0]
        assert len(entry["paths"]) == 1 and entry["paths"][0]["method"] == "POST"

    def test_remove_nonexistent_host_is_noop(self, policy_dir):
        srv._save_policy("enforce", [{"host": "a.com", "ports": [443]}])
        result = srv._policy_remove("enforce", {"host": "z.com", "scope": "host"})
        assert result["ok"] and len(result["policy"]["enforce"]) == 1

    def test_missing_host_returns_error(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_remove("enforce", {"host": "", "scope": "host"})
        assert not result["ok"]


# ── Input validation ─────────────────────────────────────────────────────────

class TestInputValidation:
    def test_add_host_with_newline_rejected(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {"host": "evil.com\ninjected:", "port": 443, "scope": "host"})
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_add_prefix_with_newline_rejected(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {
            "host": "api.example.com", "port": 443, "scope": "path",
            "method": "GET", "prefix": "/v1/\nmalicious:",
        })
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_add_method_with_null_byte_rejected(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {
            "host": "api.example.com", "port": 443, "scope": "path",
            "method": "GET\x00", "prefix": "/v1/",
        })
        assert not result["ok"]

    def test_remove_host_with_newline_rejected(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_remove("enforce", {"host": "evil.com\ninjected:", "scope": "host"})
        assert not result["ok"]
        assert "invalid" in result["error"]

    def test_valid_inputs_still_work(self, policy_dir):
        srv._save_policy("enforce", [])
        result = srv._policy_add("enforce", {"host": "api.example.com", "port": 443, "scope": "host"})
        assert result["ok"]
