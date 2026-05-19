"""
Unit tests for addon/allowlist_logger.py.

mitmproxy is not installed in the test environment, so the package is mocked
at the module level before the addon is imported.
"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import yaml

# ── Mock mitmproxy before import ──────────────────────────────────────────────
_mitm = MagicMock()
sys.modules.setdefault("mitmproxy", _mitm)
sys.modules.setdefault("mitmproxy.ctx", _mitm.ctx)
sys.modules.setdefault("mitmproxy.http", _mitm.http)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from addon import allowlist_logger as al  # noqa: E402
from addon.allowlist_logger import AllowlistLogger, BODY_LIMIT  # noqa: E402


def _make_addon(**env):
    """Construct an AllowlistLogger with env overrides.

    The module reads LEASH_DIR at import time into a module-level constant —
    re-read it here so the addon picks up the overridden path.
    """
    with patch.dict(os.environ, env):
        with patch.object(al, "LEASH_DIR", env.get("LEASH_DIR", al.LEASH_DIR)):
            addon = AllowlistLogger()
        # __init__ already captured LEASH_DIR into instance attrs; re-set them
        # to honour the env override even after the patch context exits.
        if "LEASH_DIR" in env:
            base = env["LEASH_DIR"]
            addon.mode_path      = os.path.join(base, "mode")
            addon.enforce_path   = os.path.join(base, "enforce.yaml")
            addon.blocklist_path = os.path.join(base, "blocklist.yaml")
        return addon


def _write_policy_files(tmp_path, *, mode="enforce", enforce=None, block=None):
    if mode is not None:
        (tmp_path / "mode").write_text(mode + "\n")
    if enforce is not None:
        (tmp_path / "enforce.yaml").write_text(yaml.dump({"allow": enforce}, default_flow_style=False))
    if block is not None:
        (tmp_path / "blocklist.yaml").write_text(yaml.dump({"block": block}, default_flow_style=False))


# ── _find_entry ───────────────────────────────────────────────────────────────

class TestFindEntry:
    def setup_method(self):
        self.rules = {
            "api.github.com": {"ports": {443}, "paths": None},
            "github.com":     {"ports": {443, 80}, "paths": None},
        }

    def test_exact_match(self):
        assert AllowlistLogger._find_entry(self.rules, "api.github.com") is not None

    def test_subdomain_wildcard(self):
        entry = AllowlistLogger._find_entry(self.rules, "foo.github.com")
        assert entry is not None
        assert 80 in entry["ports"]

    def test_exact_beats_wildcard(self):
        entry = AllowlistLogger._find_entry(self.rules, "api.github.com")
        assert 80 not in entry["ports"]

    def test_no_match(self):
        assert AllowlistLogger._find_entry(self.rules, "example.com") is None

    def test_deep_subdomain(self):
        assert AllowlistLogger._find_entry(self.rules, "a.b.github.com") is not None

    def test_tld_only_not_matched(self):
        assert AllowlistLogger._find_entry(self.rules, "notgithub.com") is None


# ── _decide ───────────────────────────────────────────────────────────────────

class TestDecide:
    def setup_method(self):
        self.addon = _make_addon()
        self.addon._enforce = {
            "api.example.com": {
                "ports": {443},
                "paths": [
                    {"method": "GET",  "prefix": "/v1/"},
                    {"method": "",     "prefix": "/public/"},
                ],
            },
            "open.example.com": {"ports": {443, 8080}, "paths": None},
        }
        self.addon._block = {
            "pastebin.com": {"ports": {443}, "paths": None},
            "github.com": {
                "ports": {443},
                "paths": [{"method": "", "prefix": "/raw/"}],
            },
        }

    def _decide(self, host, port, method="", path=""):
        with patch.object(self.addon, "_reload_if_changed"):
            return self.addon._decide(host, port, method, path)

    # enforce mode
    def test_enforce_unknown_host_blocked(self):
        self.addon._mode = "enforce"
        action, reason, audit = self._decide("other.com", 443)
        assert action == "block" and reason == "not_in_allowlist" and audit == ""

    def test_enforce_wrong_port_blocked(self):
        self.addon._mode = "enforce"
        action, reason, _ = self._decide("open.example.com", 9999)
        assert action == "block" and reason == "not_in_allowlist"

    def test_enforce_host_allowed_no_paths(self):
        self.addon._mode = "enforce"
        action, _, _ = self._decide("open.example.com", 443)
        assert action == "pass"

    def test_enforce_path_allowed(self):
        self.addon._mode = "enforce"
        action, _, _ = self._decide("api.example.com", 443, "GET", "/v1/users")
        assert action == "pass"

    def test_enforce_path_blocked_wrong_method(self):
        self.addon._mode = "enforce"
        action, reason, _ = self._decide("api.example.com", 443, "POST", "/v1/users")
        assert action == "block" and reason == "path_not_allowed"

    def test_enforce_path_blocked_unmatched_prefix(self):
        self.addon._mode = "enforce"
        action, reason, _ = self._decide("api.example.com", 443, "GET", "/private/")
        assert action == "block" and reason == "path_not_allowed"

    def test_enforce_connect_stage_skips_path_check(self):
        self.addon._mode = "enforce"
        action, _, _ = self._decide("api.example.com", 443)
        assert action == "pass"

    # audit mode
    def test_audit_passes_unknown_host_with_signal(self):
        self.addon._mode = "audit"
        action, reason, audit = self._decide("other.com", 443)
        assert action == "pass" and reason == ""
        assert audit == "would_block_in_enforce"

    def test_audit_passes_in_allowlist_no_signal(self):
        self.addon._mode = "audit"
        action, _, audit = self._decide("open.example.com", 443)
        assert action == "pass" and audit == ""

    def test_audit_does_not_block_blocklisted_host(self):
        # audit mode is "log everything, block nothing"; blocklist is ignored
        self.addon._mode = "audit"
        action, _, _ = self._decide("pastebin.com", 443)
        assert action == "pass"

    # blocklist mode
    def test_blocklist_blocks_listed_host(self):
        self.addon._mode = "blocklist"
        action, reason, audit = self._decide("pastebin.com", 443)
        assert action == "block" and reason == "in_blocklist" and audit == ""

    def test_blocklist_blocks_listed_path(self):
        self.addon._mode = "blocklist"
        action, reason, _ = self._decide("github.com", 443, "GET", "/raw/foo")
        assert action == "block" and reason == "in_blocklist"

    def test_blocklist_passes_unlisted_path_on_blocklisted_host(self):
        self.addon._mode = "blocklist"
        # github.com is only blocked on /raw/ paths; /api/ passes
        action, _, _ = self._decide("github.com", 443, "GET", "/api/")
        assert action == "pass"

    def test_blocklist_passes_unlisted_host_with_audit_signal(self):
        self.addon._mode = "blocklist"
        action, _, audit = self._decide("other.com", 443)
        assert action == "pass" and audit == "would_block_in_enforce"

    def test_blocklist_passes_allowlisted_host_no_signal(self):
        self.addon._mode = "blocklist"
        action, _, audit = self._decide("open.example.com", 443)
        assert action == "pass" and audit == ""

    def test_blocklist_subdomain_fallback(self):
        # blocklist `pastebin.com` should also block `dev.pastebin.com`
        self.addon._mode = "blocklist"
        action, _, _ = self._decide("dev.pastebin.com", 443)
        assert action == "block"


# ── Mode loading + hot reload ────────────────────────────────────────────────

class TestModeLoading:
    def test_default_enforce_on_missing_file(self, tmp_path):
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        # No files written → loader silently skips; mode stays at default
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._mode == "enforce"

    def test_invalid_mode_defaults_to_enforce(self, tmp_path):
        (tmp_path / "mode").write_text("invalid_mode\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._mode == "enforce"

    def test_audit_mode_loaded(self, tmp_path):
        (tmp_path / "mode").write_text("audit\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._mode == "audit"

    def test_mode_reloads_on_mtime_change(self, tmp_path):
        import time
        mode_file = tmp_path / "mode"
        mode_file.write_text("enforce\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._mode == "enforce"

        time.sleep(0.01)  # ensure mtime differs
        mode_file.write_text("audit\n")
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._mode == "audit"

    def test_mode_change_emits_jsonl_event(self, tmp_path):
        import time
        log_path = tmp_path / "x.jsonl"
        mode_file = tmp_path / "mode"
        mode_file.write_text("enforce\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(log_path))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        # First load → no mode_change event (mode goes from default 'enforce'
        # to 'enforce', no transition).
        assert not log_path.exists() or "mode_change" not in log_path.read_text()

        time.sleep(0.01)
        mode_file.write_text("audit\n")
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        # Force the log fh to flush
        if addon._log_fh:
            addon._log_fh.flush()
        events = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        mc = [e for e in events if e["event"] == "mode_change"]
        assert len(mc) == 1
        assert mc[0]["previous"] == "enforce"
        assert mc[0]["mode"] == "audit"
        assert "ts" in mc[0]


class TestEnforceBareStringWarning:
    def test_bare_string_in_enforce_warns(self, tmp_path):
        (tmp_path / "enforce.yaml").write_text("allow:\n  - pastebin.com\n  - {host: api.example.com, ports: [443]}\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("addon.allowlist_logger.ctx") as mock_ctx:
            addon._reload_if_changed()
            # Warn was called for the bare string
            warn_calls = [c for c in mock_ctx.log.warn.call_args_list
                          if "bare-string" in c.args[0] and "pastebin.com" in c.args[0]]
            assert len(warn_calls) == 1
        # The object entry still loaded
        assert "api.example.com" in addon._enforce
        # The bare string was dropped
        assert "pastebin.com" not in addon._enforce

    def test_bare_string_in_blocklist_silent(self, tmp_path):
        (tmp_path / "blocklist.yaml").write_text("block:\n  - pastebin.com\n")
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("addon.allowlist_logger.ctx") as mock_ctx:
            addon._reload_if_changed()
            # No warn for bare-string in blocklist (it's the supported shorthand)
            bare_warns = [c for c in mock_ctx.log.warn.call_args_list
                          if "bare-string" in c.args[0]]
            assert bare_warns == []
        assert "pastebin.com" in addon._block


# ── Policy file loading ──────────────────────────────────────────────────────

class TestPolicyLoading:
    def test_enforce_yaml_basic(self, tmp_path):
        _write_policy_files(tmp_path, enforce=[
            {"host": "api.example.com", "ports": [443]},
        ])
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "api.example.com" in addon._enforce
        assert 443 in addon._enforce["api.example.com"]["ports"]

    def test_enforce_path_rules(self, tmp_path):
        _write_policy_files(tmp_path, enforce=[
            {"host": "api.example.com", "ports": [443], "paths": [{"method": "GET", "prefix": "/v1/"}]},
        ])
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        paths = addon._enforce["api.example.com"]["paths"]
        assert paths is not None and paths[0]["prefix"] == "/v1/"

    def test_blocklist_bare_string_entries(self, tmp_path):
        # Bare-string shorthand is unique to the blocklist
        (tmp_path / "blocklist.yaml").write_text(
            "block:\n  - pastebin.com\n  - \"*.doubleclick.net\"\n"
        )
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "pastebin.com" in addon._block
        # *. prefix is stripped during normalization
        assert "doubleclick.net" in addon._block

    def test_blocklist_object_entries(self, tmp_path):
        _write_policy_files(tmp_path, block=[
            {"host": "github.com", "ports": [443], "paths": [{"prefix": "/raw/"}]},
        ])
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "github.com" in addon._block
        assert addon._block["github.com"]["paths"][0]["prefix"] == "/raw/"

    def test_empty_host_skipped(self, tmp_path):
        _write_policy_files(tmp_path, enforce=[{"host": "", "ports": [443]}])
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "" not in addon._enforce

    def test_missing_files_leave_state_intact(self, tmp_path):
        addon = _make_addon(LEASH_DIR=str(tmp_path), LOG_PATH=str(tmp_path / "x.jsonl"))
        addon._enforce = {"keep.me": {"ports": {443}, "paths": None}}
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "keep.me" in addon._enforce


# ── _capture_body ─────────────────────────────────────────────────────────────

class TestCaptureBody:
    def setup_method(self):
        self.addon = _make_addon()

    def test_empty_bytes(self):
        body, trunc = self.addon._capture_body(b"")
        assert body is None and not trunc

    def test_short_text(self):
        body, trunc = self.addon._capture_body(b"hello")
        assert body == "hello" and not trunc

    def test_truncation_at_limit(self):
        big = b"a" * (BODY_LIMIT + 1000)
        body, trunc = self.addon._capture_body(big)
        assert trunc and len(body) == BODY_LIMIT

    def test_binary_content(self):
        body, trunc = self.addon._capture_body(b"\xff\xfe\x00data")
        assert "[binary" in body and not trunc


# ── _is_text_response ─────────────────────────────────────────────────────────

class TestIsTextResponse:
    def setup_method(self):
        self.addon = _make_addon()

    def _flow(self, content_type):
        flow = MagicMock()
        flow.response.headers.get.return_value = content_type
        return flow

    def test_json(self):
        assert self.addon._is_text_response(self._flow("application/json"))

    def test_plain_text(self):
        assert self.addon._is_text_response(self._flow("text/plain"))

    def test_html_with_charset(self):
        assert self.addon._is_text_response(self._flow("text/html; charset=utf-8"))

    def test_yaml(self):
        assert self.addon._is_text_response(self._flow("application/yaml"))

    def test_binary(self):
        assert not self.addon._is_text_response(self._flow("application/octet-stream"))

    def test_image(self):
        assert not self.addon._is_text_response(self._flow("image/png"))

    def test_no_response(self):
        flow = MagicMock()
        flow.response = None
        assert not self.addon._is_text_response(flow)


# ── responseheaders ───────────────────────────────────────────────────────────

class TestResponseheaders:
    def setup_method(self):
        self.addon = _make_addon()

    def test_no_crash_when_response_is_none(self):
        flow = MagicMock()
        flow.metadata.get.side_effect = lambda k, *a: True if k == "log_allowed" else None
        flow.response = None
        self.addon.responseheaders(flow)  # must not raise

    def test_skipped_when_not_log_allowed(self):
        flow = MagicMock()
        flow.metadata.get.return_value = False
        flow.response = None
        self.addon.responseheaders(flow)  # must not raise

    def test_stream_set_for_event_stream(self):
        flow = MagicMock()
        flow.metadata.get.side_effect = lambda k, *a: True if k == "log_allowed" else None
        flow.response.headers.get.return_value = "text/event-stream"
        self.addon.responseheaders(flow)
        assert flow.response.stream is True


# ── Hook pipeline integration ─────────────────────────────────────────────────

def _make_connect_flow(host, port, client_ip="10.0.0.1"):
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.client_conn.peername = (client_ip, 12345)
    return flow


def _make_request_flow(host, port, method, path, client_ip="10.0.0.1"):
    flow = MagicMock()
    flow.request.host = host
    flow.request.port = port
    flow.request.method = method
    flow.request.path = path
    flow.request.pretty_url = f"https://{host}{path}"
    flow.request.content = b""
    flow.request.headers.items.return_value = []
    flow.client_conn.peername = (client_ip, 12345)
    flow.metadata = {}
    return flow


class TestHookPipeline:
    """End-to-end verification of the multi-hook request flow."""

    def setup_method(self):
        self.addon = _make_addon()
        self.addon._enforce = {
            "api.example.com": {"ports": {443}, "paths": None},
        }
        self.addon._block = {
            "evil.example.com": {"ports": {443}, "paths": None},
        }
        self.addon._mode = "enforce"
        self._log_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.addon.log_path = self._log_file.name

    def teardown_method(self):
        if self.addon._log_fh and not self.addon._log_fh.closed:
            self.addon._log_fh.close()
        os.unlink(self._log_file.name)

    def _entries(self):
        if self.addon._log_fh:
            self.addon._log_fh.flush()
        with open(self._log_file.name) as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_connect_allowed_logged(self):
        flow = _make_connect_flow("api.example.com", 443)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "connect_allowed"
        assert entries[0]["host"] == "api.example.com"

    def test_connect_blocked_logs_and_sets_403(self):
        flow = _make_connect_flow("other.example.com", 443)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "blocked"
        assert entries[0]["reason"] == "not_in_allowlist"
        assert flow.response is not None

    def test_request_allowed_stores_metadata(self):
        flow = _make_request_flow("api.example.com", 443, "GET", "/v1/test")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        assert flow.metadata.get("log_allowed") is True
        assert flow.metadata.get("log_client") == "10.0.0.1"
        assert flow.metadata.get("log_req_headers") == []

    def test_request_blocked_logs_and_sets_403(self):
        flow = _make_request_flow("other.example.com", 443, "GET", "/")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        assert not flow.metadata.get("log_allowed")
        entries = self._entries()
        assert any(e["event"] == "blocked" for e in entries)

    def test_response_logs_allowed_with_status(self):
        flow = _make_request_flow("api.example.com", 443, "GET", "/v1/test")
        flow.metadata = {
            "log_allowed": True,
            "log_client": "10.0.0.1",
            "log_audit": "",
            "log_req_headers": [],
            "log_req_body": None,
            "log_req_truncated": False,
        }
        flow.response = MagicMock()
        flow.response.status_code = 200
        flow.response.stream = False
        flow.response.raw_content = b"ok"
        flow.response.content = b"ok"
        flow.response.headers.items.return_value = []
        self.addon.response(flow)
        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "allowed"
        assert entries[0]["status"] == 200
        # audit field omitted when empty
        assert "audit" not in entries[0]

    def test_audit_mode_request_passes_with_signal(self):
        # In audit mode, request() never blocks; the audit field carries
        # "would_block_in_enforce" for non-allowlisted hosts.
        self.addon._mode = "audit"
        flow = _make_request_flow("other.example.com", 443, "GET", "/")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        assert flow.metadata.get("log_allowed") is True
        assert flow.metadata.get("log_audit") == "would_block_in_enforce"

    def test_blocklist_mode_blocks_blocklisted_host(self):
        self.addon._mode = "blocklist"
        flow = _make_request_flow("evil.example.com", 443, "GET", "/")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        entries = self._entries()
        assert entries[-1]["event"] == "blocked"
        assert entries[-1]["reason"] == "in_blocklist"

    def test_blocklist_mode_passes_unlisted_host(self):
        self.addon._mode = "blocklist"
        flow = _make_request_flow("random.example.com", 443, "GET", "/")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        assert flow.metadata.get("log_allowed") is True

    def test_error_hook_logs_error(self):
        flow = _make_request_flow("api.example.com", 443, "GET", "/v1/test")
        flow.error = MagicMock()
        flow.error.msg = "Connection reset by peer"
        flow.response = None
        self.addon.error(flow)
        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "error"
        assert "Connection reset" in entries[0]["reason"]

    def test_intentional_block_skipped_in_error_hook(self):
        """error() must not double-log flows that were intentionally blocked (403)."""
        flow = _make_request_flow("evil.example.com", 443, "GET", "/")
        flow.error = MagicMock()
        flow.error.msg = "some error"
        flow.response = MagicMock()
        flow.response.status_code = 403
        self.addon.error(flow)
        assert self._entries() == []


class TestLogRotationRobustness:
    """The persistent _log_fh must survive external file replacement
    (logrotate, manual rm, logviewer clear-logs creating a new inode)."""

    def setup_method(self):
        self.addon = _make_addon()
        self.addon._enforce = {"api.example.com": {"ports": {443}, "paths": None}}
        self.addon._mode = "enforce"
        self._log_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.addon.log_path = self._log_file.name

    def teardown_method(self):
        if self.addon._log_fh and not self.addon._log_fh.closed:
            self.addon._log_fh.close()
        try:
            os.unlink(self._log_file.name)
        except FileNotFoundError:
            pass

    def test_reopens_after_external_replace(self):
        flow = _make_connect_flow("api.example.com", 443)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        # Externally replace the file (rm + recreate gives a new inode).
        os.unlink(self._log_file.name)
        open(self._log_file.name, "w").close()
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        self.addon._log_fh.flush()
        with open(self._log_file.name) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 1, "post-replace write must land in the new inode"

    def test_reopens_when_file_deleted(self):
        flow = _make_connect_flow("api.example.com", 443)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        os.unlink(self._log_file.name)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        self.addon._log_fh.flush()
        assert os.path.exists(self._log_file.name)
        with open(self._log_file.name) as f:
            lines = [line for line in f if line.strip()]
        assert len(lines) == 1
