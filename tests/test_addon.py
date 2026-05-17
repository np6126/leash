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
from addon.allowlist_logger import AllowlistLogger, BODY_LIMIT  # noqa: E402


def _make_addon(**env):
    with patch.dict(os.environ, env):
        return AllowlistLogger()


# ── _find_entry ───────────────────────────────────────────────────────────────

class TestFindEntry:
    def setup_method(self):
        self.addon = _make_addon()
        self.addon._allowed = {
            "api.github.com": {"ports": {443}, "paths": None},
            "github.com":     {"ports": {443, 80}, "paths": None},
        }

    def test_exact_match(self):
        assert self.addon._find_entry("api.github.com") is not None

    def test_subdomain_wildcard(self):
        # foo.github.com → falls back to github.com
        entry = self.addon._find_entry("foo.github.com")
        assert entry is not None
        assert 80 in entry["ports"]

    def test_exact_beats_wildcard(self):
        # api.github.com has its own entry with only port 443
        entry = self.addon._find_entry("api.github.com")
        assert 80 not in entry["ports"]

    def test_no_match(self):
        assert self.addon._find_entry("example.com") is None

    def test_deep_subdomain(self):
        # a.b.github.com → tries b.github.com then github.com
        assert self.addon._find_entry("a.b.github.com") is not None

    def test_tld_only_not_matched(self):
        # should not match on just "com"
        assert self.addon._find_entry("notgithub.com") is None


# ── _is_allowed ───────────────────────────────────────────────────────────────

class TestIsAllowed:
    def setup_method(self):
        self.addon = _make_addon()
        self.addon._allowed = {
            "api.example.com": {
                "ports": {443},
                "paths": [
                    {"method": "GET",  "prefix": "/v1/"},
                    {"method": "",     "prefix": "/public/"},
                ],
            },
            "open.example.com": {"ports": {443, 8080}, "paths": None},
        }

    def _check(self, host, port, method="", path=""):
        with patch.object(self.addon, "_reload_if_changed"):
            return self.addon._is_allowed(host, port, method, path)

    def test_unknown_host_blocked(self):
        ok, reason = self._check("other.com", 443)
        assert not ok and reason == "not_in_allowlist"

    def test_wrong_port_blocked(self):
        ok, reason = self._check("open.example.com", 9999)
        assert not ok and reason == "not_in_allowlist"

    def test_host_allowed_no_paths(self):
        ok, _ = self._check("open.example.com", 443)
        assert ok

    def test_host_allowed_second_port(self):
        ok, _ = self._check("open.example.com", 8080)
        assert ok

    def test_path_allowed_exact_method(self):
        ok, _ = self._check("api.example.com", 443, "GET", "/v1/users")
        assert ok

    def test_path_blocked_wrong_method(self):
        ok, reason = self._check("api.example.com", 443, "POST", "/v1/users")
        assert not ok and reason == "path_not_allowed"

    def test_path_allowed_wildcard_method(self):
        ok, _ = self._check("api.example.com", 443, "DELETE", "/public/data")
        assert ok

    def test_path_blocked_unmatched_prefix(self):
        ok, reason = self._check("api.example.com", 443, "GET", "/private/")
        assert not ok and reason == "path_not_allowed"

    def test_connect_stage_skips_path_check(self):
        # No method/path supplied → CONNECT stage, only host:port checked
        ok, _ = self._check("api.example.com", 443)
        assert ok


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


# ── allowlist loading ─────────────────────────────────────────────────────────

class TestAllowlistLoading:
    def test_basic_host(self, tmp_path):
        f = tmp_path / "allowlist.yaml"
        f.write_text("allowed_destinations:\n  - host: api.example.com\n    ports: [443]\n")
        addon = _make_addon(ALLOWLIST_PATH=str(f), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "api.example.com" in addon._allowed
        assert 443 in addon._allowed["api.example.com"]["ports"]

    def test_path_rules_loaded(self, tmp_path):
        f = tmp_path / "allowlist.yaml"
        f.write_text(
            "allowed_destinations:\n"
            "  - host: api.example.com\n"
            "    ports: [443]\n"
            "    paths:\n"
            "      - method: GET\n"
            "        prefix: /v1/\n"
        )
        addon = _make_addon(ALLOWLIST_PATH=str(f), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        paths = addon._allowed["api.example.com"]["paths"]
        assert paths is not None and paths[0]["prefix"] == "/v1/"

    def test_no_paths_key_means_all_paths(self, tmp_path):
        f = tmp_path / "allowlist.yaml"
        f.write_text("allowed_destinations:\n  - host: open.example.com\n    ports: [443]\n")
        addon = _make_addon(ALLOWLIST_PATH=str(f), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert addon._allowed["open.example.com"]["paths"] is None

    def test_empty_host_skipped(self, tmp_path):
        f = tmp_path / "allowlist.yaml"
        f.write_text("allowed_destinations:\n  - host: ''\n    ports: [443]\n")
        addon = _make_addon(ALLOWLIST_PATH=str(f), LOG_PATH=str(tmp_path / "x.jsonl"))
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "" not in addon._allowed

    def test_missing_file_leaves_allowed_unchanged(self, tmp_path):
        addon = _make_addon(
            ALLOWLIST_PATH=str(tmp_path / "nonexistent.yaml"),
            LOG_PATH=str(tmp_path / "x.jsonl"),
        )
        addon._allowed = {"keep.me": {}}
        with patch("mitmproxy.ctx"):
            addon._reload_if_changed()
        assert "keep.me" in addon._allowed


# ── responseheaders ───────────────────────────────────────────────────────────

class TestResponseheaders:
    def setup_method(self):
        self.addon = _make_addon()

    def test_no_crash_when_response_is_none(self):
        # flow.response is None but log_allowed is set — must not raise AttributeError
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
        self.addon._allowed = {
            "api.example.com": {"ports": {443}, "paths": None},
        }
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
        flow = _make_connect_flow("evil.example.com", 443)
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.http_connect(flow)
        entries = self._entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "blocked"
        assert entries[0]["reason"] == "not_in_allowlist"
        # mitmproxy http.Response.make is mocked, so just verify it was assigned
        assert flow.response is not None

    def test_request_allowed_stores_metadata(self):
        flow = _make_request_flow("api.example.com", 443, "GET", "/v1/test")
        with patch.object(self.addon, "_reload_if_changed"):
            self.addon.request(flow)
        assert flow.metadata.get("log_allowed") is True
        assert flow.metadata.get("log_client") == "10.0.0.1"
        assert flow.metadata.get("log_req_headers") == []

    def test_request_blocked_logs_and_sets_403(self):
        flow = _make_request_flow("evil.example.com", 443, "GET", "/")
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
