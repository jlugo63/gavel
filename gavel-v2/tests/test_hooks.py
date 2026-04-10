"""Tests for risk classification and scope extraction."""

from __future__ import annotations

import pytest

from gavel.hooks import (
    build_risk_factors,
    classify_risk,
    extract_scope_from_tool_input,
    format_action_log,
    should_govern,
)


class TestRiskClassification:
    # -- Low-risk tools --
    @pytest.mark.parametrize("tool", ["Read", "Glob", "Grep"])
    def test_read_tools_low_risk(self, tool):
        risk = classify_risk(tool)
        assert risk <= 0.2

    def test_web_search_low_risk(self):
        assert classify_risk("WebSearch") <= 0.2

    # -- Medium-risk tools --
    @pytest.mark.parametrize("tool", ["Edit", "Write", "NotebookEdit"])
    def test_write_tools_medium_risk(self, tool):
        risk = classify_risk(tool)
        assert 0.3 <= risk <= 0.5

    # -- High-risk tools --
    def test_bash_high_risk(self):
        risk = classify_risk("Bash")
        assert risk >= 0.5

    # -- Pattern escalation --
    def test_rm_rf_escalates(self):
        risk = classify_risk("Bash", {"command": "rm -rf /tmp/test"})
        assert risk >= 0.8

    def test_git_push_escalates(self):
        risk = classify_risk("Bash", {"command": "git push origin main"})
        assert risk >= 0.8

    def test_docker_push_escalates(self):
        risk = classify_risk("Bash", {"command": "docker push myimage:latest"})
        assert risk >= 0.8

    def test_drop_table_escalates(self):
        risk = classify_risk("Bash", {"command": "psql -c 'DROP TABLE users'"})
        assert risk >= 0.8

    def test_kubectl_delete_escalates(self):
        risk = classify_risk("Bash", {"command": "kubectl delete pod my-pod"})
        assert risk >= 0.8

    def test_npm_publish_escalates(self):
        risk = classify_risk("Bash", {"command": "npm publish"})
        assert risk >= 0.8

    def test_safe_bash_not_escalated(self):
        risk = classify_risk("Bash", {"command": "ls -la"})
        assert risk < 0.8

    # -- Sensitive file writes --
    def test_write_env_file_critical(self):
        risk = classify_risk("Write", {"file_path": "/app/.env"})
        assert risk >= 0.9

    def test_write_credentials_critical(self):
        risk = classify_risk("Write", {"file_path": "/home/user/credentials.json"})
        assert risk >= 0.9

    def test_write_secret_file_critical(self):
        risk = classify_risk("Write", {"file_path": "/etc/secrets/db.key"})
        assert risk >= 0.9

    def test_write_normal_file_not_critical(self):
        risk = classify_risk("Write", {"file_path": "/app/src/main.py"})
        assert risk < 0.9

    # -- Unknown tools --
    def test_unknown_tool_default_risk(self):
        risk = classify_risk("UnknownTool")
        assert risk == 0.3

    # -- Risk cap --
    def test_risk_capped_at_1(self):
        risk = classify_risk("Bash", {"command": "rm -rf /"})
        assert risk <= 1.0


class TestShouldGovern:
    def test_below_threshold(self):
        assert should_govern(0.3) is False

    def test_at_threshold(self):
        assert should_govern(0.5) is True

    def test_above_threshold(self):
        assert should_govern(0.8) is True

    def test_custom_threshold(self):
        assert should_govern(0.3, threshold=0.2) is True
        assert should_govern(0.3, threshold=0.5) is False


class TestBuildRiskFactors:
    def test_production_indicator(self):
        factors = build_risk_factors("Bash", {"command": "deploy to production"})
        assert factors["touches_production"] is True

    def test_financial_indicator(self):
        factors = build_risk_factors("Bash", {"command": "process stripe payment"})
        assert factors["touches_financial"] is True

    def test_pii_indicator(self):
        factors = build_risk_factors("Bash", {"command": "query customer email"})
        assert factors["touches_pii"] is True

    def test_no_indicators(self):
        factors = build_risk_factors("Read", {"file_path": "/tmp/test.txt"})
        assert factors["touches_production"] is False
        assert factors["touches_financial"] is False
        assert factors["touches_pii"] is False

    def test_scope_breadth(self):
        assert build_risk_factors("Read", {})["scope_breadth"] == 0.1
        assert build_risk_factors("Bash", {})["scope_breadth"] == 0.5
        assert build_risk_factors("Agent", {})["scope_breadth"] == 0.6


class TestExtractScope:
    def test_read_tool(self):
        scope = extract_scope_from_tool_input("Read", {"file_path": "/app/main.py"})
        assert "/app/main.py" in scope["allow_paths"]
        assert scope["allow_network"] is False

    def test_write_tool(self):
        scope = extract_scope_from_tool_input("Write", {"file_path": "/app/out.txt"})
        assert "/app/out.txt" in scope["allow_paths"]

    def test_bash_with_paths(self):
        scope = extract_scope_from_tool_input("Bash", {"command": "cat /etc/hosts"})
        assert "/etc/hosts" in scope["allow_paths"]

    def test_bash_with_curl(self):
        scope = extract_scope_from_tool_input("Bash", {"command": "curl https://api.example.com"})
        assert scope["allow_network"] is True

    def test_web_fetch(self):
        scope = extract_scope_from_tool_input("WebFetch", {"url": "https://example.com"})
        assert scope["allow_network"] is True
        assert scope["allow_paths"] == []

    def test_agent_tool(self):
        scope = extract_scope_from_tool_input("Agent", {"prompt": "do something"})
        assert scope["allow_network"] is False


class TestFormatActionLog:
    def test_format_basic(self):
        log = format_action_log("agent:test", "Read", "pre_tool_use", 0.1)
        assert log["agent_id"] == "agent:test"
        assert log["tool"] == "Read"
        assert log["risk"] == 0.1
        assert log["governed"] is False

    def test_format_governed(self):
        log = format_action_log("agent:test", "Bash", "pre_tool_use", 0.8)
        assert log["governed"] is True
