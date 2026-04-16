"""Tests for Blast Box — sandboxed speculative execution (ATF S-5)."""

from __future__ import annotations

import hashlib

import pytest

from gavel.blastbox import BlastBox, EvidencePacket, ScopeDeclaration


# ── ScopeDeclaration ──────────────────────────────────────────────


class TestScopeDeclaration:
    def test_defaults(self):
        scope = ScopeDeclaration()
        assert scope.allow_paths == []
        assert scope.allow_commands == []
        assert scope.allow_network is False
        assert scope.max_duration_seconds == 30
        assert scope.max_memory_mb == 512
        assert scope.max_cpu == 1

    def test_custom_values(self):
        scope = ScopeDeclaration(
            allow_paths=["/tmp"],
            allow_commands=["ls"],
            allow_network=True,
            max_duration_seconds=60,
            max_memory_mb=1024,
            max_cpu=4,
        )
        assert scope.allow_paths == ["/tmp"]
        assert scope.allow_network is True
        assert scope.max_cpu == 4


# ── EvidencePacket ────────────────────────────────────────────────


class TestEvidencePacket:
    def test_packet_id_generated(self):
        pkt = EvidencePacket()
        assert pkt.packet_id.startswith("ep-")
        assert len(pkt.packet_id) == 11  # "ep-" + 8 hex chars

    def test_unique_ids(self):
        ids = {EvidencePacket().packet_id for _ in range(50)}
        assert len(ids) == 50

    def test_default_exit_code(self):
        assert EvidencePacket().exit_code == -1

    def test_default_network_mode(self):
        assert EvidencePacket().network_mode == "none"

    def test_compute_hash_deterministic(self):
        pkt = EvidencePacket(
            packet_id="ep-fixed",
            chain_id="c-test",
            command_argv=["echo", "hi"],
            exit_code=0,
            stdout_hash="abc",
            stderr_hash="def",
            diff_hash="000",
            image="python:3.12-slim",
            image_digest="sha256:aaa",
            network_mode="none",
        )
        h1 = pkt.compute_hash()
        h2 = pkt.compute_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_hash_changes_on_mutation(self):
        pkt = EvidencePacket(packet_id="ep-fixed", chain_id="c-1", exit_code=0)
        h1 = pkt.compute_hash()
        pkt.exit_code = 1
        h2 = pkt.compute_hash()
        assert h1 != h2

    def test_compute_hash_includes_files(self):
        pkt = EvidencePacket(packet_id="ep-fixed", chain_id="c-1")
        h1 = pkt.compute_hash()
        pkt.files_modified = ["/tmp/foo"]
        h2 = pkt.compute_hash()
        assert h1 != h2

    def test_timestamps_are_utc(self):
        from datetime import timezone
        pkt = EvidencePacket()
        assert pkt.started_at.tzinfo == timezone.utc
        assert pkt.finished_at.tzinfo == timezone.utc


# ── BlastBox ──────────────────────────────────────────────────────


class TestBlastBox:
    def test_default_image(self):
        bb = BlastBox()
        assert bb.default_image == "python:3.12-slim"

    def test_custom_image(self):
        bb = BlastBox(default_image="node:20-slim")
        assert bb.default_image == "node:20-slim"

    @pytest.mark.asyncio
    async def test_execute_returns_evidence_packet(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp"])
        pkt = await bb.execute(
            chain_id="c-test",
            intent_event_id="ev-1",
            command_argv=["echo", "hello"],
            scope=scope,
        )
        assert isinstance(pkt, EvidencePacket)
        assert pkt.chain_id == "c-test"
        assert pkt.intent_event_id == "ev-1"
        assert pkt.command_argv == ["echo", "hello"]
        assert pkt.exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_sets_resource_limits_from_scope(self):
        bb = BlastBox()
        scope = ScopeDeclaration(max_cpu=2, max_memory_mb=256)
        pkt = await bb.execute("c-1", "ev-1", ["ls"], scope)
        assert pkt.cpu == "2"
        assert pkt.memory == "256m"

    @pytest.mark.asyncio
    async def test_execute_network_disabled(self):
        bb = BlastBox()
        scope = ScopeDeclaration()
        pkt = await bb.execute("c-1", "ev-1", ["curl", "http://evil.com"], scope)
        assert pkt.network_mode == "none"

    @pytest.mark.asyncio
    async def test_execute_stdout_hash_is_sha256(self):
        bb = BlastBox()
        pkt = await bb.execute("c-1", "ev-1", ["echo", "hi"], ScopeDeclaration())
        expected_stdout = "Simulated execution of: echo hi"
        expected_hash = hashlib.sha256(expected_stdout.encode()).hexdigest()
        assert pkt.stdout_hash == expected_hash

    @pytest.mark.asyncio
    async def test_execute_stdout_preview_truncated(self):
        bb = BlastBox()
        pkt = await bb.execute("c-1", "ev-1", ["echo", "hi"], ScopeDeclaration())
        assert len(pkt.stdout_preview) <= 1000

    @pytest.mark.asyncio
    async def test_execute_timing(self):
        bb = BlastBox()
        pkt = await bb.execute("c-1", "ev-1", ["ls"], ScopeDeclaration())
        assert pkt.started_at <= pkt.finished_at

    @pytest.mark.asyncio
    async def test_execute_uses_default_image(self):
        bb = BlastBox(default_image="alpine:3.19")
        pkt = await bb.execute("c-1", "ev-1", ["ls"], ScopeDeclaration())
        assert pkt.image == "alpine:3.19"


# ── Scope Compliance Validation ───────────────────────────────────


class TestScopeCompliance:
    def test_compliant_no_violations(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp/project"])
        pkt = EvidencePacket(
            files_modified=["/tmp/project/main.py"],
            files_created=["/tmp/project/new.py"],
            network_mode="none",
        )
        violations = bb.validate_scope_compliance(pkt, scope)
        assert violations == []

    def test_file_outside_scope(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp/project"])
        pkt = EvidencePacket(files_modified=["/etc/important.conf"])
        violations = bb.validate_scope_compliance(pkt, scope)
        assert len(violations) == 1
        assert "outside declared allow_paths" in violations[0]

    def test_created_file_outside_scope(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp/project"])
        pkt = EvidencePacket(files_created=["/var/log/sneaky.log"])
        violations = bb.validate_scope_compliance(pkt, scope)
        assert len(violations) == 1

    def test_deleted_file_outside_scope(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp/project"])
        pkt = EvidencePacket(files_deleted=["/usr/bin/something"])
        violations = bb.validate_scope_compliance(pkt, scope)
        assert len(violations) == 1
        assert "Deleted file" in violations[0]

    def test_network_violation(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_network=False)
        pkt = EvidencePacket(network_mode="bridge")
        violations = bb.validate_scope_compliance(pkt, scope)
        assert any("Network access" in v for v in violations)

    def test_network_allowed(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_network=True)
        pkt = EvidencePacket(network_mode="bridge")
        violations = bb.validate_scope_compliance(pkt, scope)
        assert not any("Network" in v for v in violations)

    def test_multiple_violations(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp"], allow_network=False)
        pkt = EvidencePacket(
            files_modified=["/etc/shadow"],
            files_created=["/var/sneaky"],
            files_deleted=["/home/user/.bashrc"],
            network_mode="host",
        )
        violations = bb.validate_scope_compliance(pkt, scope)
        assert len(violations) >= 4  # 3 file violations + 1 network

    def test_empty_packet_no_violations(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=[])
        pkt = EvidencePacket()
        violations = bb.validate_scope_compliance(pkt, scope)
        assert violations == []

    def test_multiple_allow_paths(self):
        bb = BlastBox()
        scope = ScopeDeclaration(allow_paths=["/tmp", "/var/log"])
        pkt = EvidencePacket(
            files_modified=["/tmp/a.txt", "/var/log/b.log"],
        )
        violations = bb.validate_scope_compliance(pkt, scope)
        assert violations == []
