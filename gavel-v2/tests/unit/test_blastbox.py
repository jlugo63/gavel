"""Unit tests for BlastBox — evidence packet creation and scope validation."""

import pytest

from gavel.blastbox import BlastBox, EvidencePacket, ScopeDeclaration


class TestEvidencePacket:
    def test_packet_has_unique_id(self):
        p1 = EvidencePacket()
        p2 = EvidencePacket()
        assert p1.packet_id != p2.packet_id

    def test_packet_hash_is_deterministic(self, clean_evidence_packet):
        h1 = clean_evidence_packet.compute_hash()
        h2 = clean_evidence_packet.compute_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_different_packets_different_hashes(self):
        p1 = EvidencePacket(chain_id="c-1", exit_code=0)
        p2 = EvidencePacket(chain_id="c-2", exit_code=0)
        assert p1.compute_hash() != p2.compute_hash()

    def test_exit_code_affects_hash(self):
        p1 = EvidencePacket(chain_id="c-1", exit_code=0)
        p2 = EvidencePacket(chain_id="c-1", exit_code=1)
        assert p1.compute_hash() != p2.compute_hash()


class TestScopeDeclaration:
    def test_default_scope(self):
        scope = ScopeDeclaration()
        assert scope.allow_paths == []
        assert scope.allow_network is False
        assert scope.max_duration_seconds == 30
        assert scope.max_memory_mb == 512

    def test_custom_scope(self, scope):
        assert "k8s/deployments/payments-service.yaml" in scope.allow_paths
        assert scope.allow_network is False


class TestBlastBoxExecution:
    @pytest.mark.asyncio
    async def test_execute_returns_evidence(self, blastbox, scope):
        packet = await blastbox.execute(
            chain_id="c-test",
            intent_event_id="evt-test",
            command_argv=["kubectl", "scale", "--replicas=6"],
            scope=scope,
        )
        assert isinstance(packet, EvidencePacket)
        assert packet.chain_id == "c-test"
        assert packet.exit_code == 0
        assert packet.network_mode == "none"

    @pytest.mark.asyncio
    async def test_execute_captures_timing(self, blastbox, scope):
        packet = await blastbox.execute(
            chain_id="c-test",
            intent_event_id="evt-test",
            command_argv=["echo", "hello"],
            scope=scope,
        )
        assert packet.started_at <= packet.finished_at

    @pytest.mark.asyncio
    async def test_execute_produces_hashable_packet(self, blastbox, scope):
        packet = await blastbox.execute(
            chain_id="c-test",
            intent_event_id="evt-test",
            command_argv=["echo", "hello"],
            scope=scope,
        )
        h = packet.compute_hash()
        assert len(h) == 64


class TestScopeCompliance:
    def test_files_within_scope_pass(self, blastbox, scope, clean_evidence_packet):
        violations = blastbox.validate_scope_compliance(clean_evidence_packet, scope)
        assert violations == []

    def test_files_outside_scope_detected(self, blastbox, scope, dirty_evidence_packet):
        violations = blastbox.validate_scope_compliance(dirty_evidence_packet, scope)
        assert len(violations) > 0
        assert any("/etc/shadow" in v for v in violations)

    def test_network_violation_detected(self, blastbox, scope, dirty_evidence_packet):
        violations = blastbox.validate_scope_compliance(dirty_evidence_packet, scope)
        assert any("network" in v.lower() for v in violations)

    def test_created_files_outside_scope_detected(self, blastbox, scope, dirty_evidence_packet):
        violations = blastbox.validate_scope_compliance(dirty_evidence_packet, scope)
        assert any("backdoor" in v for v in violations)
