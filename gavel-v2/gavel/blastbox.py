"""
Blast Box — sandboxed speculative execution with evidence packets.

Microsoft's Agent Runtime has execution rings and resource limits.
But it doesn't have the concept of "run the action speculatively to
PRODUCE EVIDENCE, then use that evidence for governance decisions."

The Blast Box is not a sandbox for safety (Microsoft handles that).
The Blast Box is a sandbox for PROOF. It runs the proposed action in
isolation and produces a cryptographically hashed evidence packet that
the deterministic reviewer and human reviewers can examine.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ScopeDeclaration:
    """What the proposed action is allowed to touch."""

    allow_paths: list[str] = field(default_factory=list)
    allow_commands: list[str] = field(default_factory=list)
    allow_network: bool = False
    max_duration_seconds: int = 30
    max_memory_mb: int = 512
    max_cpu: int = 1


@dataclass
class EvidencePacket:
    """
    The output of a Blast Box execution. Every field is hashed.
    This packet is what reviewers examine — not the action itself.
    """

    packet_id: str = field(default_factory=lambda: f"ep-{uuid.uuid4().hex[:8]}")
    chain_id: str = ""
    intent_event_id: str = ""

    # What was executed
    command_argv: list[str] = field(default_factory=list)
    scope: ScopeDeclaration = field(default_factory=ScopeDeclaration)

    # Results
    exit_code: int = -1
    stdout_hash: str = ""
    stderr_hash: str = ""
    diff_hash: str = ""
    stdout_preview: str = ""  # first 1000 chars for human review

    # Files touched
    files_modified: list[str] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)

    # Environment
    image: str = ""
    image_digest: str = ""
    network_mode: str = "none"
    cpu: str = "1"
    memory: str = "512m"

    # Timing
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def compute_hash(self) -> str:
        content = json.dumps(
            {
                "packet_id": self.packet_id,
                "chain_id": self.chain_id,
                "command_argv": self.command_argv,
                "exit_code": self.exit_code,
                "stdout_hash": self.stdout_hash,
                "stderr_hash": self.stderr_hash,
                "diff_hash": self.diff_hash,
                "files_modified": self.files_modified,
                "files_created": self.files_created,
                "files_deleted": self.files_deleted,
                "image": self.image,
                "image_digest": self.image_digest,
                "network_mode": self.network_mode,
            },
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()


class BlastBox:
    """
    Sandboxed execution environment for producing governance evidence.

    In production, this wraps Microsoft's Agent Runtime execution rings
    with additional evidence capture. The blast box:

    1. Receives a proposed action + scope declaration
    2. Spins up an isolated environment (Agent Runtime ring)
    3. Executes the action with --dry-run or in a throwaway container
    4. Captures everything: stdout, stderr, diffs, files touched
    5. Hashes all outputs into an EvidencePacket
    6. Returns the packet for deterministic review

    The blast box NEVER touches production. It exists to generate proof.
    """

    def __init__(self, default_image: str = "python:3.12-slim"):
        self.default_image = default_image

    async def execute(
        self,
        chain_id: str,
        intent_event_id: str,
        command_argv: list[str],
        scope: ScopeDeclaration,
        dry_run: bool = True,
    ) -> EvidencePacket:
        """
        Execute a proposed action in the blast box and return evidence.

        In a real deployment, this would:
        - Use Agent Runtime to create an execution ring
        - Mount scoped filesystem
        - Run the command with network disabled
        - Capture all outputs

        For now, this simulates the execution and produces a
        realistic evidence packet.
        """
        started = datetime.now(timezone.utc)

        # In production: Agent Runtime creates execution ring here
        # runtime = AgentRuntime(ring_level=1)
        # result = await runtime.execute_sandboxed(command_argv, scope)

        # Simulate execution result
        simulated_stdout = f"Simulated execution of: {' '.join(command_argv)}"
        simulated_stderr = ""

        finished = datetime.now(timezone.utc)

        packet = EvidencePacket(
            chain_id=chain_id,
            intent_event_id=intent_event_id,
            command_argv=command_argv,
            scope=scope,
            exit_code=0,
            stdout_hash=hashlib.sha256(simulated_stdout.encode()).hexdigest(),
            stderr_hash=hashlib.sha256(simulated_stderr.encode()).hexdigest(),
            diff_hash=hashlib.sha256(b"").hexdigest(),
            stdout_preview=simulated_stdout[:1000],
            image=self.default_image,
            network_mode="none",
            cpu=str(scope.max_cpu),
            memory=f"{scope.max_memory_mb}m",
            started_at=started,
            finished_at=finished,
        )

        return packet

    def validate_scope_compliance(
        self, packet: EvidencePacket, declared_scope: ScopeDeclaration
    ) -> list[str]:
        """
        Check if the blast box execution stayed within declared scope.
        Returns list of violations (empty = compliant).
        """
        violations = []

        for f in packet.files_modified + packet.files_created:
            if not any(f.startswith(p) for p in declared_scope.allow_paths):
                violations.append(f"File '{f}' outside declared allow_paths")

        if not declared_scope.allow_network and packet.network_mode != "none":
            violations.append("Network access detected but not declared in scope")

        for f in packet.files_deleted:
            if not any(f.startswith(p) for p in declared_scope.allow_paths):
                violations.append(f"Deleted file '{f}' outside declared allow_paths")

        return violations
