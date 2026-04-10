"""Tests for gavel.rollback — ATF R-4 state rollback + compensating transactions."""

from __future__ import annotations

from pathlib import Path

import pytest

from gavel.rollback import Snapshotter, SnapshotManifest


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hello')\n")
    (tmp_path / "src" / "util.py").write_text("x = 1\n")
    (tmp_path / "README.md").write_text("# project\n")
    return tmp_path


class TestSnapshot:
    def test_snapshot_captures_scoped_files(self, workspace: Path):
        snap = Snapshotter()
        manifest = snap.snapshot("chain-1", ["src"], root=workspace)
        assert isinstance(manifest, SnapshotManifest)
        assert len(manifest.files) == 2
        paths = {f for f in manifest.files}
        assert any(p.endswith("app.py") for p in paths)
        assert any(p.endswith("util.py") for p in paths)

    def test_snapshot_ignores_out_of_scope(self, workspace: Path):
        snap = Snapshotter()
        manifest = snap.snapshot("chain-1", ["src"], root=workspace)
        assert not any("README.md" in f for f in manifest.files)

    def test_snapshot_handles_missing_paths(self, workspace: Path):
        snap = Snapshotter()
        manifest = snap.snapshot("chain-1", ["does-not-exist/"], root=workspace)
        assert manifest.files == {}

    def test_manifest_hash_deterministic(self, workspace: Path):
        snap = Snapshotter()
        m1 = snap.snapshot("chain-1", ["src"], root=workspace)
        m2 = snap.snapshot("chain-2", ["src"], root=workspace)
        # Different chain_ids but same files → same manifest hash
        assert m1.manifest_hash() == m2.manifest_hash()

    def test_manifest_hash_changes_on_file_change(self, workspace: Path):
        snap = Snapshotter()
        m1 = snap.snapshot("chain-1", ["src"], root=workspace)
        (workspace / "src" / "app.py").write_text("print('changed')\n")
        m2 = snap.snapshot("chain-2", ["src"], root=workspace)
        assert m1.manifest_hash() != m2.manifest_hash()

    def test_oversize_file_captured_hash_only(self, workspace: Path):
        big = workspace / "src" / "big.bin"
        big.write_bytes(b"x" * 1024)
        snap = Snapshotter(max_bytes_per_file=256)  # force oversize
        manifest = snap.snapshot("chain-1", ["src"], root=workspace)
        big_snap = next(s for k, s in manifest.files.items() if k.endswith("big.bin"))
        assert not big_snap.captured_full
        assert big_snap.content_b64 is None
        assert big_snap.sha256


class TestVerifyUntouched:
    def test_no_drift_on_fresh_snapshot(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        assert snap.verify_untouched("chain-1", root=workspace) == []

    def test_detects_modification(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        (workspace / "src" / "app.py").write_text("modified\n")
        drifted = snap.verify_untouched("chain-1", root=workspace)
        assert any("app.py" in p for p in drifted)

    def test_detects_deletion(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        (workspace / "src" / "app.py").unlink()
        drifted = snap.verify_untouched("chain-1", root=workspace)
        assert any("app.py" in p for p in drifted)


class TestRollback:
    def test_rollback_restores_modified_file(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        (workspace / "src" / "app.py").write_text("BAD\n")

        report = snap.rollback("chain-1", reason="review failed", root=workspace)
        assert report.fully_restored
        assert (workspace / "src" / "app.py").read_text() == "print('hello')\n"
        # Action should record what was restored.
        restore_actions = [a for a in report.actions if a.kind == "restore"]
        assert len(restore_actions) >= 1

    def test_rollback_restores_deleted_file(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        (workspace / "src" / "app.py").unlink()

        report = snap.rollback("chain-1", reason="review failed", root=workspace)
        assert report.fully_restored
        assert (workspace / "src" / "app.py").exists()

    def test_rollback_removes_files_added_by_action(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        # Action creates a new file outside the snapshot
        (workspace / "src" / "new.py").write_text("new stuff\n")

        report = snap.rollback(
            "chain-1",
            reason="review failed",
            root=workspace,
            files_added_by_action=["src/new.py"],
        )
        assert not (workspace / "src" / "new.py").exists()
        assert any(a.kind == "delete_added" for a in report.actions)

    def test_rollback_missing_snapshot_returns_report(self, workspace: Path):
        snap = Snapshotter()
        report = snap.rollback("chain-nope", reason="test", root=workspace)
        assert not report.fully_restored
        assert report.snapshot_id == ""

    def test_oversize_file_rollback_declined(self, workspace: Path):
        big = workspace / "src" / "big.bin"
        big.write_bytes(b"x" * 1024)
        snap = Snapshotter(max_bytes_per_file=256)
        snap.snapshot("chain-1", ["src"], root=workspace)
        big.write_bytes(b"y" * 1024)

        report = snap.rollback("chain-1", reason="review failed", root=workspace)
        assert not report.fully_restored
        declined_actions = [a for a in report.actions if a.kind == "declined_oversize"]
        assert any("big.bin" in a.path for a in declined_actions)

    def test_report_includes_trigger_reason(self, workspace: Path):
        snap = Snapshotter()
        snap.snapshot("chain-1", ["src"], root=workspace)
        report = snap.rollback("chain-1", reason="integrity violation", root=workspace)
        assert "integrity violation" in report.trigger_reason
