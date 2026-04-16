"""Tests that GAVEL_ADMIN_MODE is snapshotted at import and immutable thereafter.

Per ARCHITECTURE_REVIEW_2026-04-14 §5.6: an attacker with post-startup
process-env write access must not be able to flip admin mode on.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path

import pytest

import gavel.admin as admin_module

# Snapshot every top-level symbol of gavel.admin before any reload. After a
# reload, importlib.reload mutates the module's globals dict in-place, which
# replaces every class object (SecurityViolation, AdminAgent, etc.). Other
# test modules that imported these symbols still hold the ORIGINAL class
# objects, but code paths executing inside the module (e.g. AdminAgent.create
# raising SecurityViolation) will look up the NEW class via module globals —
# causing pytest.raises(OriginalSecurityViolation) to miss.
#
# Restoring the original symbols to module globals in teardown keeps class
# identity stable across test files.
_ORIGINAL_ADMIN_GLOBALS = dict(admin_module.__dict__)


@pytest.fixture
def env_guard():
    """Save/restore GAVEL_ADMIN_MODE, module snapshot, and module identity.

    Tests here use importlib.reload, which creates a new module object. Other
    test files import class symbols (e.g. SecurityViolation) directly, so they
    hold references to the ORIGINAL module's classes. After a reload, those
    bindings go stale relative to the new module. To keep cross-file test
    isolation, we restore the original module object into sys.modules on
    teardown and refresh its snapshot to match the current (restored) env.
    """
    saved = os.environ.get("GAVEL_ADMIN_MODE")
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("GAVEL_ADMIN_MODE", None)
        else:
            os.environ["GAVEL_ADMIN_MODE"] = saved
        # Restore original class identities so other test files' imports
        # (which bound at their module-load time) stay consistent with the
        # classes executed inside admin_module.
        admin_module.__dict__.clear()
        admin_module.__dict__.update(_ORIGINAL_ADMIN_GLOBALS)
        admin_module._reset_admin_mode_snapshot_for_tests()


class TestAdminModeSnapshotAtImport:
    def test_snapshot_taken_at_reload_time_true(self, env_guard):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is True

    def test_snapshot_taken_at_reload_time_false(self, env_guard):
        os.environ["GAVEL_ADMIN_MODE"] = "false"
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is False

    def test_snapshot_defaults_to_false_when_unset(self, env_guard):
        os.environ.pop("GAVEL_ADMIN_MODE", None)
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is False


class TestAdminModePostImportMutationIgnored:
    def test_flipping_env_after_import_does_not_change_snapshot(self, env_guard):
        os.environ["GAVEL_ADMIN_MODE"] = "false"
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is False

        # Attacker flips env var at runtime — snapshot must not follow.
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        assert reloaded.is_admin_mode_enabled() is False

    def test_flipping_env_from_true_to_false_also_ignored(self, env_guard):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is True

        os.environ["GAVEL_ADMIN_MODE"] = "false"
        assert reloaded.is_admin_mode_enabled() is True

    def test_deleting_env_after_import_ignored(self, env_guard):
        os.environ["GAVEL_ADMIN_MODE"] = "true"
        reloaded = importlib.reload(admin_module)
        assert reloaded.is_admin_mode_enabled() is True

        os.environ.pop("GAVEL_ADMIN_MODE", None)
        assert reloaded.is_admin_mode_enabled() is True


class TestNoDirectEnvReadsRemain:
    """Every GAVEL_ADMIN_MODE read must go through the snapshot helper."""

    def _admin_source(self) -> str:
        path = Path(admin_module.__file__)
        return path.read_text(encoding="utf-8")

    def test_admin_py_has_no_direct_env_read_of_admin_mode(self):
        source = self._admin_source()
        # Strip the single allowed read site: the private snapshot initializer.
        allowed_line_re = re.compile(
            r'os\.environ\.get\("GAVEL_ADMIN_MODE", "false"\)\.lower\(\)\.strip\(\) == "true"'
        )
        sanitized = allowed_line_re.sub("<SNAPSHOT_INIT>", source)

        offenders = re.findall(r'os\.environ[^\n]*GAVEL_ADMIN_MODE', sanitized)
        assert offenders == [], (
            f"Found direct os.environ reads of GAVEL_ADMIN_MODE in admin.py "
            f"outside the snapshot initializer: {offenders}"
        )

    def test_claude_code_adapter_has_no_direct_env_read_of_admin_mode(self):
        from gavel.adapters import claude_code as adapter_module

        source = Path(adapter_module.__file__).read_text(encoding="utf-8")
        offenders = re.findall(r'os\.environ[^\n]*GAVEL_ADMIN_MODE', source)
        assert offenders == [], (
            f"Found direct os.environ reads of GAVEL_ADMIN_MODE in "
            f"claude_code adapter: {offenders}"
        )


class TestResetHelperIsPrivate:
    def test_reset_helper_is_underscore_prefixed(self):
        assert hasattr(admin_module, "_reset_admin_mode_snapshot_for_tests")
        assert not hasattr(admin_module, "reset_admin_mode_snapshot_for_tests")
