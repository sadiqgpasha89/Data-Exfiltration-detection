"""Containment is the dangerous action: it must be honest, bounded and protected."""

import pytest
from src.agents.tools.remediation_tool import ContainmentGuard, RemediationExecutionTool, SimulatedBackend
from src.core.config import settings


class RecordingBackend:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def _do(self, name, *args):
        if self.fail_on == name:
            raise ConnectionError("backend down")
        self.calls.append((name, *args))
        return {"action": name, "status": "APPLIED"}

    def isolate_endpoint(self, ip, reason): return self._do("isolate", ip)
    def revoke_session(self, user, reason): return self._do("session", user)
    def revoke_leases(self, user): return self._do("leases", user)


def tool(backend=None):
    return RemediationExecutionTool(backend or RecordingBackend())


def test_default_mode_is_dry_run_and_changes_nothing():
    assert settings.AUTO_REMEDIATION_MODE == "dry_run"
    backend = RecordingBackend()
    out = tool(backend).automated_containment("10.240.5.10", "usr_x", "CASE-1")
    assert out["executed"] is True and out["effective"] is False
    assert [a["status"] for a in out["actions"]] == ["DRY_RUN"] * 3 and backend.calls == []


def test_enforce_applies_and_reports_effective(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    backend = RecordingBackend()
    out = tool(backend).automated_containment("10.240.5.10", "usr_x", "CASE-2")
    assert out["effective"] is True and [c[0] for c in backend.calls] == ["isolate", "session", "leases"]


def test_simulated_backend_is_never_reported_as_applied(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    out = RemediationExecutionTool(SimulatedBackend()).automated_containment("10.240.5.10", "usr_x", "CASE-3")
    assert out["executed"] is True and out["effective"] is False
    assert {a["status"] for a in out["actions"]} == {"SIMULATED"}


def test_a_failing_backend_is_visible_and_not_effective(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    out = tool(RecordingBackend(fail_on="session")).automated_containment("10.240.5.10", "usr_x", "CASE-4")
    statuses = {a["action"]: a["status"] for a in out["actions"]}
    assert out["effective"] is False and statuses["IDP_SESSION_REVOCATION"] == "FAILED"
    assert statuses["NEUTRON_QUARANTINE_ISOLATION"] == "APPLIED"  # the other steps still ran; the failure is not hidden


def test_off_mode_never_acts(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "off")
    out = tool().automated_containment("10.240.5.10", "usr_x", "CASE-5")
    assert out["executed"] is False and "switched off" in out["blocked_reason"]


def test_protected_users_and_ranges_are_never_contained_automatically(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    monkeypatch.setattr(settings, "PROTECTED_USER_IDS", "usr_ceo, usr_breakglass")
    monkeypatch.setattr(settings, "PROTECTED_IPS", "10.0.0.0/24, 192.0.2.7")
    backend = RecordingBackend()
    t = tool(backend)
    assert "protected" in t.automated_containment("10.240.5.10", "usr_ceo", "CASE-6")["blocked_reason"]
    assert "protected range" in t.automated_containment("10.0.0.9", "usr_x", "CASE-7")["blocked_reason"]
    assert "protected range" in t.automated_containment("192.0.2.7", "usr_x", "CASE-8")["blocked_reason"]
    assert "not a valid address" in t.automated_containment("garbage", "usr_x", "CASE-9")["blocked_reason"]
    assert backend.calls == []


def test_blast_radius_cap_stops_a_flood(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    monkeypatch.setattr(settings, "MAX_AUTO_CONTAINMENTS_PER_HOUR", 2)
    t = tool()
    results = [t.automated_containment(f"10.240.5.{i}", f"usr_{i}", f"CASE-F{i}") for i in range(4)]
    assert [r["executed"] for r in results] == [True, True, False, False]
    assert "blast-radius cap" in results[2]["blocked_reason"]


def test_cap_recovers_after_an_hour():
    now = [0.0]
    guard = ContainmentGuard(clock=lambda: now[0])
    assert guard.reserve_slot() and guard.reserve_slot() and guard.reserve_slot() and guard.reserve_slot() and guard.reserve_slot()
    assert guard.reserve_slot() is False
    now[0] = 3601.0
    assert guard.reserve_slot() is True


def test_retries_do_not_contain_twice(monkeypatch):
    monkeypatch.setattr(settings, "AUTO_REMEDIATION_MODE", "enforce")
    backend = RecordingBackend()
    t = tool(backend)
    first = t.automated_containment("10.240.5.10", "usr_x", "CASE-R")
    again = t.automated_containment("10.240.5.10", "usr_x", "CASE-R")
    assert again["idempotent_replay"] is True and len(backend.calls) == 3 and first["effective"]
