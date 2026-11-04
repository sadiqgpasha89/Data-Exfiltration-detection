"""Closed-Loop Remediation API Tool.

Containment is the one action in this system that can hurt the business: it cuts a host off the network and kills a
person's sessions. So it is guarded:

* `AUTO_REMEDIATION_MODE=dry_run` (the default) records exactly what would be done and changes nothing. `enforce`
  executes. `off` never acts automatically.
* Automated containment never touches a protected identity or address (executives, break-glass accounts, core
  infrastructure), and it is capped per hour, so a flood of crafted events cannot be turned into a denial of service
  against the bank's own staff.
* Every action reports an honest status: APPLIED, DRY_RUN, SIMULATED, SKIPPED or FAILED. A containment that did not
  verifiably happen is never reported as done.

The default backend only simulates, because the Neutron, IdP and Vault adapters are deployment-specific. Production
registers real adapters with `register_backend()` (they implement `ContainmentBackend`).
"""

import collections
import ipaddress
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Protocol

from src.core.config import settings
from src.core.telemetry import TelemetryTimer, logger


class ContainmentBackend(Protocol):
    """What a real integration must provide. Each method returns a dict with at least a `status` of APPLIED or FAILED."""

    def isolate_endpoint(self, ip_address: str, reason: str) -> Dict[str, Any]: ...
    def revoke_session(self, user_id: str, reason: str) -> Dict[str, Any]: ...
    def revoke_leases(self, user_id: str) -> Dict[str, Any]: ...


class SimulatedBackend:
    """Stand-in used when no real adapter is registered: it records the intended action and reports SIMULATED, never APPLIED."""

    def isolate_endpoint(self, ip_address: str, reason: str) -> Dict[str, Any]:
        return {
            "action": "NEUTRON_QUARANTINE_ISOLATION",
            "target_ip": ip_address,
            "neutron_endpoint": settings.OPENSTACK_NEUTRON_ENDPOINT,
            "security_group_rule_id": f"secgroup-rule-quarantine-{ip_address.replace('.', '-').replace(':', '-')}",
            "status": "SIMULATED",
            "reason": reason,
        }

    def revoke_session(self, user_id: str, reason: str) -> Dict[str, Any]:
        return {"action": "IDP_SESSION_REVOCATION", "target_user_id": user_id, "status": "SIMULATED", "reason": reason}

    def revoke_leases(self, user_id: str) -> Dict[str, Any]:
        return {"action": "VAULT_LEASE_REVOCATION", "target_user_id": user_id, "status": "SIMULATED"}


class ContainmentGuard:
    """Protected-target list and an hourly blast-radius cap for automated containment."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._recent: Deque[float] = collections.deque()
        self._done_cases: Dict[str, Dict[str, Any]] = {}

    def protected_reason(self, ip_address: str, user_id: str) -> Optional[str]:
        if user_id in settings.protected_user_ids:
            return f"user '{user_id}' is on the protected list"
        try:
            addr = ipaddress.ip_address(ip_address)
        except ValueError:
            return f"'{ip_address}' is not a valid address"
        for entry in settings.protected_ips:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return f"address {ip_address} is inside protected range {entry}"
            except ValueError:
                continue
        return None

    def reserve_slot(self) -> bool:
        """Takes one of the automated-containment slots for the current hour, or returns False when none are left."""
        with self._lock:
            now = self._clock()
            while self._recent and now - self._recent[0] > 3600:
                self._recent.popleft()
            if len(self._recent) >= settings.MAX_AUTO_CONTAINMENTS_PER_HOUR:
                return False
            self._recent.append(now)
            return True

    def previous(self, case_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._done_cases.get(case_id)

    def remember(self, case_id: str, outcome: Dict[str, Any]) -> None:
        with self._lock:
            self._done_cases[case_id] = outcome
            while len(self._done_cases) > 10_000:
                self._done_cases.pop(next(iter(self._done_cases)))


class RemediationExecutionTool:
    """Executes guarded containment playbooks against the registered backend."""

    def __init__(self, backend: Optional[ContainmentBackend] = None):
        self.backend: ContainmentBackend = backend or SimulatedBackend()
        self.guard = ContainmentGuard()

    def register_backend(self, backend: ContainmentBackend) -> None:
        self.backend = backend

    # ---- single actions, kept for the SOC cockpit ---------------------------------------------------------
    def _run(self, name: str, fn, *args, dry_run: bool = False) -> Dict[str, Any]:
        with TelemetryTimer(name) as timer:
            if dry_run:
                result: Dict[str, Any] = {"action": name, "status": "DRY_RUN", "args": [str(a) for a in args]}
            else:
                try:
                    result = {**fn(*args), "action": name}  # the canonical action name, whatever the adapter calls it
                except Exception as exc:  # a failed containment must be visible, never swallowed
                    logger.error("containment_action_failed", action=name, error=type(exc).__name__)
                    result = {"action": name, "status": "FAILED", "error": type(exc).__name__}
        result["latency_ms"] = round(timer.elapsed_ms, 2)
        logger.info("remediation_action", **{k: v for k, v in result.items() if k != "args"})
        return result

    def isolate_endpoint_openstack(self, ip_address: str, reason: str, dry_run: bool = False) -> Dict[str, Any]:
        return self._run("NEUTRON_QUARANTINE_ISOLATION", self.backend.isolate_endpoint, ip_address, reason, dry_run=dry_run)

    def revoke_identity_session(self, user_id: str, reason: str, dry_run: bool = False) -> Dict[str, Any]:
        return self._run("IDP_SESSION_REVOCATION", self.backend.revoke_session, user_id, reason, dry_run=dry_run)

    def revoke_vault_db_tokens(self, user_id: str, dry_run: bool = False) -> Dict[str, Any]:
        return self._run("VAULT_LEASE_REVOCATION", self.backend.revoke_leases, user_id, dry_run=dry_run)

    def execute_containment_playbook(self, ip_address: str, user_id: str, case_id: str, dry_run: bool = False) -> List[Dict[str, Any]]:
        """Full containment sequence requested by a human analyst. Authorization is the caller's job (the API enforces it)."""
        return [
            self.isolate_endpoint_openstack(ip_address, f"Containment approved for {case_id}", dry_run),
            self.revoke_identity_session(user_id, f"Containment approved for {case_id}", dry_run),
            self.revoke_vault_db_tokens(user_id, dry_run),
        ]

    # ---- automated containment ------------------------------------------------------------------------------
    def automated_containment(self, ip_address: str, user_id: str, case_id: str) -> Dict[str, Any]:
        """Applies the automation policy and returns what happened.

        `effective` is True only when every action reports APPLIED. `executed` is True when the playbook ran at all,
        including as a dry run.
        """
        mode = settings.AUTO_REMEDIATION_MODE
        outcome: Dict[str, Any] = {"mode": mode, "executed": False, "effective": False, "blocked_reason": None, "actions": []}

        previous = self.guard.previous(case_id)
        if previous is not None:  # a retried request must not contain twice
            return {**previous, "idempotent_replay": True}

        if mode == "off":
            outcome["blocked_reason"] = "automatic remediation is switched off"
        elif (reason := self.guard.protected_reason(ip_address, user_id)) is not None:
            outcome["blocked_reason"] = f"protected target: {reason}"
        elif mode == "enforce" and not self.guard.reserve_slot():
            outcome["blocked_reason"] = f"blast-radius cap reached ({settings.MAX_AUTO_CONTAINMENTS_PER_HOUR} automatic containments per hour)"
        else:
            actions = self.execute_containment_playbook(ip_address, user_id, case_id, dry_run=(mode != "enforce"))
            outcome["actions"] = actions
            outcome["executed"] = True
            outcome["effective"] = mode == "enforce" and all(a.get("status") == "APPLIED" for a in actions)

        if outcome["blocked_reason"]:
            logger.warning("automatic_containment_blocked", case_id=case_id, reason=outcome["blocked_reason"])
        self.guard.remember(case_id, outcome)
        return outcome


remediation_tool = RemediationExecutionTool()
