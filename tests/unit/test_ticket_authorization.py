"""A change ticket is authority only when every condition holds. Each case here was a hole in the original matching."""

from datetime import datetime, timezone

import pytest
from src.agents.tools.graph_rag_tool import graph_rag_tool

IN_WINDOW = datetime(2026, 9, 14, 11, 0, tzinfo=timezone.utc)
SQL = "SELECT * FROM quarterly_regulatory_staging WHERE report_quarter = '2026-Q3'"


def decide(user="usr_analyst_3030", when=IN_WINDOW, target=SQL, dest="192.0.2.100"):
    return graph_rag_tool.query_context(user, target, dest, event_time=when)


def test_valid_ticket_matches():
    ctx = decide()
    assert ctx["has_approved_change_ticket"] and ctx["approved_tickets"][0]["ticket_id"] == "REG-2026-8910"


@pytest.mark.parametrize("when,label", [
    (datetime(2026, 8, 31, 23, 59, tzinfo=timezone.utc), "before"),
    (datetime(2026, 10, 1, 0, 1, tzinfo=timezone.utc), "after"),
    (datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc), "long after"),
])
def test_ticket_is_only_valid_inside_its_window(when, label):
    ctx = decide(when=when)
    assert ctx["has_approved_change_ticket"] is False, label
    assert "validity window" in ctx["rejected_tickets"][0]["reason"]
    assert any("does not authorize" in c and "REG-2026-8910" in c for c in ctx["citations"])  # the analyst is told why


def test_window_boundaries_are_inclusive():
    assert decide(when=datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc))["has_approved_change_ticket"]
    assert decide(when=datetime(2026, 9, 30, 23, 59, 59, tzinfo=timezone.utc))["has_approved_change_ticket"]


@pytest.mark.parametrize("dest", ["192.0.2.10", "192.0.2.101", "8.8.8.8", "not-an-ip", None])
def test_destination_must_be_inside_an_approved_subnet(dest):
    ctx = decide(dest=dest)
    assert ctx["has_approved_change_ticket"] is False
    assert "destination" in ctx["rejected_tickets"][0]["reason"]  # 192.0.2.10 is not inside 192.0.2.100/32 (it was, as a substring)


@pytest.mark.parametrize("target", ["DROP TABLE x", "SELECT * FROM quarterly_regulatory_staging_backup", "SELECT * FROM old_quarterly_regulatory_staging", None])
def test_data_must_be_an_approved_table_by_whole_name(target):
    ctx = decide(target=target)
    assert ctx["has_approved_change_ticket"] is False
    assert "tables" in ctx["rejected_tickets"][0]["reason"]


def test_ticket_belongs_to_its_requester():
    assert decide(user="usr_dba_1022")["has_approved_change_ticket"] is False
    assert decide(user="usr_unknown")["has_approved_change_ticket"] is False


def test_unscoped_ticket_authorizes_nothing():
    ticket = {"ticket_id": "T-X", "requester_id": "usr_analyst_3030", "status": "APPROVED", "approver": "A. Approver",
              "valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-09-30T00:00:00Z"}
    ok, reason = graph_rag_tool.check_ticket(ticket, "usr_analyst_3030", IN_WINDOW, SQL, "192.0.2.100")
    assert ok is False and "does not limit" in reason


def test_ticket_without_window_or_approver_or_with_self_approval_is_rejected():
    base = {"ticket_id": "T-Y", "requester_id": "usr_analyst_3030", "status": "APPROVED", "approver": "A. Approver",
            "approved_tables": ["quarterly_regulatory_staging"], "valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-09-30T00:00:00Z"}
    assert graph_rag_tool.check_ticket(base, "usr_analyst_3030", IN_WINDOW, SQL, None)[0] is True
    assert "validity window" in graph_rag_tool.check_ticket({**base, "valid_until": None}, "usr_analyst_3030", IN_WINDOW, SQL, None)[1]
    assert "validity window" in graph_rag_tool.check_ticket({**base, "valid_from": "garbage"}, "usr_analyst_3030", IN_WINDOW, SQL, None)[1]
    assert "approved by its own requester" in graph_rag_tool.check_ticket({**base, "approver": ""}, "usr_analyst_3030", IN_WINDOW, SQL, None)[1]
    self_approved = {**base, "approver": "Samantha Liu (Lead Regulatory Reporting Analyst)"}
    assert "approved by its own requester" in graph_rag_tool.check_ticket(self_approved, "usr_analyst_3030", IN_WINDOW, SQL, None)[1]
    assert "not an approved ticket" in graph_rag_tool.check_ticket({**base, "status": "PENDING"}, "usr_analyst_3030", IN_WINDOW, SQL, None)[1]
