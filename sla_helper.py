# sla_helper.py

from datetime import UTC, datetime


def get_sla_summary(tickets):
    """
    Returns SLA compliance summary for a list of tickets.
    Example output:
    {
        "total": 10,
        "within_sla": 7,
        "breached": 3
    }
    """
    total = len(tickets)
    breached = 0

    for ticket in tickets:
        if ticket.get("due_date"):
            due_date = datetime.fromisoformat(ticket["due_date"]).replace(tzinfo=UTC)
            if datetime.now(UTC) > due_date and ticket.get("status") != "Resolved":
                breached += 1

    return {"total": total, "within_sla": total - breached, "breached": breached}


def get_breached_tickets(tickets):
    """
    Returns a list of tickets that have breached their SLA.
    """
    breached_list = []
    for ticket in tickets:
        if ticket.get("due_date"):
            due_date = datetime.fromisoformat(ticket["due_date"]).replace(tzinfo=UTC)
            if datetime.now(UTC) > due_date and ticket.get("status") != "Resolved":
                breached_list.append(ticket)
    return breached_list


def get_on_time_tickets(tickets):
    """
    Returns a list of tickets still within SLA (not breached).
    """
    on_time_list = []
    for ticket in tickets:
        if ticket.get("due_date"):
            due_date = datetime.fromisoformat(ticket["due_date"]).replace(tzinfo=UTC)
            if datetime.now(UTC) <= due_date or ticket.get("status") == "Resolved":
                on_time_list.append(ticket)
    return on_time_list
