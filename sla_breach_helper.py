from datetime import datetime, timedelta
import mysql.connector

def get_sla_breach_status(ticket_id, db_connection):
    """
    Get comprehensive SLA breach status for a single ticket.
    
    Args:
        ticket_id (int): The ticket ID
        db_connection: Database connection object
    
    Returns:
        dict: Complete SLA breach information
    """
    cursor = db_connection.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT 
            id, title, status, urgency, created_at,
            sla_response_due, sla_resolution_due,
            assigned_agent_id
        FROM tickets 
        WHERE id = %s
    """, (ticket_id,))
    
    ticket = cursor.fetchone()
    cursor.close()
    
    if not ticket:
        return None
    
    now = datetime.utcnow()
    
    # Calculate breach status
    response_breach = False
    resolution_breach = False
    response_breach_time = None
    resolution_breach_time = None
    
    if ticket['sla_response_due']:
        response_breach = now > ticket['sla_response_due']
        if response_breach:
            response_breach_time = now - ticket['sla_response_due']
    
    if ticket['sla_resolution_due']:
        resolution_breach = now > ticket['sla_resolution_due']
        if resolution_breach:
            resolution_breach_time = now - ticket['sla_resolution_due']
    
    # Determine severity
    severity = 'normal'
    if resolution_breach:
        severity = 'critical' if resolution_breach_time and resolution_breach_time > timedelta(hours=24) else 'high'
    elif response_breach:
        severity = 'high' if response_breach_time and response_breach_time > timedelta(hours=4) else 'medium'
    
    return {
        'ticket_id': ticket['id'],
        'title': ticket['title'],
        'status': ticket['status'],
        'urgency': ticket['urgency'],
        'response_breach': response_breach,
        'resolution_breach': resolution_breach,
        'response_breach_time': response_breach_time,
        'resolution_breach_time': resolution_breach_time,
        'sla_response_due': ticket['sla_response_due'],
        'sla_resolution_due': ticket['sla_resolution_due'],
        'severity': severity,
        'time_remaining_response': ticket['sla_response_due'] - now if ticket['sla_response_due'] and not response_breach else None,
        'time_remaining_resolution': ticket['sla_resolution_due'] - now if ticket['sla_resolution_due'] and not resolution_breach else None
    }

def get_tickets_with_sla_breach(db_connection, user_id=None, agent_id=None, include_resolved=False):
    """
    Get all tickets with SLA breach information.
    
    Args:
        db_connection: Database connection object
        user_id (int, optional): Filter by user ID
        agent_id (int, optional): Filter by agent ID
        include_resolved (bool): Include resolved/closed tickets
    
    Returns:
        list: List of tickets with SLA breach information
    """
    cursor = db_connection.cursor(dictionary=True)
    
    query = """
        SELECT 
            t.id, t.title, t.description, t.status, t.urgency, 
            t.created_at, t.sla_response_due, t.sla_resolution_due,
            t.assigned_agent_id, u.name as user_name,
            a.name as assigned_agent_name,
            c.name as category_name, c.color as category_color
        FROM tickets t
        JOIN users u ON t.user_id = u.id
        LEFT JOIN users a ON t.assigned_agent_id = a.id
        LEFT JOIN categories c ON t.category_id = c.id
        WHERE t.is_deleted = FALSE
    """
    
    params = []
    
    if not include_resolved:
        query += " AND t.status NOT IN ('Resolved', 'Closed')"
    
    if user_id:
        query += " AND t.user_id = %s"
        params.append(user_id)
    
    if agent_id:
        query += " AND t.assigned_agent_id = %s"
        params.append(agent_id)
    
    query += " ORDER BY t.created_at DESC"
    
    cursor.execute(query, params)
    tickets = cursor.fetchall()
    cursor.close()
    
    # Add SLA breach information
    enhanced_tickets = []
    for ticket in tickets:
        now = datetime.utcnow()
        
        response_breach = False
        resolution_breach = False
        
        if ticket['sla_response_due']:
            response_breach = now > ticket['sla_response_due']
        
        if ticket['sla_resolution_due']:
            resolution_breach = now > ticket['sla_resolution_due']
        
        # Determine severity
        severity = 'normal'
        if resolution_breach:
            severity = 'critical'
        elif response_breach:
            severity = 'high'
        
        ticket.update({
            'response_breach': response_breach,
            'resolution_breach': resolution_breach,
            'severity': severity
        })
        
        enhanced_tickets.append(ticket)
    
    return enhanced_tickets

def get_sla_summary(db_connection):
    """
    Get SLA breach summary statistics.
    
    Args:
        db_connection: Database connection object
    
    Returns:
        dict: SLA breach summary
    """
    cursor = db_connection.cursor(dictionary=True)
    
    now = datetime.utcnow()
    
    # Get active tickets
    cursor.execute("""
        SELECT 
            COUNT(*) as total_active,
            SUM(CASE WHEN sla_response_due IS NOT NULL AND sla_response_due < %s THEN 1 ELSE 0 END) as response_breach,
            SUM(CASE WHEN sla_resolution_due IS NOT NULL AND sla_resolution_due < %s THEN 1 ELSE 0 END) as resolution_breach,
            SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) as open_tickets,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress
        FROM tickets 
        WHERE is_deleted = FALSE AND status NOT IN ('Resolved', 'Closed')
    """, (now, now))
    
    summary = cursor.fetchone()
    cursor.close()
    
    return summary

def format_time_remaining(time_delta):
    """
    Format time remaining for display.
    
    Args:
        time_delta (timedelta): Time remaining
    
    Returns:
        str: Formatted time remaining
    """
    if not time_delta:
        return "N/A"
    
    total_seconds = int(time_delta.total_seconds())
    
    if total_seconds < 0:
        return "Overdue"
    
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

def get_breach_color(severity):
    """
    Get color based on breach severity.
    
    Args:
        severity (str): Severity level
    
    Returns:
        str: CSS color class
    """
    color_map = {
        'normal': 'badge-status',
        'medium': 'badge-urgency-medium',
        'high': 'badge-urgency-high',
        'critical': 'badge-urgency-critical'
    }
    return color_map.get(severity, 'badge-status')
