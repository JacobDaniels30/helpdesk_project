from datetime import datetime, timedelta
import mysql.connector

def calculate_sla_times(urgency, db_connection):
    """
    Calculate SLA response and resolution due times based on urgency.
    
    Args:
        urgency (str): The urgency level of the ticket
        db_connection: Database connection object
    
    Returns:
        tuple: (sla_response_due, sla_resolution_due)
    """
    cursor = db_connection.cursor(dictionary=True)
    
    # Get SLA policy for the given urgency
    cursor.execute(
        "SELECT response_hours, resolution_hours FROM sla_policies WHERE urgency = %s",
        (urgency,)
    )
    
    sla_policy = cursor.fetchone()
    cursor.close()
    
    if not sla_policy:
        # Default SLA if no policy found
        sla_policy = {'response_hours': 24, 'resolution_hours': 72}
    
    now = datetime.utcnow()
    sla_response_due = now + timedelta(hours=sla_policy['response_hours'])
    sla_resolution_due = now + timedelta(hours=sla_policy['resolution_hours'])
    
    return sla_response_due, sla_resolution_due

def check_sla_breach(ticket_id, db_connection):
    """
    Check if a ticket has breached its SLA times.
    
    Args:
        ticket_id (int): The ticket ID
        db_connection: Database connection object
    
    Returns:
        dict: SLA breach status
    """
    cursor = db_connection.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT sla_response_due, sla_resolution_due, status 
        FROM tickets WHERE id = %s
    """, (ticket_id,))
    
    ticket = cursor.fetchone()
    cursor.close()
    
    if not ticket:
        return None
    
    now = datetime.utcnow()
    response_breach = now > ticket['sla_response_due'] if ticket['sla_response_due'] else False
    resolution_breach = now > ticket['sla_resolution_due'] if ticket['sla_resolution_due'] else False
    
    return {
        'response_breach': response_breach,
        'resolution_breach': resolution_breach,
        'status': ticket['status']
    }
