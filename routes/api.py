from flask import Blueprint, request, jsonify, session
from db import get_db_connection
from datetime import datetime
import bleach

api_bp = Blueprint('api', __name__)

ALLOWED_TAGS = ['b', 'i', 'u', 'a', 'strong', 'em', 'p', 'br']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}

@api_bp.route('/api/tickets/<int:ticket_id>/comments', methods=['GET'])
def get_ticket_comments(ticket_id):
    """Get all comments for a specific ticket"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT tc.*, u.name as commenter_name, u.role as commenter_role
            FROM ticket_comments tc
            JOIN users u ON tc.agent_id = u.id
            WHERE tc.ticket_id = %s
            ORDER BY tc.created_at ASC
        """, (ticket_id,))
        
        comments = cursor.fetchall()
        
        # Format datetime objects
        for comment in comments:
            comment['created_at'] = comment['created_at'].isoformat() if comment['created_at'] else None
        
        return jsonify({'comments': comments}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@api_bp.route('/api/tickets/<int:ticket_id>/comments', methods=['POST'])
def add_ticket_comment(ticket_id):
    """Add a new comment to a ticket"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    comment_text = data.get('comment', '').strip()
    
    if not comment_text:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    # Clean comment text
    cleaned_comment = bleach.clean(comment_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            INSERT INTO ticket_comments (ticket_id, agent_id, comment, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (ticket_id, session['user_id'], cleaned_comment))
        conn.commit()
        
        return jsonify({'success': True}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@api_bp.route('/api/tickets/<int:ticket_id>/comments/<int:comment_id>', methods=['PUT'])
def update_comment(ticket_id, comment_id):
    """Update an existing comment"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    comment_text = data.get('comment', '').strip()
    
    if not comment_text:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    # Clean comment text
    cleaned_comment = bleach.clean(comment_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE ticket_comments 
            SET comment = %s 
            WHERE id = %s AND ticket_id = %s
        """, (cleaned_comment, comment_id, ticket_id))
        conn.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@api_bp.route('/api/tickets/<int:ticket_id>/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(ticket_id, comment_id):
    """Delete a comment"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            DELETE FROM ticket_comments 
            WHERE id = %s AND ticket_id = %s
        """, (comment_id, ticket_id))
        conn.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@api_bp.route('/api/tickets/<int:ticket_id>/sla-status', methods=['GET'])
def get_sla_status(ticket_id):
    """Get SLA status for a ticket"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT 
                id, title, status, urgency, created_at,
                sla_response_due, sla_resolution_due,
                assigned_agent_id
            FROM tickets 
            WHERE id = %s
        """, (ticket_id,))
        
        ticket = cursor.fetchone()
        
        if not ticket:
            return jsonify({'error': 'Ticket not found'}), 404
        
        now = datetime.utcnow()
        
        # Calculate SLA breach status
        response_breach = False
        resolution_breach = False
        
        if ticket['sla_response_due']:
            response_breach = now > ticket['sla_response_due']
        
        if ticket['sla_resolution_due']:
            resolution_breach = now > ticket['sla_resolution_due']
        
        return jsonify({
            'ticket_id': ticket['id'],
            'title': ticket['title'],
            'status': ticket['status'],
            'urgency': ticket['urgency'],
            'response_breach': response_breach,
            'resolution_breach': resolution_breach,
            'sla_response_due': ticket['sla_response_due'].isoformat() if ticket['sla_response_due'] else None,
            'sla_resolution_due': ticket['sla_resolution_due'].isoformat() if ticket['sla_resolution_due'] else None
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()
