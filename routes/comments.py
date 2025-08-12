from flask import Blueprint, request, jsonify, session
from db import get_db_connection
from datetime import datetime
import bleach

comments_bp = Blueprint('comments', __name__)

ALLOWED_TAGS = ['b', 'i', 'u', 'a', 'strong', 'em', 'p', 'br']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}

@comments_bp.route('/api/tickets/<int:ticket_id>/comments', methods=['GET'])
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

@comments_bp.route('/api/tickets/<int:ticket_id>/comments', methods=['POST'])
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
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO ticket_comments (ticket_id, agent_id, comment, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (ticket_id, session['user_id'], cleaned_comment))
        
        conn.commit()
        
        # Get the newly created comment
        comment_id = cursor.lastrowid
        cursor.execute("""
            SELECT tc.*, u.name as commenter_name, u.role as commenter_role
            FROM ticket_comments tc
            JOIN users u ON tc.agent_id = u.id
            WHERE tc.id = %s
        """, (comment_id,))
        
        new_comment = cursor.fetchone()
        
        # Optional: trigger notification
        # from notifications import notify_new_comment
        # notify_new_comment(ticket_id, session['user_id'], cleaned_comment)
        
        return jsonify({
            'success': True,
            'comment': {
                'id': new_comment['id'],
                'comment': new_comment['comment'],
                'commenter_name': new_comment['commenter_name'],
                'commenter_role': new_comment['commenter_role'],
                'created_at': new_comment['created_at'].isoformat()
            }
        }), 201
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@comments_bp.route('/api/tickets/<int:ticket_id>/comments/<int:comment_id>', methods=['PUT'])
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
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if user owns the comment or is admin
        cursor.execute("""
            SELECT agent_id FROM ticket_comments 
            WHERE id = %s AND ticket_id = %s
        """, (comment_id, ticket_id))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Comment not found'}), 404
        
        if result['agent_id'] != session['user_id'] and not session.get('is_admin'):
            return jsonify({'error': 'Permission denied'}), 403
        
        cursor.execute("""
            UPDATE ticket_comments 
            SET comment = %s 
            WHERE id = %s AND ticket_id = %s
        """, (cleaned_comment, comment_id, ticket_id))
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'comment': cleaned_comment
        }), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@comments_bp.route('/api/tickets/<int:ticket_id>/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(ticket_id, comment_id):
    """Delete a comment"""
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if user owns the comment or is admin
        cursor.execute("""
            SELECT agent_id FROM ticket_comments 
            WHERE id = %s AND ticket_id = %s
        """, (comment_id, ticket_id))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'error': 'Comment not found'}), 404
        
        if result['agent_id'] != session['user_id'] and not session.get('is_admin'):
            return jsonify({'error': 'Permission denied'}), 403
        
        cursor.execute("""
            DELETE FROM ticket_comments 
            WHERE id = %s AND ticket_id = %s
        """, (comment_id, ticket_id))
        
        conn.commit()
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()
