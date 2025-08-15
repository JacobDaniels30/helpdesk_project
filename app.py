import os
from dotenv import load_dotenv
import uuid
import logging
import re
import bleach
from datetime import datetime, timedelta

# Load environment variables from .env
load_dotenv()

# Debug prints to confirm they loaded
print("DB_HOST:", os.getenv("DB_HOST"))
print("DB_NAME:", os.getenv("DB_NAME"))

# Flask and related imports
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_mail import Mail, Message

# Database functions (import after load_dotenv)
from db import get_db_connection, get_user_by_email

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask app
app = Flask(__name__)

# Set SECRET_KEY at the top using os.getenv() with dev fallback
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configure logging
logging.basicConfig(
    filename='helpdesk.log',
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Production-ready session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Disabled for local development
    SESSION_COOKIE_NAME='helpdesk_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_COOKIE_DOMAIN=None,
    SESSION_COOKIE_PATH='/',
    SESSION_PERMANENT=True,
)

# Explicitly assign app.secret_key
app.secret_key = app.config['SECRET_KEY']

# ALLOWED_TAGS for sanitization
ALLOWED_TAGS = ['b', 'i', 'u', 'a']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title']}

# Configure Flask-Limiter with in-memory storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# =======================
# Flask-Mail Configuration
# =======================
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'exampletest739@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'gokk duhw qjis layb')
app.config['MAIL_DEFAULT_SENDER'] = (
    os.environ.get('MAIL_DEFAULT_SENDER_NAME', 'Helpdesk Support'),
    os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', 'your_test_email@gmail.com')
)

mail = Mail(app)

# =======================
# CSRF and Bcrypt
# =======================
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)


# =============================
# REGISTER ROUTE
# =============================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        # Basic Validation
        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        import re
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('register'))

        import re
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(password_pattern, password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "danger")
            return redirect(url_for('register'))

        # Check if email exists
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered. Please login.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('login'))

        # Save to DB with verification token
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_token = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO users (name, email, password_hash, is_verified, verification_token, created_at) VALUES (%s, %s, %s, %s, %s, NOW())",
            (name, email, hashed_password, False, verification_token)
        )
        conn.commit()

        # Send verification email
        verification_link = url_for('verify_email', token=verification_token, _external=True)
        msg = Message(
            subject="Verify your Helpdesk Account",
            recipients=[email],
            body=f"Hi {name},\n\nPlease verify your account by clicking this link:\n{verification_link}\n\nThank you!"
        )
        mail.send(msg)

        cursor.close()
        conn.close()

        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# =============================
# VERIFY EMAIL ROUTE
# =============================
@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE verification_token = %s", (token,))
    user = cursor.fetchone()

    if user:
        cursor.execute("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE id = %s", (user['id'],))
        conn.commit()
        flash('Email verified successfully! You can now log in.', 'success')
    else:
        flash('Invalid or expired verification link.', 'danger')

    cursor.close()
    conn.close()
    return redirect(url_for('login'))


# =============================
# ENHANCED LOGIN ROUTE
# =============================
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 5 minutes")  # Stricter rate limiting
def login():
    if request.method == 'POST':
        try:
            email = request.form['email'].strip()
            password = request.form['password']
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            user_agent = request.headers.get('User-Agent', '')

            # Enhanced debugging
            print(f"DEBUG: Login attempt for email: {email}")
            print(f"DEBUG: Form data received: {request.form}")
            print(f"DEBUG: Session before login: {dict(session)}")

            # Check if account is locked
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Check for recent failed attempts
            cursor.execute("""
                SELECT COUNT(*) as failed_attempts 
                FROM login_attempts 
                WHERE email = %s AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE) 
                AND success = FALSE
            """, (email,))
            failed_count = cursor.fetchone()['failed_attempts']
            
            # Check if account is locked
            cursor.execute("""
                SELECT account_locked_until 
                FROM users 
                WHERE email = %s AND account_locked_until > NOW()
            """, (email,))
            locked = cursor.fetchone()
            
            if locked:
                flash('Account temporarily locked due to multiple failed login attempts. Please try again later.', 'danger')
                cursor.close()
                conn.close()
                return render_template('login.html')

            # Get user details
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user and bcrypt.check_password_hash(user['password_hash'], password):
                # Check if account is verified (only in production)
                if os.environ.get('FLASK_ENV') == 'production':
                    if not (user['is_verified'] or user['is_admin']):
                        # Log failed attempt
                        cursor.execute("""
                            INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason)
                            VALUES (%s, %s, %s, FALSE, 'email_not_verified')
                        """, (email, ip_address, user_agent))
                        conn.commit()
                        
                        flash('Please verify your email before logging in.', 'warning')
                        cursor.close()
                        conn.close()
                        return render_template('login.html')

                # Reset failed attempts and lockout
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = 0, account_locked_until = NULL, last_login_at = NOW(), last_login_ip = %s
                    WHERE id = %s
                """, (ip_address, user['id']))
                
                # Log successful login
                cursor.execute("""
                    INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason)
                    VALUES (%s, %s, %s, TRUE, NULL)
                """, (email, ip_address, user_agent))
                
                # Create session
                session_token = str(uuid.uuid4())
                cursor.execute("""
                    INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
                    VALUES (%s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 24 HOUR))
                """, (user['id'], session_token, ip_address, user_agent))
                
                conn.commit()
                
                # Set session variables
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                session['name'] = user['name']
                session['is_admin'] = user['is_admin']
                session['session_token'] = session_token
                
                # Debug logging for session
                logging.info(f"Login successful for user: {email}, user_id: {user['id']}, is_admin: {user['is_admin']}")
                
                cursor.close()
                conn.close()
                
                return redirect(url_for('dashboard'))
            else:
                # Log failed attempt
                failure_reason = 'invalid_credentials' if user else 'user_not_found'
                cursor.execute("""
                    INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason)
                    VALUES (%s, %s, %s, FALSE, %s)
                """, (email, ip_address, user_agent, failure_reason))
                
                # Update failed attempts count
                if user:
                    cursor.execute("""
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1,
                        account_locked_until = CASE 
                            WHEN failed_login_attempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                            ELSE account_locked_until
                        END
                        WHERE email = %s
                    """, (email,))
                
                conn.commit()
                
                # Check if account should be locked
                if user and user['failed_login_attempts'] >= 4:
                    flash('Account temporarily locked due to multiple failed login attempts. Please try again in 30 minutes.', 'danger')
                else:
                    flash('Invalid email or password', 'danger')
                
                cursor.close()
                conn.close()
                return render_template('login.html')
                
        except Exception as e:
            import traceback
            logging.error(f"Exception during login for email {request.form.get('email')}: {str(e)}")
            logging.error(traceback.format_exc())
            flash('An internal error occurred. Please try again later.', 'danger')
            return render_template('login.html')

    return render_template('login.html')


# =============================
# DASHBOARD ROUTES
# =============================
@app.route('/dashboard')
def dashboard():
    user_email = session.get('user_email')
    if not user_email:
        return redirect(url_for('login'))

    user = get_user_by_email(user_email)
    
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if user.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    elif user.get('role') == 'agent':
        return redirect(url_for('agent_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    if not user or not user.get('is_admin'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Import SLA helper
    from sla_breach_helper import get_tickets_with_sla_breach, get_sla_summary
    
    # Get all tickets with SLA breach information
    tickets = get_tickets_with_sla_breach(conn, include_resolved=False)
    
    # Get all agents
    cursor.execute("SELECT id, name FROM users WHERE role = 'agent'")
    agents = cursor.fetchall()
    
    # Get SLA summary
    sla_summary = get_sla_summary(conn)
    
    cursor.close()
    conn.close()
    
    return render_template('admin_dashboard_modern.html', 
                         tickets=tickets, 
                         agents=agents,
                         sla_summary=sla_summary)

@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
def delete_ticket(ticket_id):
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE tickets SET is_deleted = TRUE WHERE id = %s", (ticket_id,))
        conn.commit()
        flash('Ticket deleted successfully (soft delete).', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error deleting ticket.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))


@app.route('/user_dashboard')
def user_dashboard():
    user = get_user_by_email(session['user_email'])
    category_id = request.args.get('category_id', type=int)
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Import SLA helper
    from sla_breach_helper import get_tickets_with_sla_breach
    
    # Get all categories for filter dropdown
    cursor.execute("SELECT id, name, color FROM categories ORDER BY name")
    categories = cursor.fetchall()
    
    # Get tickets with SLA breach information
    tickets = get_tickets_with_sla_breach(conn, user_id=user['id'])
    
    # Filter by category if specified
    if category_id:
        tickets = [t for t in tickets if t.get('category_id') == category_id]
    
    cursor.close()
    conn.close()
    
    return render_template('user_dashboard_modern.html', 
                         user=user, 
                         tickets=tickets, 
                         categories=categories, 
                         selected_category=category_id)


# =============================
# AGENT DASHBOARD ROUTES
# =============================
@app.route('/agent_dashboard')
def agent_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    
    # Check if user is an agent (has role 'agent' or is_admin)
    if not (user.get('role') == 'agent' or user.get('is_admin')):
        flash('Access denied. Agent privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get tickets assigned to this agent
    cursor.execute("""
        SELECT tickets.*, users.name AS user_name
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        WHERE tickets.assigned_agent_id = %s AND tickets.archived = FALSE
        ORDER BY tickets.created_at DESC
    """, (user['id'],))
    
    tickets = cursor.fetchall()
    
    # Get stats for the agent
    cursor.execute("""
        SELECT 
            COUNT(*) as total_assigned,
            SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) as open_tickets,
            SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'Resolved' AND DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as resolved_today
        FROM tickets 
        WHERE assigned_agent_id = %s AND archived = FALSE
    """, (user['id'],))
    
    stats = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    return render_template('agent_dashboard_modern.html', user=user, tickets=tickets, stats=stats)


@app.route('/ticket/<int:ticket_id>')
def ticket_detail(ticket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get ticket details with user info
    cursor.execute("""
        SELECT tickets.*, users.name AS user_name, users.email AS user_email,
               a.name AS assigned_agent_name
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        LEFT JOIN users a ON tickets.assigned_agent_id = a.id
        WHERE tickets.id = %s
    """, (ticket_id,))
    
    ticket = cursor.fetchone()
    
    if not ticket:
        cursor.close()
        conn.close()
        flash('Ticket not found.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Check if user owns the ticket or is admin/agent
    if not (user['is_admin'] or user.get('role') == 'agent' or ticket['user_id'] == user['id']):
        cursor.close()
        conn.close()
        flash('Access denied. You can only view your own tickets.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    # Get comments for this ticket
    cursor.execute("""
        SELECT tc.*, u.name AS commenter_name, u.role AS commenter_role
        FROM ticket_comments tc
        JOIN users u ON tc.agent_id = u.id
        WHERE tc.ticket_id = %s
        ORDER BY tc.created_at ASC
    """, (ticket_id,))
    
    comments = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('ticket_detail.html', ticket=ticket, comments=comments, user=user)

@app.route('/agent/ticket/<int:ticket_id>')
def agent_ticket_detail(ticket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    
    # Check if user is an agent
    if not (user.get('role') == 'agent' or user.get('is_admin')):
        flash('Access denied. Agent privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get ticket details with user info
    cursor.execute("""
        SELECT tickets.*, users.name AS user_name, users.email AS user_email
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        WHERE tickets.id = %s AND tickets.assigned_agent_id = %s
    """, (ticket_id, user['id']))
    
    ticket = cursor.fetchone()
    
    if not ticket:
        cursor.close()
        conn.close()
        flash('Ticket not found or not assigned to you.', 'danger')
        return redirect(url_for('agent_dashboard'))
    
    cursor.close()
    conn.close()
    
    return render_template('agent_ticket_detail.html', ticket=ticket, user=user)
                              
@app.route('/agent/update_status/<int:ticket_id>', methods=['POST'])
def agent_update_status(ticket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    
    # Check if user is an agent
    if not (user.get('role') == 'agent' or user.get('is_admin')):
        return "Unauthorized", 403

    new_status = request.form.get('status', '').strip()
    internal_notes = request.form.get('internal_notes', '').strip()
    
    allowed_statuses = ['Open', 'In Progress', 'Resolved', 'Closed']
    if new_status not in allowed_statuses:
        return "Invalid status", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "UPDATE tickets SET status = %s, internal_notes = %s, updated_at = NOW() WHERE id = %s AND assigned_agent_id = %s",
            (new_status, internal_notes, ticket_id, user['id'])
        )
        conn.commit()
        flash('Ticket updated successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error updating ticket.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('agent_ticket_detail', ticket_id=ticket_id))


@app.route('/agent/add_comment/<int:ticket_id>', methods=['POST'])
def agent_add_comment(ticket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    user = get_user_by_email(session['user_email'])
    
    # Check if user is an agent
    if not (user.get('role') == 'agent' or user.get('is_admin')):
        return "Unauthorized", 403

    comment = request.form.get('comment', '').strip()
    if not comment:
        flash('Comment cannot be empty.', 'warning')
        return redirect(url_for('agent_ticket_detail', ticket_id=ticket_id))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO ticket_comments (ticket_id, agent_id, comment, created_at) VALUES (%s, %s, %s, NOW())",
            (ticket_id, session['user_id'], comment)
        )
        conn.commit()
        flash('Comment added successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error adding comment.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('agent_ticket_detail', ticket_id=ticket_id))


# =============================
# SUBMIT TICKET ROUTE
# =============================
@app.route('/submit', methods=['GET', 'POST'])
def submit_ticket():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        title = bleach.clean(request.form['title'], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
        description = bleach.clean(request.form['description'], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
        urgency = request.form['urgency']
        category_id = request.form.get('category_id')
        user_id = session['user_id']

        # Import SLA helper function
        from sla_helper import calculate_sla_times
        
        # Calculate SLA response and resolution due times
        sla_response_due, sla_resolution_due = calculate_sla_times(urgency, conn)

        cursor.execute(
            "INSERT INTO tickets (user_id, title, description, urgency, category_id, sla_response_due, sla_resolution_due, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())",
            (user_id, title, description, urgency, category_id, sla_response_due, sla_resolution_due)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash('Ticket submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Get categories for the form
    cursor.execute("SELECT id, name, color FROM categories ORDER BY name")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('submit_ticket.html', categories=categories)


# =============================
# UPDATE TICKET STATUS (ADMIN ONLY)
# =============================
@app.route('/update_status/<int:ticket_id>', methods=['POST'])
def update_status(ticket_id):
    if 'user_email' not in session:
        return redirect(url_for('login'))

    if not session.get('is_admin'):
        logging.warning(f"Unauthorized admin action attempt by user: {session.get('user_email')}")
        return "Unauthorized", 403

    new_status = request.form.get('status', '').strip()

    allowed_statuses = ['Open', 'In Progress', 'Resolved']
    if new_status not in allowed_statuses:
        return "Invalid status value", 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE tickets SET status = %s WHERE id = %s", (new_status, ticket_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash('Ticket status updated.', 'success')
    return redirect(url_for('admin_dashboard'))


# =============================
# EDIT TICKET ROUTE
# =============================
# This duplicate route has been removed - use /ticket/<int:ticket_id> instead


@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
    ticket = cursor.fetchone()

    if not ticket:
        cursor.close()
        conn.close()
        flash('Ticket not found.', 'danger')
        return redirect(url_for('dashboard'))

    user = get_user_by_email(session['user_email'])
    if not user['is_admin'] and ticket['user_id'] != user_id:
        logging.warning(f"Unauthorized ticket edit attempt by user: {session.get('user_email')}")
        cursor.close()
        conn.close()
        return "Unauthorized", 403

    if request.method == 'POST':
        title = bleach.clean(request.form['title'], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
        description = bleach.clean(request.form['description'], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
        urgency = request.form['urgency']

        cursor.execute(
            "UPDATE tickets SET title = %s, description = %s, urgency = %s WHERE id = %s",
            (title, description, urgency, ticket_id)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash('Ticket updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    cursor.close()
    conn.close()

    return render_template('edit_ticket.html', ticket=ticket)


# =============================
# LOGOUT ROUTE
# =============================
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/assign_agent/<int:ticket_id>', methods=['POST'])
def assign_agent(ticket_id):
    if 'user_email' not in session:
        flash('Please login to continue.', 'warning')
        return redirect(url_for('login'))

    # Get current user
    user = get_user_by_email(session['user_email'])
    if not user:
        session.clear()
        flash('Session expired. Please login again.', 'warning')
        return redirect(url_for('login'))

    # Check authorization - allow admins and users with appropriate roles
    if not (user.get('is_admin') or user.get('role') in ['admin', 'agent']):
        logging.warning(f"Unauthorized agent assignment attempt by user: {session.get('user_email')} (ID: {user.get('id')})")
        flash('You do not have permission to assign agents.', 'error')
        return redirect(url_for('dashboard'))

    agent_id = request.form.get('assigned_agent_id')
    
    # Validate agent_id
    if agent_id and not agent_id.isdigit():
        flash('Invalid agent selection.', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify the agent exists if agent_id is provided
        if agent_id:
            cursor.execute("SELECT id FROM users WHERE id = %s AND role = 'agent'", (int(agent_id),))
            if not cursor.fetchone():
                flash('Selected agent not found or invalid.', 'error')
                return redirect(url_for('admin_dashboard'))
        
        # Update ticket assignment
        if agent_id:
            cursor.execute("UPDATE tickets SET assigned_agent_id = %s, updated_at = NOW() WHERE id = %s", (int(agent_id), ticket_id))
        else:
            cursor.execute("UPDATE tickets SET assigned_agent_id = NULL, updated_at = NOW() WHERE id = %s", (ticket_id,))
        
        conn.commit()
        flash('Agent assigned successfully!', 'success')
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error assigning agent to ticket {ticket_id}: {str(e)}")
        flash('Error assigning agent. Please try again.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/archive_ticket/<int:ticket_id>', methods=['POST'])
def archive_ticket(ticket_id):
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE tickets SET archived = TRUE WHERE id = %s", (ticket_id,))
        conn.commit()
        flash('Ticket archived successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error archiving ticket: ' + str(e), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/archived_tickets')
def archived_tickets():
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT tickets.*, users.name AS user_name, 
               a.name AS assigned_agent_name
        FROM tickets
        JOIN users ON tickets.user_id = users.id
        LEFT JOIN users a ON tickets.assigned_agent_id = a.id
        WHERE tickets.archived = TRUE
    """)
    tickets = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('archived_tickets.html', tickets=tickets)

@app.route('/restore_ticket/<int:ticket_id>', methods=['POST'])
def restore_ticket(ticket_id):
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE tickets SET archived = FALSE WHERE id = %s", (ticket_id,))
        conn.commit()
        flash('Ticket restored successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error restoring ticket: ' + str(e), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('archived_tickets'))

@app.route('/delete_permanently/<int:ticket_id>', methods=['POST'])
def delete_permanently(ticket_id):
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM tickets WHERE id = %s", (ticket_id,))
        conn.commit()
        flash('Ticket permanently deleted.', 'success')
    except Exception as e:
        conn.rollback()
        flash('Error deleting ticket: ' + str(e), 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('archived_tickets'))


# =============================
# REGISTER AGENT ROUTE
# =============================
@app.route('/register_agent', methods=['GET', 'POST'])
def register_agent():
    if 'user_email' not in session or not session.get('is_admin'):
        flash('Unauthorized access. Admin privileges required.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        
        # Basic validation
        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register_agent'))
        
        import re
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('register_agent'))
        
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(password_pattern, password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "danger")
            return redirect(url_for('register_agent'))
        
        # Check if email already exists
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already exists. Please choose another.', 'danger')
            cursor.close()
            conn.close()
            return render_template('register_agent.html')
        
        # Insert agent
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_token = str(uuid.uuid4())
        
        cursor.execute(
            "INSERT INTO users (name, email, password_hash, role, is_verified, verification_token, created_at) VALUES (%s, %s, %s, %s, %s, %s, NOW())",
            (name, email, hashed_password, 'agent', True, verification_token)
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('Agent registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('register_agent.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Too many login attempts. Please try again later.", 429

from datetime import datetime, timedelta

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email'].strip()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            token = str(uuid.uuid4())
            expiry = datetime.utcnow() + timedelta(hours=1)  # token valid 1 hour
            cursor.execute(
                "UPDATE users SET password_reset_token=%s, token_expiry=%s WHERE email=%s",
                (token, expiry, email)
            )
            conn.commit()

            # Send reset email
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          recipients=[email])
            msg.body = f"To reset your password, click the following link:\n{reset_link}\nThis link expires in 1 hour."
            mail.send(msg)

            flash('Password reset email sent. Check your inbox.', 'info')
        else:
            flash('Email not found.', 'warning')

        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    return render_template('reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE password_reset_token = %s", (token,))
    user = cursor.fetchone()

    if not user or user['token_expiry'] < datetime.utcnow():
        logging.warning(f"Suspicious password reset attempt with invalid or expired token: {token}")
        flash('Invalid or expired token.', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        new_password = request.form['password'].strip()

        import re
        password_pattern = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(password_pattern, new_password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.", "danger")
            cursor.close()
            conn.close()
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        cursor.execute(
            "UPDATE users SET password_hash=%s, password_reset_token=NULL, token_expiry=NULL WHERE id=%s",
            (hashed_password, user['id'])
        )
        conn.commit()
        flash('Password reset successful! Please login.', 'success')
        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    cursor.close()
    conn.close()
    return render_template('reset_password.html', token=token)

@app.context_processor
def inject_user():
    """Inject user object into all templates globally."""
    if 'user_email' in session:
        user = get_user_by_email(session['user_email'])
        return dict(user=user)
    return dict(user=None)

@app.route('/')
def index():
    """Root route that redirects based on authentication status."""
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
