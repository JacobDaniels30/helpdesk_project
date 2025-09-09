import logging
import os
import re
import uuid
from datetime import UTC, datetime, timedelta

import bleach
from dotenv import load_dotenv
from flask import (Flask, flash, jsonify, redirect, render_template, request, session,
                   url_for)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect

# Load environment variables
load_dotenv()

# Supabase import
from db import get_user_by_email, insert_user, supabase
# Blueprint imports (must be before registering them)
from routes.api import api_bp
from routes.comments import comments_bp


# ================================
# SLA calculation helper
# ================================
def calculate_sla_times(urgency, created_at=None):
    """
    Returns a tuple (response_due, resolution_due) based on urgency.
    """
    if created_at is None:
        created_at = datetime.now(UTC)

    # Standardize urgency values to match SLA policies
    urgency = urgency.title()  # Convert to title case

    if urgency == "Critical":
        sla_response_due = created_at + timedelta(hours=1)
        sla_resolution_due = created_at + timedelta(hours=4)
    elif urgency == "High":
        sla_response_due = created_at + timedelta(hours=4)
        sla_resolution_due = created_at + timedelta(hours=12)
    elif urgency == "Normal":
        sla_response_due = created_at + timedelta(hours=8)
        sla_resolution_due = created_at + timedelta(hours=24)
    elif urgency == "Low":
        sla_response_due = created_at + timedelta(hours=24)
        sla_resolution_due = created_at + timedelta(hours=72)
    else:
        # Default to Normal if unknown urgency
        sla_response_due = created_at + timedelta(hours=8)
        sla_resolution_due = created_at + timedelta(hours=24)

    return sla_response_due, sla_resolution_due


# ================================
# Flask app & config
# ================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# Session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # False for local dev, True in production
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_PERMANENT=True,
    SESSION_COOKIE_NAME="helpdesk_session",
    SESSION_REFRESH_EACH_REQUEST=True,
)

# Logging
logging.basicConfig(
    filename="helpdesk.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Initialize Flask extensions
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"]
)

# Register API blueprints
app.register_blueprint(api_bp)
app.register_blueprint(comments_bp)

# Mail configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = (
    os.getenv("MAIL_DEFAULT_SENDER_NAME", "Helpdesk Support"),
    os.getenv("MAIL_DEFAULT_SENDER_EMAIL"),
)
mail = Mail(app)

# Allowed tags for sanitization
ALLOWED_TAGS = ["b", "i", "u", "a"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}


# ================================
# Date Formatting Utilities
# ================================
def format_ticket_dates(tickets):
    """Convert ticket date strings to datetime objects for template rendering"""
    for ticket in tickets:
        if "created_at" in ticket and ticket["created_at"]:
            # Convert string to datetime if needed
            if isinstance(ticket["created_at"], str):
                ticket["created_at_dt"] = datetime.fromisoformat(
                    ticket["created_at"]
                ).replace(tzinfo=UTC)
            else:
                ticket["created_at_dt"] = ticket["created_at"]
        else:
            ticket["created_at_dt"] = None

        if "updated_at" in ticket and ticket["updated_at"]:
            if isinstance(ticket["updated_at"], str):
                ticket["updated_at_dt"] = datetime.fromisoformat(
                    ticket["updated_at"]
                ).replace(tzinfo=UTC)
            else:
                ticket["updated_at_dt"] = ticket["updated_at"]
        else:
            ticket["updated_at_dt"] = None

        if "sla_response_due" in ticket and ticket["sla_response_due"]:
            if isinstance(ticket["sla_response_due"], str):
                ticket["sla_response_due_dt"] = datetime.fromisoformat(
                    ticket["sla_response_due"]
                ).replace(tzinfo=UTC)
            else:
                ticket["sla_response_due_dt"] = ticket["sla_response_due"]
        else:
            ticket["sla_response_due_dt"] = None

        if "sla_resolution_due" in ticket and ticket["sla_resolution_due"]:
            if isinstance(ticket["sla_resolution_due"], str):
                ticket["sla_resolution_due_dt"] = datetime.fromisoformat(
                    ticket["sla_resolution_due"]
                ).replace(tzinfo=UTC)
            else:
                ticket["sla_resolution_due_dt"] = ticket["sla_resolution_due"]
        else:
            ticket["sla_resolution_due_dt"] = None
    return tickets


def format_date_for_display(date_obj, format_string="%Y-%m-%d %H:%M"):
    """Format a datetime object for display in templates"""
    if date_obj:
        return date_obj.strftime(format_string)
    return "N/A"


@app.context_processor
def utility_processor():
    """Make utility functions available in all templates"""
    return dict(format_date=format_date_for_display)


# ================================
# Context processor
# ================================
@app.context_processor
def inject_user():
    if "user_email" in session:
        user = get_user_by_email(session["user_email"])
        return dict(user=user)
    return dict(user=None)


# ================================
# ROUTES
# ================================


@app.route("/")
def index():
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/welcome", methods=["GET"])
def welcome():
    logging.info(f"Request received: {request.method} {request.path}")
    return jsonify({"message": "Welcome to the Helpdesk API!"})


# # ------------------------
# LOGIN
# ------------------------
from flask import Flask, request, redirect, url_for, flash, render_template, session
import logging
import bcrypt  # if you still have legacy bcrypt hashes
from db import get_user_by_email
from scrypt_utils import is_scrypt_hash, is_bcrypt_hash, verify_scrypt_hash

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        logging.info(f"[LOGIN] Attempt for email: {email}")

        # Basic validation
        if not email or not password:
            flash("Email and password are required.", "danger")
            logging.warning(f"[LOGIN] Missing email or password for: {email}")
            return redirect(url_for("login"))

        # Fetch user
        user = get_user_by_email(email)
        if not user:
            flash("Invalid email or password.", "danger")
            logging.warning(f"[LOGIN] User not found: {email}")
            return redirect(url_for("login"))

        # Email verification check
        if not user.get("is_verified", False):
            flash("Please verify your email before logging in.", "warning")
            logging.warning(f"[LOGIN] Unverified email: {email}")
            return redirect(url_for("login"))

        # Password verification
        password_hash = user.get("password_hash", "").strip()
        if not password_hash:
            flash("Invalid email or password.", "danger")
            logging.error(f"[LOGIN] Missing password hash for user: {email}")
            return redirect(url_for("login"))

        # Determine hash type
        if is_scrypt_hash(password_hash):
            if not verify_scrypt_hash(password, password_hash):
                flash("Invalid email or password.", "danger")
                logging.warning(f"[LOGIN] Invalid password (scrypt) for: {email}")
                return redirect(url_for("login"))

        elif is_bcrypt_hash(password_hash):
            try:
                if not bcrypt.checkpw(password.encode(), password_hash.encode()):
                    flash("Invalid email or password.", "danger")
                    logging.warning(f"[LOGIN] Invalid password (bcrypt) for: {email}")
                    return redirect(url_for("login"))
            except Exception as e:
                logging.error(f"[LOGIN] Bcrypt error for {email}: {str(e)}")
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))
        else:
            flash("Invalid email or password.", "danger")
            logging.error(f"[LOGIN] Unknown hash type for user: {email}")
            return redirect(url_for("login"))

        # Successful login: set session
        session["user_email"] = user["email"]
        session["user_id"] = user["id"]
        session["role"] = user.get("role", "user")

        logging.info(f"[LOGIN] Success for {email}. Session data: {dict(session)}")
        flash("Login successful!", "success")

        # Redirect based on role
        role = session["role"]
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "agent":
            return redirect(url_for("agent_dashboard"))
        else:
            return redirect(url_for("user_dashboard"))

    # GET request
    return render_template("login.html")

# ------------------------
# REGISTER
# ------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"].strip()

        # Validation
        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format.", "danger")
            return redirect(url_for("register"))

        password_pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$"
        if not re.match(password_pattern, password):
            flash(
                "Password must be at least 8 chars, contain uppercase, number, special char.",
                "danger",
            )
            return redirect(url_for("register"))

        # Check email
        existing_user = get_user_by_email(email)
        if existing_user:
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for("login"))

        # Insert user
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        verification_token = str(uuid.uuid4())
        insert_user(
            {
                "name": name,
                "email": email,
                "password_hash": hashed_password,
                "is_verified": False,
                "verification_token": verification_token,
            }
        )

        # Send verification email
        verification_link = url_for(
            "verify_email", token=verification_token, _external=True
        )
        msg = Message(
            subject="Verify your Helpdesk Account",
            recipients=[email],
            body=f"Hi {name},\n\nVerify your account: {verification_link}\n\nThanks!",
        )
        mail.send(msg)

        flash("Registration successful! Check your email to verify.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ------------------------
# VERIFY EMAIL
# ------------------------
@app.route("/verify/<token>")
def verify_email(token):
    response = (
        supabase.table("users").select("*").eq("verification_token", token).execute()
    )
    if response.data:
        user = response.data[0]
        supabase.table("users").update(
            {"is_verified": True, "verification_token": None}
        ).eq("id", user["id"]).execute()
        flash("Email verified successfully! Login now.", "success")
    else:
        flash("Invalid or expired verification link.", "danger")
    return redirect(url_for("login"))


# ================================
# DASHBOARD
# ================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get user role and redirect to appropriate dashboard
    user = get_user_by_email(session["user_email"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    role = user.get("role", "user")
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    else:
        return redirect(url_for("user_dashboard"))


# ================================
# Admin, Agent, User dashboards (Supabase only)
# ================================

# Removed duplicate imports


# -------------------------
# Admin Dashboard
# -------------------------
@app.route("/admin_dashboard")
def admin_dashboard():
    # Get logged-in user
    user_resp = (
        supabase.table("users")
        .select("*")
        .eq("email", session.get("user_email"))
        .execute()
    )
    user = user_resp.data[0] if user_resp.data else None

    if not user or user.get("role") != "admin":
        flash("Admin access required.", "danger")
        return redirect(url_for("login"))

    # Fetch all agents
    agents_resp = (
        supabase.table("users").select("id, name").eq("role", "agent").execute()
    )
    agents = agents_resp.data or []

    # Fetch all tickets (non-deleted)
    tickets_resp = (
        supabase.table("tickets").select("*, categories!tickets_category_id_fkey(name, color)").eq("is_deleted", False).execute()
    )
    tickets = tickets_resp.data or []

    # Fetch agent names for assigned tickets
    agent_ids = [t["assigned_agent_id"] for t in tickets if t.get("assigned_agent_id")]
    agents_dict = {}
    if agent_ids:
        agents_resp = (
            supabase.table("users").select("id, name").in_("id", agent_ids).execute()
        )
        agents_dict = {agent["id"]: agent["name"] for agent in agents_resp.data or []}

    # Add agent names and category info to tickets
    for ticket in tickets:
        if (
            ticket.get("assigned_agent_id")
            and ticket["assigned_agent_id"] in agents_dict
        ):
            ticket["assigned_agent_name"] = agents_dict[ticket["assigned_agent_id"]]
        else:
            ticket["assigned_agent_name"] = None

        # Add category info to tickets
        if ticket.get("categories"):
            ticket["category_name"] = ticket["categories"]["name"]
            ticket["category_color"] = ticket["categories"]["color"]
        else:
            ticket["category_name"] = "Uncategorized"
            ticket["category_color"] = "#6c757d"  # Default gray

    # Convert string dates to datetime objects and ensure timezone awareness
    for ticket in tickets:
        if "created_at" in ticket and ticket["created_at"]:
            ticket["created_at_dt"] = datetime.fromisoformat(
                ticket["created_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["created_at_dt"] = None

        if "sla_response_due" in ticket and ticket["sla_response_due"]:
            ticket["sla_response_due_dt"] = datetime.fromisoformat(
                ticket["sla_response_due"]
            ).replace(tzinfo=UTC)
        else:
            ticket["sla_response_due_dt"] = None

        if "sla_resolution_due" in ticket and ticket["sla_resolution_due"]:
            ticket["sla_resolution_due_dt"] = datetime.fromisoformat(
                ticket["sla_resolution_due"]
            ).replace(tzinfo=UTC)
        else:
            ticket["sla_resolution_due_dt"] = None

    # Compute SLA summary
    sla_summary = {
        "resolution_breaches": sum(
            1
            for t in tickets
            if t.get("sla_resolution_due_dt")
            and t["sla_resolution_due_dt"] < datetime.now(UTC)
            and t["status"] not in ["Resolved", "Closed"]
        ),
        "response_breaches": sum(
            1
            for t in tickets
            if t.get("sla_response_due_dt")
            and t["sla_response_due_dt"] < datetime.now(UTC)
            and t["status"] not in ["Resolved", "Closed"]
        ),
    }

    return render_template(
        "admin_dashboard_modern.html",
        tickets=tickets,
        agents=agents,
        sla_summary=sla_summary,
    )


# -------------------------
# Add Agent (Admin)
# -------------------------
@app.route("/register_agent", methods=["GET", "POST"], endpoint="register_agent")
def add_agent():
    if "user_email" not in session:
        flash("Please login.", "warning")
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if not name or not email or not password:
            flash("All fields are required.", "warning")
            return redirect(url_for("register_agent"))

        # Check if user exists
        existing_user_resp = (
            supabase.table("users").select("*").eq("email", email).execute()
        )
        if existing_user_resp.data:
            flash("Email already exists.", "danger")
            return redirect(url_for("register_agent"))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # Insert new agent
        supabase.table("users").insert(
            {
                "name": name,
                "email": email,
                "password": hashed_password,
                "role": "agent",
                "is_admin": False,
                "created_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
            }
        ).execute()

        flash(f"Agent '{name}' added successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_add_agent.html")


# -------------------------
# Agent Dashboard
# -------------------------
@app.route("/agent_dashboard")
def agent_dashboard():
    # Debug logging
    user_email = session.get("user_email")
    logging.info(f"[AGENT_DASHBOARD] Session user_email: {user_email}, type: {type(user_email)}")

    # Ensure user_email is a string
    if user_email and not isinstance(user_email, str):
        logging.error(f"[AGENT_DASHBOARD] user_email is not a string: {user_email}")
        session.clear()
        return redirect(url_for("login"))

    if not user_email:
        logging.warning("[AGENT_DASHBOARD] No user_email in session")
        return redirect(url_for("login"))

    user_resp = (
        supabase.table("users")
        .select("*")
        .eq("email", user_email)
        .execute()
    )
    user = user_resp.data[0] if user_resp.data else None

    if not user or user.get("role") != "agent":
        flash("Agent access required.", "danger")
        return redirect(url_for("login"))

    # Fetch all tickets assigned to this agent (including resolved/closed, excluding archived and deleted)
    tickets_resp = (
        supabase.table("tickets")
        .select("*, categories!tickets_category_id_fkey(name, color)")
        .eq("assigned_agent_id", user["id"])
        .eq("archived", False)
        .eq("is_deleted", False)
        .execute()
    )
    tickets = tickets_resp.data or []

    # Add category info to tickets
    for ticket in tickets:
        if ticket.get("categories"):
            ticket["category_name"] = ticket["categories"]["name"]
            ticket["category_color"] = ticket["categories"]["color"]
        else:
            ticket["category_name"] = "Uncategorized"
            ticket["category_color"] = "#6c757d"  # Default gray

    # Convert created_at and updated_at to datetime objects and ensure timezone awareness
    for ticket in tickets:
        if "created_at" in ticket and ticket["created_at"]:
            ticket["created_at_dt"] = datetime.fromisoformat(
                ticket["created_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["created_at_dt"] = None

        if "updated_at" in ticket and ticket["updated_at"]:
            ticket["updated_at_dt"] = datetime.fromisoformat(
                ticket["updated_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["updated_at_dt"] = None

    # Separate active and completed tickets
    active_tickets = [t for t in tickets if t["status"] in ["Open", "In Progress"]]
    completed_tickets = [t for t in tickets if t["status"] in ["Resolved", "Closed"]]

    stats = {
        "total_assigned": len(tickets),
        "open_tickets": sum(1 for t in tickets if t["status"] == "Open"),
        "in_progress": sum(1 for t in tickets if t["status"] == "In Progress"),
        "completed": sum(1 for t in tickets if t["status"] in ["Resolved", "Closed"]),
    }

    return render_template(
        "agent_dashboard_modern.html",
        tickets=tickets,
        active_tickets=active_tickets,
        completed_tickets=completed_tickets,
        stats=stats,
    )


# -------------------------
# User Dashboard
# -------------------------
@app.route("/user_dashboard")
def user_dashboard():
    user_resp = (
        supabase.table("users")
        .select("*")
        .eq("email", session.get("user_email"))
        .execute()
    )
    user = user_resp.data[0] if user_resp.data else None

    if not user:
        session.clear()
        return redirect(url_for("login"))

    category_id = request.args.get("category_id", type=int)

    categories_resp = supabase.table("categories").select("*").order("name").execute()
    categories = categories_resp.data or []

    tickets_resp = (
        supabase.table("tickets")
        .select("*, categories!tickets_category_id_fkey(name, color)")
        .eq("user_id", user["id"])
        .eq("is_deleted", False)
        .execute()
    )
    tickets = tickets_resp.data or []

    # Add category info to tickets
    for ticket in tickets:
        if ticket.get("categories"):
            ticket["category_name"] = ticket["categories"]["name"]
            ticket["category_color"] = ticket["categories"]["color"]
        else:
            ticket["category_name"] = "Uncategorized"
            ticket["category_color"] = "#6c757d"  # Default gray

    # Convert created_at and updated_at to datetime objects and ensure timezone awareness
    for ticket in tickets:
        if "created_at" in ticket and ticket["created_at"]:
            ticket["created_at_dt"] = datetime.fromisoformat(
                ticket["created_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["created_at_dt"] = None

        if "updated_at" in ticket and ticket["updated_at"]:
            ticket["updated_at_dt"] = datetime.fromisoformat(
                ticket["updated_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["updated_at_dt"] = None

    if category_id:
        tickets = [t for t in tickets if t.get("category_id") == category_id]

    return render_template(
        "user_dashboard_modern.html",
        user=user,
        tickets=tickets,
        categories=categories,
        selected_category=category_id,
    )


# ================================
# SUBMIT TICKET
# ================================
@app.route("/submit", methods=["GET", "POST"])
def submit_ticket():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Sanitize inputs
        title = bleach.clean(
            request.form["title"], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
        )
        description = bleach.clean(
            request.form["description"],
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
        )
        urgency = request.form["urgency"]
        category_id = request.form.get("category_id")
        user_id = session["user_id"]

        # SLA calculation
        sla_response_due, sla_resolution_due = calculate_sla_times(urgency)

        # Create ticket object
        now = datetime.now(UTC)
        ticket_data = {
            "user_id": user_id,
            "title": title,
            "description": description,
            "urgency": urgency,
            "category_id": category_id,
            "status": "Open",
            "sla_response_due": sla_response_due.isoformat(),
            "sla_resolution_due": sla_resolution_due.isoformat(),
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "archived": False,
            "is_deleted": False,
        }

        # Insert into Supabase
        supabase.table("tickets").insert(ticket_data).execute()
        flash("Ticket submitted successfully!", "success")
        return redirect(url_for("dashboard"))

    # Fetch categories for dropdown
    categories_resp = supabase.table("categories").select("*").order("name").execute()
    categories = categories_resp.data or []

    return render_template("submit_ticket.html", categories=categories)


# ================================
# EDIT TICKET
# ================================
@app.route("/edit_ticket/<uuid:ticket_id>", methods=["GET", "POST"])
def edit_ticket(ticket_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])

    # Fetch ticket
    response = (
        supabase.table("tickets").select("*").eq("id", ticket_id).single().execute()
    )
    ticket = response.data

    if not ticket:
        flash("Ticket not found.", "danger")
        return redirect(url_for("dashboard"))

    # Fetch assigned agent name if assigned
    if ticket.get("assigned_agent_id"):
        agent_resp = supabase.table("users").select("name").eq("id", ticket["assigned_agent_id"]).single().execute()
        if agent_resp.data:
            ticket["assigned_agent_name"] = agent_resp.data["name"]

    # Convert date strings to datetime objects with timezone info
    if "created_at" in ticket and ticket["created_at"]:
        ticket["created_at_dt"] = datetime.fromisoformat(ticket["created_at"]).replace(
            tzinfo=UTC
        )
    else:
        ticket["created_at_dt"] = None

    if "updated_at" in ticket and ticket["updated_at"]:
        ticket["updated_at"] = datetime.fromisoformat(ticket["updated_at"]).replace(
            tzinfo=UTC
        )
    else:
        ticket["updated_at"] = None

    # Permissions
    role = user.get("role", "user")
    if role == "admin":
        # Admins can edit any ticket
        pass
    elif role == "agent":
        # Agents can edit tickets assigned to them
        if ticket.get("assigned_agent_id") != user["id"]:
            flash("Unauthorized to edit this ticket.", "danger")
            return redirect(url_for("agent_dashboard"))
    else:
        # Regular users can only edit their own tickets
        if ticket["user_id"] != session["user_id"]:
            flash("Unauthorized to edit this ticket.", "danger")
            return redirect(url_for("user_dashboard"))

    # Fetch categories for dropdown
    categories_resp = supabase.table("categories").select("*").order("name").execute()
    categories = categories_resp.data or []

    # Fetch agents for admin dropdown
    agents = []
    if role == "admin":
        agents_resp = supabase.table("users").select("id, name").eq("role", "agent").execute()
        agents = agents_resp.data or []

    if request.method == "POST":
        title = bleach.clean(
            request.form["title"], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
        )
        description = bleach.clean(
            request.form["description"],
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
        )
        urgency = request.form["urgency"]
        category_id = request.form.get("category_id")

        update_data = {
            "title": title,
            "description": description,
            "urgency": urgency,
            "category_id": category_id,
            "updated_at": datetime.now(UTC).isoformat(),
        }

        # Only admin can update assigned_agent_id and status
        if role == "admin":
            assigned_agent_id = request.form.get("assigned_agent_id")
            status = request.form.get("status")

            if assigned_agent_id:
                update_data["assigned_agent_id"] = assigned_agent_id
            if status:
                update_data["status"] = status

        supabase.table("tickets").update(update_data).eq("id", ticket_id).execute()

        flash("Ticket updated successfully!", "success")
        return redirect(url_for("dashboard"))

    # Fetch comments for the ticket with user info
    try:
        comments_resp = (
            supabase.table("ticket_comments")
            .select(
                """
            *,
            users!ticket_comments_agent_id_fkey(name, role)
        """
            )
            .eq("ticket_id", str(ticket_id))
            .order("created_at")
            .execute()
        )
        comments = comments_resp.data or []

        # Format comments to include commenter_name and commenter_role
        for comment in comments:
            if comment.get("users"):
                comment["commenter_name"] = comment["users"]["name"]
                comment["commenter_role"] = comment["users"]["role"]
                del comment["users"]

        # Convert created_at to datetime objects
        for comment in comments:
            if "created_at" in comment and comment["created_at"]:
                if isinstance(comment["created_at"], str):
                    comment["created_at"] = datetime.fromisoformat(
                        comment["created_at"]
                    ).replace(tzinfo=UTC)
    except Exception:
        comments = []

    return render_template("edit_ticket.html", ticket=ticket, comments=comments, categories=categories, agents=agents)


# ================================
# UPDATE STATUS (ADMIN)
# ================================
@app.route("/update_status/<uuid:ticket_id>", methods=["POST"])
def update_status(ticket_id):
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        return "Unauthorized", 403

    new_status = request.form.get("status", "").strip()
    allowed_statuses = ["Open", "In Progress", "Resolved", "Closed"]
    if new_status not in allowed_statuses:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {"success": False, "error": "Invalid status"}, 400
        return "Invalid status", 400

    supabase.table("tickets").update(
        {"status": new_status, "updated_at": datetime.now(UTC).isoformat()}
    ).eq("id", ticket_id).execute()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"success": True, "status": new_status}

    flash("Ticket status updated.", "success")
    return redirect(url_for("admin_dashboard"))


# ================================
# UPDATE STATUS (AGENT)
# ================================
@app.route("/agent_update_status/<uuid:ticket_id>", methods=["POST"])
def agent_update_status(ticket_id):
    if "user_email" not in session:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {"success": False, "error": "Unauthorized"}, 401
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "agent":
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {"success": False, "error": "Unauthorized"}, 403
        return "Unauthorized", 403

    new_status = request.form.get("status", "").strip()
    allowed_statuses = ["Open", "In Progress", "Resolved", "Closed"]
    if new_status not in allowed_statuses:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {"success": False, "error": "Invalid status"}, 400
        return "Invalid status", 400

    # Check if the ticket is assigned to this agent
    ticket_resp = (
        supabase.table("tickets").select("*").eq("id", ticket_id).single().execute()
    )
    ticket = ticket_resp.data

    if not ticket:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {"success": False, "error": "Ticket not found"}, 404
        flash("Ticket not found.", "danger")
        return redirect(url_for("user_dashboard"))

    if ticket.get("assigned_agent_id") != user["id"] and not user.get("is_admin"):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return {
                "success": False,
                "error": "Unauthorized to update this ticket",
            }, 403
        flash("Unauthorized to update this ticket.", "danger")
        return redirect(url_for("user_dashboard"))

    # Update internal notes if provided
    internal_notes = request.form.get("internal_notes", "").strip()
    update_data = {"status": new_status, "updated_at": datetime.now(UTC).isoformat()}

    if internal_notes:
        update_data["internal_notes"] = internal_notes

    supabase.table("tickets").update(update_data).eq("id", ticket_id).execute()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"success": True}
    flash("Ticket status updated.", "success")
    return redirect(url_for("edit_ticket", ticket_id=ticket_id))


# ================================
# ASSIGN AGENT (ADMIN)
# ================================
@app.route("/assign_agent/<uuid:ticket_id>", methods=["POST"])
def assign_agent(ticket_id):
    if "user_email" not in session:
        flash("Please login.", "warning")
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    agent_id = request.form.get("agent_id")
    supabase.table("tickets").update(
        {"assigned_agent_id": agent_id, "updated_at": datetime.now(UTC).isoformat()}
    ).eq("id", ticket_id).execute()

    flash("Agent assigned successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# ================================
# ARCHIVE / RESTORE TICKET
# ================================
@app.route("/archive_ticket/<uuid:ticket_id>", methods=["POST"])
def archive_ticket(ticket_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        return "Unauthorized", 403

    supabase.table("tickets").update(
        {"archived": True, "updated_at": datetime.now(UTC).isoformat()}
    ).eq("id", ticket_id).execute()
    flash("Ticket archived.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/restore_ticket/<uuid:ticket_id>", methods=["POST"])
def restore_ticket(ticket_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        return "Unauthorized", 403

    supabase.table("tickets").update(
        {"archived": False, "updated_at": datetime.now(UTC).isoformat()}
    ).eq("id", ticket_id).execute()
    flash("Ticket restored.", "success")
    return redirect(url_for("admin_dashboard"))


# ================================
# DELETE TICKET PERMANENTLY (ADMIN)
# ================================
@app.route("/delete_ticket/<uuid:ticket_id>", methods=["POST"])
def delete_ticket(ticket_id):
    if "user_email" not in session:
        return redirect(url_for("login"))
    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "admin":
        return "Unauthorized", 403

    supabase.table("tickets").delete().eq("id", ticket_id).execute()
    flash("Ticket permanently deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ================================
# TICKET DETAIL ROUTES
# ================================





# ================================
# ARCHIVED TICKETS ROUTE
# ================================
@app.route("/archived_tickets")
def archived_tickets():
    """View archived tickets"""
    if "user_email" not in session:
        return redirect(url_for("login"))

    user = get_user_by_email(session["user_email"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if user.get("role") != "admin":
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    # Fetch archived tickets with category info
    tickets_resp = (
        supabase.table("tickets")
        .select("*, categories!tickets_category_id_fkey(name, color)")
        .eq("archived", True)
        .eq("is_deleted", False)
        .execute()
    )
    tickets = tickets_resp.data or []

    # Fetch agent names for assigned tickets
    agent_ids = [t["assigned_agent_id"] for t in tickets if t.get("assigned_agent_id")]
    agents_dict = {}
    if agent_ids:
        agents_resp = (
            supabase.table("users").select("id, name").in_("id", agent_ids).execute()
        )
        agents_dict = {agent["id"]: agent["name"] for agent in agents_resp.data or []}

    # Add agent names and category info to tickets
    for ticket in tickets:
        if (
            ticket.get("assigned_agent_id")
            and ticket["assigned_agent_id"] in agents_dict
        ):
            ticket["assigned_agent_name"] = agents_dict[ticket["assigned_agent_id"]]
        else:
            ticket["assigned_agent_name"] = None

        # Add category info to tickets
        if ticket.get("categories"):
            ticket["category_name"] = ticket["categories"]["name"]
            ticket["category_color"] = ticket["categories"]["color"]
        else:
            ticket["category_name"] = "Uncategorized"
            ticket["category_color"] = "#6c757d"  # Default gray

    # Convert string dates to datetime objects and ensure timezone awareness
    for ticket in tickets:
        if "created_at" in ticket and ticket["created_at"]:
            ticket["created_at_dt"] = datetime.fromisoformat(
                ticket["created_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["created_at_dt"] = None

        if "updated_at" in ticket and ticket["updated_at"]:
            ticket["updated_at_dt"] = datetime.fromisoformat(
                ticket["updated_at"]
            ).replace(tzinfo=UTC)
        else:
            ticket["updated_at_dt"] = None

    return render_template("archived_tickets.html", tickets=tickets)


# ================================
# PASSWORD RESET ROUTES
# ================================
@app.route("/reset_password_request", methods=["GET", "POST"])
def reset_password_request():
    """Handle password reset request"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            flash("Please provide your email address.", "danger")
            return redirect(url_for("reset_password_request"))

        # Check if user exists
        user_resp = (
            supabase.table("users").select("*").eq("email", email).execute()
        )
        user = user_resp.data[0] if user_resp.data else None
        if not user:
            # Don't reveal if email exists or not for security
            flash(
                "If an account exists with this email, you will receive a password reset link shortly.",
                "success",
            )
            return redirect(url_for("login"))

        # Generate reset token
        reset_token = str(uuid.uuid4())
        reset_expires = datetime.now(UTC) + timedelta(hours=24)

        # Store token in database
        supabase.table("users").update(
            {"reset_token": reset_token, "reset_expires": reset_expires.isoformat()}
        ).eq("id", user["id"]).execute()

        # Send reset email
        reset_link = url_for("reset_password", token=reset_token, _external=True)
        msg = Message(
            subject="Password Reset - Help Desk",
            recipients=[email],
            body=f"Hi {user['name']},\n\n"
            f"You requested a password reset. Click the link below to reset your password:\n\n"
            f"{reset_link}\n\n"
            f"This link will expire in 24 hours.\n\n"
            f"If you didn't request this, please ignore this email.",
        )
        mail.send(msg)

        flash("Password reset email sent! Please check your inbox.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password_request.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Handle password reset with token"""
    # Verify token
    response = (
        supabase.table("users").select("*").eq("reset_token", token).single().execute()
    )
    if not response.data:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("login"))

    user = response.data
    reset_expires = datetime.fromisoformat(user["reset_expires"]).replace(tzinfo=UTC)

    if datetime.now(UTC) > reset_expires:
        flash("Reset link has expired.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password or not confirm_password:
            flash("Please fill in all fields.", "danger")
            return redirect(url_for("reset_password", token=token))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("reset_password", token=token))

        # Validate password strength
        password_pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$"
        if not re.match(password_pattern, password):
            flash(
                "Password must be at least 8 characters with uppercase, number, and special character.",
                "danger",
            )
            return redirect(url_for("reset_password", token=token))

        # Update password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        supabase.table("users").update(
            {
                "password_hash": hashed_password,
                "reset_token": None,
                "reset_expires": None,
            }
        ).eq("id", user["id"]).execute()

        flash(
            "Password reset successful! You can now log in with your new password.",
            "success",
        )
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ================================
# LOGOUT
# ================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================================
# RUN APP
# ================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
