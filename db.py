import os
import pymysql
from supabase import Client, create_client
from datetime import datetime, timezone

# -----------------------------
# Supabase Configuration
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://dcizwjswncdoegeycwpt.supabase.co")
SUPABASE_KEY = os.getenv(
    "SUPABASE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRjaXp3anN3bmNkb2VnZXljd3B0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTU2NzYxNDUsImV4cCI6MjA3MTI1MjE0NX0.dclVUNWJU-ez9AavDEGv3WTrIn6ZBIUJrdv--zfQUAQ",
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -----------------------------
# MySQL Configuration (Optional)
# -----------------------------
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "helpdesk"),
    "cursorclass": pymysql.cursors.DictCursor,
}

def get_db_connection():
    """Return a MySQL database connection"""
    return pymysql.connect(**DB_CONFIG)


# -----------------------------
# Supabase Helper Functions
# -----------------------------

def get_users():
    """Fetch all users from Supabase"""
    response = supabase.table("users").select("*").execute()
    return response.data or []

def get_user_by_email(email):
    """Fetch a single user by email"""
    # Corrected: no extra quotes
    response = supabase.table("users").select("*").eq("email", email).execute()
    if response.data:
        return response.data[0]
    return None

def insert_user(user_dict):
    """Insert a new user into Supabase"""
    response = supabase.table("users").insert(user_dict).execute()
    return response.data or []

def update_user(user_id, update_dict):
    """Update user details by user ID"""
    response = supabase.table("users").update(update_dict).eq("id", user_id).execute()
    return response.data or []

def delete_user(user_id):
    """Delete a user by ID"""
    response = supabase.table("users").delete().eq("id", user_id).execute()
    return response.data or []


# -----------------------------
# Ticket Helper Functions
# -----------------------------

def get_tickets(filter_dict=None):
    """Fetch tickets with optional filters"""
    query = supabase.table("tickets").select("*")
    if filter_dict:
        for key, value in filter_dict.items():
            query = query.eq(key, value)
    response = query.execute()
    return response.data or []

def get_ticket_by_id(ticket_id):
    """Fetch a single ticket by ID"""
    response = supabase.table("tickets").select("*").eq("id", ticket_id).single().execute()
    return response.data

def insert_ticket(ticket_dict):
    """Insert a new ticket"""
    response = supabase.table("tickets").insert(ticket_dict).execute()
    return response.data or []

def update_ticket(ticket_id, update_dict):
    """Update a ticket by ID"""
    response = supabase.table("tickets").update(update_dict).eq("id", ticket_id).execute()
    return response.data or []

def delete_ticket(ticket_id):
    """Delete a ticket by ID"""
    response = supabase.table("tickets").delete().eq("id", ticket_id).execute()
    return response.data or []


# -----------------------------
# Comment Helper Functions
# -----------------------------

def get_ticket_comments(ticket_id):
    """Fetch comments for a ticket"""
    response = supabase.table("ticket_comments").select("*").eq("ticket_id", ticket_id).order("created_at").execute()
    return response.data or []

def insert_ticket_comment(comment_dict):
    """Insert a comment for a ticket"""
    # Ensure created_at in UTC ISO format
    comment_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    response = supabase.table("ticket_comments").insert(comment_dict).execute()
    return response.data or []
