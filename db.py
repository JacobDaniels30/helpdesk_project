# db.py
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error

# Load .env file first
load_dotenv()

# ----------------------------
# Database connection settings
# ----------------------------
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Jd!2025$MySQLRoot")
DB_NAME = os.getenv("DB_NAME", "helpdesk")
DB_PORT = int(os.getenv("DB_PORT", 3306))

# ----------------------------
# Create database connection
# ----------------------------
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        print(f"✅ Connected to database {DB_NAME} at {DB_HOST}:{DB_PORT}")
        return connection
    except Error as err:
        print(f"❌ Database Connection Error: {err}")
        return None

# ----------------------------
# Get user by email
# ----------------------------
def get_user_by_email(email):
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        return cursor.fetchone()
    except Error as err:
        print(f"Database Error retrieving user by email: {err}")
        return None
    finally:
        cursor.close()
        conn.close()
