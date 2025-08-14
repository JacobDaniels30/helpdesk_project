
# db.py
import os
import mysql.connector

# ----------------------------
# Get database connection settings from environment variables
# ----------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "helpdesk")
DB_PORT = int(os.getenv("DB_PORT", 3306))

# ----------------------------
# Create database connection
# ----------------------------
def get_db_connection():
    """
    Creates and returns a MySQL database connection using environment variables.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        print("✅ Connected to the database successfully!")
        return connection
    except mysql.connector.Error as err:
        print(f"❌ Database Connection Error: {err}")
        return None

# ----------------------------
# Get user by email
# ----------------------------
def get_user_by_email(email):
    """
    Retrieves a user by their email address.

    Args:
        email (str): The email address to search for

    Returns:
        dict: User dictionary with user data, or None if not found
    """
    conn = get_db_connection()
    if conn is None:
        return None

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        return user
    except mysql.connector.Error as err:
        print(f"Database Error retrieving user by email: {err}")
        return None
    finally:
        cursor.close()
        conn.close()

# ----------------------------
# Quick test (optional)
# ----------------------------
if __name__ == "__main__":
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        print("DB Time:", cursor.fetchone())
        conn.close()
