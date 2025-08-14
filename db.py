# db.py
import mysql.connector

# ----------------------------
# Database connection settings
# ----------------------------
DB_HOST = "sql3.freesqldatabase.com"
DB_USER = "sql3794977"
DB_PASSWORD = "rpFYhYuBqw"
DB_NAME = "sql3794977"
DB_PORT = 3306

# ----------------------------
# Get database connection
# ----------------------------
def get_db_connection():
    """
    Creates and returns a MySQL database connection to FreeSQLDatabase.
    """
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        print("✅ Connected to FreeSQLDatabase successfully!")
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
