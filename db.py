import mysql.connector
import os

def get_db_connection():
    """
    Establish a connection to the MySQL database using environment variables.
    Defaults are provided for local development.
    """
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'mysql.railway.internal'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'UGLlIfmOaUwBrMtunDtWjFJcSjSfKcVU'),  # fallback for local dev
        database=os.getenv('DB_NAME', 'railway'),  # fallback for local dev
        port=int(os.getenv('DB_PORT', 3306))
    )

def get_user_by_email(email):
    """
    Fetch a user record from the 'users' table by email.
    Returns None if no user is found.
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user
