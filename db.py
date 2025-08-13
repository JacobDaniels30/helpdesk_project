# db.py
import os
import mysql.connector
from urllib.parse import urlparse

def get_db_connection():
    """
    Creates and returns a MySQL database connection.
    Automatically switches between local Railway Public URL (when running locally)
    and Railway's internal host (when running inside Railway).
    """
    
    # Get environment variables from Railway
    mysql_url = os.getenv("MYSQL_URL")  # Internal URL for Railway deployments
    mysql_public_url = os.getenv("MYSQL_PUBLIC_URL")  # Public URL for local dev
    mysql_root_password = os.getenv("MYSQL_ROOT_PASSWORD", "")
    mysql_database = os.getenv("MYSQL_DATABASE", "railway")

    if mysql_url and "mysql.railway.internal" in mysql_url:
        # 🟢 Running inside Railway — use internal DB
        parsed = urlparse(mysql_url)
        host = parsed.hostname
        port = parsed.port or 3306
        user = parsed.username
        password = parsed.password
        
        print("Connecting to Railway internal MySQL...")
        connection = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password or mysql_root_password,
            database=mysql_database
        )
    else:
        # 🟢 Running locally — use Railway public proxy connection
        print("Connecting to Railway public MySQL for local development...")
        connection = mysql.connector.connect(
            host="trolley.proxy.rlwy.net",
            port=19887,
            user="root",
            password="UGLlIfmOaUwBrMtunDtWjFJcSjSfKcVU",
            database="railway"
        )
    
    return connection

# Quick test (optional)
if __name__ == "__main__":
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        print("DB Time:", cursor.fetchone())
        conn.close()
    except mysql.connector.Error as err:
        print("Database Connection Error:", err)
