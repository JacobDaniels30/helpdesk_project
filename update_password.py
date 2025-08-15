from db import get_db_connection
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# Replace with the email of the user you want to reset
email = "jacobdaniels237@gmail.com"
new_password = "Lathan-jay"  # the password you want to use

# Generate bcrypt hash
password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

# Connect to DB
conn = get_db_connection()
if conn:
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (password_hash, email)
        )
        conn.commit()
        print(f"✅ Password updated for {email}")
    except Exception as e:
        print("❌ Error:", e)
    finally:
        cursor.close()
        conn.close()
