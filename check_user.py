# check_user.py
import sys
from db import get_db_connection

EMAIL_TO_CHECK = 'jacobdaniels237@gmail.com'  # change this to the user you want to test

def main():
    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if the user exists and fetch account info
        cursor.execute(
            'SELECT id, email, is_verified, failed_login_attempts, account_locked_until FROM users WHERE email=%s',
            (EMAIL_TO_CHECK,)
        )
        user = cursor.fetchone()

        if user:
            print('User found:', user)

            # Reset failed attempts and lockout if needed
            if user['failed_login_attempts'] > 0 or user['account_locked_until']:
                cursor.execute(
                    'UPDATE users SET failed_login_attempts=0, account_locked_until=NULL WHERE email=%s',
                    (EMAIL_TO_CHECK,)
                )
                conn.commit()
                print('Account lockout reset successfully')

            # Check recent failed login attempts
            cursor.execute(
                'SELECT COUNT(*) as failed_attempts FROM login_attempts WHERE email=%s AND success=FALSE AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)',
                (EMAIL_TO_CHECK,)
            )
            failed = cursor.fetchone()
            print('Recent failed attempts in last 15 minutes:', failed['failed_attempts'])

        else:
            print('User not found. Please check the email or create a test account.')

        cursor.close()
        conn.close()

    except Exception as e:
        print('Database error:', e)

if __name__ == '__main__':
    main()
