#!/usr/bin/env python3
"""
Diagnostic script to identify login page refresh issues
"""

import os
import sys
import mysql.connector
from datetime import datetime, timedelta

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import get_db_connection

def check_database_connection():
    """Test database connectivity"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return True, "Database connection successful"
    except Exception as e:
        return False, f"Database connection failed: {str(e)}"

def check_user_accounts():
    """Check user accounts and their status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check for locked accounts
        cursor.execute("""
            SELECT email, account_locked_until, failed_login_attempts, is_verified, is_admin, role
            FROM users
            WHERE account_locked_until > NOW()
        """)
        locked_accounts = cursor.fetchall()
        
        # Check for recent failed attempts
        cursor.execute("""
            SELECT email, COUNT(*) as failed_attempts 
            FROM login_attempts 
            WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE) 
            AND success = FALSE 
            GROUP BY email
        """)
        failed_attempts = cursor.fetchall()
        
        # Check total users
        cursor.execute("SELECT COUNT(*) as total_users FROM users")
        total_users = cursor.fetchone()['total_users']
        
        cursor.close()
        conn.close()
        
        return {
            'locked_accounts': locked_accounts,
            'recent_failed_attempts': failed_attempts,
            'total_users': total_users
        }
    except Exception as e:
        return {'error': str(e)}

def check_session_tables():
    """Check session-related tables"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check user_sessions table
        cursor.execute("SELECT COUNT(*) as active_sessions FROM user_sessions WHERE expires_at > NOW()")
        active_sessions = cursor.fetchone()['active_sessions']
        
        # Check login_attempts table
        cursor.execute("SELECT COUNT(*) as total_attempts FROM login_attempts WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 1 DAY)")
        total_attempts = cursor.fetchone()['total_attempts']
        
        cursor.close()
        conn.close()
        
        return {
            'active_sessions': active_sessions,
            'total_attempts_today': total_attempts
        }
    except Exception as e:
        return {'error': str(e)}

def check_csrf_tokens():
    """Check if CSRF tokens are being generated properly"""
    try:
        # This would need to be tested with actual Flask app
        return "CSRF token check requires running Flask app"
    except Exception as e:
        return f"CSRF check failed: {str(e)}"

def main():
    """Run all diagnostic checks"""
    print("=== Helpdesk Login Diagnostic Report ===")
    print(f"Generated at: {datetime.now()}")
    print("=" * 50)
    
    # Check database connection
    db_ok, db_msg = check_database_connection()
    print(f"Database Status: {db_msg}")
    
    if db_ok:
        # Check user accounts
        user_info = check_user_accounts()
        if 'error' not in user_info:
            print(f"\nUser Accounts:")
            print(f"  Total users: {user_info['total_users']}")
            print(f"  Locked accounts: {len(user_info['locked_accounts'])}")
            if user_info['locked_accounts']:
                for account in user_info['locked_accounts']:
                    print(f"    - {account['email']} (locked until: {account['account_locked_until']})")
            
            print(f"\nRecent Failed Login Attempts:")
            print(f"  Total failed attempts in last 15 minutes: {len(user_info['recent_failed_attempts'])}")
            for attempt in user_info['recent_failed_attempts']:
                print(f"    - {attempt['email']}: {attempt['failed_attempts']} attempts")
        else:
            print(f"User account check failed: {user_info['error']}")
        
        # Check session tables
        session_info = check_session_tables()
        if 'error' not in session_info:
            print(f"\nSession Information:")
            print(f"  Active sessions: {session_info['active_sessions']}")
            print(f"  Login attempts today: {session_info['total_attempts_today']}")
        else:
            print(f"Session check failed: {session_info['error']}")
    
    print("\n=== Common Login Issues ===")
    print("1. Account locked due to failed attempts")
    print("2. Email not verified")
    print("3. CSRF token issues")
    print("4. Session configuration problems")
    print("5. Database connection issues")
    
    print("\n=== Next Steps ===")
    print("1. Check the application logs for detailed error messages")
    print("2. Verify email verification status for users")
    print("3. Test with a known good account")
    print("4. Check browser console for JavaScript errors")
    print("5. Verify CSRF token is being submitted with form")

if __name__ == "__main__":
    main()
