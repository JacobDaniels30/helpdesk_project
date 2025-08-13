#!/usr/bin/env python3
"""
Script to fix database connection issues and ensure all required tables exist
"""

import os
import sys
import mysql.connector
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import get_db_connection

def check_and_create_tables():
    """Check if all required tables exist and create them if they don't"""
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # List of required tables
    tables = [
        'users', 'tickets', 'categories', 'ticket_comments', 
        'login_attempts', 'user_sessions'
    ]
    
    # Check existing tables
    cursor.execute("SHOW TABLES")
    existing_tables = [table[0] for table in cursor.fetchall()]
    
    print(f"Existing tables: {existing_tables}")
    
    # Create missing tables
    missing_tables = [table for table in tables if table not in existing_tables]
    
    if missing_tables:
        print(f"Missing tables: {missing_tables}")
        
        # Create users table
        if 'users' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    role VARCHAR(50) DEFAULT 'user',
                    is_verified BOOLEAN DEFAULT FALSE,
                    verification_token VARCHAR(255),
                    password_reset_token VARCHAR(255),
                    token_expiry DATETIME,
                    failed_login_attempts INT DEFAULT 0,
                    account_locked_until DATETIME,
                    last_login_at DATETIME,
                    last_login_ip VARCHAR(45),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            print("Created users table")
        
        # Create tickets table
        if 'tickets' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tickets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    urgency ENUM('Low', 'Medium', 'High', 'Critical') DEFAULT 'Medium',
                    status ENUM('Open', 'In Progress', 'Resolved', 'Closed') DEFAULT 'Open',
                    category_id INT,
                    assigned_agent_id INT,
                    internal_notes TEXT,
                    archived BOOLEAN DEFAULT FALSE,
                    is_deleted BOOLEAN DEFAULT FALSE,
                    sla_response_due DATETIME,
                    sla_resolution_due DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (assigned_agent_id) REFERENCES users(id) ON DELETE SET NULL
                )
            """)
            print("Created tickets table")
        
        # Create categories table
        if 'categories' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS categories (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    color VARCHAR(7) DEFAULT '#007bff',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            print("Created categories table")
            
            # Insert default categories
            default_categories = [
                ('Technical Support', '#007bff'),
                ('Billing', '#28a745'),
                ('General Inquiry', '#ffc107'),
                ('Bug Report', '#dc3545'),
                ('Feature Request', '#6f42c1')
            ]
            
            for name, color in default_categories:
                cursor.execute(
                    "INSERT IGNORE INTO categories (name, color) VALUES (%s, %s)",
                    (name, color)
                )
            print("Inserted default categories")
        
        # Create ticket_comments table
        if 'ticket_comments' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ticket_comments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ticket_id INT NOT NULL,
                    agent_id INT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
                    FOREIGN KEY (agent_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            print("Created ticket_comments table")
        
        # Create login_attempts table
        if 'login_attempts' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    failure_reason VARCHAR(255)
                )
            """)
            print("Created login_attempts table")
        
        # Create user_sessions table
        if 'user_sessions' not in existing_tables:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            print("Created user_sessions table")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True, "All tables created successfully"
    else:
        cursor.close()
        conn.close()
        return True, "All required tables already exist"

def test_database_connection():
    """Test the database connection with detailed error reporting"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Test basic connection
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        
        # Test table existence
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return True, f"Database connection successful. Found {len(tables)} tables: {[table[0] for table in tables]}"
        
    except mysql.connector.Error as e:
        return False, f"MySQL Error: {str(e)}"
    except Exception as e:
        return False, f"General Error: {str(e)}"

def check_environment_variables():
    """Check if all required environment variables are set"""
    required_vars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SECRET_KEY']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    return missing_vars

if __name__ == "__main__":
    print("=== Database Connection Diagnostic ===")
    
    # Check environment variables
    missing_vars = check_environment_variables()
    if missing_vars:
        print(f"❌ Missing environment variables: {missing_vars}")
        print("Please set these variables in your Render environment")
    else:
        print("✅ All required environment variables are set")
    
    # Test database connection
    success, message = test_database_connection()
    print(f"Database Connection: {'✅' if success else '❌'} {message}")
    
    if success:
        # Check and create tables
        table_success, table_message = check_and_create_tables()
        print(f"Table Check: {'✅' if table_success else '❌'} {table_message}")
    
    print("\n=== Next Steps ===")
    print("1. Ensure all environment variables are set in Render")
    print("2. Run this script to verify database connectivity")
    print("3. Check application logs for any remaining errors")
    print("4. Test login functionality with a known good account")
