#!/usr/bin/env python3
"""
Test script to verify database functions are working correctly.
This script tests both get_db_connection and get_user_by_email functions.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from db import get_db_connection, get_user_by_email
    print("✅ Successfully imported functions from db.py")
    
    # Test database connection
    print("\n🔍 Testing database connection...")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT NOW() as current_time")
    result = cursor.fetchone()
    print(f"✅ Database connection successful - Current time: {result[0]}")
    cursor.close()
    conn.close()
    
    # Test get_user_by_email function
    print("\n🔍 Testing get_user_by_email function...")
    test_user = get_user_by_email("test@example.com")
    if test_user:
        print(f"The import statement in app.py is correct and matches the function defined in db.py.

Given that the function exists in db.py and the import statement is correct, the ImportError might be caused by one of the following:

- There might be a circular import issue.
- There might be a naming conflict or a stale __pycache__.
- The environment or path might be misconfigured.

To diagnose further, I will check if there are any circular imports involving db.py and app.py by searching for imports of app or db in db.py.

<search_files>
<path>c:/Users/Jacob.Daniels/Desktop/helpdesk_project</path>
<regex>import.*app|from.*app</regex>
</search_files>
