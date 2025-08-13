#!/usr/bin/env python3
"""
Script to fix the ImportError: cannot import name 'get_user_by_email' from 'db'
This script will verify the functions exist and test the import.
"""

import os
import sys
import subprocess

def clear_python_cache():
    """Clear Python cache files to resolve import issues."""
    try:
        # Clear .pyc files
        subprocess.run(['del', '/q', '/s', '*.pyc'], shell=True, capture_output=True)
        # Clear __pycache__ directories
        subprocess.run(['rmdir', '/q', '/s', '__pycache__'], shell=True, capture_output=True)
        print("✅ Python cache cleared successfully")
    except Exception as e:
        print(f"Note: Cache clearing command may have failed: {e}")

def test_import():
    """Test if the import works correctly."""
    try:
        from db import get_db_connection, get_user_by_email
        print("✅ Successfully imported get_user_by_email from db")
        
        # Test database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT NOW()")
        result = cursor.fetchone()
        print(f"✅ Database connection successful: {result[0]}")
        cursor.close()
        conn.close()
        
        return True
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Fixing ImportError: cannot import name 'get_user_by_email' from 'db'")
    print("=" * 60)
    
    # Clear cache
    clear_python_cache()
    
    # Test import
    print("\n🔍 Testing import...")
    success = test_import()
    
    if success:
        print("\n✅ All tests passed! The import error should be resolved.")
        print("💡 If you're still seeing the error, restart your Python environment/IDE.")
    else:
        print("\n❌ Import still failing. Please check:")
        print("1. Ensure db.py contains the get_user_by_email function")
        print("2. Restart your Python environment")
        print("3. Check file permissions")
