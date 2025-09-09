#!/usr/bin/env python3
"""
Verification script to check if the SECRET_KEY is properly configured.
"""

import os

from dotenv import load_dotenv


def verify_secret_key():
    """Verify that SECRET_KEY is properly set in environment."""
    print("🔍 Verifying SECRET_KEY configuration...")

    # Load environment variables
    load_dotenv()

    # Check for SECRET_KEY
    secret_key = os.environ.get("SECRET_KEY")

    if secret_key:
        print("✅ SECRET_KEY found in environment")
        print(f"🔑 Key length: {len(secret_key)} characters")
        print(f"🔑 Key preview: {secret_key[:8]}...{secret_key[-8:]}")

        # Validate key strength
        if len(secret_key) >= 64:  # 32 bytes hex = 64 chars
            print("✅ Key meets security requirements (64+ characters)")
        else:
            print("⚠️  Key may be too short for production use")

        return True
    else:
        print("❌ SECRET_KEY not found in environment")
        print("💡 Make sure .env file exists and contains SECRET_KEY")
        return False


if __name__ == "__main__":
    verify_secret_key()
