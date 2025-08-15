#!/usr/bin/env python3
"""
Setup script to generate and configure a secure SECRET_KEY for the Flask application.
This script will:
1. Generate a new secure random SECRET_KEY using secrets.token_hex(32)
2. Update the .env file with the new SECRET_KEY
3. Provide instructions for manual setup if .env file doesn't exist
"""

import secrets
import os
import sys

def generate_secret_key():
    """Generate a secure random SECRET_KEY."""
    return secrets.token_hex(32)

def update_env_file(secret_key):
    """Update the .env file with the new SECRET_KEY."""
    env_file = '.env'
    env_example_file = '.env.example'
    
    # Check if .env file exists
    if os.path.exists(env_file):
        # Read current .env content
        with open(env_file, 'r') as f:
            lines = f.readlines()
        
        # Update or add SECRET_KEY
        secret_key_found = False
        new_lines = []
        
        for line in lines:
            if line.startswith('SECRET_KEY='):
                new_lines.append(f'SECRET_KEY={secret_key}\n')
                secret_key_found = True
            else:
                new_lines.append(line)
        
        if not secret_key_found:
            new_lines.append(f'\nSECRET_KEY={secret_key}\n')
        
        # Write updated content
        with open(env_file, 'w') as f:
            f.writelines(new_lines)
        
        print(f"✅ SECRET_KEY updated in {env_file}")
        
    else:
        # Create new .env file
        with open(env_file, 'w') as f:
            f.write(f"SECRET_KEY={secret_key}\n")
        print(f"✅ Created new {env_file} with SECRET_KEY")
    
    # Also update .env.example if it exists
    if os.path.exists(env_example_file):
        with open(env_example_file, 'r') as f:
            lines = f.readlines()
        
        secret_key_found = False
        new_lines = []
        
        for line in lines:
            if line.startswith('SECRET_KEY='):
                new_lines.append('SECRET_KEY=your-secret-key-here\n')
                secret_key_found = True
            else:
                new_lines.append(line)
        
        if not secret_key_found:
            new_lines.append('\nSECRET_KEY=your-secret-key-here\n')
        
        with open(env_example_file, 'w') as f:
            f.writelines(new_lines)
        
        print(f"✅ Updated {env_example_file} template")

def main():
    """Main function to setup the SECRET_KEY."""
    print("🔐 Setting up secure SECRET_KEY for Flask application...")
    
    # Generate new secret key
    new_secret_key = generate_secret_key()
    print(f"🔑 Generated SECRET_KEY: {new_secret_key}")
    
    # Update environment files
    update_env_file(new_secret_key)
    
    print("\n" + "="*60)
    print("✅ SECRET_KEY setup complete!")
    print("="*60)
    print("\n📋 Next steps:")
    print("1. The SECRET_KEY has been added to your .env file")
    print("2. Restart your Flask application to use the new key")
    print("3. Ensure .env is in your .gitignore file")
    print("\n🔒 Security reminder:")
    print("- Never commit the .env file to version control")
    print("- Use a different SECRET_KEY for each environment")
    print("- Rotate keys periodically for enhanced security")

if __name__ == "__main__":
    main()
