# SECRET_KEY Setup Guide

## Overview
This guide explains how to set up and manage the SECRET_KEY for the Flask helpdesk application.

## Current Configuration
- **Generated SECRET_KEY**: `dffc959a7c5fa92975abbc58054080090582809e1d61f06cc8b5d0b75cb5d634`
- **Key Length**: 64 characters (32 bytes hex-encoded)
- **Security Level**: High (cryptographically secure random)

## Setup Process

### 1. Automatic Setup (Recommended)
The `setup_secret_key.py` script has been created to automatically:
- Generate a new secure SECRET_KEY
- Update your `.env` file
- Create `.env` file if it doesn't exist
- Update `.env.example` template

Run it with:
```bash
python setup_secret_key.py
```

### 2. Manual Setup
If you prefer manual setup:

1. **Generate a new key**:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Add to .env file**:
   ```
   SECRET_KEY=your-generated-key-here
   ```

3. **Verify the setup**:
   ```bash
   python verify_secret_key.py
   ```

## Environment Variables

### Required Variables
- `SECRET_KEY`: Your secure application secret key

### Optional Variables
- `FLASK_ENV`: Set to 'production' for production mode
- `PORT`: Port to run the application on (default: 5000)

## Security Best Practices

### 1. Key Management
- **Never commit** the `.env` file to version control
- **Use different keys** for development, staging, and production
- **Rotate keys periodically** (every 90-180 days)
- **Store keys securely** in production (use environment variables or key management services)

### 2. Production Deployment
- Ensure `.env` is listed in `.gitignore`
- Use environment-specific configuration
- Consider using Docker secrets or cloud key management services

### 3. Key Validation
The application validates the SECRET_KEY in production mode:
- Raises `ValueError` if SECRET_KEY is not set
- Provides clear error messages for missing configuration

## Verification

### Check Current Configuration
```bash
python verify_secret_key.py
```

### Test Application
```bash
# Development
python app.py

# Production
FLASK_ENV=production python app.py
```

## Troubleshooting

### Common Issues

1. **SECRET_KEY not found**
   - Ensure `.env` file exists in project root
   - Check file permissions
   - Verify key format in `.env`

2. **Application won't start in production**
   - Set `FLASK_ENV=production`
   - Ensure SECRET_KEY is properly configured

3. **Session issues**
   - Clear browser cookies
   - Restart the application
   - Check SECRET_KEY consistency

### Debug Commands
```bash
# Check environment variables
python -c "from dotenv import load_dotenv; import os; load_dotenv(); print('SECRET_KEY:', os.environ.get('SECRET_KEY', 'NOT SET'))"

# Test Flask app initialization
python -c "from app import app; print('App initialized successfully')"
```

## Files Created
- `setup_secret_key.py`: Automated setup script
- `verify_secret_key.py`: Verification script
- `SECRET_KEY_SETUP.md`: This documentation

## Support
For issues with SECRET_KEY setup, check:
1. Application logs in `helpdesk.log`
2. Environment variable configuration
3. File permissions on `.env`
