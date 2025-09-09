# Render Deployment Login Issue - Troubleshooting Guide

## Problem Description
Getting refreshed login page when trying to login on deployment side using Render.

## Root Cause Analysis
This is typically caused by session configuration issues between HTTP/HTTPS, missing environment variables, or CSRF token problems.

## Step-by-Step Solutions

### 1. Check Environment Variables
Ensure these are set in your Render dashboard:
- `SECRET_KEY`: A secure random string (32+ characters)
- `FLASK_ENV`: Set to `production`
- `DATABASE_URL`: Your PostgreSQL connection string

### 2. Fix Session Configuration
Update your session settings in `app.py`:

```python
# Replace lines 61-67 with:
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Change this for Render
    SESSION_COOKIE_NAME='helpdesk_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    SESSION_PERMANENT=True,
)
```

### 3. Add Debug Logging
Add this to your login route to debug:

```python
print(f"DEBUG: Session before login: {dict(session)}")
print(f"DEBUG: Request URL: {request.url}")
print(f"DEBUG: Request scheme: {request.scheme}")
```

### 4. Check CSRF Configuration
Ensure CSRF token is properly configured:

```python
# Add this to your login template form:
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

### 5. Database Session Storage (Optional)
If issues persist, consider using server-side sessions:

```python
# Install: pip install Flask-Session
from flask_session import Session
import redis

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
Session(app)
```

### 6. Render-Specific Configuration
Create a `render.yaml` file:

```yaml
services:
  - type: web
    name: helpdesk-app
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app
    envVars:
      - key: SECRET_KEY
        generateValue: true
      - key: FLASK_ENV
        value: production
      - key: DATABASE_URL
        fromDatabase:
          name: helpdesk-db
          property: connectionString
```

### 7. Quick Test Commands
Run these to verify:
```bash
# Check if SECRET_KEY is set
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('SECRET_KEY:', bool(os.getenv('SECRET_KEY')))"

# Test database connection
python -c "from db import get_db_connection; conn = get_db_connection(); print('DB connected:', conn.is_connected()); conn.close()"
```

## Common Fixes

### Fix A: Disable Secure Cookies for Development
```python
# In app.py, change:
SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
```

### Fix B: Add Health Check
```python
@app.route('/health')
def health():
    return {'status': 'ok', 'session': dict(session)}
```

### Fix C: Clear Browser Cache
1. Open browser dev tools (F12)
2. Go to Application tab
3. Clear cookies for your domain
4. Try logging in again

## Verification Steps
1. Check Render logs for any errors
2. Verify HTTPS is working (should show green lock)
3. Test with a simple route first:
```python
@app.route('/test')
def test():
    session['test'] = 'working'
    return {'session': dict(session)}
```

## Support Resources
- Render Documentation: https://render.com/docs
- Flask Deployment Guide: https://flask.palletsprojects.com/en/latest/deploying/
