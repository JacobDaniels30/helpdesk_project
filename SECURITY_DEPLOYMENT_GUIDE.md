# Flask Helpdesk Security Deployment Guide

## Overview
This guide ensures your Flask helpdesk application is properly configured for secure session management and HTTPS deployment.

## 1. Environment Variables

### Required Environment Variables
```bash
# Core Flask Configuration
export FLASK_ENV=production
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export DATABASE_URL="postgresql://username:password@localhost/helpdesk_db"

# Security Settings
export SESSION_COOKIE_SECURE=true
export SESSION_COOKIE_HTTPONLY=true
export SESSION_COOKIE_SAMESITE=Lax

# Mail Configuration (update with your credentials)
export MAIL_SERVER=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USE_TLS=true
export MAIL_USERNAME=your-email@gmail.com
export MAIL_PASSWORD=your-app-password
```

### Generate Secure Secret Key
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## 2. HTTPS Configuration

### Production Deployment with Gunicorn
```bash
# Install gunicorn
pip install gunicorn

# Run with HTTPS support
gunicorn app:app \
  --bind 0.0.0.0:5000 \
  --forwarded-allow-ips="*" \
  --proxy-headers \
  --workers=4 \
  --timeout=120
```

### Nginx Reverse Proxy Configuration
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 3. Session Security Verification

### Check Session Cookies
1. Open browser developer tools (F12)
2. Go to Application/Storage → Cookies
3. Verify:
   - Cookie name: `helpdesk_session`
   - Secure flag: ✅ (in production)
   - HttpOnly flag: ✅
   - SameSite: Lax
   - Domain matches your site

### Test HTTPS Redirect
```bash
# Test HTTP to HTTPS redirect
curl -I http://yourdomain.com

# Should return 301 redirect to HTTPS
```

## 4. Security Testing Checklist

### Session Management
- [ ] Login creates secure session cookie
- [ ] Logout clears session completely
- [ ] Session timeout works (24 hours)
- [ ] Session persists across page reloads

### HTTPS Enforcement
- [ ] HTTP redirects to HTTPS
- [ ] Session cookies only sent over HTTPS
- [ ] No mixed content warnings
- [ ] SSL certificate valid

### Security Headers
- [ ] Strict-Transport-Security
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] X-XSS-Protection

## 5. Production Deployment Commands

### Using systemd (Linux)
Create `/etc/systemd/system/helpdesk.service`:
```ini
[Unit]
Description=Helpdesk Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/helpdesk
Environment="PATH=/path/to/venv/bin"
Environment="FLASK_ENV=production"
Environment="SECRET_KEY=your-secure-secret-key"
ExecStart=/path/to/venv/bin/gunicorn app:app --bind 0.0.0.0:5000 --forwarded-allow-ips="*" --proxy-headers
Restart=always

[Install]
WantedBy=multi-user.target
```

### Enable and start service
```bash
sudo systemctl enable helpdesk
sudo systemctl start helpdesk
sudo systemctl status helpdesk
```

## 6. Security Monitoring

### Log Monitoring
Monitor these security events:
- Failed login attempts
- Unauthorized access attempts
- Password reset requests
- Session anomalies

### Log File Location
- Application logs: `helpdesk.log`
- Nginx access logs: `/var/log/nginx/access.log`
- Nginx error logs: `/var/log/nginx/error.log`

## 7. Common Issues and Solutions

### Issue: Session lost after redirect
**Solution**: Ensure `SECRET_KEY` is consistent across server restarts

### Issue: Cookies not secure
**Solution**: Verify `FLASK_ENV=production` is set

### Issue: HTTPS not working
**Solution**: Check reverse proxy configuration and SSL certificate

## 8. Security Best Practices

1. **Regular Updates**: Keep Flask and dependencies updated
2. **Secret Rotation**: Change `SECRET_KEY` periodically
3. **Access Control**: Regularly audit user permissions
4. **Backup**: Regular database backups with encryption
5. **Monitoring**: Set up alerts for security events

## 9. Quick Security Test

Run this test after deployment:
```bash
# Test HTTPS redirect
curl -I http://yourdomain.com

# Test secure cookies
curl -I https://yourdomain.com/login

# Check security headers
curl -I https://yourdomain.com
```

Your Flask helpdesk application is now configured for secure session management and HTTPS deployment!
