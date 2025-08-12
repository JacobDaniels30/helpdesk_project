# Environment Variables Setup Guide

This guide will help you set up the required environment variables for the Flask Helpdesk application.

## Quick Setup

1. **Copy the example file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit the .env file:**
   Open the `.env` file in your text editor and update the values with your actual configuration.

3. **Required Variables:**
   - `SECRET_KEY`: A long, random string for session security
   - `DB_PASSWORD`: Your MySQL database password
   - `MAIL_USERNAME` & `MAIL_PASSWORD`: Email credentials for sending notifications

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret key | `your-super-secret-key-here` |
| `DB_HOST` | Database host | `localhost` |
| `DB_USER` | Database username | `root` |
| `DB_PASSWORD` | Database password | `your-secure-password` |
| `DB_NAME` | Database name | `helpdesk` |
| `MAIL_SERVER` | SMTP server | `smtp.gmail.com` |
| `MAIL_PORT` | SMTP port | `587` |
| `MAIL_USERNAME` | Email username | `your-email@gmail.com` |
| `MAIL_PASSWORD` | Email password | `your-email-password` |

## Security Notes

- **Never commit your `.env` file** to version control
- Use strong, unique passwords for database and email credentials
- Generate a secure `SECRET_KEY` using: `python -c "import secrets; print(secrets.token_hex(32))"`

## Testing Your Setup

After setting up your environment variables, test the application:

```bash
python app.py
```

The application should start without any configuration errors.
