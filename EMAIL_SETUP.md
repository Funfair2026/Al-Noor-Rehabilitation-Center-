# Email Setup Instructions

## Problem: Outlook Basic Authentication Disabled

Outlook/Office365 has **disabled basic authentication** (username/password) for SMTP. This means you cannot use regular passwords with Outlook SMTP anymore.

## Solution: Use Gmail Instead

Gmail still supports basic authentication with App Passwords. Here's how to set it up:

### Step 1: Create a Gmail Account (or use existing)

### Step 2: Enable 2-Factor Authentication

1. Go to: https://myaccount.google.com/security
2. Enable **2-Step Verification**

### Step 3: Generate App Password

1. Go to: https://myaccount.google.com/apppasswords
2. Select **Mail** and **Other (Custom name)**
3. Enter "Funfair System" or similar
4. Click **Generate**
5. Copy the 16-character password (no spaces)

### Step 4: Set Environment Variables

**Windows PowerShell:**
```powershell
$env:MAIL_USERNAME="your-email@gmail.com"
$env:MAIL_PASSWORD="your-16-char-app-password"
```

**Windows Command Prompt:**
```cmd
set MAIL_USERNAME=your-email@gmail.com
set MAIL_PASSWORD=your-16-char-app-password
```

**Or use the startup scripts** - they will be updated to use Gmail.

### Step 5: Restart Server

Restart your Flask server with the new Gmail credentials.

## Alternative: Use Email Service Provider

If you don't want to use Gmail, consider:
- **SendGrid** (free tier: 100 emails/day)
- **Mailgun** (free tier: 5,000 emails/month)
- **Amazon SES** (very cheap, pay per email)

These services are more reliable and don't have authentication issues.

## Testing

Run the test script to verify email works:
```bash
python test_email.py
```




