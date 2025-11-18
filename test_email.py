#!/usr/bin/env python3
"""
Test email sending with Outlook SMTP
Run this to diagnose email issues
"""

import os
import sys
from flask import Flask
from flask_mail import Mail, Message
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Set email environment variables if not set
# NOTE: Outlook basic auth is disabled - use Gmail instead
os.environ.setdefault('MAIL_USERNAME', '')
os.environ.setdefault('MAIL_PASSWORD', '')
os.environ.setdefault('MAIL_SERVER', 'smtp.gmail.com')
os.environ.setdefault('MAIL_PORT', '587')

app = Flask(__name__)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', '')

mail = Mail(app)

def test_email():
    """Test sending an email"""
    print("=" * 60)
    print("Testing Email Configuration")
    print("=" * 60)
    print(f"Server: {app.config['MAIL_SERVER']}")
    print(f"Port: {app.config['MAIL_PORT']}")
    print(f"Username: {app.config['MAIL_USERNAME']}")
    print(f"Password: {'*' * len(app.config['MAIL_PASSWORD']) if app.config['MAIL_PASSWORD'] else 'NOT SET'}")
    print(f"TLS: {app.config['MAIL_USE_TLS']}")
    print(f"SSL: {app.config['MAIL_USE_SSL']}")
    print("=" * 60)
    print()
    
    if not app.config['MAIL_PASSWORD']:
        print("ERROR: MAIL_PASSWORD is not set!")
        return False
    
    # Get recipient email (use sender email by default)
    recipient = app.config['MAIL_USERNAME']
    print(f"Using recipient: {recipient}")
    
    print(f"\nSending test email to: {recipient}")
    print("Please wait...")
    
    try:
        msg = Message(
            subject='Funfair 2025 - Test Email',
            recipients=[recipient],
            sender=app.config['MAIL_USERNAME'],
            body='''Hello!

This is a test email from Funfair 2025.

If you receive this email, your email configuration is working correctly!

Best regards,
Funfair 2025 Team'''
        )
        
        mail.send(msg)
        print("\n[SUCCESS] Email sent successfully!")
        print(f"Check {recipient} inbox (and spam folder) for the test email.")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Failed to send email")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print()
        
        error_str = str(e).lower()
        if "authentication" in error_str or "535" in error_str:
            print("AUTHENTICATION ERROR DETECTED!")
            print()
            print("Possible solutions:")
            print("1. For Gmail:")
            print("   - Enable 2FA at: https://myaccount.google.com/security")
            print("   - Create App Password at: https://myaccount.google.com/apppasswords")
            print("   - Use the 16-character app password (not your regular password)")
            print("2. For Outlook:")
            print("   - Basic authentication is DISABLED by Microsoft")
            print("   - You MUST use Gmail or an email service provider")
            print("   - Or use OAuth2 (complex setup required)")
            print("3. Make sure SMTP authentication is enabled in email settings")
        elif "connection" in error_str or "timeout" in error_str:
            print("CONNECTION ERROR DETECTED!")
            print()
            print("Possible solutions:")
            print("1. Check your internet connection")
            print("2. Check if port 587 is blocked by firewall")
            print("3. Try using port 465 with SSL instead")
        elif "535" in error_str:
            print("SMTP AUTHENTICATION FAILED!")
            print("This usually means:")
            print("- Wrong password")
            print("- Need app password (if 2FA is enabled)")
            print("- SMTP not enabled for your account")
        
        return False

if __name__ == '__main__':
    print("\nFunfair 2025 - Email Test Script")
    print("=" * 60)
    print()
    
    success = test_email()
    
    print()
    print("=" * 60)
    if success:
        print("Email test completed successfully!")
    else:
        print("Email test failed. Check the error messages above.")
    print("=" * 60)
    print()
    
    input("Press Enter to exit...")

