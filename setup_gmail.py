#!/usr/bin/env python3
"""
Quick Gmail Setup Guide
This will help you set up Gmail for sending emails
"""

print("=" * 60)
print("Gmail Setup for Funfair 2025")
print("=" * 60)
print()
print("Outlook basic authentication is DISABLED by Microsoft.")
print("We need to use Gmail instead.")
print()
print("STEP 1: Create or use a Gmail account")
print("  - Go to: https://accounts.google.com/signup")
print("  - Create a new Gmail account (or use existing)")
print()
print("STEP 2: Enable 2-Factor Authentication")
print("  - Go to: https://myaccount.google.com/security")
print("  - Click '2-Step Verification'")
print("  - Follow the steps to enable it")
print()
print("STEP 3: Generate App Password")
print("  - Go to: https://myaccount.google.com/apppasswords")
print("  - Select 'Mail' and 'Other (Custom name)'")
print("  - Enter name: 'Funfair System'")
print("  - Click 'Generate'")
print("  - Copy the 16-character password (no spaces)")
print()
print("STEP 4: Set Environment Variables")
print("  Run these commands in PowerShell:")
print()
print('  $env:MAIL_USERNAME="your-email@gmail.com"')
print('  $env:MAIL_PASSWORD="your-16-char-app-password"')
print()
print("STEP 5: Restart Server")
print("  The server will automatically use Gmail SMTP")
print()
print("=" * 60)
print()
input("Press Enter when you have your Gmail App Password ready...")




