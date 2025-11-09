# FUNFAIR QR CODE PAYMENT SYSTEM

A complete QR-based payment platform for funfair events built with Flask, SQLite, and Tailwind CSS.  
Includes real-time payments, admin dashboard, and secure authentication.

---

## Quick Start MAC
```bash
python3 setup.py      # Auto-setup
python3 app_sqlite.py # Start server
# Visit http://localhost:5001

## Quick Start (Windows)
```bash
python setup.py      # Auto-setup
python app_sqlite.py # Start server
# Visit http://localhost:5001


User Roles

Visitors: Check balance, top-up information

Booth Staff: Issue and recharge QR codes

Stall Staff: Scan and process payments

Admin: Manage users, reports, and settings

Tech Stack

Backend: Python (Flask), SQLite

Frontend: HTML5, Tailwind CSS, JavaScript

Extras: Excel export, charts, live updates

Default Settings

Port: 5001

Admin: admin / admin123

Booth PINs: BOOTH001–BOOTH006


# Funfair QR Code Payment System - Python Dependencies
# Install with: pip install -r requirements.txt

# Core Web Framework
Flask>=2.3.0

# Authentication
PyJWT>=2.8.0

# QR Code Generation
qrcode[pil]>=7.4.0
Pillow>=10.0.0

# CORS Support
Flask-CORS>=4.0.0

# Data Analysis and Reporting
pandas>=2.0.0
matplotlib>=3.7.0
openpyxl>=3.1.0

# Additional Utilities
python-dotenv>=1.0.0