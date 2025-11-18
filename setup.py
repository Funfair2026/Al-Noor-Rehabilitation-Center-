#!/usr/bin/env python3
"""
Funfair QR Code Payment System - Setup Script
Run this script to automatically set up the entire system
"""

import os
import sys
import subprocess
import sqlite3
from pathlib import Path

def print_header():
    print("🎪" + "="*60 + "🎪")
    print("🎪  FUNFAIR QR CODE PAYMENT SYSTEM - SETUP SCRIPT  🎪")
    print("🎪" + "="*60 + "🎪")
    print()

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    print()

def install_dependencies():
    """Install required Python packages"""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("   Please run: pip install -r requirements.txt")
        sys.exit(1)
    print()

def initialize_database():
    """Initialize the SQLite database"""
    print("🗄️ Initializing database...")
    try:
        # Check if init_sqlite.py exists
        if not os.path.exists("init_sqlite.py"):
            print("❌ Error: init_sqlite.py not found")
            sys.exit(1)
        
        # Run the initialization script
        subprocess.check_call([sys.executable, "init_sqlite.py"])
        print("✅ Database initialized successfully")
        
        # Check if database file was created
        if os.path.exists("funfair.db"):
            print("✅ Database file 'funfair.db' created")
        else:
            print("⚠️ Warning: Database file not found after initialization")
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Error initializing database: {e}")
        sys.exit(1)
    print()

def check_templates():
    """Check if all template files exist"""
    print("📄 Checking template files...")
    templates = [
        "templates/index.html",
        "templates/admin_login.html",
        "templates/admin.html",
        "templates/admin_dashboard.html",
        "templates/issue_coupon.html",
        "templates/recharge_coupon.html",
        "templates/check_balance.html",
        "templates/topup_instructions.html"
    ]
    
    missing_templates = []
    for template in templates:
        if not os.path.exists(template):
            missing_templates.append(template)
    
    if missing_templates:
        print("❌ Missing template files:")
        for template in missing_templates:
            print(f"   - {template}")
        print("   Please ensure all template files are present")
        return False
    else:
        print("✅ All template files found")
        return True

def create_startup_script():
    """Create a startup script for easy launching"""
    startup_content = """#!/usr/bin/env python3
\"\"\"
Funfair QR Code Payment System - Startup Script
\"\"\"

import subprocess
import sys
import os

def main():
    print("🎪 Starting Funfair QR Code Payment System...")
    print("📱 Open your browser and go to: http://localhost:5001")
    print("🛑 Press Ctrl+C to stop the server")
    print()
    
    try:
        subprocess.run([sys.executable, "app_sqlite.py"])
    except KeyboardInterrupt:
        print("\\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    main()
"""
    
    with open("start_server.py", "w") as f:
        f.write(startup_content)
    
    # Make it executable on Unix systems
    if os.name != 'nt':
        os.chmod("start_server.py", 0o755)
    
    print("✅ Created startup script: start_server.py")

def main():
    """Main setup function"""
    print_header()
    
    # Check Python version
    check_python_version()
    
    # Install dependencies
    install_dependencies()
    
    # Check templates
    if not check_templates():
        print("❌ Setup incomplete due to missing template files")
        sys.exit(1)
    
    # Initialize database
    initialize_database()
    
    # Create startup script
    create_startup_script()
    
    # Final success message
    print("🎉" + "="*60 + "🎉")
    print("🎉  SETUP COMPLETED SUCCESSFULLY!  🎉")
    print("🎉" + "="*60 + "🎉")
    print()
    print("🚀 To start the server, run:")
    print("   python3 app_sqlite.py")
    print("   OR")
    print("   python3 start_server.py")
    print()
    print("📱 Then open your browser and go to:")
    print("   http://localhost:5001")
    print()
    print("🔐 Default admin credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print()
    print("🎪 Your Funfair QR Code Payment System is ready!")
    print("   Enjoy your stunning new system! ✨")

if __name__ == "__main__":
    main()
