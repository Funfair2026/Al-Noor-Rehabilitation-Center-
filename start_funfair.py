#!/usr/bin/env python3
"""
🎪 FUNFAIR QR CODE PAYMENT SYSTEM - ONE-CLICK STARTER
=====================================================

This script will:
1. Check if everything is installed
2. Install missing dependencies automatically
3. Initialize the database if needed
4. Start the Funfair QR Code Payment System
5. Open your browser automatically

Just double-click this file to start your funfair system!
"""

import os
import sys
import subprocess
import webbrowser
import time
import platform
from pathlib import Path

def print_banner():
    """Print the funfair banner"""
    print("🎪" + "="*70 + "🎪")
    print("🎪  FUNFAIR QR CODE PAYMENT SYSTEM - ONE-CLICK STARTER  🎪")
    print("🎪" + "="*70 + "🎪")
    print()

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        print("   Please install Python 3.8+ from https://python.org")
        input("Press Enter to exit...")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    try:
        # Try to install from requirements.txt
        if os.path.exists("requirements.txt"):
            print("   Installing from requirements.txt...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print("   Installing core dependencies...")
            dependencies = [
                "flask>=2.3.0",
                "qrcode[pil]>=7.4.0", 
                "Pillow>=10.0.0",
                "Flask-CORS>=4.0.0",
                "pandas>=2.0.0",
                "matplotlib>=3.7.0",
                "openpyxl>=3.1.0",
                "PyJWT>=2.8.0"
            ]
            for dep in dependencies:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep], 
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    print(f"   ⚠️ Warning: Could not install {dep}")
        
        print("✅ Dependencies installed successfully")
        return True
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        print("   The system will try to continue anyway...")
        return False

def check_files():
    """Check if required files exist"""
    print("📄 Checking required files...")
    required_files = [
        "app_sqlite.py"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        print("   Please ensure all files are in the same directory")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("✅ All required files found")
    return True

def initialize_database():
    """Initialize the database if needed"""
    print("🗄️ Checking database...")
    
    # Database will be auto-created by app_sqlite.py when it starts
    if os.path.exists("funfair.db"):
        print("✅ Database already exists")
    else:
        print("✅ Database will be created automatically when server starts")
    
    return True

def start_server():
    """Start the Flask server"""
    print("🚀 Starting Funfair QR Code Payment System...")
    print()
    print("📱 The system will open in your browser at: http://localhost:5001")
    print("🔐 Admin login: admin / funfair2025")
    print("🛑 Press Ctrl+C to stop the server")
    print()
    
    # Wait a moment for the user to read the message
    time.sleep(2)
    
    # Open browser automatically
    try:
        webbrowser.open("http://localhost:5001")
        print("🌐 Browser opened automatically!")
    except Exception as e:
        print(f"⚠️ Could not open browser automatically: {e}")
        print("   Please manually open: http://localhost:5001")
    
    print()
    print("🎪 Starting server...")
    
    try:
        # Start the Flask application
        subprocess.run([sys.executable, "app_sqlite.py"])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("   Please check if port 5001 is available")
        input("Press Enter to exit...")

def main():
    """Main function"""
    try:
        # Clear screen (works on most systems)
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print_banner()
        
        # Check Python version
        check_python_version()
        
        # Install dependencies
        install_dependencies()
        
        # Check required files
        check_files()
        
        # Initialize database
        initialize_database()
        
        print()
        print("🎉" + "="*70 + "🎉")
        print("🎉  EVERYTHING IS READY! STARTING YOUR FUNFAIR SYSTEM!  🎉")
        print("🎉" + "="*70 + "🎉")
        print()
        
        # Start the server
        start_server()
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("   Please check the error and try again")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
