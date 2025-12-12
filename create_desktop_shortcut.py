#!/usr/bin/env python3
"""
🎪 FUNFAIR QR CODE PAYMENT SYSTEM - DESKTOP SHORTCUT CREATOR
============================================================

This script creates a desktop shortcut for easy access to your Funfair system.
Works on Windows, macOS, and Linux.
"""

import os
import sys
import platform
from pathlib import Path

def create_windows_shortcut():
    """Create Windows desktop shortcut"""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        path = os.path.join(desktop, "Funfair QR Payment System.lnk")
        target = os.path.join(os.getcwd(), "START_FUNFAIR.bat")
        wDir = os.getcwd()
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = wDir
        shortcut.IconLocation = target
        shortcut.save()
        
        print("✅ Windows desktop shortcut created successfully!")
        print(f"   Shortcut: {path}")
        return True
        
    except ImportError:
        print("⚠️ Windows shortcut libraries not available")
        print("   You can manually create a shortcut to START_FUNFAIR.bat")
        return False
    except Exception as e:
        print(f"❌ Error creating Windows shortcut: {e}")
        return False

def create_macos_shortcut():
    """Create macOS application bundle"""
    try:
        app_name = "Funfair QR Payment System.app"
        app_path = os.path.expanduser(f"~/Desktop/{app_name}")
        
        # Create app bundle structure
        os.makedirs(f"{app_path}/Contents/MacOS", exist_ok=True)
        os.makedirs(f"{app_path}/Contents/Resources", exist_ok=True)
        
        # Create Info.plist
        info_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>start_funfair</string>
    <key>CFBundleIdentifier</key>
    <string>com.funfair.qrpayment</string>
    <key>CFBundleName</key>
    <string>Funfair QR Payment System</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>"""
        
        with open(f"{app_path}/Contents/Info.plist", "w") as f:
            f.write(info_plist)
        
        # Create executable script
        script_content = f"""#!/bin/bash
cd "{os.getcwd()}"
python3 start_funfair.py"""
        
        with open(f"{app_path}/Contents/MacOS/start_funfair", "w") as f:
            f.write(script_content)
        
        os.chmod(f"{app_path}/Contents/MacOS/start_funfair", 0o755)
        
        print("✅ macOS application bundle created successfully!")
        print(f"   App: {app_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error creating macOS shortcut: {e}")
        return False

def create_linux_shortcut():
    """Create Linux desktop file"""
    try:
        desktop_file = os.path.expanduser("~/Desktop/funfair-qr-payment.desktop")
        
        desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Funfair QR Payment System
Comment=Start the Funfair QR Code Payment System
Exec=python3 {os.path.join(os.getcwd(), 'start_funfair.py')}
Icon=applications-games
Terminal=true
StartupNotify=true
Path={os.getcwd()}
Categories=Office;Finance;"""
        
        with open(desktop_file, "w") as f:
            f.write(desktop_content)
        
        os.chmod(desktop_file, 0o755)
        
        print("✅ Linux desktop shortcut created successfully!")
        print(f"   Desktop file: {desktop_file}")
        return True
        
    except Exception as e:
        print(f"❌ Error creating Linux shortcut: {e}")
        return False

def main():
    """Main function"""
    print("🎪" + "="*60 + "🎪")
    print("🎪  FUNFAIR QR CODE PAYMENT SYSTEM - DESKTOP SHORTCUT  🎪")
    print("🎪" + "="*60 + "🎪")
    print()
    
    system = platform.system().lower()
    
    print(f"🖥️ Detected operating system: {system}")
    print()
    
    if system == "windows":
        success = create_windows_shortcut()
    elif system == "darwin":  # macOS
        success = create_macos_shortcut()
    elif system == "linux":
        success = create_linux_shortcut()
    else:
        print(f"❌ Unsupported operating system: {system}")
        success = False
    
    print()
    if success:
        print("🎉 Desktop shortcut created successfully!")
        print("   You can now double-click the shortcut to start your Funfair system!")
    else:
        print("⚠️ Could not create desktop shortcut automatically")
        print("   You can manually create shortcuts to the starter files:")
        print("   - Windows: START_FUNFAIR.bat")
        print("   - macOS/Linux: start_funfair.py or start_funfair.sh")
    
    print()
    print("🎪 Enjoy your Funfair QR Code Payment System! 🎪")

if __name__ == "__main__":
    main()
