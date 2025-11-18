#!/usr/bin/env python3
"""
Setup script to create initial admin accounts for Funfair QR Code Payment System
"""

import sqlite3
import sys
import getpass
from app_sqlite import (
    DATABASE, hash_password, validate_password_strength, 
    generate_secure_password, get_db_connection
)

def create_admin_account(username, password, role='admin', created_by='setup_script'):
    """Create an admin account"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute("SELECT id FROM admin_users WHERE username = ?", (username,))
        if cursor.fetchone():
            print(f"Error: Username '{username}' already exists")
            return False
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            print(f"Error: {message}")
            return False
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create admin account
        cursor.execute("""
            INSERT INTO admin_users (username, password_hash, role, created_by)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, role, created_by))
        
        conn.commit()
        print(f"Success: {role} account '{username}' created successfully")
        return True
        
    except sqlite3.Error as err:
        print(f"Database error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

def main():
    print("=" * 70)
    print("Funfair QR Code Payment System - Admin Account Setup")
    print("=" * 70)
    print()
    
    # Check if database exists
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM admin_users")
        existing_count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        
        if existing_count > 0:
            print(f"Warning: {existing_count} admin account(s) already exist in the database.")
            print("This script is for initial setup only. To create additional admin accounts,")
            print("please use the super admin panel in the web interface.")
            print("Setup cancelled.")
            return
    except Exception as e:
        print(f"Error checking database: {e}")
        print("Make sure the database is initialized first by running app_sqlite.py")
        return
    
    print()
    print("Creating Super Admin Account (Required)")
    print("-" * 70)
    
    # Create super admin
    super_admin_username = input("Enter super admin username: ").strip()
    if not super_admin_username:
        print("Error: Username cannot be empty")
        return
    
    while True:
        password = getpass.getpass("Enter super admin password: ")
        if not password:
            print("Error: Password cannot be empty")
            continue
        
        confirm_password = getpass.getpass("Confirm super admin password: ")
        if password != confirm_password:
            print("Error: Passwords do not match. Please try again.")
            continue
        
        # Super admin requires stricter password validation
        is_valid, message = validate_password_strength(password, is_super_admin=True)
        if not is_valid:
            print(f"Error: {message}")
            print("Super admin password requirements:")
            print("  - At least 12 characters")
            print("  - At least one uppercase letter")
            print("  - At least one lowercase letter")
            print("  - At least 2 numbers")
            print("  - At least 2 special characters")
            continue
        
        break
    
    if not create_admin_account(super_admin_username, password, role='super_admin'):
        print("Failed to create super admin account")
        return
    
    print()
    print("=" * 70)
    print("Setup Complete!")
    print("=" * 70)
    print("Super admin account created successfully!")
    print()
    print("You can now log in with your super admin credentials at:")
    print("  http://localhost:5001/admin_login")
    print()
    print("Note: To create additional admin accounts, use the super admin panel")
    print("      in the web interface after logging in.")
    print()

if __name__ == "__main__":
    main()

