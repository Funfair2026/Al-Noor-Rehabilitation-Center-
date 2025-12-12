#!/usr/bin/env python3
"""
Script to create an admin account or unlock an existing one.
Usage: python create_and_unlock_admin.py <username> <password>
"""
import sqlite3
import sys
from app_sqlite import DATABASE, hash_password, get_db_connection

def create_or_unlock_admin(username, password):
    """Create an admin account or unlock if it exists"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        cursor.execute("SELECT id, username, failed_login_attempts, locked_until FROM admin_users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            # User exists - unlock it
            print(f"User '{username}' found. Unlocking account...")
            cursor.execute("UPDATE admin_users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
            conn.commit()
            print(f"Success: Account '{username}' has been unlocked.")
            print("Failed login attempts have been reset.")
            return True
        else:
            # User doesn't exist - create it
            print(f"User '{username}' not found. Creating new admin account...")
            
            # Hash password
            password_hash = hash_password(password)
            
            # Create admin account (regular admin, not super_admin)
            cursor.execute("""
                INSERT INTO admin_users (username, password_hash, role, created_by)
                VALUES (?, ?, ?, ?)
            """, (username, password_hash, 'admin', 'script'))
            
            conn.commit()
            print(f"Success: Admin account '{username}' created successfully.")
            print("You can now log in with these credentials.")
            return True
            
    except sqlite3.Error as err:
        print(f"Database error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python create_and_unlock_admin.py <username> <password>")
        print("Example: python create_and_unlock_admin.py funfair MyPassword123!")
        sys.exit(1)
    
    username = sys.argv[1].strip()
    password = sys.argv[2].strip()
    
    if not username or not password:
        print("Error: Username and password cannot be empty")
        sys.exit(1)
    
    create_or_unlock_admin(username, password)

