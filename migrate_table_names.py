#!/usr/bin/env python3
"""
Migration script to rename database tables to more suitable names
"""

import sqlite3
import os

DATABASE = 'funfair.db'

# Table name mappings: old_name -> new_name
TABLE_MAPPINGS = {
    'admin_users': 'admins',
    'coupons': 'visitors',
    'revenue': 'topup_transactions',
    'counters': 'payments',
    'authenticator': 'access_keys',
    'system_logs': 'audit_logs',
    'corporate_accounts': 'corporates'
}

def migrate_tables():
    """Rename all tables to new names"""
    if not os.path.exists(DATABASE):
        print(f"Database {DATABASE} not found!")
        return False
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check which tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        print("Starting table migration...")
        print(f"Existing tables: {existing_tables}")
        
        # Rename each table
        for old_name, new_name in TABLE_MAPPINGS.items():
            if old_name in existing_tables:
                if new_name in existing_tables:
                    print(f"Warning: {new_name} already exists. Skipping {old_name}.")
                    continue
                
                print(f"Renaming {old_name} -> {new_name}...")
                cursor.execute(f"ALTER TABLE {old_name} RENAME TO {new_name}")
                print(f"[OK] Renamed {old_name} to {new_name}")
            else:
                print(f"Table {old_name} not found. Skipping.")
        
        conn.commit()
        print("\nMigration completed successfully!")
        return True
        
    except sqlite3.Error as err:
        print(f"Error during migration: {err}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    print("=" * 70)
    print("Database Table Name Migration")
    print("=" * 70)
    print()
    print("This will rename the following tables:")
    for old, new in TABLE_MAPPINGS.items():
        print(f"  {old} -> {new}")
    print()
    print("Starting migration...")
    
    if migrate_tables():
        print("\n[SUCCESS] Migration successful! Database tables renamed.")
        print("Note: app_sqlite.py has already been updated with new table names.")
    else:
        print("\n[ERROR] Migration failed!")

