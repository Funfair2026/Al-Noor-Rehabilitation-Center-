#!/usr/bin/env python3
"""
Initialize SQLite Database with Tables and Sample Data
"""

import sqlite3

DATABASE = 'funfair.db'

def create_database_and_tables():
    """Create database and all tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create coupons table
    create_coupons_table = '''
    CREATE TABLE IF NOT EXISTS coupons (
        ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        amount REAL,
        balance REAL,
        qr_code TEXT,
        issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pin TEXT
    );
    '''
    
    # Create revenue table
    create_revenue_table = '''
    CREATE TABLE IF NOT EXISTS revenue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        amount REAL NOT NULL,
        pin TEXT,
        type TEXT CHECK(type IN ('Issue', 'Top up')) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''
    
    # Create counters table
    create_counters_table = '''
    CREATE TABLE IF NOT EXISTS counters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        staff TEXT,
        customer TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''
    
    # Create authenticator table
    create_authenticator_table = '''
    CREATE TABLE IF NOT EXISTS authenticator (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        counter TEXT,
        pass_key TEXT NOT NULL
    );
    '''
    
    # Create Generate_qr table
    create_generate_qr_table = '''
    CREATE TABLE IF NOT EXISTS Generate_qr (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Name TEXT NOT NULL,
        Pin TEXT NOT NULL
    );
    '''
    
    # Execute table creation
    cursor.execute(create_coupons_table)
    cursor.execute(create_revenue_table)
    cursor.execute(create_counters_table)
    cursor.execute(create_authenticator_table)
    cursor.execute(create_generate_qr_table)
    
    print("✅ All tables created successfully")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return True

def insert_sample_data():
    """Insert sample data for testing"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Clear existing data
    cursor.execute("DELETE FROM Generate_qr")
    cursor.execute("DELETE FROM authenticator")
    cursor.execute("DELETE FROM coupons")
    cursor.execute("DELETE FROM revenue")
    cursor.execute("DELETE FROM counters")
    
    # Insert booth PINs
    booth_pins = [
        ('Booth 1', 'BOOTH001'),
        ('Booth 2', 'BOOTH002'),
        ('Booth 3', 'BOOTH003'),
        ('Booth 4', 'BOOTH004'),
        ('Booth 5', 'BOOTH005'),
        ('Booth 6', 'BOOTH006'),
    ]
    
    for name, pin in booth_pins:
        cursor.execute(
            "INSERT INTO Generate_qr (Name, Pin) VALUES (?, ?)",
            (name, pin)
        )
    
    print(f"✅ Inserted {len(booth_pins)} booth PINs")
    
    # Insert stall staff accounts
    stall_staff = [
        ('Food Stall 1', 'Food Stall 1', 'FOOD001'),
        ('Food Stall 2', 'Food Stall 2', 'FOOD002'),
        ('Game Booth 1', 'Game Booth 1', 'GAME001'),
        ('Game Booth 2', 'Game Booth 2', 'GAME002'),
        ('Drink Stall 1', 'Drink Stall 1', 'DRINK001'),
        ('Drink Stall 2', 'Drink Stall 2', 'DRINK002'),
        ('Souvenir Shop 1', 'Souvenir Shop 1', 'SOUV001'),
        ('Souvenir Shop 2', 'Souvenir Shop 2', 'SOUV002'),
        ('Ride Booth 1', 'Ride Booth 1', 'RIDE001'),
        ('Ride Booth 2', 'Ride Booth 2', 'RIDE002'),
    ]
    
    for user, counter, passkey in stall_staff:
        cursor.execute(
            "INSERT INTO authenticator (user, counter, pass_key) VALUES (?, ?, ?)",
            (user, counter, passkey)
        )
    
    print(f"✅ Inserted {len(stall_staff)} stall staff accounts")
    
    # Insert sample coupons
    sample_coupons = [
        ('Ahmed Malfi', 50.00, 50.00, 'BOOTH001'),
        ('Sarah Mohammed', 25.00, 25.00, 'BOOTH002'),
        ('Ahmed Ali', 100.00, 85.50, 'BOOTH003'),
        ('Maria Garcia', 30.00, 30.00, 'BOOTH001'),
        ('David Johnson', 75.00, 60.25, 'BOOTH002'),
    ]
    
    for name, amount, balance, pin in sample_coupons:
        cursor.execute(
            "INSERT INTO coupons (full_name, amount, balance, pin) VALUES (?, ?, ?, ?)",
            (name, amount, balance, pin)
        )
    
    print(f"✅ Inserted {len(sample_coupons)} sample coupons")
    
    # Insert sample revenue records
    sample_revenue = [
        ('Ahmed Malfi', 50.00, 'BOOTH001', 'Issue'),
        ('Sarah Mohammed', 25.00, 'BOOTH002', 'Issue'),
        ('Ahmed Ali', 100.00, 'BOOTH003', 'Issue'),
        ('Maria Garcia', 30.00, 'BOOTH001', 'Issue'),
        ('David Johnson', 75.00, 'BOOTH002', 'Issue'),
        ('Ahmed Ali', 20.00, 'BOOTH003', 'Top up'),
    ]
    
    for name, amount, pin, type_val in sample_revenue:
        cursor.execute(
            "INSERT INTO revenue (full_name, amount, pin, type) VALUES (?, ?, ?, ?)",
            (name, amount, pin, type_val)
        )
    
    print(f"✅ Inserted {len(sample_revenue)} revenue records")
    
    # Insert sample counter transactions
    sample_counters = [
        ('Food Stall 1', 12.50, 'Food Stall 1', 'Ahmed Ali'),
        ('Game Booth 1', 8.00, 'Game Booth 1', 'Ahmed Ali'),
        ('Drink Stall 1', 5.50, 'Drink Stall 1', 'Ahmed Ali'),
        ('Food Stall 2', 15.00, 'Food Stall 2', 'David Johnson'),
        ('Ride Booth 1', 10.00, 'Ride Booth 1', 'David Johnson'),
    ]
    
    for name, amount, staff, customer in sample_counters:
        cursor.execute(
            "INSERT INTO counters (name, amount, staff, customer) VALUES (?, ?, ?, ?)",
            (name, amount, staff, customer)
        )
    
    print(f"✅ Inserted {len(sample_counters)} counter transactions")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print("\n🎉 Sample data inserted successfully!")
    
    return True

def main():
    print("🚀 Funfair QR Code Payment System - SQLite Database Initialization")
    print("=" * 70)
    
    # Step 1: Create database and tables
    if create_database_and_tables():
        # Step 2: Insert sample data
        if insert_sample_data():
            print("\n✅ Database setup completed successfully!")
            print("\n📋 Test Accounts Created:")
            print("=" * 50)
            
            print("\n🏪 BOOTH STAFF PINS (for issuing/recharging QR codes):")
            booth_pins = [
                ('Booth 1', 'BOOTH001'), ('Booth 2', 'BOOTH002'), ('Booth 3', 'BOOTH003'),
                ('Booth 4', 'BOOTH004'), ('Booth 5', 'BOOTH005'), ('Booth 6', 'BOOTH006'),
            ]
            for name, pin in booth_pins:
                print(f"   {name}: {pin}")
            
            print("\n🏪 STALL STAFF ACCOUNTS (for processing payments):")
            stall_staff = [
                ('Food Stall 1', 'FOOD001'), ('Food Stall 2', 'FOOD002'),
                ('Game Booth 1', 'GAME001'), ('Game Booth 2', 'GAME002'),
                ('Drink Stall 1', 'DRINK001'), ('Drink Stall 2', 'DRINK002'),
                ('Souvenir Shop 1', 'SOUV001'), ('Souvenir Shop 2', 'SOUV002'),
                ('Ride Booth 1', 'RIDE001'), ('Ride Booth 2', 'RIDE002'),
            ]
            for user, passkey in stall_staff:
                print(f"   {user}: {passkey}")
            
            print("\n👥 SAMPLE VISITORS (you can check their balances):")
            visitors = ['John Doe', 'Sarah Smith', 'Ahmed Ali', 'Maria Garcia', 'David Johnson']
            for visitor in visitors:
                print(f"   - {visitor}")
            
            print("\n🚀 Now you can run: python3 app.py")
        else:
            print("❌ Failed to insert sample data")
    else:
        print("❌ Failed to create database and tables")

if __name__ == "__main__":
    main()
