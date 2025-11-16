#!/usr/bin/env python3
"""Test database connection from Kali Linux to Windows Docker MySQL."""

import pymysql
import os
from dotenv import load_dotenv

def test_connection():
    """Test database connection."""
    # Check if .env file exists
    env_file = '.env'
    if os.path.exists(env_file):
        print(f"✓ Found .env file: {os.path.abspath(env_file)}")
        # Load environment variables
        load_dotenv()
    else:
        print(f"✗ .env file not found in: {os.getcwd()}")
        print("Available files:")
        for f in os.listdir('.'):
            if f.startswith('.env') or 'env' in f.lower():
                print(f"  - {f}")
    
    # Show what environment variables are loaded
    print(f"\nEnvironment variables:")
    print(f"  DB_HOST: {os.getenv('DB_HOST', 'NOT SET')}")
    print(f"  DB_PORT: {os.getenv('DB_PORT', 'NOT SET')}")
    print(f"  DB_USER: {os.getenv('DB_USER', 'NOT SET')}")
    print(f"  DB_NAME: {os.getenv('DB_NAME', 'NOT SET')}")
    
    config = {
        'host': os.getenv('DB_HOST', 'localhost'),  # Default to localhost if not set
        'port': int(os.getenv('DB_PORT', 3305)),
        'user': os.getenv('DB_USER', 'scuser'),
        'password': os.getenv('DB_PASSWORD', 'scpass'),
        'database': os.getenv('DB_NAME', 'securechat'),
        'charset': 'utf8mb4',
        'connect_timeout': 10
    }
    
    print(f"\nTesting connection to {config['host']}:{config['port']}")
    print(f"Database: {config['database']}, User: {config['user']}")
    
    try:
        conn = pymysql.connect(**config)
        print("✓ Database connection successful!")
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"✓ Found {user_count} users in database")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False

if __name__ == '__main__':
    test_connection()