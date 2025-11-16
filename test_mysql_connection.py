#!/usr/bin/env python3
"""
Simple test to debug MySQL connection issues.
"""
import os
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_mysql_connection():
    """Test different connection configurations."""
    
    # Configuration from .env file
    config_env = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 3306)),
        'user': os.getenv('DB_USER', 'scuser'),
        'password': os.getenv('DB_PASSWORD', 'scpass'),
        'database': os.getenv('DB_NAME', 'securechat'),
        'charset': 'utf8mb4'
    }
    
    # Try port 3305 (what we saw in docker ps)
    config_3305 = {
        'host': 'localhost',
        'port': 3305,
        'user': 'scuser',
        'password': 'scpass',
        'database': 'securechat',
        'charset': 'utf8mb4'
    }
    
    # Try root user
    config_root = {
        'host': 'localhost',
        'port': 3305,
        'user': 'root',
        'password': 'rootpass',
        'database': 'securechat',
        'charset': 'utf8mb4'
    }
    
    configs = [
        ("Config from .env", config_env),
        ("Config with port 3305", config_3305),
        ("Config with root user", config_root)
    ]
    
    for name, config in configs:
        print(f"\nTesting {name}:")
        print(f"  Host: {config['host']}")
        print(f"  Port: {config['port']}")
        print(f"  User: {config['user']}")
        print(f"  Database: {config['database']}")
        
        try:
            conn = pymysql.connect(**config)
            with conn.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()
                print(f"  ✓ SUCCESS - MySQL version: {version[0]}")
            conn.close()
            return config  # Return working config
            
        except Exception as e:
            print(f"  ✗ FAILED - {e}")
    
    return None

if __name__ == "__main__":
    print("MySQL Connection Debug Test")
    print("=" * 40)
    
    working_config = test_mysql_connection()
    
    if working_config:
        print(f"\n🎉 Found working configuration!")
        print("Update your .env file with these values:")
        print(f"DB_HOST={working_config['host']}")
        print(f"DB_PORT={working_config['port']}")
        print(f"DB_USER={working_config['user']}")
        print(f"DB_PASSWORD={working_config['password']}")
        print(f"DB_NAME={working_config['database']}")
    else:
        print(f"\n❌ No working configuration found!")
        print("Check if MySQL container is running: docker ps")