#!/usr/bin/env python3
"""
Test MySQL database connection for SecureChat.
"""
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def test_database_connection():
    """Test database connection and basic operations."""
    try:
        from app.storage.db import get_database
        
        print("Testing MySQL database connection...")
        
        # Get database instance
        db = get_database()
        
        # Test connection
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT VERSION()")
                version = cursor.fetchone()
                print(f"✓ Connected to MySQL version: {version[0]}")
        
        # Test table creation
        print("Testing table initialization...")
        db.initialize_database()
        print("✓ Database tables initialized successfully")
        
        # Test user operations
        print("Testing user operations...")
        
        # Try to register a test user
        try:
            db.register_user("test@example.com", "testuser", "testpassword")
            print("✓ User registration works")
            
            # Try to authenticate
            user = db.authenticate_user("test@example.com", "testpassword")
            if user:
                print("✓ User authentication works")
            else:
                print("✗ User authentication failed")
                
        except Exception as e:
            print(f"User operations test failed: {e}")
        
        print("\n🎉 Database connection test completed successfully!")
        print("Your MySQL container is ready for SecureChat!")
        
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure MySQL container is running: docker ps")
        print("2. Check container logs: docker logs securechat-db")
        print("3. Verify connection settings in .env file")
        return False
    
    return True

if __name__ == "__main__":
    test_database_connection()