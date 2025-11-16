"""MySQL users table + salted hashing (no chat storage)."""
import os
import secrets
import pymysql
from contextlib import contextmanager
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from ..common.utils import sha256_hex

# Load environment variables
load_dotenv()


class DatabaseError(Exception):
    """Database operation error."""
    pass


class UserDatabase:
    """MySQL database for user management with salted password hashing."""
    
    def __init__(self, host: str = 'localhost', port: int = 3306, 
                 user: str = 'scuser', password: str = 'scpass', 
                 database: str = 'securechat'):
        """Initialize database connection parameters."""
        self.config = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': database,
            'charset': 'utf8mb4',
            'autocommit': True
        }
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup."""
        conn = None
        try:
            conn = pymysql.connect(**self.config)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise DatabaseError(f"Database error: {e}")
        finally:
            if conn:
                conn.close()
    
    def initialize_database(self):
        """Create users table if it doesn't exist."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB;
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(create_table_sql)
                conn.commit()
    
    def generate_salt(self) -> bytes:
        """Generate a random 16-byte salt."""
        return secrets.token_bytes(16)
    
    def hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash password with salt using SHA-256.
        
        Args:
            password: Plain text password
            salt: 16-byte salt
            
        Returns:
            Hex-encoded SHA-256 hash of salt||password
        """
        # Concatenate salt and password
        salted_password = salt + password.encode('utf-8')
        
        # Return hex-encoded SHA-256 hash
        return sha256_hex(salted_password)
    
    def register_user(self, email: str, username: str, password: str) -> bool:
        """
        Register a new user with salted password hash.
        
        Args:
            email: User email address
            username: Unique username
            password: Plain text password
            
        Returns:
            True if registration successful
            
        Raises:
            DatabaseError: If user already exists or database error occurs
        """
        # Check if user already exists
        if self.user_exists(email, username):
            raise DatabaseError("User already exists")
        
        # Generate salt and hash password
        salt = self.generate_salt()
        pwd_hash = self.hash_password(password, salt)
        
        # Insert user into database
        insert_sql = """
        INSERT INTO users (email, username, salt, pwd_hash)
        VALUES (%s, %s, %s, %s)
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(insert_sql, (email, username, salt, pwd_hash))
                conn.commit()
        
        return True
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with email and password.
        
        Args:
            email: User email address
            password: Plain text password
            
        Returns:
            User record dict if authentication successful, None otherwise
        """
        # Get user record
        user = self.get_user_by_email(email)
        if not user:
            return None
        
        # Hash provided password with stored salt
        provided_hash = self.hash_password(password, user['salt'])
        
        # Compare hashes (constant-time comparison)
        if self.constant_time_compare(provided_hash, user['pwd_hash']):
            return user
        
        return None
    
    def constant_time_compare(self, a: str, b: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def user_exists(self, email: str, username: str) -> bool:
        """
        Check if user exists by email or username.
        
        Args:
            email: User email address
            username: Username
            
        Returns:
            True if user exists
        """
        select_sql = """
        SELECT COUNT(*) as count FROM users 
        WHERE email = %s OR username = %s
        """
        
        with self.get_connection() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(select_sql, (email, username))
                result = cursor.fetchone()
                return result['count'] > 0
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get user record by email address.
        
        Args:
            email: User email address
            
        Returns:
            User record dict or None if not found
        """
        select_sql = """
        SELECT id, email, username, salt, pwd_hash, created_at
        FROM users WHERE email = %s
        """
        
        with self.get_connection() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(select_sql, (email,))
                return cursor.fetchone()
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Get user record by username.
        
        Args:
            username: Username
            
        Returns:
            User record dict or None if not found
        """
        select_sql = """
        SELECT id, email, username, salt, pwd_hash, created_at
        FROM users WHERE username = %s
        """
        
        with self.get_connection() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(select_sql, (username,))
                return cursor.fetchone()


# Global database instance
db = None


def get_database() -> UserDatabase:
    """Get global database instance."""
    global db
    if db is None:
        # Load config from environment
        # Try both MYSQL_PASSWORD and MYSQL_PASS for compatibility
        db_password = os.getenv('DB_PASSWORD') or os.getenv('MYSQL_PASS', 'scpass')
        db = UserDatabase(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'scuser'),
            password=db_password,
            database=os.getenv('DB_NAME', 'securechat')
        )
    return db


def main():
    """Initialize database tables."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Database initialization')
    parser.add_argument('--init', action='store_true', help='Initialize database tables')
    args = parser.parse_args()
    
    if args.init:
        db = get_database()
        db.initialize_database()
        print("Database initialized successfully")


if __name__ == '__main__':
    main()
