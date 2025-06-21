#!/usr/bin/env python3
# run_server.py

import os
import sys
import subprocess
import uvicorn
from pathlib import Path

def check_requirements():
    """Check if all required packages are installed"""
    print("Checking requirements...")
    
    required_packages = [
        'fastapi', 'uvicorn', 'pyzbar', 'cv2', 'sqlalchemy', 
        'mysql.connector', 'dotenv', 'requests', 'PIL'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'cv2':
                import cv2
            elif package == 'PIL':
                from PIL import Image
            elif package == 'mysql.connector':
                import mysql.connector
            else:
                __import__(package)
            print(f"✓ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package} - MISSING")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Please install missing packages using:")
        print("pip install -r requirements.txt")
        return False
    
    print("All requirements satisfied!")
    return True

def check_env_file():
    """Check if .env file exists and contains required variables"""
    print("\nChecking environment configuration...")
    
    env_file = Path('.env')
    if not env_file.exists():
        print("✗ .env file not found!")
        print("Please create a .env file based on .env.template")
        return False
    
    required_vars = [
        'MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DB'
    ]
    
    from dotenv import load_dotenv
    load_dotenv()
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"✗ Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    print("✓ Environment configuration OK")
    return True

def check_database_connection():
    """Check if database connection is working"""
    print("\nChecking database connection...")
    
    try:
        from app.database.db import engine
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        print("✓ Database connection successful")
        return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        print("Please check your database configuration and ensure MySQL is running")
        return False

def create_tables():
    """Create database tables if they don't exist"""
    print("\nCreating database tables...")
    
    try:
        from app.database.db import engine, Base
        from app.models.result_model import QRScanResult
        
        Base.metadata.create_all(bind=engine)
        print("✓ Database tables created/verified")
        return True
    except Exception as e:
        print(f"✗ Failed to create tables: {e}")
        return False

def run_server(host="0.0.0.0", port=8000, reload=True, log_level="info"):
    """Run the FastAPI server"""
    print(f"\nStarting QRShield server on {host}:{port}")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        uvicorn.run(
            "app:app",
            host=host,
            port=port,
            reload=reload,
            log_level=log_level,
            access_log=True
        )
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")

def main():
    """Main function to run all checks and start server"""
    print("QRShield FastAPI Server Startup")
    print("=" * 40)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check environment
    if not check_env_file():
        sys.exit(1)
    
    # Check database
    if not check_database_connection():
        sys.exit(1)
    
    # Create tables
    if not create_tables():
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("All checks passed! Starting server...")
    print("=" * 40)
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='QRShield FastAPI Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--no-reload', action='store_true', help='Disable auto-reload')
    parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error'])
    
    args = parser.parse_args()
    
    # Run server
    run_server(
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
        log_level=args.log_level
    )

if __name__ == "__main__":
    main()
