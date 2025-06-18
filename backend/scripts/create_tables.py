import sys
import os

# Add app/ to the path
APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app'))
if APP_PATH not in sys.path:
    sys.path.insert(0, APP_PATH)

print(f"Using APP_PATH: {APP_PATH}")

from app.database.db import engine, Base
from app.models.result_model import QRScanResult

print(f"Loaded model QRScanResult: {QRScanResult}")

# Create tables
print("Creating tables...")
Base.metadata.create_all(bind=engine)
print("Tables created successfully.")
