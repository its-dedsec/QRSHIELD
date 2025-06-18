import sys
import os

# Add app/ to the path
APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app'))
if APP_PATH not in sys.path:
    sys.path.insert(0, APP_PATH)

print(f"Using APP_PATH: {APP_PATH}")

from app.database.db import engine
from sqlalchemy import text

# Verify tables
with engine.connect() as connection:
    result = connection.execute(text("SHOW FULL TABLES"))
    tables = result.fetchall()

    print(f"\nTables in database '{connection.engine.url.database}':")
    if not tables:
        print("No tables found!")
    else:
        for row in tables:
            print(row[0])
