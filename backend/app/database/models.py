# database/models.py

from sqlalchemy import Column, Integer, Text, String, TIMESTAMP, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ScanReport(Base):
    __tablename__ = 'scan_reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    original_url = Column(Text, nullable=True)
    qr_text = Column(Text, nullable=True)
    vt_result = Column(Text, nullable=True)  # Store API results as JSON string
    google_safe_result = Column(Text, nullable=True)
    urlscan_result = Column(Text, nullable=True)
    ip_geolocation = Column(Text, nullable=True)
    scanned_at = Column(TIMESTAMP, server_default=func.now())
