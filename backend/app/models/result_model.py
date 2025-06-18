# app/models/result_model.py

from sqlalchemy import Column, Integer, String, Text, DateTime
from app.database.db import Base
from datetime import datetime

class QRScanResult(Base):
    __tablename__ = 'qr_scan_results'

    id = Column(Integer, primary_key=True, index=True)
    qr_content = Column(Text, nullable=False)
    decoded_url = Column(String(500), nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    scan_status = Column(String(100), nullable=True)
    virus_total_result = Column(Text, nullable=True)
    google_safe_browsing_result = Column(Text, nullable=True)
    urlscan_result = Column(Text, nullable=True)
    ip_info = Column(Text, nullable=True)
