# app.py

from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import cv2
import numpy as np
from pyzbar import pyzbar
import json
import re
from urllib.parse import urlparse
from datetime import datetime
import io
from PIL import Image

# Import our modules
from app.database.db import get_db, engine, Base
from app.models.result_model import QRScanResult
from app.services.virus_total_service import scan_url as vt_scan_url
from app.services.google_safe_browsing_service import check_url as gsb_check_url
from app.services.urlscan_service import scan_url as urlscan_scan_url

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="QRShield API",
    description="A backend API to analyze and verify QR codes for safety",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def decode_qr_from_image(image_bytes: bytes):
    """Decode QR code from image bytes"""
    try:
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        
        # Decode image
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return None, "Invalid image format"
        
        # Convert to grayscale for better QR detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Decode QR codes
        qr_codes = pyzbar.decode(gray)
        
        if not qr_codes:
            return None, "No QR code found in image"
        
        # Return the first QR code found
        qr_data = qr_codes[0].data.decode('utf-8')
        return qr_data, None
        
    except Exception as e:
        return None, f"Error processing image: {str(e)}"

def is_url(text: str) -> bool:
    """Check if text is a valid URL"""
    try:
        result = urlparse(text)
        return all([result.scheme, result.netloc])
    except:
        return False

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""

async def analyze_url(url: str):
    """Analyze URL using multiple security services"""
    results = {
        "virus_total": None,
        "google_safe_browsing": None,
        "urlscan": None,
        "domain": extract_domain(url),
        "is_safe": True,
        "threats_found": []
    }
    
    try:
        # VirusTotal analysis
        vt_result = vt_scan_url(url)
        results["virus_total"] = vt_result
        
        if "error" not in vt_result:
            # Check if there are any malicious detections
            data = vt_result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("stats", {})
            
            if stats.get("malicious", 0) > 0:
                results["is_safe"] = False
                results["threats_found"].append("VirusTotal detected malicious content")
    
    except Exception as e:
        results["virus_total"] = {"error": str(e)}
    
    try:
        # Google Safe Browsing analysis
        gsb_result = gsb_check_url(url)
        results["google_safe_browsing"] = gsb_result
        
        if "matches" in gsb_result and gsb_result["matches"]:
            results["is_safe"] = False
            results["threats_found"].append("Google Safe Browsing detected threats")
    
    except Exception as e:
        results["google_safe_browsing"] = {"error": str(e)}
    
    try:
        # URLScan analysis
        urlscan_result = urlscan_scan_url(url)
        results["urlscan"] = urlscan_result
        
        # URLScan typically returns a scan ID, not immediate results
        # In a production app, you'd poll for results after submission
        
    except Exception as e:
        results["urlscan"] = {"error": str(e)}
    
    return results

@app.get("/")
def read_root():
    """Health check endpoint"""
    return {
        "message": "QRShield Backend is running!",
        "version": "1.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "database": "connected",
        "services": ["VirusTotal", "Google Safe Browsing", "URLScan"],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/scan-qr")
async def scan_qr_code(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Upload and scan a QR code image for safety analysis
    """
    # Validate file type
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    try:
        # Read image bytes
        image_bytes = await file.read()
        
        # Decode QR code
        qr_content, error = decode_qr_from_image(image_bytes)
        
        if error:
            raise HTTPException(status_code=400, detail=error)
        
        # Initialize scan result
        scan_result = QRScanResult(
            qr_content=qr_content,
            scan_date=datetime.utcnow(),
            scan_status="processing"
        )
        
        response_data = {
            "qr_content": qr_content,
            "content_type": "url" if is_url(qr_content) else "text",
            "scan_date": datetime.utcnow().isoformat(),
            "analysis": None
        }
        
        # If QR contains a URL, analyze it
        if is_url(qr_content):
            scan_result.decoded_url = qr_content
            
            # Perform security analysis
            analysis = await analyze_url(qr_content)
            response_data["analysis"] = analysis
            
            # Store detailed results
            scan_result.virus_total_result = json.dumps(analysis["virus_total"])
            scan_result.google_safe_browsing_result = json.dumps(analysis["google_safe_browsing"])
            scan_result.urlscan_result = json.dumps(analysis["urlscan"])
            scan_result.ip_info = json.dumps({"domain": analysis["domain"]})
            
            scan_result.scan_status = "safe" if analysis["is_safe"] else "unsafe"
        else:
            scan_result.scan_status = "completed"
            response_data["analysis"] = {
                "is_safe": True,
                "message": "QR contains text content, no URL analysis performed"
            }
        
        # Save to database
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        response_data["scan_id"] = scan_result.id
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/scan-history")
def get_scan_history(
    limit: int = 10,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    Get scan history with pagination
    """
    try:
        # Get total count
        total = db.query(QRScanResult).count()
        
        # Get paginated results
        scans = db.query(QRScanResult)\
                 .order_by(QRScanResult.scan_date.desc())\
                 .offset(offset)\
                 .limit(limit)\
                 .all()
        
        scan_list = []
        for scan in scans:
            scan_data = {
                "id": scan.id,
                "qr_content": scan.qr_content,
                "decoded_url": scan.decoded_url,
                "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
                "scan_status": scan.scan_status,
            }
            
            # Parse JSON results if they exist
            if scan.virus_total_result:
                try:
                    scan_data["virus_total_result"] = json.loads(scan.virus_total_result)
                except:
                    scan_data["virus_total_result"] = scan.virus_total_result
            
            if scan.google_safe_browsing_result:
                try:
                    scan_data["google_safe_browsing_result"] = json.loads(scan.google_safe_browsing_result)
                except:
                    scan_data["google_safe_browsing_result"] = scan.google_safe_browsing_result
            
            scan_list.append(scan_data)
        
        return {
            "scans": scan_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan history: {str(e)}")

@app.get("/scan/{scan_id}")
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed information about a specific scan
    """
    try:
        scan = db.query(QRScanResult).filter(QRScanResult.id == scan_id).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = {
            "id": scan.id,
            "qr_content": scan.qr_content,
            "decoded_url": scan.decoded_url,
            "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
            "scan_status": scan.scan_status,
            "virus_total_result": None,
            "google_safe_browsing_result": None,
            "urlscan_result": None,
            "ip_info": None
        }
        
        # Parse JSON results
        for field in ["virus_total_result", "google_safe_browsing_result", "urlscan_result", "ip_info"]:
            value = getattr(scan, field)
            if value:
                try:
                    scan_data[field] = json.loads(value)
                except:
                    scan_data[field] = value
        
        return scan_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan details: {str(e)}")

@app.post("/analyze-url")
async def analyze_url_endpoint(url_data: dict):
    """
    Analyze a URL directly without QR code
    """
    url = url_data.get("url")
    
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    if not is_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    try:
        analysis = await analyze_url(url)
        
        return {
            "url": url,
            "analysis": analysis,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """
    Delete a scan record
    """
    try:
        scan = db.query(QRScanResult).filter(QRScanResult.id == scan_id).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        db.delete(scan)
        db.commit()
        
        return {"message": "Scan deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)