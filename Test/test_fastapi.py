# test_app.py

import requests
import json
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import qrcode

# Base URL for your FastAPI app
BASE_URL = "http://localhost:8000"

def create_test_qr_image(data: str, filename: str = None):
    """Create a test QR code image"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save to bytes
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    
    if filename:
        with open(filename, 'wb') as f:
            f.write(img_byte_arr)
    
    return img_byte_arr

def test_health_check():
    """Test the health check endpoint"""
    print("Testing health check...")
    
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
        response = requests.get(f"{BASE_URL}/health")
        print(f"Health Status: {response.status_code}")
        print(f"Health Response: {response.json()}")
        
    except Exception as e:
        print(f"Health check failed: {e}")

def test_qr_scan_url():
    """Test QR code scanning with URL"""
    print("\nTesting QR scan with URL...")
    
    try:
        # Create a test QR code with a URL
        test_url = "https://www.example.com"
        qr_image = create_test_qr_image(test_url, "test_qr_url.png")
        
        # Upload and scan
        files = {"file": ("test_qr.png", qr_image, "image/png")}
        response = requests.post(f"{BASE_URL}/scan-qr", files=files)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
    except Exception as e:
        print(f"QR URL scan test failed: {e}")

def test_qr_scan_text():
    """Test QR code scanning with text"""
    print("\nTesting QR scan with text...")
    
    try:
        # Create a test QR code with text
        test_text = "Hello, this is a test QR code!"
        qr_image = create_test_qr_image(test_text, "test_qr_text.png")
        
        # Upload and scan
        files = {"file": ("test_qr_text.png", qr_image, "image/png")}
        response = requests.post(f"{BASE_URL}/scan-qr", files=files)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
    except Exception as e:
        print(f"QR text scan test failed: {e}")

def test_qr_scan_malicious():
    """Test QR code scanning with potentially malicious URL"""
    print("\nTesting QR scan with suspicious URL...")
    
    try:
        # Create a test QR code with a suspicious URL
        test_url = "http://suspicious-site.tk/login?verify=true&urgent=now"
        qr_image = create_test_qr_image(test_url, "test_qr_suspicious.png")
        
        # Upload and scan
        files = {"file": ("test_qr_suspicious.png", qr_image, "image/png")}
        response = requests.post(f"{BASE_URL}/scan-qr", files=files)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
    except Exception as e:
        print(f"QR suspicious scan test failed: {e}")

def test_url_analysis():
    """Test direct URL analysis"""
    print("\nTesting direct URL analysis...")
    
    try:
        test_urls = [
            "https://www.google.com",
            "http://suspicious-site.tk/login",
            "https://bit.ly/3example"
        ]
        
        for url in test_urls:
            print(f"\nAnalyzing: {url}")
            response = requests.post(
                f"{BASE_URL}/analyze-url",
                json={"url": url},
                headers={"Content-Type": "application/json"}
            )
            
            print(f"Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"Risk Level: {data.get('analysis', {}).get('risk_level', 'unknown')}")
                print(f"Risk Score: {data.get('analysis', {}).get('risk_score', 0)}")
                warnings = data.get('analysis', {}).get('warnings', [])
                if warnings:
                    print(f"Warnings: {warnings[:3]}")  # Show first 3 warnings
            else:
                print(f"Error: {response.text}")
                
    except Exception as e:
        print(f"URL analysis test failed: {e}")

def test_scan_history():
    """Test scan history retrieval"""
    print("\nTesting scan history...")
    
    try:
        response = requests.get(f"{BASE_URL}/scan-history?limit=5")
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Total scans: {data.get('total', 0)}")
            print(f"Returned scans: {len(data.get('scans', []))}")
            
            for scan in data.get('scans', [])[:2]:  # Show first 2 scans
                print(f"Scan ID: {scan.get('id')}")
                print(f"Content: {scan.get('qr_content', '')[:50]}...")
                print(f"Status: {scan.get('scan_status')}")
                print("---")
        else:
            print(f"Error: {response.text}")
            
    except Exception as e:
        print(f"Scan history test failed: {e}")

def test_invalid_image():
    """Test with invalid image"""
    print("\nTesting with invalid image...")
    
    try:
        # Create a text file pretending to be an image
        fake_image = b"This is not an image file"
        
        files = {"file": ("fake_image.png", fake_image, "image/png")}
        response = requests.post(f"{BASE_URL}/scan-qr", files=files)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
    except Exception as e:
        print(f"Invalid image test failed: {e}")

def test_no_qr_code():
    """Test with image that has no QR code"""
    print("\nTesting with image without QR code...")
    
    try:
        # Create a simple image without QR code
        img = Image.new('RGB', (200, 200), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((50, 50), "No QR Code Here", fill='black')
        
        img_byte_arr = BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        files = {"file": ("no_qr.png", img_byte_arr, "image/png")}
        response = requests.post(f"{BASE_URL}/scan-qr", files=files)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
    except Exception as e:
        print(f"No QR code test failed: {e}")

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("QRShield FastAPI Application Tests")
    print("=" * 60)
    
    test_health_check()
    test_qr_scan_url()
    test_qr_scan_text()
    test_qr_scan_malicious()
    test_url_analysis()
    test_scan_history()
    test_invalid_image()
    test_no_qr_code()
    
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    # Install required packages first:
    # pip install requests pillow qrcode[pil]
    
    run_all_tests()
