# app/services/qr_decoder.py

import cv2
import numpy as np
from pyzbar import pyzbar
from urllib.parse import urlparse
import base64
from io import BytesIO
from PIL import Image

def decode_qr_from_bytes(image_bytes: bytes):
    """
    Decode QR code from image bytes
    
    Args:
        image_bytes: Raw image bytes
        
    Returns:
        tuple: (decoded_text, error_message)
    """
    try:
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        
        # Decode image using OpenCV
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return None, "Invalid image format or corrupted image"
        
        # Convert to grayscale for better QR detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Apply some preprocessing to improve detection
        # Gaussian blur to reduce noise
        blurred = cv2.GaussianBlur(gray, (3, 3), 0)
        
        # Try to decode QR codes
        qr_codes = pyzbar.decode(blurred)
        
        if not qr_codes:
            # Try with original grayscale if preprocessing didn't work
            qr_codes = pyzbar.decode(gray)
        
        if not qr_codes:
            # Try with different preprocessing - adaptive threshold
            adaptive_thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            qr_codes = pyzbar.decode(adaptive_thresh)
        
        if not qr_codes:
            return None, "No QR code found in the image"
        
        # Get the first QR code found
        qr_code = qr_codes[0]
        
        # Decode the data
        try:
            decoded_data = qr_code.data.decode('utf-8')
        except UnicodeDecodeError:
            # Try with different encodings
            try:
                decoded_data = qr_code.data.decode('latin-1')
            except UnicodeDecodeError:
                decoded_data = qr_code.data.decode('ascii', errors='ignore')
        
        # Get QR code type
        qr_type = qr_code.type
        
        # Get bounding box coordinates
        rect = qr_code.rect
        
        return {
            'data': decoded_data,
            'type': qr_type,
            'rect': {
                'left': rect.left,
                'top': rect.top,
                'width': rect.width,
                'height': rect.height
            }
        }, None
        
    except Exception as e:
        return None, f"Error processing image: {str(e)}"

def decode_qr_from_base64(base64_string: str):
    """
    Decode QR code from base64 encoded image
    
    Args:
        base64_string: Base64 encoded image string
        
    Returns:
        tuple: (decoded_text, error_message)
    """
    try:
        # Remove data URL prefix if present
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]
        
        # Decode base64 to bytes
        image_bytes = base64.b64decode(base64_string)
        
        return decode_qr_from_bytes(image_bytes)
        
    except Exception as e:
        return None, f"Error decoding base64 image: {str(e)}"

def is_url(text: str) -> bool:
    """
    Check if the decoded text is a URL
    
    Args:
        text: Text to check
        
    Returns:
        bool: True if text is a valid URL
    """
    try:
        result = urlparse(text)
        return all([result.scheme, result.netloc])
    except:
        return False

def analyze_qr_content(qr_data: str):
    """
    Analyze QR code content and determine its type
    
    Args:
        qr_data: Decoded QR code data
        
    Returns:
        dict: Analysis results
    """
    analysis = {
        'content': qr_data,
        'type': 'unknown',
        'details': {}
    }
    
    # Check if it's a URL
    if is_url(qr_data):
        analysis['type'] = 'url'
        parsed_url = urlparse(qr_data)
        analysis['details'] = {
            'scheme': parsed_url.scheme,
            'domain': parsed_url.netloc,
            'path': parsed_url.path,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment
        }
    
    # Check for email
    elif '@' in qr_data and '.' in qr_data.split('@')[-1]:
        analysis['type'] = 'email'
        analysis['details'] = {'email': qr_data}
    
    # Check for phone number (simple check)
    elif qr_data.startswith(('tel:', '+', '0')) or qr_data.replace('-', '').replace(' ', '').replace('(', '').replace(')', '').isdigit():
        analysis['type'] = 'phone'
        analysis['details'] = {'phone': qr_data}
    
    # Check for WiFi configuration
    elif qr_data.startswith('WIFI:'):
        analysis['type'] = 'wifi'
        # Parse WiFi QR format: WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:false;
        wifi_parts = qr_data.replace('WIFI:', '').split(';')
        wifi_details = {}
        for part in wifi_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                wifi_details[key] = value
        analysis['details'] = wifi_details
    
    # Check for SMS
    elif qr_data.startswith('sms:') or qr_data.startswith('smsto:'):
        analysis['type'] = 'sms'
        analysis['details'] = {'sms': qr_data}
    
    # Check for calendar event
    elif qr_data.startswith('BEGIN:VEVENT'):
        analysis['type'] = 'calendar'
        analysis['details'] = {'vevent': qr_data}
    
    # Check for contact (vCard)
    elif qr_data.startswith('BEGIN:VCARD'):
        analysis['type'] = 'contact'
        analysis['details'] = {'vcard': qr_data}
    
    # Check for coordinates
    elif qr_data.startswith('geo:'):
        analysis['type'] = 'location'
        coords = qr_data.replace('geo:', '').split(',')
        if len(coords) >= 2:
            analysis['details'] = {
                'latitude': coords[0],
                'longitude': coords[1]
            }
    
    # Otherwise, it's plain text
    else:
        analysis['type'] = 'text'
        analysis['details'] = {'text': qr_data}
    
    return analysis

def validate_qr_image(image_bytes: bytes) -> tuple:
    """
    Validate if the uploaded image is suitable for QR code detection
    
    Args:
        image_bytes: Raw image bytes
        
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        # Check file size (max 10MB)
        if len(image_bytes) > 10 * 1024 * 1024:
            return False, "Image file too large (max 10MB)"
        
        # Try to decode the image
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return False, "Invalid image format"
        
        # Check image dimensions
        height, width = img.shape[:2]
        
        if width < 50 or height < 50:
            return False, "Image too small (minimum 50x50 pixels)"
        
        if width > 4000 or height > 4000:
            return False, "Image too large (maximum 4000x4000 pixels)"
        
        return True, None
        
    except Exception as e:
        return False, f"Error validating image: {str(e)}"