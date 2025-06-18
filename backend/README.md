# QRShield 🛡️  
A backend API to analyze and verify QR codes for safety using free APIs and URL analysis.

---

## 🚀 Features

- Upload QR code images (JPG, PNG)
- Decode QR content (URL or text)
- Analyze destination URL for safety using:
  - VirusTotal
  - Google Safe Browsing
  - URLScan.io
  - IP Geolocation APIs
- Save scan reports in MySQL database
- REST API — ready to connect with frontend app

---

## 🛠️ Stack

- Python 3.13
- FastAPI
- Uvicorn
- OpenCV (cv2)
- Pyzbar (QR decoding)
- MySQL Connector
- dotenv (for API keys)

---

## ⚙️ Setup

```bash
# Clone repo
git clone <your-repo-url>

# Enter project folder
cd QRSHIELD

# Create virtual environment
python -m venv venv

# Activate venv
# For Windows (Powershell):
.\venv\Scripts\activate

# Upgrade tools
pip install --upgrade pip setuptools wheel

# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn app:app --reload
