# app/services/urlscan_service.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("URLSCAN_API_KEY")
BASE_URL = "https://urlscan.io/api/v1/scan/"

def scan_url(url_to_scan):
    headers = {
        "API-Key": API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "url": url_to_scan,
        "visibility": "private"  # or "public" if you want public results
    }

    response = requests.post(BASE_URL, headers=headers, json=payload)

    if response.status_code == 200:
        return response.json()  # contains scan id + link to results
    else:
        return {"error": "Failed to submit URL", "status_code": response.status_code}
