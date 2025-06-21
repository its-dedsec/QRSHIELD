# app/services/google_safe_browsing_service.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
BASE_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_url(url_to_check):
    payload = {
        "client": {
            "clientId": "qrshield",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url_to_check}
            ]
        }
    }

    response = requests.post(BASE_URL, json=payload)

    if response.status_code == 200:
        return response.json()  # empty {} = safe
    else:
        return {"error": "Failed to check URL", "status_code": response.status_code}
