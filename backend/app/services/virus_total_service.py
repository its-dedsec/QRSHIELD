# app/services/virus_total_service.py

import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3/urls"

def scan_url(url_to_scan):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.post(BASE_URL, headers=headers, data={"url": url_to_scan})

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # Polling result (simplified)
        analysis_response = requests.get(analysis_url, headers=headers)
        
        if analysis_response.status_code == 200:
            return analysis_response.json()
        else:
            return {"error": "Failed to retrieve analysis", "status_code": analysis_response.status_code}
    else:
        return {"error": "Failed to submit URL", "status_code": response.status_code}
