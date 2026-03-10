import requests
from urllib.parse import quote
from typing import Dict, Any, Optional, List
from config.settings import settings
import json


class VirusTotalClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.base_url = settings.VIRUSTOTAL_BASE_URL
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP reputation"""
        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(
                url, headers=self.headers, timeout=settings.API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "data": data.get("data", {}),
                    "stats": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {}),
                    "reputation": data.get("data", {})
                    .get("attributes", {})
                    .get("reputation", 0),
                    "last_analysis": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_results", {}),
                }
            return {"found": False, "error": f"Status: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain reputation"""
        url = f"{self.base_url}/domains/{domain}"
        try:
            response = requests.get(
                url, headers=self.headers, timeout=settings.API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "data": data.get("data", {}),
                    "stats": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {}),
                    "reputation": data.get("data", {})
                    .get("attributes", {})
                    .get("reputation", 0),
                }
            return {"found": False, "error": f"Status: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Look up URL analysis"""
        url_id = quote(url, safe="")
        api_url = f"{self.base_url}/urls/{url_id}"
        try:
            response = requests.get(
                api_url, headers=self.headers, timeout=settings.API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "stats": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {}),
                    "last_analysis": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_results", {}),
                }
            return {"found": False, "error": f"Status: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up file hash analysis"""
        url = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(
                url, headers=self.headers, timeout=settings.API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "stats": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {}),
                    "meaningful_names": data.get("data", {})
                    .get("attributes", {})
                    .get("meaningful_names", []),
                    "first_submission": data.get("data", {})
                    .get("attributes", {})
                    .get("first_submission_date"),
                    "last_analysis": data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_results", {}),
                }
            return {"found": False, "error": f"Status: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup(self, indicator: Dict[str, str]) -> Dict[str, Any]:
        """Generic lookup based on indicator type"""
        ind_type = indicator.get("type", "").lower()
        value = indicator.get("value", "")

        if ind_type == "ip":
            return self.lookup_ip(value)
        elif ind_type == "domain":
            return self.lookup_domain(value)
        elif ind_type == "url":
            return self.lookup_url(value)
        elif ind_type == "hash":
            return self.lookup_hash(value)
        return {"found": False, "error": "Unknown indicator type"}
