import requests
from typing import Dict, Any
from config.settings import settings


class AbuseIPDBClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.base_url = settings.ABUSEIPDB_BASE_URL
        self.headers = {"Key": self.api_key, "Accept": "application/json"}

    def lookup_ip(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        """Look up IP reputation and abuse reports"""
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}
        try:
            response = requests.get(
                f"{self.base_url}/check",
                headers=self.headers,
                params=params,
                timeout=settings.API_TIMEOUT,
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "data": data.get("data", {}),
                    "ip_address": data.get("data", {}).get("ipAddress"),
                    "is_public": data.get("data", {}).get("isPublic"),
                    "ip_version": data.get("data", {}).get("ipVersion"),
                    "is_whitelisted": data.get("data", {}).get("isWhitelisted"),
                    "abuse_confidence_score": data.get("data", {}).get(
                        "abuseConfidenceScore"
                    ),
                    "country_code": data.get("data", {}).get("countryCode"),
                    "country_name": data.get("data", {}).get("countryName"),
                    "isp": data.get("data", {}).get("isp"),
                    "domain": data.get("data", {}).get("domain"),
                    "total_reports": data.get("data", {}).get("totalReports"),
                    "num_unique_users": data.get("data", {}).get("numDistinctUsers"),
                    "last_reported": data.get("data", {}).get("lastReportedAt"),
                    "reports": data.get("data", {}).get("reports", [])[:5],
                }
            return {
                "found": False,
                "error": f"Status: {response.status_code}",
                "detail": response.text,
            }
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup(self, indicator: Dict[str, str]) -> Dict[str, Any]:
        """Generic lookup - AbuseIPDB only supports IPs"""
        ind_type = indicator.get("type", "").lower()
        value = indicator.get("value", "")

        if ind_type == "ip":
            return self.lookup_ip(value)
        return {"found": False, "error": "AbuseIPDB only supports IP addresses"}
