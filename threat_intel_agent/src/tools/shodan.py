import requests
from typing import Dict, Any
from config.settings import settings


class ShodanClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or settings.SHODAN_API_KEY
        self.base_url = settings.SHODAN_BASE_URL

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up IP information from Shodan"""
        try:
            response = requests.get(
                f"{self.base_url}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=settings.API_TIMEOUT,
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "found": True,
                    "ip": data.get("ip_str"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "country_name": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "tags": data.get("tags", []),
                    "services": [
                        {
                            "port": svc.get("port"),
                            "product": svc.get("product"),
                            "version": svc.get("version"),
                            "_shodan": svc.get("_shodan", {}).get("module"),
                        }
                        for svc in data.get("data", [])[:10]
                    ],
                }
            return {"found": False, "error": f"Status: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up domain information - Shodan doesn't have direct domain lookup, return not supported"""
        return {"found": False, "error": "Shodan does not support domain lookups"}

    def lookup(self, indicator: Dict[str, str]) -> Dict[str, Any]:
        """Generic lookup based on indicator type"""
        ind_type = indicator.get("type", "").lower()
        value = indicator.get("value", "")

        if ind_type == "ip":
            return self.lookup_ip(value)
        elif ind_type == "domain":
            return self.lookup_domain(value)
        return {"found": False, "error": "Shodan only supports IP addresses"}
