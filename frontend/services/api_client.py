from typing import Any, Dict, List, Optional

import requests

from frontend.models.types import AppStats


class APIClient:
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url

    def check_status(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def get_investigation_stats(self, investigation_id: str) -> Optional[AppStats]:
        try:
            response = requests.get(
                f"{self.base_url}/investigation/{investigation_id}/stats", timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("error"):
                    return None
                return AppStats(
                    avg_risk_score=data.get("risk_score", 0.0),
                    confidence=data.get("confidence", 0.0),
                    indicator_count=data.get("indicator_count", 0),
                    source_count=data.get("source_count", 0),
                    status=data.get("status", "unknown"),
                )
        except Exception:
            pass
        return None

    def get_investigations(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            response = requests.get(
                f"{self.base_url}/investigations?limit={limit}", timeout=10
            )
            if response.status_code == 200:
                return response.json().get("investigations", [])
        except Exception:
            pass
        return []

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        try:
            response = requests.get(
                f"{self.base_url}/investigation/{investigation_id}", timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("error"):
                    return None
                return data
        except Exception:
            pass
        return None

    def submit_investigation(self, query: str) -> Optional[str]:
        try:
            response = requests.post(
                f"{self.base_url}/investigate", json={"query": query}, timeout=120
            )
            if response.status_code == 200:
                return response.json().get("investigation_id")
        except Exception:
            pass
        return None

    def delete_investigation(self, investigation_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.base_url}/investigation/{investigation_id}", timeout=10
            )
            if response.status_code == 200:
                return bool(response.json().get("deleted", False))
        except Exception:
            pass
        return False
