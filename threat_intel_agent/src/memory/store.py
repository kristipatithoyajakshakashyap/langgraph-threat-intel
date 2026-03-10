import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MemoryStore:
    def __init__(self, storage_path: str = None):
        if storage_path is None:
            storage_path = os.path.join(BASE_DIR, "..", "memory_store")
        self.storage_path = os.path.abspath(storage_path)
        self.investigations_file = os.path.join(
            self.storage_path, "investigations.json"
        )
        self._ensure_storage()

    def _ensure_storage(self):
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)
        if not os.path.exists(self.investigations_file):
            with open(self.investigations_file, "w") as f:
                json.dump([], f)

    def save_investigation(self, state: Dict[str, Any]) -> None:
        investigation = {
            "investigation_id": state.get("investigation_id"),
            "user_query": state.get("user_query", ""),
            "indicators": state.get("indicators", []),
            "risk_score": state.get("risk_score", 0),
            "confidence": state.get("confidence", 0),
            "raw_intel": state.get("raw_intel", {}),
            "correlated_findings": state.get("correlated_findings", {}),
            "gemini_analysis": state.get("gemini_analysis", ""),
            "threat_explanation": state.get("threat_explanation", ""),
            "resolution_steps": state.get("resolution_steps", ""),
            "recommendations": state.get("recommendations", []),
            "executed_actions": state.get("executed_actions", []),
            "report": state.get("report", ""),
            "summary": state.get("gemini_analysis", "")[:200],
            "timestamp": state.get("timestamp"),
            "status": state.get("status"),
            "errors": state.get("errors", []),
        }

        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)

        existing_index = None
        for idx, inv in enumerate(investigations):
            if inv.get("investigation_id") == investigation.get("investigation_id"):
                existing_index = idx
                break

        if existing_index is not None:
            investigations[existing_index] = investigation
        else:
            investigations.append(investigation)

        with open(self.investigations_file, "w") as f:
            json.dump(investigations, f, indent=2)

    def get_similar_cases(
        self, indicator_value: str, limit: int = 5
    ) -> List[Dict[str, Any]]:
        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)

        similar = [
            inv
            for inv in investigations
            if any(
                ind.get("value") == indicator_value for ind in inv.get("indicators", [])
            )
        ]
        return similar[:limit]

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)

        for inv in investigations:
            if inv.get("investigation_id") == investigation_id:
                return inv
        return None

    def delete_investigation(self, investigation_id: str) -> bool:
        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)

        original_count = len(investigations)
        investigations = [
            inv
            for inv in investigations
            if inv.get("investigation_id") != investigation_id
        ]

        if len(investigations) == original_count:
            return False

        with open(self.investigations_file, "w") as f:
            json.dump(investigations, f, indent=2)
        return True

    def get_recent_investigations(self, limit: int = 10) -> List[Dict[str, Any]]:
        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)
        return sorted(
            investigations, key=lambda x: x.get("timestamp", ""), reverse=True
        )[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        with open(self.investigations_file, "r") as f:
            investigations = json.load(f)

        if not investigations:
            return {"total": 0, "avg_risk_score": 0}

        risk_scores = [inv.get("risk_score", 0) for inv in investigations]
        return {
            "total": len(investigations),
            "avg_risk_score": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "high_risk_count": len([r for r in risk_scores if r >= 80]),
            "recent": len(
                [inv for inv in investigations if inv.get("status") == "completed"]
            ),
        }


memory_store = MemoryStore()
