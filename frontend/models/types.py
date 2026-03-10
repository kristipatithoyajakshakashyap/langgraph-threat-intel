from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AppStats:
    total: int = 0
    avg_risk_score: float = 0.0
    high_risk_count: int = 0
    confidence: float = 0.0
    indicator_count: int = 0
    source_count: int = 0
    status: str = "unknown"


@dataclass
class InvestigationResult:
    investigation_id: str
    risk_score: float
    confidence: float
    status: str
    indicators: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    raw_intel: Dict[str, Any] = field(default_factory=dict)
    gemini_analysis: str = ""
    threat_explanation: str = ""
    resolution_steps: str = ""
    timestamp: str = ""


@dataclass
class ExampleIndicator:
    value: str
    description: str
