from typing import TypedDict, List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class Indicator(BaseModel):
    type: Literal["ip", "domain", "hash", "url"]
    value: str
    source: Optional[str] = None


class ThreatData(BaseModel):
    virustotal: Optional[Dict[str, Any]] = None
    abuseipdb: Optional[Dict[str, Any]] = None
    shodan: Optional[Dict[str, Any]] = None


class AgentState(TypedDict):
    user_query: str
    indicators: List[Dict[str, str]]
    investigation_id: str

    raw_intel: Dict[str, Any]
    correlated_findings: Dict[str, Any]
    risk_score: float

    gemini_analysis: str
    threat_explanation: str
    resolution_steps: str
    recommendations: List[str]

    requires_human_review: bool
    approved_actions: List[str]
    executed_actions: List[Dict[str, Any]]

    conversation_id: str
    memory_context: Optional[Dict[str, Any]]

    confidence: float
    errors: List[str]
    status: str
    report: str

    timestamp: str


class InvestigationResult(BaseModel):
    investigation_id: str
    indicators: List[Indicator]
    risk_score: float
    severity: str
    confidence: float
    summary: str
    recommendations: List[str]
    raw_intel: ThreatData
    timestamp: datetime = Field(default_factory=datetime.now)
