from typing import Dict, Any
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from config.settings import settings
from config.prompts import ANALYZER_PROMPT

llm = ChatOllama(
    model=settings.OLLAMA_MODEL,
    base_url=settings.OLLAMA_BASE_URL,
    temperature=0.2,
)


def reasoning_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Use Gemini to analyze the correlated findings and provide AI-powered insights"""
    indicators = state.get("indicators", [])
    raw_intel = state.get("raw_intel", {})
    risk_score = state.get("risk_score", 0)
    correlated_findings = state.get("correlated_findings", {})

    indicators_str = ", ".join(
        [f"{ind.get('type')}: {ind.get('value')}" for ind in indicators]
    )

    summary_parts = []

    vt_data = raw_intel.get("virustotal", {})
    if vt_data:
        vt_summary = []
        for value, data in vt_data.items():
            stats = data.get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            vt_summary.append(
                f"{value}: {malicious} malicious, {suspicious} suspicious detections"
            )
        if vt_summary:
            summary_parts.append(f"VirusTotal: {'; '.join(vt_summary)}")

    abuse_data = raw_intel.get("abuseipdb", {})
    if abuse_data:
        abuse_summary = []
        for value, data in abuse_data.items():
            score = data.get("abuse_confidence_score", 0)
            reports = data.get("total_reports", 0)
            country = data.get("country_name", "Unknown")
            abuse_summary.append(
                f"{value}: {score}% confidence, {reports} reports, {country}"
            )
        if abuse_summary:
            summary_parts.append(f"AbuseIPDB: {'; '.join(abuse_summary)}")

    shodan_data = raw_intel.get("shodan", {})
    if shodan_data:
        shodan_summary = []
        for value, data in shodan_data.items():
            ports = data.get("ports", [])
            org = data.get("org", "Unknown")
            services = len(data.get("services", []))
            shodan_summary.append(
                f"{value}: {org}, {len(ports)} open ports, {services} services"
            )
        if shodan_summary:
            summary_parts.append(f"Shodan: {'; '.join(shodan_summary)}")

    source_data = (
        "\n".join(summary_parts)
        if summary_parts
        else "No data available from threat intelligence sources"
    )

    prompt = ANALYZER_PROMPT.format(indicator=indicators_str, source_data=source_data)

    try:
        messages = [
            SystemMessage(
                content="You are a threat intelligence analyst AI. Provide detailed, actionable analysis."
            ),
            HumanMessage(content=prompt),
        ]
        response = llm.invoke(messages)
        gemini_analysis = response.content
    except Exception as e:
        gemini_analysis = f"Analysis unavailable due to error: {str(e)}"

    recommendations = generate_recommendations(risk_score, raw_intel, indicators)

    confidence = calculate_confidence(raw_intel, indicators)

    state["gemini_analysis"] = gemini_analysis
    state["recommendations"] = recommendations
    state["confidence"] = confidence
    state["status"] = "reasoning_complete"

    return state


def generate_recommendations(
    risk_score: float, raw_intel: Dict, indicators: list
) -> list:
    """Generate actionable recommendations based on risk score and intel"""
    recommendations = []

    if risk_score >= 80:
        recommendations.append(
            "CRITICAL: Immediately block all identified malicious indicators at network perimeter"
        )
        recommendations.append("Quarantine affected systems for forensic analysis")
        recommendations.append("Activate incident response team")
    elif risk_score >= 60:
        recommendations.append(
            "HIGH: Implement enhanced monitoring on affected indicators"
        )
        recommendations.append("Block IPs at firewall if malicious activity confirmed")
        recommendations.append("Review recent access logs for compromise indicators")
    elif risk_score >= 40:
        recommendations.append(
            "MEDIUM: Add indicators to watchlist for continued monitoring"
        )
        recommendations.append(
            "Review user/endpoint activity associated with indicators"
        )
    else:
        recommendations.append(
            "LOW: Add to baseline monitoring, no immediate action required"
        )

    vt_data = raw_intel.get("virustotal", {})
    for value, data in vt_data.items():
        stats = data.get("stats", {})
        if stats.get("malicious", 0) > 5:
            recommendations.append(
                f"High malicious detection rate on {value} - consider blocking"
            )

    abuse_data = raw_intel.get("abuseipdb", {})
    for value, data in abuse_data.items():
        if data.get("abuse_confidence_score", 0) > 70:
            recommendations.append(
                f"High abuse confidence ({data.get('abuse_confidence_score')}%) for {value}"
            )

    if not recommendations:
        recommendations.append(
            "No specific threats detected based on available intelligence"
        )

    return recommendations[:5]


def calculate_confidence(raw_intel: Dict, indicators: list) -> float:
    """Calculate confidence score based on data availability"""
    sources_found = 0

    if raw_intel.get("virustotal"):
        sources_found += 1
    if raw_intel.get("abuseipdb"):
        sources_found += 1
    if raw_intel.get("shodan"):
        sources_found += 1

    if not indicators:
        return 0.0

    base_confidence = sources_found / 3.0

    for indicator in indicators:
        if indicator.get("type") == "ip" and sources_found >= 2:
            return min(base_confidence * 1.2, 1.0)

    return base_confidence
