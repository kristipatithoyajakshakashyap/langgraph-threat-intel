from typing import Dict, Any
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from config.settings import settings


def correlator_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Correlate findings from multiple sources and calculate risk scores"""
    raw_intel = state.get("raw_intel", {})
    indicators = state.get("indicators", [])

    vt_data = raw_intel.get("virustotal", {})
    abuse_data = raw_intel.get("abuseipdb", {})
    shodan_data = raw_intel.get("shodan", {})

    total_risk = 0
    correlation_details = []

    for indicator in indicators:
        value = indicator.get("value", "")
        ind_type = indicator.get("type", "")

        ind_risk = 0
        sources_found = 0

        if value in vt_data:
            sources_found += 1
            vt_stats = vt_data[value].get("stats", {})
            malicious = vt_stats.get("malicious", 0)
            suspicious = vt_stats.get("suspicious", 0)
            total = sum(vt_stats.values())

            if total > 0:
                vt_score = ((malicious * 100) + (suspicious * 50)) / total
                ind_risk += vt_score * 0.4

        if ind_type == "ip" and value in abuse_data:
            sources_found += 1
            abuse_score = abuse_data[value].get("abuse_confidence_score", 0)
            ind_risk += abuse_score * 0.4

        if ind_type == "ip" and value in shodan_data:
            sources_found += 1
            shodan_info = shodan_data[value]
            ports = shodan_info.get("ports", [])
            risky_ports = [21, 22, 23, 25, 53, 135, 139, 443, 445, 3389, 8080, 8443]
            port_risk = sum(1 for p in ports if p in risky_ports) * 10
            ind_risk = min(ind_risk + port_risk, 100)

        if sources_found > 0:
            ind_risk = ind_risk / (sources_found * 0.8)

        total_risk += ind_risk

        correlation_details.append(
            {
                "indicator": value,
                "type": ind_type,
                "risk_score": min(ind_risk, 100),
                "sources_found": sources_found,
            }
        )

    avg_risk = total_risk / len(indicators) if indicators else 0

    correlated_findings = {
        "details": correlation_details,
        "indicators_analyzed": len(indicators),
        "sources_queried": ["VirusTotal", "AbuseIPDB", "Shodan"],
    }

    state["correlated_findings"] = correlated_findings
    state["risk_score"] = min(avg_risk, 100)
    state["status"] = "correlation_complete"

    return state
