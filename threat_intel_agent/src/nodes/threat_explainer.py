from typing import Any, Dict, List


def threat_explanation_node(state: Dict[str, Any]) -> Dict[str, Any]:
    indicators = state.get("indicators", [])
    raw_intel = state.get("raw_intel", {})

    sections: List[str] = []
    for indicator in indicators:
        ind_type = indicator.get("type", "unknown")
        value = indicator.get("value", "")
        section = [f"### {ind_type.upper()}: {value}"]

        vt_data = raw_intel.get("virustotal", {}).get(value, {})
        if vt_data:
            stats = vt_data.get("stats", {})
            section.append(
                "- VirusTotal: "
                f"malicious={stats.get('malicious', 0)}, "
                f"suspicious={stats.get('suspicious', 0)}, "
                f"undetected={stats.get('undetected', 0)}"
            )

        if ind_type == "ip":
            abuse_data = raw_intel.get("abuseipdb", {}).get(value, {})
            if abuse_data:
                section.append(
                    "- AbuseIPDB: "
                    f"score={abuse_data.get('abuse_confidence_score', 0)}%, "
                    f"reports={abuse_data.get('total_reports', 0)}, "
                    f"country={abuse_data.get('country_name', 'Unknown')}"
                )

            shodan_data = raw_intel.get("shodan", {}).get(value, {})
            if shodan_data:
                ports = shodan_data.get("ports", [])
                section.append(
                    "- Shodan: "
                    f"org={shodan_data.get('org', 'Unknown')}, open_ports={len(ports)}"
                )

        if len(section) == 1:
            section.append(
                "- No threat intelligence data available for this indicator."
            )

        sections.append("\n".join(section))

    state["threat_explanation"] = (
        "\n\n".join(sections) if sections else "No indicators found."
    )
    state["status"] = "explanation_complete"
    return state


def resolution_node(state: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = state.get("risk_score", 0.0)
    indicators = state.get("indicators", [])

    steps: List[str] = []
    if risk_score >= 80:
        steps.extend(
            [
                "Critical risk actions:",
                "1. Block indicators immediately at firewall/proxy.",
                "2. Isolate affected hosts and start incident response.",
                "3. Preserve logs and artifacts for forensics.",
            ]
        )
    elif risk_score >= 60:
        steps.extend(
            [
                "High risk actions:",
                "1. Block confirmed malicious indicators.",
                "2. Hunt for related activity in SIEM logs.",
                "3. Increase monitoring and alert sensitivity.",
            ]
        )
    elif risk_score >= 40:
        steps.extend(
            [
                "Medium risk actions:",
                "1. Add indicators to watchlists.",
                "2. Monitor endpoints and DNS/proxy telemetry.",
                "3. Reassess if detections increase.",
            ]
        )
    else:
        steps.extend(
            [
                "Low risk actions:",
                "1. Keep indicators in baseline monitoring.",
                "2. No immediate containment needed.",
            ]
        )

    if indicators:
        steps.append("Indicator-specific guidance:")
        for indicator in indicators:
            ind_type = indicator.get("type", "unknown")
            value = indicator.get("value", "")
            if ind_type == "ip":
                steps.append(
                    f"- IP {value}: block at edge and check inbound/outbound logs."
                )
            elif ind_type == "domain":
                steps.append(
                    f"- Domain {value}: block DNS resolution and inspect DNS queries."
                )
            elif ind_type == "url":
                steps.append(f"- URL {value}: block at web proxy and notify users.")
            elif ind_type == "hash":
                steps.append(
                    f"- Hash {value}: search endpoints and quarantine matching files."
                )

    state["resolution_steps"] = "\n".join(steps)
    state["status"] = "resolution_complete"
    return state
