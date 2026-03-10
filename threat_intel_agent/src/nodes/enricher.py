import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from src.tools import VirusTotalClient, AbuseIPDBClient, ShodanClient

vt_client = VirusTotalClient()
abuse_client = AbuseIPDBClient()
shodan_client = ShodanClient()


def enricher_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich indicators with data from all threat intelligence sources"""
    indicators = state.get("indicators", [])

    raw_intel = {"virustotal": {}, "abuseipdb": {}, "shodan": {}}

    errors = []

    for indicator in indicators:
        ind_type = indicator.get("type", "")
        value = indicator.get("value", "")

        vt_result = vt_client.lookup(indicator)
        if vt_result.get("found"):
            raw_intel["virustotal"][value] = vt_result
        elif "error" in vt_result:
            errors.append(f"VirusTotal error for {value}: {vt_result.get('error')}")

        if ind_type == "ip":
            abuse_result = abuse_client.lookup(indicator)
            if abuse_result.get("found"):
                raw_intel["abuseipdb"][value] = abuse_result
            elif "error" in abuse_result:
                errors.append(
                    f"AbuseIPDB error for {value}: {abuse_result.get('error')}"
                )

            shodan_result = shodan_client.lookup(indicator)
            if shodan_result.get("found"):
                raw_intel["shodan"][value] = shodan_result
            elif "error" in shodan_result:
                errors.append(f"Shodan error for {value}: {shodan_result.get('error')}")

    state["raw_intel"] = raw_intel
    state["errors"].extend(errors)
    state["status"] = "enrichment_complete"

    return state
