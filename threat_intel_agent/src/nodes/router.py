import re
from typing import Dict, Any, List
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def router_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Parse user query and extract indicators"""
    user_query = state.get("user_query", "")

    indicators = extract_indicators(user_query)

    state["indicators"] = indicators
    state["status"] = "indicators_extracted"

    return state


def extract_indicators(query: str) -> List[Dict[str, str]]:
    """Extract indicators from user query using regex patterns"""
    indicators = []

    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ips = re.findall(ip_pattern, query)
    for ip in ips:
        indicators.append({"type": "ip", "value": ip, "source": "query"})

    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, query)
    for url in urls:
        indicators.append({"type": "url", "value": url, "source": "query"})

    hash_patterns = [
        r"\b[a-fA-F0-9]{32}\b",
        r"\b[a-fA-F0-9]{40}\b",
        r"\b[a-fA-F0-9]{64}\b",
    ]
    for pattern in hash_patterns:
        hashes = re.findall(pattern, query)
        for h in hashes:
            if len(h) == 32:
                indicators.append(
                    {"type": "hash", "value": h, "source": "query", "hash_type": "md5"}
                )
            elif len(h) == 40:
                indicators.append(
                    {"type": "hash", "value": h, "source": "query", "hash_type": "sha1"}
                )
            elif len(h) == 64:
                indicators.append(
                    {
                        "type": "hash",
                        "value": h,
                        "source": "query",
                        "hash_type": "sha256",
                    }
                )

    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    domains = re.findall(domain_pattern, query)
    for domain in domains:
        if domain not in [
            ind["value"] for ind in indicators if ind.get("type") in ["ip", "url"]
        ]:
            indicators.append({"type": "domain", "value": domain, "source": "query"})

    if not indicators:
        words = query.split()
        for word in words:
            if (
                re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$", word)
                and len(word) > 3
            ):
                if "." in word:
                    indicators.append(
                        {"type": "domain", "value": word, "source": "query"}
                    )

    return indicators
