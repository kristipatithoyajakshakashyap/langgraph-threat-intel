import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threat_intel_agent.src.graph import run_investigation
from threat_intel_agent.src.memory.store import memory_store


async def main():
    print("=" * 70)
    print("   THREAT INTELLIGENCE AGENT - AI SECURITY SYSTEM")
    print("=" * 70)
    print()

    test_queries = ["1.1.1.1", "8.8.8.8", "evil.com", "https://malware.test/payload"]

    for query in test_queries:
        print(f"\n[>] Testing with query: {query}")
        print("-" * 60)

        result = await run_investigation(query)

        print(f"\n[+] Investigation ID: {result.get('investigation_id')}")
        print(f"[*] Risk Score: {result.get('risk_score', 0):.1f}/100")
        print(f"[*] Confidence: {result.get('confidence', 0):.1%}")
        print(f"[*] Status: {result.get('status', 'unknown')}")

        indicators = result.get("indicators", [])
        if indicators:
            print(f"\n[>] Indicators Found: {len(indicators)}")
            for ind in indicators:
                print(f"   - {ind.get('type').upper()}: {ind.get('value')}")

        raw_intel = result.get("raw_intel", {})

        vt_data = raw_intel.get("virustotal", {})
        if vt_data:
            print(f"\n[VIRUSTOTAL] Results:")
            for value, data in vt_data.items():
                stats = data.get("stats", {})
                print(f"   {value}:")
                print(f"      Malicious: {stats.get('malicious', 0)}")
                print(f"      Suspicious: {stats.get('suspicious', 0)}")
                print(f"      Undetected: {stats.get('undetected', 0)}")

        abuse_data = raw_intel.get("abuseipdb", {})
        if abuse_data:
            print(f"\n[ABUSEIPDB] Results:")
            for value, data in abuse_data.items():
                print(f"   {value}:")
                print(
                    f"      Confidence Score: {data.get('abuse_confidence_score', 0)}%"
                )
                print(f"      Total Reports: {data.get('total_reports', 0)}")
                print(f"      Country: {data.get('country_name', 'Unknown')}")

        shodan_data = raw_intel.get("shodan", {})
        if shodan_data:
            print(f"\n[SHODAN] Results:")
            for value, data in shodan_data.items():
                print(f"   {value}:")
                print(f"      Organization: {data.get('org', 'Unknown')}")
                print(f"      ISP: {data.get('isp', 'Unknown')}")
                print(f"      Open Ports: {len(data.get('ports', []))}")
                print(f"      Country: {data.get('country_name', 'Unknown')}")

        recommendations = result.get("recommendations", [])
        if recommendations:
            print(f"\n[!] Recommendations:")
            for rec in recommendations[:3]:
                print(f"   - {rec}")

        print("\n" + "=" * 70)

    print("\n[*] All tests completed!")
    stats = memory_store.get_statistics()
    print(f"[*] Total Investigations: {stats.get('total', 0)}")


if __name__ == "__main__":
    asyncio.run(main())
