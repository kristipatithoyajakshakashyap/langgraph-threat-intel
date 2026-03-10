from src.memory.store import memory_store
from src.graph import run_investigation
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_banner():
    print("""
================================================================
                                                             
     THREAT INTELLIGENCE AGENT - AI SECURITY SYSTEM           
                                                             
================================================================
    """)


def print_result(result):
    print("\n" + "=" * 70)
    print("INVESTIGATION RESULTS")
    print("=" * 70)

    print(f"\n[+] Investigation ID: {result.get('investigation_id')}")
    print(f"[*] Risk Score: {result.get('risk_score', 0):.1f}/100")
    print(f"[*] Confidence: {result.get('confidence', 0):.1%}")
    print(f"[*] Status: {result.get('status', 'unknown')}")

    indicators = result.get("indicators", [])
    if indicators:
        print("\n[>] Indicators Analyzed:")
        for ind in indicators:
            print(f"   - {ind.get('type').upper()}: {ind.get('value')}")

    recommendations = result.get("recommendations", [])
    if recommendations:
        print("\n[!] Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")

    executed = result.get("executed_actions", [])
    if executed:
        print("\n[>] Actions Taken:")
        for action in executed:
            print(
                f"   - {action.get('action')}: {action.get('simulated_action', 'completed')}"
            )

    print("\n[>] Full Report:")
    print("-" * 70)
    print(result.get("report", "No report generated"))

    memory_store.save_investigation(result)

    print("\n" + "=" * 70)


async def interactive_mode():
    print_banner()
    print("[*] Threat Intelligence Investigation System")
    print("-" * 50)
    print("Enter threat indicators (IP, domain, URL, hash) to investigate")
    print("Type 'exit' or 'quit' to end the session")
    print("Type 'stats' to see investigation statistics")
    print("-" * 50)

    while True:
        try:
            query = input("\n[*] Enter query > ").strip()

            if query.lower() in ["exit", "quit"]:
                print("\n[!] Goodbye!")
                break

            if query.lower() == "stats":
                stats = memory_store.get_statistics()
                print(f"\n[*] Investigation Statistics:")
                print(f"   Total Investigations: {stats.get('total', 0)}")
                print(f"   Average Risk Score: {stats.get('avg_risk_score', 0):.1f}")
                print(f"   High Risk Cases: {stats.get('high_risk_count', 0)}")
                continue

            if not query:
                continue

            print("\n[*] Investigating... (this may take a moment)")
            result = await run_investigation(query)
            print_result(result)

        except KeyboardInterrupt:
            print("\n\n[!] Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n[!] Error: {str(e)}")
            import traceback

            traceback.print_exc()


def main():
    try:
        asyncio.run(interactive_mode())
    except:
        pass


if __name__ == "__main__":
    main()
