from typing import Dict, Any
import json
from datetime import datetime


def executor_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Execute approved actions - in a real system, this would integrate with SIEM, firewall, etc."""
    approved_actions = state.get("approved_actions", [])
    indicators = state.get("indicators", [])
    risk_score = state.get("risk_score", 0)

    executed_actions = []

    for action in approved_actions:
        action_result = {
            "action": action,
            "status": "simulated",
            "timestamp": datetime.now().isoformat(),
            "note": "Action logged for demonstration - integrate with actual security tools for production",
        }

        if "block" in action.lower():
            action_result["simulated_action"] = "Added to blocklist"
            action_result["indicators"] = [ind.get("value") for ind in indicators]

        elif "monitor" in action.lower():
            action_result["simulated_action"] = "Added to watchlist"
            action_result["indicators"] = [ind.get("value") for ind in indicators]

        elif "quarantine" in action.lower():
            action_result["simulated_action"] = "Quarantine alert generated"
            action_result["severity"] = "HIGH" if risk_score > 70 else "MEDIUM"

        elif "incident" in action.lower():
            action_result["simulated_action"] = "Incident ticket created"
            action_result["ticket_id"] = (
                f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            )

        executed_actions.append(action_result)

    state["executed_actions"] = executed_actions
    state["status"] = "execution_complete"

    return state
