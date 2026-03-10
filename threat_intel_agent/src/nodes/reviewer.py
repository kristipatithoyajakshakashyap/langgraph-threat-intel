from typing import Dict, Any, Literal
from langgraph.types import interrupt
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from config.settings import settings


def reviewer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Human-in-the-loop review node - pauses for human approval on high-risk items"""
    risk_score = state.get("risk_score", 0)
    confidence = state.get("confidence", 0)
    recommendations = state.get("recommendations", [])

    requires_review = False
    review_reason = ""

    if risk_score >= settings.RISK_THRESHOLD_HIGH:
        requires_review = True
        review_reason = f"High risk score ({risk_score:.1f}%)"
    elif confidence < settings.CONFIDENCE_THRESHOLD:
        requires_review = True
        review_reason = f"Low confidence ({confidence:.1%})"
    elif any("CRITICAL" in rec for rec in recommendations):
        requires_review = True
        review_reason = "Critical threat detected"

    state["requires_human_review"] = requires_review

    if requires_review:
        try:
            approval_request = {
                "type": "human_review",
                "reason": review_reason,
                "risk_score": risk_score,
                "recommendations": recommendations,
                "indicators": state.get("indicators", []),
                "analysis": state.get("gemini_analysis", ""),
            }

            result = interrupt(approval_request)

            if result and isinstance(result, dict):
                approved = result.get("approved", False)
                state["approved_actions"] = (
                    result.get("actions", recommendations) if approved else []
                )
            else:
                state["approved_actions"] = []
        except:
            state["approved_actions"] = recommendations[:3]
    else:
        state["approved_actions"] = recommendations[:3]

    state["status"] = "review_complete"
    return state


def should_review(state: Dict[str, Any]) -> Literal["review", "proceed"]:
    """Determine if human review is needed"""
    risk_score = state.get("risk_score", 0)
    confidence = state.get("confidence", 0)
    recommendations = state.get("recommendations", [])

    if risk_score >= settings.RISK_THRESHOLD_HIGH:
        return "review"
    elif confidence < settings.CONFIDENCE_THRESHOLD:
        return "review"
    elif any("CRITICAL" in rec for rec in recommendations):
        return "review"

    return "proceed"
