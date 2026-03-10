from langgraph.graph import StateGraph, START, END
from typing import Dict, Any
from .state import AgentState
from .nodes import (
    router_node,
    enricher_node,
    correlator_node,
    reasoning_node,
    threat_explanation_node,
    resolution_node,
    reviewer_node,
    should_review,
    executor_node,
    reporter_node,
)


def create_threat_intel_graph() -> StateGraph:
    """Create the LangGraph workflow for threat intelligence investigation"""

    workflow = StateGraph(AgentState)

    workflow.add_node("router", router_node)
    workflow.add_node("enricher", enricher_node)
    workflow.add_node("correlator", correlator_node)
    workflow.add_node("reasoning", reasoning_node)
    workflow.add_node("threat_explainer", threat_explanation_node)
    workflow.add_node("resolution", resolution_node)
    workflow.add_node("reviewer", reviewer_node)
    workflow.add_node("executor", executor_node)
    workflow.add_node("reporter", reporter_node)

    workflow.add_edge(START, "router")
    workflow.add_edge("router", "enricher")
    workflow.add_edge("enricher", "correlator")
    workflow.add_edge("correlator", "reasoning")
    workflow.add_edge("reasoning", "threat_explainer")
    workflow.add_edge("threat_explainer", "resolution")

    workflow.add_conditional_edges(
        "resolution", should_review, {"review": "reviewer", "proceed": "executor"}
    )

    workflow.add_edge("reviewer", "executor")
    workflow.add_edge("executor", "reporter")
    workflow.add_edge("reporter", END)

    return workflow


def compile_graph():
    """Compile the graph with checkpointing for persistence"""
    from langgraph.checkpoint.memory import MemorySaver

    workflow = create_threat_intel_graph()
    checkpointer = MemorySaver()

    return workflow.compile(checkpointer=checkpointer)


graph = compile_graph()


async def run_investigation(query: str, investigation_id: str = None) -> Dict[str, Any]:
    """Run a threat intelligence investigation"""
    import uuid
    from datetime import datetime

    if investigation_id is None:
        investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"

    initial_state: AgentState = {
        "user_query": query,
        "indicators": [],
        "investigation_id": investigation_id,
        "raw_intel": {},
        "correlated_findings": {},
        "risk_score": 0.0,
        "gemini_analysis": "",
        "threat_explanation": "",
        "resolution_steps": "",
        "recommendations": [],
        "requires_human_review": False,
        "approved_actions": [],
        "executed_actions": [],
        "conversation_id": investigation_id,
        "memory_context": None,
        "confidence": 0.0,
        "errors": [],
        "status": "initialized",
        "report": "",
        "timestamp": datetime.now().isoformat(),
    }

    config = {"configurable": {"thread_id": investigation_id}}

    try:
        result = await graph.ainvoke(initial_state, config)
        return result
    except Exception as e:
        initial_state["status"] = "error"
        initial_state["errors"].append(str(e))
        return initial_state
