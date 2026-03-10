import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uuid

from threat_intel_agent.src.graph import run_investigation
from threat_intel_agent.src.memory.store import memory_store

app = FastAPI(
    title="Threat Intelligence API",
    description="AI-powered threat intelligence investigation system",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvestigationRequest(BaseModel):
    query: str


class InvestigationResponse(BaseModel):
    investigation_id: str
    status: str
    message: str


@app.get("/")
async def root():
    return {
        "name": "Threat Intelligence API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "POST /investigate": "Submit a threat query for investigation",
            "GET /investigation/{id}": "Get investigation result by ID",
            "GET /investigation/{id}/stats": "Get stats for one investigation",
            "DELETE /investigation/{id}": "Delete one investigation",
            "GET /investigations": "List all past investigations",
            "GET /stats": "Get investigation statistics",
        },
    }


@app.post("/investigate", response_model=InvestigationResponse)
async def investigate(request: InvestigationRequest):
    investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"

    try:
        result = await run_investigation(request.query, investigation_id)
        memory_store.save_investigation(result)

        return InvestigationResponse(
            investigation_id=investigation_id,
            status="completed",
            message="Investigation completed successfully",
        )

    except Exception as e:
        return InvestigationResponse(
            investigation_id=investigation_id, status="error", message=str(e)
        )


@app.get("/investigation/{investigation_id}")
async def get_investigation(investigation_id: str):
    investigation = memory_store.get_investigation(investigation_id)
    if investigation:
        return investigation

    return {"error": "Investigation not found", "investigation_id": investigation_id}


@app.get("/investigation/{investigation_id}/stats")
async def get_investigation_stats(investigation_id: str):
    inv = memory_store.get_investigation(investigation_id)
    if not inv:
        return {
            "error": "Investigation not found",
            "investigation_id": investigation_id,
        }

    indicators = inv.get("indicators", [])
    raw_intel = inv.get("raw_intel", {})
    source_hits = 0
    if raw_intel.get("virustotal"):
        source_hits += 1
    if raw_intel.get("abuseipdb"):
        source_hits += 1
    if raw_intel.get("shodan"):
        source_hits += 1

    return {
        "investigation_id": investigation_id,
        "risk_score": inv.get("risk_score", 0),
        "confidence": inv.get("confidence", 0),
        "indicator_count": len(indicators),
        "source_count": source_hits,
        "status": inv.get("status", "unknown"),
    }


@app.delete("/investigation/{investigation_id}")
async def delete_investigation(investigation_id: str):
    deleted = memory_store.delete_investigation(investigation_id)
    if not deleted:
        return {
            "deleted": False,
            "investigation_id": investigation_id,
            "message": "Not found",
        }
    return {"deleted": True, "investigation_id": investigation_id}


@app.get("/investigations")
async def list_investigations(limit: int = 20):
    investigations = memory_store.get_recent_investigations(limit)
    return {"total": len(investigations), "investigations": investigations}


@app.get("/stats")
async def get_stats():
    return memory_store.get_statistics()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
