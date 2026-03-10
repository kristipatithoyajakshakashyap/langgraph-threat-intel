from typing import Dict, List
from fastapi import WebSocket
import json
import asyncio
from collections import defaultdict


class ConnectionManager:
    """Manages WebSocket connections for real-time progress updates"""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = defaultdict(list)

    async def connect(self, investigation_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[investigation_id].append(websocket)

    def disconnect(self, investigation_id: str, websocket: WebSocket):
        if investigation_id in self.active_connections:
            if websocket in self.active_connections[investigation_id]:
                self.active_connections[investigation_id].remove(websocket)
            if not self.active_connections[investigation_id]:
                del self.active_connections[investigation_id]

    async def send_progress(self, investigation_id: str, progress_data: dict):
        """Send progress update to all connected clients for an investigation"""
        if investigation_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[investigation_id]:
                try:
                    await connection.send_json(progress_data)
                except Exception:
                    disconnected.append(connection)

            for ws in disconnected:
                self.disconnect(investigation_id, ws)

    async def send_message(
        self,
        investigation_id: str,
        message: str,
        step: str = None,
        status: str = "running",
    ):
        """Send a simple progress message"""
        await self.send_progress(
            investigation_id, {"message": message, "step": step, "status": status}
        )

    def get_connection_count(self, investigation_id: str) -> int:
        return len(self.active_connections.get(investigation_id, []))


manager = ConnectionManager()
