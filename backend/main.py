from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from response_engine import unblock_ip

app = FastAPI(title="Sentinel-X Backend API")

# Allow the React frontend to make requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic schema for an Alert
class Alert(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "Unknown"
    packet_length: int = 0
    alert_type: str
    status: str
    explanation: str = "No explanation provided."
    timestamp: str

class PacketCountUpdate(BaseModel):
    count: int

class UnblockRequest(BaseModel):
    ip: str

# In-memory database to store alerts and stats
alerts_db: List[Alert] = []
global_stats = {"packets_monitored": 0}

@app.get("/")
def read_root():
    return {"status": "Sentinel-X Engine is Running"}

@app.get("/alerts", response_model=List[Alert])
def get_alerts():
    """
    Returns list of detected alerts.
    """
    return alerts_db

@app.post("/alerts")
def store_alert(alert: Alert):
    """
    Store new alert. Keeps only the latest 100 to prevent Dashboard lag.
    """
    alerts_db.append(alert)
    if len(alerts_db) > 100:
        alerts_db.pop(0)
    return {"message": "Alert stored successfully"}

@app.post("/update_packet_count")
def update_packet_count(update: PacketCountUpdate):
    """
    Updates the total number of packets monitored.
    """
    global_stats["packets_monitored"] += update.count
    return {"status": "success"}

@app.post("/unblock")
def handle_unblock(request: UnblockRequest):
    """
    Handles request to unblock an IP.
    """
    success = unblock_ip(request.ip)
    if success:
        # Update internal alerts DB so the UI reflects the change
        for alert in alerts_db:
            if alert.source_ip == request.ip and alert.status == "BLOCKED":
                alert.status = "SAFE"
                alert.explanation = "Manually unblocked by Administrator."
        return {"status": "success", "message": f"IP {request.ip} unblocked successfully."}
    else:
        return {"status": "error", "message": f"Failed to unblock {request.ip}. Check script permissions."}

@app.get("/stats")
def get_stats():
    """
    Returns dashboard statistics.
    """
    threats_detected = sum(1 for a in alerts_db if a.status == "WARNING")
    threats_blocked = sum(1 for a in alerts_db if a.status == "BLOCKED")
    
    # Ensure packets monitored is at least the number of threats
    packets = max(global_stats["packets_monitored"], len(alerts_db))
    
    return {
        "packets_monitored": packets,
        "threats_detected": threats_detected,
        "threats_blocked": threats_blocked
    }
