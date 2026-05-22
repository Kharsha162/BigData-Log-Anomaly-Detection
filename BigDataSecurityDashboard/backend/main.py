import asyncio
import json
import random
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from routes import auth, logs, predict, spark, geomap
from services.state import app_state
from utils.log_generator import generate_apache_log_line

# Initialize FastAPI App
app = FastAPI(
    title="Big Data Security Analytics & Anomaly Detection Platform",
    description="Backend API powered by Apache Spark, Scikit-learn, and FastAPI",
    version="1.0.0"
)

# CORS Policy configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers under prefix '/api'
app.include_router(auth.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(predict.router, prefix="/api")
app.include_router(spark.router, prefix="/api")
app.include_router(geomap.router, prefix="/api")
app.include_router(geomap.router) # Top-level fallback for direct matching

# Connection manager for WebSockets
class WebSocketManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                # Remove stale connection
                print(f"Failed to send websocket message, connection may be closed: {e}")

manager = WebSocketManager()

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Big Data Security Analytics Platform Backend",
        "documentation": "/docs"
    }

# Background streaming task state
stream_interval = 2.0  # seconds between logs
is_streaming = True

@app.websocket("/ws/logs")
async def websocket_logs_feed(websocket: WebSocket):
    await manager.connect(websocket)
    global stream_interval, is_streaming
    
    try:
        # Keep receiving user control commands or streaming logs
        while True:
            # We run a loop to stream log lines and yield control back
            # Wait for any setting changes or messages from the client
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                cmd = json.loads(data)
                
                # Support control commands from Settings UI
                if cmd.get("action") == "set_interval":
                    stream_interval = float(cmd.get("value", 2.0))
                    print(f"Stream interval set to {stream_interval}s")
                elif cmd.get("action") == "toggle_stream":
                    is_streaming = bool(cmd.get("value", True))
                    print(f"Streaming toggled to {is_streaming}")
                elif cmd.get("action") == "trigger_anomaly":
                    # Generate a forced attack log immediately
                    scenario = cmd.get("scenario", "exploit")
                    res = generate_apache_log_line(scenario=scenario)
                    enriched = app_state.add_log_line(res["line"])
                    if enriched:
                        await websocket.send_text(json.dumps({
                            "type": "log_entry",
                            "data": enriched
                        }))
            except asyncio.TimeoutError:
                # Normal behavior: no message received, continue streaming
                pass
                
            if is_streaming:
                # 85% normal traffic, 15% threat traffic
                scenario = None
                if random.random() < 0.15:
                    scenario = random.choice(['exploit', 'brute_force', 'ddos', 'exploit'])
                
                # Generate a single log line
                res = generate_apache_log_line(scenario=scenario)
                enriched = app_state.add_log_line(res["line"])
                
                if enriched:
                    # Broadcast the new log to all connected clients
                    await manager.broadcast({
                        "type": "log_entry",
                        "data": enriched
                    })
                    
            # Pause execution before sending next log line
            # Introduce a slight jitter to make it look realistic
            sleep_time = max(0.2, stream_interval + random.uniform(-0.3, 0.3))
            await asyncio.sleep(sleep_time)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket processing error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    # Start the server on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
