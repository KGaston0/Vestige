import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.v1.ingest import router as ingest_router
from app.api.v1.expand import router as expand_router

app = FastAPI(
    title="Vestige API",
    description="Tactical Ephemeral Visual Forensic Engine for Lateral Movement Detection",
    version="1.1.0"
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router, prefix="/api")
app.include_router(expand_router, prefix="/api")

@app.get("/health")
def health_check():
    return {"status": "online", "system": "Vestige Forensic Engine"}

# Serve production frontend static build if dist exists
dist_dir = os.path.join(os.path.dirname(__file__), "../frontend/dist")
if os.path.exists(dist_dir):
    app.mount("/", StaticFiles(directory=dist_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)

