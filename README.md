# Vestige - Tactical Ephemeral Forensic Graph Visualizer

**Vestige** is a tactical, offline, visual forensic tool designed for post-incident analysis. Its primary goal is to help forensic auditors detect and visualize "lateral movement" within a compromised network using graph topology.

## Key Features
- **Tactical & Ephemeral:** 100% session-based. Upload a log, process & visualize, export report, and wipe all data when the session closes.
- **Linux SSH `auth.log` Ingestion:** Ultra-fast multi-threaded log parsing powered by Polars.
- **Mathematical Noise Reduction & Semantic Clustering:** Algorithmic filtering of regular baseline connections (high-frequency automated jumps, cron jobs) without brittle manual whitelists. Dynamically collapses static assets, numeric/UUID path segments, and benign background web noise to reduce visual clutter.
- **WebGL Kill-Chain Topology:** High-performance WebGL node-based network canvas powered by Sigma.js / Graphology. Renders a deterministic Multi-Layer DAG layout (External IPs → Web Resources → Internal Hosts) to clearly visualize attack paths.

## Architecture
See detailed architectural specifications, data flows, JSON payload contracts, and performance bottleneck mitigations in [ARCHITECTURE.md](file:///home/klu/Desktop/Vestige/ARCHITECTURE.md).

## Project Structure
```
Vestige/
├── ARCHITECTURE.md          # Complete architectural specification & documentation
├── README.md                # Overview & quickstart guide
├── backend/                 # FastAPI + Polars + Rustworkx/NetworkX engine
│   ├── app/
│   │   ├── api/             # REST Endpoints
│   │   ├── core/            # Config & Ephemeral state manager
│   │   ├── engine/          # Polars Log Parser & Graph Noise Reduction Engine
│   │   └── models/          # Pydantic Schemas & Data Contracts
│   ├── main.py              # Application entrypoint
│   └── pyproject.toml       # Python dependencies & build config
├── frontend/                # React + Vite + TypeScript + WebGL Canvas
│   ├── src/
│   │   ├── components/      # WebGL Canvas & Graph controls
│   │   ├── types/           # TypeScript payload definitions
│   │   └── App.tsx          # Main Dashboard
│   ├── package.json
│   └── vite.config.ts
└── data/
    └── samples/             # Sample Linux SSH auth logs for testing
```

## Getting Started

### Backend Setup (Python 3.11+)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt # or pdm / poetry / uv
uvicorn main:app --reload --port 8000
```

### Frontend Setup (Node 18+)
```bash
cd frontend
npm install
npm run dev
```