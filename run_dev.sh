#!/usr/bin/env bash
# ==============================================================================
# Vestige - Development Environment Launch Script
# Starts FastAPI backend (port 8000) and Vite frontend (port 3000) with hot reload.
# ==============================================================================

set -e

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo -e "${CYAN}"
echo "======================================================================"
echo "    VESTIGE - Tactical Visual Forensic Engine (DEVELOPMENT MODE)     "
echo "======================================================================"
echo -e "${NC}"

# Check Python environment
if [ ! -d "backend/.venv" ]; then
    echo -e "${YELLOW}[!] Backend virtualenv missing. Creating backend/.venv...${NC}"
    python3 -m venv backend/.venv
    backend/.venv/bin/pip install --upgrade pip
    backend/.venv/bin/pip install -r backend/pyproject.toml
fi

# Check Frontend node_modules
if [ ! -d "frontend/node_modules" ]; then
    echo -e "${YELLOW}[!] Frontend node_modules missing. Running npm install...${NC}"
    (cd frontend && npm install)
fi

# Cleanup function on interrupt
cleanup() {
    echo -e "\n${YELLOW}[!] Shutting down development services...${NC}"
    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}[✓] Vestige dev environment stopped cleanly.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Start Backend
echo -e "${BLUE}[+] Starting FastAPI backend on http://localhost:8080...${NC}"
(cd backend && .venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 8080) &
BACKEND_PID=$!

# Give backend a moment to boot
sleep 2

FRONTEND_PORT="${PORT:-3001}"

# Start Frontend
echo -e "${BLUE}[+] Starting Vite frontend on http://localhost:${FRONTEND_PORT}...${NC}"
(cd frontend && npm run dev -- --port "${FRONTEND_PORT}") &
FRONTEND_PID=$!

echo -e "${GREEN}"
echo "======================================================================"
echo " [✓] VESTIGE DEVELOPMENT ENVIRONMENT RUNNING                         "
echo "     Frontend Dashboard: http://localhost:${FRONTEND_PORT}                       "
echo "     Backend OpenAPI:   http://localhost:8080/docs                  "
echo "     Press Ctrl+C to terminate services                             "
echo "======================================================================"
echo -e "${NC}"

# Keep script active to trap signals
wait
