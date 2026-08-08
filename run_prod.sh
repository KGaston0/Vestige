#!/usr/bin/env bash
# ==============================================================================
# Vestige - Production Build & Deployment Launch Script
# Builds frontend static assets and serves application via single port (8000).
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
echo "    VESTIGE - Tactical Visual Forensic Engine (PRODUCTION MODE)      "
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
    echo -e "${YELLOW}[!] Frontend dependencies missing. Installing npm modules...${NC}"
    (cd frontend && npm install)
fi

# Build Frontend Bundle
echo -e "${BLUE}[+] Building optimized production frontend assets in frontend/dist...${NC}"
(cd frontend && npm run build)

# Cleanup function on interrupt
cleanup() {
    echo -e "\n${YELLOW}[!] Shutting down production server...${NC}"
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    echo -e "${GREEN}[✓] Vestige production server stopped cleanly.${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# Start Production Server (Serves both API and compiled React App on port 8080)
echo -e "${BLUE}[+] Starting production server on http://localhost:8080...${NC}"
(cd backend && .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080 --workers 2) &
SERVER_PID=$!

echo -e "${GREEN}"
echo "======================================================================"
echo " [✓] VESTIGE PRODUCTION ENVIRONMENT DEPLOYED                          "
echo "     Unified Application URL: http://localhost:8080                   "
echo "     API Documentation:       http://localhost:8080/docs              "
echo "     Press Ctrl+C to terminate server                                "
echo "======================================================================"
echo -e "${NC}"

# Keep script active to trap signals
wait
