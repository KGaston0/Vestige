import pytest
from fastapi.testclient import TestClient
from main import app
from app.engine.router import LogRouterEngine

client = TestClient(app)

SAMPLE_AUTH_LOG = """Aug  6 18:00:01 web-server-01 sshd[1234]: Accepted password for root from 192.168.1.100 port 54321
Aug  6 18:00:02 web-server-01 sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 54322
Aug  6 18:00:03 web-server-01 sshd[1236]: Failed password for invalid user admin from 10.0.0.5 port 54323
"""

def test_stream_chunks_generator():
    content = SAMPLE_AUTH_LOG.encode("utf-8")
    chunks = list(LogRouterEngine.stream_chunks(content, chunk_size=2))
    assert len(chunks) == 2
    df0, idx0, total0, processed0, total_lines0, fmt0 = chunks[0]
    assert idx0 == 0
    assert total0 == 2
    assert processed0 == 2
    assert total_lines0 == 3
    assert fmt0 == "SYSLOG_SSH"

def test_analyze_stream_endpoint():
    files = {"file": ("auth.log", SAMPLE_AUTH_LOG.encode("utf-8"), "text/plain")}
    response = client.post("/api/v1/analyze/stream", files=files)
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    text = response.text
    assert "data:" in text
    assert '"progress"' in text
    assert '"nodes"' in text
    assert '"edges"' in text
