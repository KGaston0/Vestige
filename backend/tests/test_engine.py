import time
import unittest
import polars as pl
from app.engine.parser import LogParserEngine
from app.engine.graph_builder import GraphBuilderEngine
from app.models.schema import PresentationPayload, NodeType, EdgeType, AnomalyFlag

SAMPLE_SSH_LOG = """Aug  5 01:15:02 jumpbox sshd[1042]: Accepted publickey for sysadmin from 192.168.1.10 port 54102 ssh2
Aug  5 03:22:10 database01 sshd[3012]: Failed password for root from 10.0.4.15 port 39102 ssh2
Aug  5 03:22:12 database01 sshd[3014]: Failed password for root from 10.0.4.15 port 39104 ssh2
Aug  5 03:25:40 database01 sshd[3099]: Accepted password for root from 10.0.4.15 port 39150 ssh2
"""

SAMPLE_HTTP_LOG = """198.51.100.42 - - [06/Aug/2026:03:20:10 +0000] "POST /api/v1/upload HTTP/1.1" 200 4520
198.51.100.42 - - [06/Aug/2026:03:20:15 +0000] "GET /admin/config HTTP/1.1" 403 120
"""

class TestEngine(unittest.TestCase):
    def test_log_parser_dual_extraction(self):
        content = (SAMPLE_SSH_LOG + SAMPLE_HTTP_LOG).encode("utf-8")
        df_ssh, df_http, total_lines = LogParserEngine.parse_auth_log_bytes(content)

        self.assertEqual(total_lines, 6)
        self.assertEqual(len(df_ssh), 4)
        self.assertEqual(len(df_http), 2)
        self.assertIn("198.51.100.42", df_http["src_ip"].to_list())
        self.assertIn("/api/v1/upload", df_http["uri"].to_list())

    def test_graph_builder_dual_payload(self):
        content = (SAMPLE_SSH_LOG + SAMPLE_HTTP_LOG).encode("utf-8")
        start_time = time.time()
        df_ssh, df_http, total_lines = LogParserEngine.parse_auth_log_bytes(content)

        payload = GraphBuilderEngine.build_presentation_payload(
            df_ssh_events=df_ssh,
            df_http_events=df_http,
            total_lines=total_lines,
            filename="dual_test.log",
            start_time=start_time
        )

        self.assertIsInstance(payload, PresentationPayload)
        self.assertGreaterEqual(payload.summary.total_nodes, 4)

        # Check URL nodes exist
        url_nodes = [n for n in payload.graph.nodes if n.node_type == NodeType.URL]
        self.assertEqual(len(url_nodes), 2)

        # Check HTTP request edge exists
        http_edges = [e for e in payload.graph.edges if e.edge_type == EdgeType.HTTP_REQUEST]
        self.assertGreater(len(http_edges), 0)
        self.assertIn(http_edges[0].http_verb, ["POST", "GET"])

if __name__ == "__main__":
    unittest.main()
