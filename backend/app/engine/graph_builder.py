import time
import math
from typing import Dict, List, Set
import polars as pl
from app.models.schema import (
    PresentationPayload, StreamChunkPayload, SessionMeta, SummaryData, GraphData,
    NodeModel, EdgeModel, NodeType, EdgeType, AnomalyFlag
)
from app.engine.noise_reduction import AlgorithmicNoiseReducer


# ── Multi-Layer X-Band Constants ─────────────────────────────────────────────
# Kill Chain flow:  External (left)  →  Web (center)  →  Internal (right)
LAYER_X = {
    "external": 0.0,
    "web":      500.0,
    "internal": 1000.0,
}

# Y-axis spacing between nodes within each column
Y_SPACING = 18.0


class GraphBuilderEngine:
    """
    Multi-layer Kill Chain Graph Topology Builder.

    Architecture
    ────────────
    • Nodes are assigned to 3 semantic layers (External → Web → Internal)
      with deterministic X-band coordinates and Y-spread by risk_score.
    • Background web noise (benign GET-only external IPs with no SSH activity)
      is collapsed into a single "Background Web Noise" super-node.
    • Static assets and dynamic URL query/numeric segments are already
      pruned/collapsed upstream in AlgorithmicNoiseReducer.
    • No force-directed layout — the frontend receives clean column positions.
    """

    # ─────────────────────────────────────────────────────────────────────────
    # Public entry point called by the SSE generator
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def build_chunk_payload(
        df_unified: pl.DataFrame,
        chunk_idx: int,
        total_chunks: int,
        processed_lines: int,
        total_lines: int,
        is_final: bool,
        filename: str,
        start_time: float,
    ) -> StreamChunkPayload:
        """Builds a StreamChunkPayload for an individual SSE batch."""
        payload = GraphBuilderEngine.build_from_unified(
            df_unified=df_unified,
            total_lines=total_lines,
            filename=filename,
            start_time=start_time,
        )
        progress = round((processed_lines / max(1, total_lines)) * 100.0, 1)

        return StreamChunkPayload(
            chunk_index=chunk_idx,
            total_chunks=total_chunks,
            processed_lines=processed_lines,
            total_lines=total_lines,
            progress=progress,
            nodes=payload.graph.nodes,
            edges=payload.graph.edges,
            summary=payload.summary,
            is_final=is_final,
            meta=payload.meta if is_final else None,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Unified schema → presentation payload
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def build_from_unified(
        df_unified: pl.DataFrame,
        total_lines: int,
        filename: str,
        start_time: float,
    ) -> PresentationPayload:
        """
        Splits the unified DataFrame into SSH and HTTP streams, runs the
        noise-reduction pipeline on each, then builds the multi-layer graph.
        """
        df_ssh_events = pl.DataFrame()
        df_http_events = pl.DataFrame()

        if not df_unified.is_empty() and "protocol" in df_unified.columns:

            # ── SSH events ──────────────────────────────────────────────────
            df_ssh_raw = df_unified.filter(pl.col("protocol") == "SSH")
            if not df_ssh_raw.is_empty():
                ssh_meta_dtype = pl.Struct([
                    pl.Field("user",        pl.Utf8),
                    pl.Field("auth_method", pl.Utf8),
                    pl.Field("dest_host",   pl.Utf8),
                ])
                df_ssh_events = (
                    df_ssh_raw
                    .with_columns([
                        pl.col("source_ip").alias("src_ip"),
                        pl.col("target").alias("dest_host"),
                        pl.col("action").alias("auth_result"),
                        pl.col("metadata")
                            .str.json_decode(dtype=ssh_meta_dtype)
                            .struct.field("user").alias("user"),
                        pl.col("metadata")
                            .str.json_decode(dtype=ssh_meta_dtype)
                            .struct.field("auth_method").alias("auth_method"),
                    ])
                )

            # ── HTTP events ─────────────────────────────────────────────────
            df_http_raw = df_unified.filter(pl.col("protocol") == "HTTP")
            if not df_http_raw.is_empty():
                http_meta_dtype = pl.Struct([
                    pl.Field("status_code", pl.Int32),
                    pl.Field("bytes_sent",  pl.Int32),
                ])
                df_http_events = (
                    df_http_raw
                    .with_columns([
                        pl.col("source_ip").alias("src_ip"),
                        pl.col("target").alias("uri"),
                        pl.col("action").alias("verb"),
                        pl.col("metadata")
                            .str.json_decode(dtype=http_meta_dtype)
                            .struct.field("status_code").alias("status_code"),
                        pl.col("metadata")
                            .str.json_decode(dtype=http_meta_dtype)
                            .struct.field("bytes_sent").alias("bytes_sent"),
                    ])
                )

        return GraphBuilderEngine._build_payload(
            df_ssh_events=df_ssh_events,
            df_http_events=df_http_events,
            total_lines=total_lines,
            filename=filename,
            start_time=start_time,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Core graph construction — Multi-Layer Kill Chain
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(
        df_ssh_events: pl.DataFrame,
        df_http_events: pl.DataFrame,
        total_lines: int,
        filename: str,
        start_time: float,
    ) -> PresentationPayload:

        nodes_dict: Dict[str, NodeModel] = {}
        edges_list: List[EdgeModel]      = []
        node_risk_map: Dict[str, float]  = {}

        # Track which source IPs have SSH activity (for noise collapsing)
        ssh_source_ips: Set[str] = set()

        anomalous_edges_count = 0
        high_risk_nodes_count = 0

        # ── HTTP edges ───────────────────────────────────────────────────────
        # Track per-IP anomaly status for background noise detection
        ip_has_anomalous_http: Set[str] = set()
        ip_has_non_get_http: Set[str] = set()

        if not df_http_events.is_empty():
            df_http_edges = AlgorithmicNoiseReducer.process_http_edges(df_http_events)

            for row in df_http_edges.iter_rows(named=True):
                src_ip      = row["src_ip"]
                uri_prefix  = row["uri_prefix"]
                verb        = row["verb"]
                status_code = row["status_code"]
                risk_score  = row["risk_score"]
                is_anomalous = row["is_anomalous"]

                src_id = f"host:{src_ip}"
                url_id = f"url:{uri_prefix}"

                flags: List[AnomalyFlag] = []
                if row.get("is_post"):
                    flags.append(AnomalyFlag.WEB_EXPLOIT_POST)
                if row.get("has_4xx"):
                    flags.append(AnomalyFlag.HTTP_4XX_SCAN)

                if is_anomalous:
                    anomalous_edges_count += 1
                    ip_has_anomalous_http.add(src_ip)

                if verb != "GET":
                    ip_has_non_get_http.add(src_ip)

                node_risk_map[src_id] = max(node_risk_map.get(src_id, 0.0), risk_score)
                node_risk_map[url_id] = max(node_risk_map.get(url_id, 0.0), risk_score)

                edges_list.append(EdgeModel(
                    id=f"edge:{src_ip}->{uri_prefix}:{verb}",
                    source=src_id,
                    target=url_id,
                    edge_type=EdgeType.HTTP_REQUEST,
                    weight=risk_score,
                    total_attempts=row["total_attempts"],
                    http_verb=verb,
                    status_code=status_code,
                    uri_path=uri_prefix,
                    is_anomalous=is_anomalous,
                    anomaly_flags=flags,
                    first_timestamp=str(row["first_timestamp"]),
                    last_timestamp=str(row["last_timestamp"]),
                    size=2.5 if is_anomalous else 1.2,
                    color="#F59E0B" if is_anomalous else "#94A3B8",
                    style="solid",
                ))

        # ── SSH edges ────────────────────────────────────────────────────────
        if not df_ssh_events.is_empty():
            df_ssh_edges = AlgorithmicNoiseReducer.process_ssh_edges(df_ssh_events)

            for row in df_ssh_edges.iter_rows(named=True):
                src_ip    = row["src_ip"]
                dest_host = row["dest_host"]
                risk_score  = row["risk_score"]
                is_anomalous = row["is_anomalous"]
                users = row["distinct_users"]

                ssh_source_ips.add(src_ip)

                src_id  = f"host:{src_ip}"
                dest_id = f"host:{dest_host}"

                flags: List[AnomalyFlag] = []
                if row.get("is_brute_force"):
                    flags.append(AnomalyFlag.BRUTE_FORCE_BURST)
                if row.get("has_priv_user"):
                    flags.append(AnomalyFlag.PRIVILEGE_PIVOT)
                    flags.append(AnomalyFlag.SSH_PRIVILEGE_PIVOT)
                if row.get("is_multi_pivot"):
                    flags.append(AnomalyFlag.RARE_PIVOT_PATH)
                # Cross-layer chain: HTTP anomalous source that also does SSH
                if node_risk_map.get(src_id, 0.0) > 2.0:
                    flags.append(AnomalyFlag.FULL_ATTACK_CHAIN)
                    risk_score = round(risk_score + 3.0, 2)

                if is_anomalous:
                    anomalous_edges_count += 1

                node_risk_map[src_id]  = max(node_risk_map.get(src_id, 0.0), risk_score)
                node_risk_map[dest_id] = max(node_risk_map.get(dest_id, 0.0), risk_score * 1.2)

                edges_list.append(EdgeModel(
                    id=f"edge:{src_ip}->{dest_host}",
                    source=src_id,
                    target=dest_id,
                    edge_type=EdgeType.SSH_AUTH,
                    weight=risk_score,
                    total_attempts=row["total_attempts"],
                    successful_auths=row["successful_auths"],
                    failed_auths=row["failed_auths"],
                    distinct_users=list(users),
                    is_anomalous=is_anomalous,
                    anomaly_flags=flags,
                    first_timestamp=str(row["first_timestamp"]),
                    last_timestamp=str(row["last_timestamp"]),
                    size=3.0 if is_anomalous else 1.5,
                    color="#DC2626" if is_anomalous else "#94A3B8",
                    style="dashed" if is_anomalous else "solid",
                ))

        # ── Background Web Noise Collapsing ──────────────────────────────────
        # Identify external IPs that are pure benign web browsers:
        #   - Only GET requests (no POST/PUT/DELETE)
        #   - No anomalous HTTP edges
        #   - No SSH activity at all
        # Collapse them into a single "Background Web Noise" super-node.
        all_node_ids = set(node_risk_map.keys())
        host_ids = {n for n in all_node_ids if n.startswith("host:")}
        url_ids  = {n for n in all_node_ids if n.startswith("url:")}

        background_noise_ips: Set[str] = set()
        for nid in host_ids:
            ip = nid.replace("host:", "")
            # Skip internal IPs (they are SSH targets, not noise sources)
            if _is_rfc1918(ip):
                continue
            # Must NOT have SSH activity
            if ip in ssh_source_ips:
                continue
            # Must NOT have anomalous HTTP edges
            if ip in ip_has_anomalous_http:
                continue
            # Must NOT have non-GET HTTP verbs
            if ip in ip_has_non_get_http:
                continue
            background_noise_ips.add(ip)

        noise_super_id = "host:background_web_noise"
        if background_noise_ips:
            # Count edges that will be collapsed
            noise_edge_count = 0
            noise_url_targets: Set[str] = set()
            new_edges: List[EdgeModel] = []

            for e in edges_list:
                src_ip = e.source.replace("host:", "")
                if src_ip in background_noise_ips:
                    noise_edge_count += e.total_attempts
                    noise_url_targets.add(e.target)

            # Remove individual noise IP nodes from node_risk_map
            for ip in background_noise_ips:
                nid = f"host:{ip}"
                node_risk_map.pop(nid, None)

            # Remove edges from noise IPs and replace with aggregated edges
            edges_list = [e for e in edges_list
                          if e.source.replace("host:", "") not in background_noise_ips]

            # Add the super-node
            node_risk_map[noise_super_id] = 0.5

            # Add one aggregated edge per target URL prefix
            for url_target in noise_url_targets:
                edges_list.append(EdgeModel(
                    id=f"edge:background_noise->{url_target}",
                    source=noise_super_id,
                    target=url_target,
                    edge_type=EdgeType.HTTP_REQUEST,
                    weight=0.5,
                    total_attempts=noise_edge_count,
                    http_verb="GET",
                    status_code=200,
                    uri_path=url_target.replace("url:", ""),
                    is_anomalous=False,
                    anomaly_flags=[],
                    size=1.0,
                    color="#94A3B8",
                    style="solid",
                ))

            # Refresh all_node_ids after collapsing
            all_node_ids = set(node_risk_map.keys())
            host_ids = {n for n in all_node_ids if n.startswith("host:")}
            url_ids  = {n for n in all_node_ids if n.startswith("url:")}

        # ── Multi-Layer Node Construction ────────────────────────────────────
        #
        # Layer assignment:
        #   Layer 0 (external, X=0):    External IPs, background noise
        #   Layer 1 (web, X=500):       URL nodes, WEB_SERVER nodes
        #   Layer 2 (internal, X=1000): Internal HOSTs (SSH targets)
        #
        # Y-coordinates: sorted by risk_score (highest at top) within each
        # layer column, then evenly spaced.

        # Classify nodes into layers
        layer_external: List[str] = []
        layer_web: List[str]      = []
        layer_internal: List[str] = []

        for nid in all_node_ids:
            if nid.startswith("url:"):
                layer_web.append(nid)
            elif nid == noise_super_id:
                layer_external.append(nid)
            elif nid.startswith("host:"):
                ip = nid.replace("host:", "")
                if _is_rfc1918(ip):
                    layer_internal.append(nid)
                else:
                    layer_external.append(nid)
            else:
                layer_internal.append(nid)

        # Sort each layer by risk_score descending (highest risk at top)
        def _sort_by_risk(ids: List[str]) -> List[str]:
            return sorted(ids, key=lambda n: node_risk_map.get(n, 0.0), reverse=True)

        layer_external = _sort_by_risk(layer_external)
        layer_web      = _sort_by_risk(layer_web)
        layer_internal = _sort_by_risk(layer_internal)

        def _assign_positions(node_ids: List[str], x_base: float) -> Dict[str, tuple]:
            """Assign (x, y) positions within a column, centered vertically."""
            n = len(node_ids)
            total_height = n * Y_SPACING
            y_start = -total_height / 2
            positions = {}
            for i, nid in enumerate(node_ids):
                # Slight X jitter by risk to prevent perfect vertical line
                jitter_x = (node_risk_map.get(nid, 0.0) % 3) * 8
                positions[nid] = (
                    round(x_base + jitter_x, 2),
                    round(y_start + i * Y_SPACING, 2),
                )
            return positions

        positions: Dict[str, tuple] = {}
        positions.update(_assign_positions(layer_external, LAYER_X["external"]))
        positions.update(_assign_positions(layer_web,      LAYER_X["web"]))
        positions.update(_assign_positions(layer_internal, LAYER_X["internal"]))

        # ── Build NodeModel objects ──────────────────────────────────────────
        for nid in all_node_ids:
            r_score = round(node_risk_map.get(nid, 1.0), 2)
            is_high_risk = r_score >= 3.0
            if is_high_risk:
                high_risk_nodes_count += 1

            x, y = positions.get(nid, (0.0, 0.0))

            # Determine type, label, color, layer
            if nid == noise_super_id:
                ntype = NodeType.HOST
                label = f"Background Web Noise ({len(background_noise_ips)} IPs)"
                color = "#64748B"  # slate gray
                layer = "external"
            elif nid.startswith("url:"):
                ntype  = NodeType.URL
                label  = nid.replace("url:", "")
                color  = "#F59E0B" if is_high_risk else "#D97706"
                layer  = "web"
            else:
                ip = nid.replace("host:", "")
                is_internal = _is_rfc1918(ip)
                ntype = NodeType.HOST
                label = ip
                layer = "internal" if is_internal else "external"
                if is_high_risk:
                    color = "#EF4444"
                elif is_internal:
                    color = "#3B82F6"
                else:
                    color = "#F97316"  # orange for external attackers

            # Size: small by default, slightly larger for high-risk
            size = 4.0 if is_high_risk else 2.0
            if nid == noise_super_id:
                size = 6.0  # background noise super-node is a bit larger

            nodes_dict[nid] = NodeModel(
                id=nid,
                label=label,
                node_type=ntype,
                in_degree=sum(1 for e in edges_list if e.target == nid),
                out_degree=sum(1 for e in edges_list if e.source == nid),
                risk_score=r_score,
                x=x,
                y=y,
                size=size,
                color=color,
                metadata={"layer": layer},
            )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        noise_ratio = round(anomalous_edges_count / len(edges_list), 3) if edges_list else 0.0

        return PresentationPayload(
            meta=SessionMeta(
                session_id=f"vestige_sess_{int(time.time())}",
                timestamp="2026-08-06T18:45:00Z",
                log_filename=filename,
                total_lines_parsed=total_lines,
                valid_ssh_events=len(df_ssh_events),
                valid_http_events=len(df_http_events),
                processing_time_ms=elapsed_ms,
                noise_reduction_ratio=noise_ratio,
            ),
            summary=SummaryData(
                total_nodes=len(nodes_dict),
                total_edges=len(edges_list),
                anomalous_edges_count=anomalous_edges_count,
                high_risk_nodes_count=high_risk_nodes_count,
                detected_lateral_chains=anomalous_edges_count,
            ),
            graph=GraphData(
                nodes=list(nodes_dict.values()),
                edges=edges_list,
            ),
            timeline=[],
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Legacy entry point (kept for backward-compat with /analyze endpoint)
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def build_presentation_payload(
        df_ssh_events: pl.DataFrame,
        df_http_events: pl.DataFrame,
        total_lines: int,
        filename: str,
        start_time: float,
    ) -> PresentationPayload:
        return GraphBuilderEngine._build_payload(
            df_ssh_events=df_ssh_events,
            df_http_events=df_http_events,
            total_lines=total_lines,
            filename=filename,
            start_time=start_time,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helper: RFC-1918 private IP detection (plain Python, for single-IP checks)
# ─────────────────────────────────────────────────────────────────────────────

def _is_rfc1918(ip: str) -> bool:
    """Returns True if the IP address is in RFC-1918 private ranges."""
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("127.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )
