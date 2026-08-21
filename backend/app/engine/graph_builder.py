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
    "external": -800.0,
    "web":      0.0,
    "internal": 800.0,
}

# ── Y-Axis Dynamic Distribution Constants ────────────────────────────────────
# The viewport is ~800 graph-units tall after Sigma autoRescale.  We want all
# nodes in a layer to fit comfortably inside that band, so spacing adapts to
# the number of nodes.  Caps prevent extremes.
CANVAS_HEIGHT = 800.0     # target vertical band per layer (graph units)
MIN_Y_SPACING = 4.0       # minimum gap — prevents overlap at huge node counts
MAX_Y_SPACING = 60.0      # maximum gap — prevents sparse layouts with few nodes
SUB_COLUMN_JITTER_X = 12.0  # ± X offset within a layer column for readability

# ── Red Thread: Signal vs. Noise Thresholds ──────────────────────────────────
# Any node at or above SIGNAL_RISK_THRESHOLD, OR connected to an anomalous
# edge, is treated as SIGNAL and is NEVER collapsed into a noise super-node.
# Everything below this threshold with no anomalous connections is NOISE.
SIGNAL_RISK_THRESHOLD = 3.0

# Visual constants for noise super-nodes (background layer)
NOISE_SUPER_COLOR  = "#1E293B"   # very dark slate — visually recessive
NOISE_SUPER_SIZE   = 8.0         # large mass but muted colour
NOISE_EDGE_COLOR   = "rgba(30, 41, 59, 0.05)"   # 5 % opacity — structural hint only
NOISE_EDGE_SIZE    = 0.3

# Visual constants for signal nodes (the Red Thread)
SIGNAL_NODE_COLOR  = "#EF4444"   # solid red
SIGNAL_EDGE_COLOR  = "#DC2626"   # deep red
SIGNAL_EDGE_SIZE   = 3.5


class GraphBuilderEngine:
    """
    Red Thread / Signal-vs-Noise Kill Chain Graph Topology Builder.

    Architecture
    ────────────
    • Data is bifurcated into two streams before graph construction:

      THE SIGNAL (Red Thread)
        Nodes with risk_score >= SIGNAL_RISK_THRESHOLD OR connected to any
        anomalous edge.  These are preserved as individual NodeModel objects
        and rendered in solid bright red at maximum z-index.

      THE NOISE
        All remaining low-risk, benign-traffic nodes are collapsed into exactly
        3 background Super-Nodes — one per Kill Chain layer:
          • super:external_noise   — External IPs, GET-only, no anomalies
          • super:web_surface      — URL/web nodes with no anomalous activity
          • super:internal_baseline — Internal hosts with no anomalous activity
        These render in very dark slate colours with 5 % edge opacity.

    • Node X-coordinates are deterministic (LAYER_X columns).
    • No force-directed layout — frontend receives clean column positions.
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

            # ── Edge bundling: re-collapse after chunked streaming ────────────────
            # Multiple parse chunks may produce the same (src_ip, uri_prefix, verb)
            # group. Merge them into ONE edge: sum counts, take max risk, OR anomaly.
            if not df_http_edges.is_empty():
                bundle_cols = ["src_ip", "uri_prefix", "verb"]
                # Only aggregate on columns that actually exist in the frame
                agg_exprs = [
                    pl.col("total_attempts").sum(),
                    pl.col("risk_score").max(),
                    pl.col("is_anomalous").any(),
                    pl.col("first_timestamp").min(),
                    pl.col("last_timestamp").max(),
                ]
                # Optional columns (may not exist in every parser variant)
                for opt_col, agg_fn in [
                    ("status_code",  pl.col("status_code").mode().first()),
                    ("count_4xx",    pl.col("count_4xx").sum()),
                    ("count_5xx",    pl.col("count_5xx").sum()),
                    ("has_4xx",      pl.col("has_4xx").any()),
                    ("has_5xx",      pl.col("has_5xx").any()),
                    ("is_post",      pl.col("is_post").any()),
                    ("is_write",     pl.col("is_write").any()),
                ]:
                    if opt_col in df_http_edges.columns:
                        agg_exprs.append(agg_fn)
                df_http_edges = df_http_edges.group_by(bundle_cols).agg(agg_exprs)

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

            # ── Edge bundling: re-collapse after chunked streaming ────────────────
            # Merge duplicate (src_ip, dest_host) pairs — sum counts, OR anomaly.
            if not df_ssh_edges.is_empty():
                bundle_cols = ["src_ip", "dest_host"]
                agg_exprs = [
                    pl.col("total_attempts").sum(),
                    pl.col("risk_score").max(),
                    pl.col("is_anomalous").any(),
                    pl.col("first_timestamp").min(),
                    pl.col("last_timestamp").max(),
                ]
                for opt_col, agg_fn in [
                    ("successful_auths", pl.col("successful_auths").sum()),
                    ("failed_auths",     pl.col("failed_auths").sum()),
                    # Merge user lists across chunks, drop nulls, then de-duplicate
                    ("distinct_users",
                     pl.col("distinct_users").explode(empty_as_null=True).drop_nulls().unique().implode()),
                    ("is_brute_force",   pl.col("is_brute_force").any()),
                    ("has_priv_user",    pl.col("has_priv_user").any()),
                    ("is_multi_pivot",   pl.col("is_multi_pivot").any()),
                ]:
                    if opt_col in df_ssh_edges.columns:
                        agg_exprs.append(agg_fn)
                df_ssh_edges = df_ssh_edges.group_by(bundle_cols).agg(agg_exprs)

            for row in df_ssh_edges.iter_rows(named=True):
                src_ip    = row["src_ip"]
                dest_host = row["dest_host"]
                risk_score  = row["risk_score"]
                is_anomalous = row["is_anomalous"]
                users = row["distinct_users"]
                # Guard: drop any None values that can emerge after list merge
                users = [u for u in (users or []) if u is not None]

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

        # ══════════════════════════════════════════════════════════════════════
        #  RED THREAD — SIGNAL VS. NOISE BIFURCATION
        #
        #  Philosophy: aggressively bifurcate ALL nodes into exactly two streams
        #  before building the presentation graph.
        #
        #  THE SIGNAL (Red Thread)
        #    Any node with risk_score >= SIGNAL_RISK_THRESHOLD OR connected to
        #    at least one anomalous edge.  These are NEVER aggregated.  They
        #    render as individual high-prominence nodes (solid red, z=3) so the
        #    exact forensic attack path is immediately legible.
        #
        #  THE NOISE
        #    All remaining benign/low-risk nodes collapse into exactly 3 massive
        #    background Super-Nodes — one per Kill Chain layer:
        #      • super:external_noise    — External IPs (GET-only, no anomalies)
        #      • super:web_surface       — URL nodes with no anomalous activity
        #      • super:internal_baseline — Internal hosts with no anomalous activity
        #    These render in very dark slate at 5% edge opacity — structural
        #    context without visual competition against the Red Thread.
        # ══════════════════════════════════════════════════════════════════════

        # ── Step 1: Identify SIGNAL nodes ───────────────────────────────────
        # Build the set of node IDs touched by any anomalous edge.
        nodes_with_anomalous_edges: Set[str] = set()
        for e in edges_list:
            if e.is_anomalous:
                nodes_with_anomalous_edges.add(e.source)
                nodes_with_anomalous_edges.add(e.target)

        # Classify every raw node ID into layer buckets and signal/noise streams.
        all_node_ids = set(node_risk_map.keys())

        # signal_nodes: kept as individual nodes (the Red Thread)
        # noise_external / noise_web / noise_internal: collapsed into super-nodes
        signal_nodes:      List[str] = []
        noise_external:    List[str] = []   # IPs
        noise_web:         List[str] = []   # URL node IDs
        noise_internal:    List[str] = []   # host node IDs (RFC-1918)

        for nid in all_node_ids:
            risk = node_risk_map.get(nid, 0.0)
            
            # STRICT SIGNAL FILTER: Nodes with risk >= 3.0 OR anomalous edges are kept as Signal.
            is_signal = risk >= SIGNAL_RISK_THRESHOLD or nid in nodes_with_anomalous_edges

            if is_signal:
                signal_nodes.append(nid)
                continue

            # Classify noise node by layer
            if nid.startswith("url:"):
                noise_web.append(nid)
            elif nid.startswith("host:"):
                ip = nid.replace("host:", "")
                if _is_rfc1918(ip):
                    noise_internal.append(nid)
                else:
                    noise_external.append(ip)   # store plain IP for collapse helper
            else:
                noise_internal.append(nid)

        # ── Step 2: Collapse each noise layer into one background super-node ──
        SUPER_EXTERNAL_ID  = "super:external_noise"
        SUPER_WEB_ID       = "super:web_surface"
        SUPER_INTERNAL_ID  = "super:internal_baseline"

        # External noise → super:external_noise
        if noise_external:
            _collapse_ips_into_super(
                super_id=SUPER_EXTERNAL_ID,
                label=f"Background Traffic ({len(noise_external)} IPs)",
                ips=set(noise_external),
                node_risk_map=node_risk_map,
                edges_list=edges_list,
                color=NOISE_SUPER_COLOR,
                risk=0.5,
            )

        # Web noise → super:web_surface
        if noise_web:
            # Remove individual URL nodes from risk map and remap edges
            for mnid in noise_web:
                node_risk_map.pop(mnid, None)
            node_risk_map[SUPER_WEB_ID] = 0.5
            _remap_edges_to_super(
                super_id=SUPER_WEB_ID,
                member_ids=set(noise_web),
                edges_list=edges_list,
            )

        # Internal noise → super:internal_baseline
        if noise_internal:
            internal_ips = {
                nid.replace("host:", "") for nid in noise_internal
                if nid.startswith("host:")
            }
            non_host_noise = [nid for nid in noise_internal if not nid.startswith("host:")]
            # Remove non-host internal noise nodes from map
            for nid in non_host_noise:
                node_risk_map.pop(nid, None)
            if internal_ips:
                _collapse_ips_into_super(
                    super_id=SUPER_INTERNAL_ID,
                    label=f"Internal Baseline ({len(noise_internal)} hosts)",
                    ips=internal_ips,
                    node_risk_map=node_risk_map,
                    edges_list=edges_list,
                    color=NOISE_SUPER_COLOR,
                    risk=0.5,
                    node_prefix="host:",
                    is_target_cluster=True,
                )
            elif non_host_noise:
                # Edge case: non-host internal noise with no IPs
                node_risk_map[SUPER_INTERNAL_ID] = 0.5

        # Collect the active noise super-node IDs (only ones with data)
        noise_super_ids: List[str] = []
        if noise_external:
            noise_super_ids.append(SUPER_EXTERNAL_ID)
        if noise_web:
            noise_super_ids.append(SUPER_WEB_ID)
        if noise_internal:
            noise_super_ids.append(SUPER_INTERNAL_ID)

        # ── Step 3: Apply Red Thread visual attributes to signal edges ────────
        # Noise edges are set to near-invisible; signal edges are thick solid red.
        for e in edges_list:
            if e.is_anomalous:
                # Keep the per-flag colour set upstream; just ensure size/style
                e.size  = SIGNAL_EDGE_SIZE
                e.style = "solid"
            else:
                # Noise edge — structurally present but visually recessive
                e.size  = NOISE_EDGE_SIZE
                e.color = NOISE_EDGE_COLOR

        # ── Build final node lists per layer ─────────────────────────────────
        # Separate signal nodes by layer so they can be positioned correctly
        keep_external: List[str] = []
        keep_url:      List[str] = []
        keep_internal: List[str] = []

        for nid in signal_nodes:
            if nid.startswith("url:"):
                keep_url.append(nid)
            elif nid.startswith("host:"):
                ip = nid.replace("host:", "")
                if _is_rfc1918(ip):
                    keep_internal.append(nid)
                else:
                    keep_external.append(nid)
            else:
                keep_internal.append(nid)

        # Add noise super-nodes to their respective layer buckets
        if SUPER_EXTERNAL_ID in node_risk_map:
            keep_external.append(SUPER_EXTERNAL_ID)
        if SUPER_WEB_ID in node_risk_map:
            keep_url.append(SUPER_WEB_ID)
        if SUPER_INTERNAL_ID in node_risk_map:
            keep_internal.append(SUPER_INTERNAL_ID)

        # These are referenced in node construction below for label building
        noise_external_count  = len(noise_external)
        noise_web_count       = len(noise_web)
        noise_internal_count  = len(noise_internal)

        # ── Multi-Layer Node Construction ────────────────────────────────────
        #
        # Layer assignment:
        #   Layer 0 (external, X=0):    External IPs, super-nodes
        #   Layer 1 (web, X=500):       URL nodes, super:url:* clusters
        #   Layer 2 (internal, X=1000): Internal HOSTs, super:subnet:* clusters

        # ── Risk-Weighted Center-Out Ordering ────────────────────────────
        def _center_out_sort(ids: List[str]) -> List[str]:
            """Sort by risk descending, then interleave into center-out order."""
            ranked = sorted(ids, key=lambda n: node_risk_map.get(n, 0.0), reverse=True)
            n = len(ranked)
            if n <= 2:
                return ranked
            result: List[str] = [None] * n  # type: ignore[list-item]
            mid = n // 2
            result[mid] = ranked[0]
            above = mid - 1
            below = mid + 1
            for i in range(1, n):
                if i % 2 == 1 and above >= 0:
                    result[above] = ranked[i]
                    above -= 1
                elif below < n:
                    result[below] = ranked[i]
                    below += 1
                elif above >= 0:
                    result[above] = ranked[i]
                    above -= 1
            return result

        def _assign_positions(node_ids: List[str], x_base: float) -> Dict[str, tuple]:
            """Assign (x, y) positions within a layer column, partitioning into a 3x3 Grid based on risk."""
            if not node_ids:
                return {}

            critical = []
            suspicious = []
            noise = []

            for nid in node_ids:
                r = node_risk_map.get(nid, 0.0)
                is_noise_super = nid in (SUPER_EXTERNAL_ID, SUPER_WEB_ID, SUPER_INTERNAL_ID)
                if is_noise_super:
                    noise.append(nid)
                elif r >= 5.0:
                    critical.append(nid)
                elif r >= 3.0:
                    suspicious.append(nid)
                else:
                    noise.append(nid)

            critical = _center_out_sort(critical)
            suspicious = _center_out_sort(suspicious)
            noise = _center_out_sort(noise)

            positions = {}

            def _place_bucket(bucket: List[str], y_center: float):
                n = len(bucket)
                if n == 0:
                    return
                if n == 1:
                    positions[bucket[0]] = (round(x_base, 2), y_center)
                    return
                
                # Place nodes into a 2D cloud (grid) so they don't stretch vertically
                cols = math.ceil(math.sqrt(n))
                rows = math.ceil(n / cols)
                spacing_x = 30.0
                spacing_y = 30.0
                
                start_x = x_base - ((cols - 1) * spacing_x) / 2
                start_y = y_center - ((rows - 1) * spacing_y) / 2
                
                for i, nid in enumerate(bucket):
                    col = i % cols
                    row = i // cols
                    
                    # Add small jitter to make it look organic
                    jitter_x = ((hash(nid) % 11) - 5) * 1.5
                    jitter_y = ((hash(nid + "y") % 11) - 5) * 1.5
                    
                    positions[nid] = (
                        round(start_x + col * spacing_x + jitter_x, 2),
                        round(start_y + row * spacing_y + jitter_y, 2),
                    )

            _place_bucket(critical, -800.0)
            _place_bucket(suspicious, 0.0)
            _place_bucket(noise, 800.0)

            return positions

        positions: Dict[str, tuple] = {}
        positions.update(_assign_positions(keep_external, LAYER_X["external"]))
        positions.update(_assign_positions(keep_url,      LAYER_X["web"]))
        positions.update(_assign_positions(keep_internal, LAYER_X["internal"]))

        layer_external = keep_external
        layer_web      = keep_url
        layer_internal = keep_internal

        # ── Build NodeModel objects ──────────────────────────────────────────
        final_node_ids = set(layer_external + layer_web + layer_internal)
        total_raw_nodes = len(all_node_ids)

        for nid in final_node_ids:
            r_score = round(node_risk_map.get(nid, 1.0), 2)
            is_high_risk = r_score >= SIGNAL_RISK_THRESHOLD
            if is_high_risk:
                high_risk_nodes_count += 1

            x, y = positions.get(nid, (0.0, 0.0))
            is_noise_super = nid in (SUPER_EXTERNAL_ID, SUPER_WEB_ID, SUPER_INTERNAL_ID)
            is_signal      = nid in signal_nodes

            # Determine layer for noise super-nodes
            if is_noise_super:
                if nid == SUPER_EXTERNAL_ID:
                    layer = "external"
                elif nid == SUPER_WEB_ID:
                    layer = "web"
                else:
                    layer = "internal"

                # ── HARDCODE X-COORDINATES BY LAYER ──
                if layer == "external":
                    x = -800.0
                elif layer == "web":
                    x = 0.0
                else:
                    x = 800.0

            if is_noise_super:
                ntype = NodeType.SUPER_NODE
                size  = NOISE_SUPER_SIZE
                color = NOISE_SUPER_COLOR

                if nid == SUPER_EXTERNAL_ID:
                    label = f"Background Traffic ({noise_external_count} IPs)"
                elif nid == SUPER_WEB_ID:
                    label = f"Web Surface ({noise_web_count} URLs)"
                else:  # SUPER_INTERNAL_ID
                    label = f"Internal Baseline ({noise_internal_count} hosts)"

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
                    metadata={
                        "layer": layer,
                        "is_noise_super": True,
                    },
                )
                continue

            # ── Signal nodes (Red Thread — individual, high-prominence) ───────
            if nid.startswith("url:"):
                ntype = NodeType.URL
                label = nid.replace("url:", "")
                layer = "web"
                # Anomalous URL → solid red; otherwise amber
                if is_signal and is_high_risk:
                    color = SIGNAL_NODE_COLOR
                    size  = 4.5
                else:
                    color = "#F59E0B"
                    size  = 3.0
            else:
                ip = nid.replace("host:", "")
                is_internal = _is_rfc1918(ip)
                ntype  = NodeType.HOST
                label  = ip
                layer  = "internal" if is_internal else "external"

                if is_signal and is_high_risk:
                    # Red Thread node — maximum prominence
                    color = SIGNAL_NODE_COLOR
                    size  = 5.5 if r_score >= 7.0 else 4.5
                elif is_internal:
                    color = "#3B82F6"
                    size  = 3.0
                else:
                    color = "#F97316"
                    size  = 3.0

            # ── HARDCODE X-COORDINATES BY LAYER ──
            if layer == "external":
                x = -800.0
            elif layer == "web":
                x = 0.0
            else:
                x = 800.0

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
                metadata={
                    "layer": layer,
                    "is_signal": is_signal,
                },
            )

        # Prune edges that reference nodes no longer in the final set
        edges_list = [e for e in edges_list
                      if e.source in final_node_ids and e.target in final_node_ids]

        # ── Safety dedup: collapse any remaining parallel edges (same id) ────────
        # This is the last line of defence. If two EdgeModel objects share the
        # same deterministic id (same source → target pair), we merge them:
        # sum total_attempts, OR is_anomalous, union anomaly_flags, keep max weight.
        seen_edge_ids: dict = {}
        for e in edges_list:
            if e.id in seen_edge_ids:
                existing = seen_edge_ids[e.id]
                existing.total_attempts += e.total_attempts
                existing.is_anomalous = existing.is_anomalous or e.is_anomalous
                existing.anomaly_flags = list(
                    dict.fromkeys(list(existing.anomaly_flags) + list(e.anomaly_flags))
                )
                existing.weight = max(existing.weight, e.weight)
                # Promote visual attributes to the more prominent edge
                if e.is_anomalous:
                    existing.size  = max(existing.size, e.size)
                    existing.color = e.color
            else:
                seen_edge_ids[e.id] = e
        edges_list = list(seen_edge_ids.values())

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


# ─────────────────────────────────────────────────────────────────────────────
# Clustering helper: collapse a set of IPs into a single Super-Node
# ─────────────────────────────────────────────────────────────────────────────

def _collapse_ips_into_super(
    super_id: str,
    label: str,
    ips: Set[str],
    node_risk_map: Dict[str, float],
    edges_list: List[EdgeModel],
    color: str,
    risk: float,
    node_prefix: str = "host:",
    is_target_cluster: bool = False,
) -> None:
    """
    Collapse a set of IPs into a single super-node in-place.

    1. Removes individual IP node IDs from node_risk_map.
    2. Removes all edges from/to individual IPs.
    3. Creates aggregated super-edges from the super-node to each
       unique target (or from each unique source to the super-node
       if is_target_cluster=True).
    4. Registers the super-node in node_risk_map.
    """
    # Build the set of node IDs being collapsed
    member_nids = {f"{node_prefix}{ip}" for ip in ips}

    # Remove individual nodes
    for nid in member_nids:
        node_risk_map.pop(nid, None)

    # Collect aggregated edge info
    # For source clusters: super -> targets
    # For target clusters: sources -> super
    agg_targets: Dict[str, int] = {}  # target_id -> total_attempts
    agg_sources: Dict[str, int] = {}  # source_id -> total_attempts

    edges_to_remove = set()
    for i, e in enumerate(edges_list):
        if e.source in member_nids:
            edges_to_remove.add(i)
            agg_targets[e.target] = agg_targets.get(e.target, 0) + e.total_attempts
        if e.target in member_nids:
            edges_to_remove.add(i)
            agg_sources[e.source] = agg_sources.get(e.source, 0) + e.total_attempts

    # Remove collapsed edges (iterate in reverse to preserve indices)
    for i in sorted(edges_to_remove, reverse=True):
        edges_list.pop(i)

    # Register the super-node
    node_risk_map[super_id] = risk

    # Add aggregated outbound edges (super -> target)
    for target_id, total_attempts in agg_targets.items():
        if target_id not in member_nids:  # don't self-loop
            edges_list.append(EdgeModel(
                id=f"edge:{super_id}->{target_id}",
                source=super_id,
                target=target_id,
                edge_type=EdgeType.HTTP_REQUEST,
                weight=risk,
                total_attempts=total_attempts,
                is_anomalous=False,
                anomaly_flags=[],
                size=1.0,
                color=color,
                style="solid",
            ))

    # Add aggregated inbound edges (source -> super) for target clusters
    if is_target_cluster:
        for source_id, total_attempts in agg_sources.items():
            if source_id not in member_nids:
                edges_list.append(EdgeModel(
                    id=f"edge:{source_id}->{super_id}",
                    source=source_id,
                    target=super_id,
                    edge_type=EdgeType.SSH_AUTH,
                    weight=risk,
                    total_attempts=total_attempts,
                    is_anomalous=False,
                    anomaly_flags=[],
                    size=1.5,
                    color="#94A3B8",
                    style="solid",
                ))


def _remap_edges_to_super(
    super_id: str,
    member_ids: Set[str],
    edges_list: List[EdgeModel],
) -> None:
    """
    Redirect all edges that connect to member node IDs so they point
    to/from the super_id instead.  Deduplicates by (source, target).
    """
    seen: Set[str] = set()
    new_edges: List[EdgeModel] = []
    remove_indices: List[int] = []

    for i, e in enumerate(edges_list):
        src_in = e.source in member_ids
        tgt_in = e.target in member_ids

        if src_in or tgt_in:
            remove_indices.append(i)
            new_src = super_id if src_in else e.source
            new_tgt = super_id if tgt_in else e.target
            dedup_key = f"{new_src}|{new_tgt}"

            if dedup_key not in seen and new_src != new_tgt:
                seen.add(dedup_key)
                new_edges.append(EdgeModel(
                    id=f"edge:{new_src}->{new_tgt}",
                    source=new_src,
                    target=new_tgt,
                    edge_type=e.edge_type,
                    weight=e.weight,
                    total_attempts=e.total_attempts,
                    http_verb=e.http_verb,
                    status_code=e.status_code,
                    uri_path=e.uri_path,
                    is_anomalous=e.is_anomalous,
                    anomaly_flags=e.anomaly_flags,
                    size=e.size,
                    color=e.color,
                    style=e.style,
                ))

    for i in sorted(remove_indices, reverse=True):
        edges_list.pop(i)

    edges_list.extend(new_edges)
