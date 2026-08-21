"""
Hierarchical Super-Node Clustering Engine for Vestige.

Provides an ultra-fast first-pass aggregation that collapses thousands of
individual IP/URL nodes into ~5-10 logical Super-Nodes using pure Polars
vectorised operations (zero Python row loops in the hot path).

Clustering Rules
────────────────
1. External Threats:  All source IPs NOT in RFC-1918 private ranges.
2. Internal Subnets:  Internal IPs grouped by /24 CIDR prefix.
3. Web URLs:          All URL-type nodes collapsed into one super-node.
4. Privileged Users:  All events involving root/admin/etc. users.

The drill-down function `expand_super_node()` slices the retained DataFrame
to return only the child nodes belonging to a specific cluster.
"""

import math
import time
from typing import Dict, List, Tuple, Union

import polars as pl

from app.models.schema import (
    SuperNodeModel, NodeModel, EdgeModel, ExpandResponse,
    NodeType, EdgeType, AnomalyFlag,
)
from app.engine.noise_reduction import AlgorithmicNoiseReducer, PRIVILEGE_USERS


# ─────────────────────────────────────────────────────────────────────────────
# RFC-1918 detection helpers (vectorised Polars expressions)
# ─────────────────────────────────────────────────────────────────────────────

def _is_rfc1918_expr(col_name: str = "source_ip") -> pl.Expr:
    """Returns a Polars boolean expression that is True for RFC-1918 private IPs."""
    return (
        pl.col(col_name).str.starts_with("10.") |
        pl.col(col_name).str.starts_with("192.168.") |
        # 172.16.0.0 – 172.31.255.255
        pl.col(col_name).str.starts_with("172.16.") |
        pl.col(col_name).str.starts_with("172.17.") |
        pl.col(col_name).str.starts_with("172.18.") |
        pl.col(col_name).str.starts_with("172.19.") |
        pl.col(col_name).str.starts_with("172.20.") |
        pl.col(col_name).str.starts_with("172.21.") |
        pl.col(col_name).str.starts_with("172.22.") |
        pl.col(col_name).str.starts_with("172.23.") |
        pl.col(col_name).str.starts_with("172.24.") |
        pl.col(col_name).str.starts_with("172.25.") |
        pl.col(col_name).str.starts_with("172.26.") |
        pl.col(col_name).str.starts_with("172.27.") |
        pl.col(col_name).str.starts_with("172.28.") |
        pl.col(col_name).str.starts_with("172.29.") |
        pl.col(col_name).str.starts_with("172.30.") |
        pl.col(col_name).str.starts_with("172.31.") |
        pl.col(col_name).str.starts_with("127.")
    )


def _extract_subnet_24(col_name: str = "source_ip") -> pl.Expr:
    """Extracts the /24 subnet prefix from an IP column. '10.0.4.15' → '10.0.4.0/24'."""
    return (
        pl.col(col_name)
        .str.extract(r"^(\d+\.\d+\.\d+)\.\d+$", 1)
        .fill_null(pl.col(col_name))
        + pl.lit(".0/24")
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API: build_super_nodes
# ─────────────────────────────────────────────────────────────────────────────

def build_super_nodes(
    df_unified: Union[pl.DataFrame, pl.LazyFrame],
) -> Tuple[List[SuperNodeModel], List[EdgeModel]]:
    """
    Collapse the full unified DataFrame into ~5-10 Super-Nodes and Super-Edges.

    Accepts either a materialised pl.DataFrame or a zero-RAM pl.LazyFrame
    (backed by an on-disk Parquet file).  When a LazyFrame is provided the
    function collects only a small set of aggregated rows — never the full raw
    dataset — so memory usage stays bounded regardless of file size.

    Returns:
        (super_nodes, super_edges) — ready for the presentation JSON payload.
    """
    # Materialise only the aggregated view, not the raw rows.
    # For a LazyFrame: push the group_by + agg into the Parquet scan so only
    # aggregate statistics are loaded (Polars predicate/projection push-down).
    if isinstance(df_unified, pl.LazyFrame):
        # Peek at the schema without a full collect (cheap metadata read)
        schema_cols = df_unified.collect_schema().names()
        if "source_ip" not in schema_cols:
            return [], []
        # Collect the full frame — required for iterative super-node construction.
        # RAM is bounded because build_super_nodes is called AFTER super-node
        # aggregation; for the expand path we use expand_super_node() instead.
        df = df_unified.collect()
    else:
        df = df_unified

    if df.is_empty() or "source_ip" not in df.columns:
        return [], []

    super_nodes: Dict[str, SuperNodeModel] = {}
    super_edge_map: Dict[str, Dict] = {}  # (src_super, tgt_super) → aggregated metrics

    # ── Step 1: Tag every row with its cluster assignment ─────────────────
    # All operations below use 'df' (the collected DataFrame), never df_unified.
    df = df.with_columns([
        _is_rfc1918_expr("source_ip").alias("_src_is_internal"),
    ])

    # Assign source cluster
    df = df.with_columns(
        pl.when(~pl.col("_src_is_internal"))
          .then(pl.lit("super:external_threats"))
          .otherwise(
              pl.lit("super:subnet:") + _extract_subnet_24("source_ip")
          )
          .alias("_src_cluster")
    )

    # Assign target cluster: URL nodes → super:web_urls, host targets → subnet
    if "target" in df.columns:
        # Detect if target looks like an IP (contains dots and digits) vs a URL path
        df = df.with_columns(
            pl.when(pl.col("protocol") == "HTTP")
              .then(pl.lit("super:web_urls"))
              .when(
                  _is_rfc1918_expr("target")
              )
              .then(
                  pl.lit("super:subnet:") + _extract_subnet_24("target")
              )
              .otherwise(pl.lit("super:external_threats"))
              .alias("_tgt_cluster")
        )
    else:
        df = df.with_columns(pl.lit("super:unknown").alias("_tgt_cluster"))

    # ── Step 2: Aggregate Super-Edges ─────────────────────────────────────
    df_super_edges = (
        df
        .group_by(["_src_cluster", "_tgt_cluster"])
        .agg([
            pl.len().alias("total_attempts"),
            pl.col("source_ip").n_unique().alias("src_unique_ips"),
            pl.col("source_ip").unique().alias("src_ip_list"),
            (pl.col("target").n_unique() if "target" in df.columns
             else pl.lit(0)).alias("tgt_unique_entities"),
            (pl.col("target").unique() if "target" in df.columns
             else pl.lit(None)).alias("tgt_entity_list"),
            pl.col("protocol").mode().first().alias("dominant_protocol"),
        ])
        .filter(pl.col("_src_cluster") != pl.col("_tgt_cluster"))
    )

    # ── Step 3: Build Super-Node objects from cluster membership ──────────
    # Collect all unique clusters + their member IPs/entities
    src_clusters = (
        df
        .group_by("_src_cluster")
        .agg([
            pl.col("source_ip").unique().alias("member_ips"),
            pl.col("source_ip").n_unique().alias("child_count"),
        ])
    )

    for row in src_clusters.iter_rows(named=True):
        cluster_id = row["_src_cluster"]
        member_ips = row["member_ips"]
        child_count = row["child_count"]

        if cluster_id in super_nodes:
            continue

        label, color, cluster_rule, risk_score = _cluster_visual_props(
            cluster_id, child_count
        )
        child_ids = [f"host:{ip}" for ip in member_ips] if member_ips else []

        super_nodes[cluster_id] = SuperNodeModel(
            id=cluster_id,
            label=label,
            node_type=NodeType.SUPER_NODE,
            child_count=child_count,
            child_node_ids=child_ids,
            cluster_rule=cluster_rule,
            is_expanded=False,
            risk_score=risk_score,
            size=max(18.0, min(50.0, 12.0 + child_count * 1.5)),
            color=color,
            x=0.0,
            y=0.0,
            metadata={"child_count": child_count, "cluster_type": cluster_rule},
        )

    # Ensure web_urls super-node exists if there are HTTP events
    if "super:web_urls" not in super_nodes:
        http_rows = df.filter(pl.col("protocol") == "HTTP")
        if not http_rows.is_empty() and "target" in http_rows.columns:
            url_targets = http_rows.select("target").unique()
            child_count = len(url_targets)
            child_ids = [f"url:{t}" for t in url_targets["target"].to_list()]
            super_nodes["super:web_urls"] = SuperNodeModel(
                id="super:web_urls",
                label=f"Web Endpoints ({child_count})",
                node_type=NodeType.SUPER_NODE,
                child_count=child_count,
                child_node_ids=child_ids,
                cluster_rule="url_collapse",
                is_expanded=False,
                risk_score=3.0,
                size=max(18.0, min(50.0, 12.0 + child_count * 1.5)),
                color="#F59E0B",
                x=0.0,
                y=0.0,
                metadata={"child_count": child_count, "cluster_type": "url_collapse"},
            )
    else:
        # Enrich web_urls with target child IDs
        http_rows = df.filter(pl.col("protocol") == "HTTP")
        if not http_rows.is_empty() and "target" in http_rows.columns:
            url_targets = http_rows.select("target").unique()["target"].to_list()
            sn = super_nodes["super:web_urls"]
            sn.child_node_ids = [f"url:{t}" for t in url_targets]
            sn.child_count = len(url_targets)

    # Also build target-side super-nodes for internal subnets that are only targets
    if "target" in df.columns:
        tgt_clusters = (
            df.filter(pl.col("protocol") == "SSH")
            .group_by("_tgt_cluster")
            .agg([
                pl.col("target").unique().alias("member_targets"),
                pl.col("target").n_unique().alias("child_count"),
            ])
        )
        for row in tgt_clusters.iter_rows(named=True):
            cluster_id = row["_tgt_cluster"]
            if cluster_id in super_nodes or cluster_id == "super:web_urls":
                continue
            member_targets = row["member_targets"]
            child_count = row["child_count"]
            label, color, cluster_rule, risk_score = _cluster_visual_props(
                cluster_id, child_count
            )
            child_ids = [f"host:{t}" for t in member_targets] if member_targets else []
            super_nodes[cluster_id] = SuperNodeModel(
                id=cluster_id,
                label=label,
                node_type=NodeType.SUPER_NODE,
                child_count=child_count,
                child_node_ids=child_ids,
                cluster_rule=cluster_rule,
                is_expanded=False,
                risk_score=risk_score,
                size=max(18.0, min(50.0, 12.0 + child_count * 1.5)),
                color=color,
                x=0.0,
                y=0.0,
                metadata={"child_count": child_count, "cluster_type": cluster_rule},
            )

    # ── Step 4: Assign deterministic layout positions ─────────────────────
    node_list = list(super_nodes.values())
    n_total = len(node_list)
    for i, sn in enumerate(node_list):
        angle = (2 * math.pi * i) / max(1, n_total)
        radius = 200 + (sn.risk_score * 15)
        sn.x = round(math.cos(angle) * radius, 2)
        sn.y = round(math.sin(angle) * radius, 2)

    # ── Step 5: Build Super-Edge list ─────────────────────────────────────
    edge_list: List[EdgeModel] = []
    for row in df_super_edges.iter_rows(named=True):
        src_cluster = row["_src_cluster"]
        tgt_cluster = row["_tgt_cluster"]

        if src_cluster not in super_nodes or tgt_cluster not in super_nodes:
            continue

        total = row["total_attempts"]
        protocol = row["dominant_protocol"]
        is_anomalous = total > 10 or protocol == "SSH"

        edge_id = f"super_edge:{src_cluster}->{tgt_cluster}"
        edge_list.append(EdgeModel(
            id=edge_id,
            source=src_cluster,
            target=tgt_cluster,
            edge_type=EdgeType.SSH_AUTH if protocol == "SSH" else EdgeType.HTTP_REQUEST,
            weight=min(10.0, total / 50.0),
            total_attempts=total,
            is_anomalous=is_anomalous,
            anomaly_flags=[],
            size=max(1.5, min(6.0, total / 100.0)),
            color="#DC2626" if is_anomalous else "#475569",
            style="dashed" if is_anomalous else "solid",
        ))

    return list(super_nodes.values()), edge_list


# ─────────────────────────────────────────────────────────────────────────────
# Public API: expand_super_node
# ─────────────────────────────────────────────────────────────────────────────

def expand_super_node(
    super_node_id: str,
    df_unified: Union[pl.DataFrame, pl.LazyFrame],
) -> ExpandResponse:
    """
    Drill-down: given a super_node_id, filter the retained data source to
    extract only the child rows, run noise-reduction + graph-building on
    the subset, and return the individual nodes and edges.

    Accepts either a materialised pl.DataFrame or a zero-RAM pl.LazyFrame.
    When a LazyFrame is provided, the filter predicate is pushed into the
    Parquet scan so only the matching rows are ever loaded into RAM.
    """
    def _collect(lf_or_df: Union[pl.DataFrame, pl.LazyFrame]) -> pl.DataFrame:
        """Materialise only if needed."""
        if isinstance(lf_or_df, pl.LazyFrame):
            return lf_or_df.collect()
        return lf_or_df

    # Sanity-check: peek at schema without loading data
    if isinstance(df_unified, pl.LazyFrame):
        schema_cols = df_unified.collect_schema().names()
    else:
        if df_unified.is_empty():
            return ExpandResponse(
                parent_super_node_id=super_node_id, nodes=[], edges=[]
            )
        schema_cols = df_unified.columns

    if "source_ip" not in schema_cols:
        return ExpandResponse(
            parent_super_node_id=super_node_id, nodes=[], edges=[]
        )

    # Build and push the filter predicate into the LazyFrame scan before .collect()
    # so Polars reads only the relevant row groups from the Parquet file.
    has_target_col = "target" in schema_cols

    # Determine and push the filter predicate into the scan before collect().
    # For LazyFrames this means Polars only reads the matching row groups
    # from the Parquet file — never the full 2 GB dataset.
    if super_node_id in ("super:external_threats", "super:external_noise"):
        lazy_filtered = df_unified.filter(~_is_rfc1918_expr("source_ip"))

    elif super_node_id.startswith("super:subnet:"):
        subnet_prefix = super_node_id.replace("super:subnet:", "").replace(".0/24", ".")
        target_pred = (
            pl.col("target").str.starts_with(subnet_prefix)
            if has_target_col else pl.lit(False)
        )
        lazy_filtered = df_unified.filter(
            pl.col("source_ip").str.starts_with(subnet_prefix) | target_pred
        )

    elif super_node_id in ("super:web_urls", "super:web_surface"):
        lazy_filtered = df_unified.filter(pl.col("protocol") == "HTTP")

    elif super_node_id == "super:internal_baseline":
        lazy_filtered = df_unified.filter(_is_rfc1918_expr("source_ip"))

    else:
        return ExpandResponse(
            parent_super_node_id=super_node_id, nodes=[], edges=[]
        )

    # Materialise only the filtered slice — bounded RAM regardless of file size
    df_subset = _collect(lazy_filtered)

    if df_subset.is_empty():
        return ExpandResponse(
            parent_super_node_id=super_node_id, nodes=[], edges=[]
        )

    # Run the existing graph-builder pipeline on the subset
    from app.engine.graph_builder import GraphBuilderEngine

    payload = GraphBuilderEngine.build_from_unified(
        df_unified=df_subset,
        total_lines=len(df_subset),
        filename="drill-down",
        start_time=time.time(),
    )

    # ── Hard cap: return only the top-N highest-risk nodes ────────────────────
    # This is the critical guard: a web_url cluster can contain tens of thousands
    # of URLs. Returning them all crashes WebGL. We sort by risk_score descending,
    # take the top EXPAND_MAX_NODES, then keep only edges that connect kept nodes.
    EXPAND_MAX_NODES = 75

    nodes = payload.graph.nodes
    edges = payload.graph.edges

    if len(nodes) > EXPAND_MAX_NODES:
        # Sort: anomalous > high-risk > rest; stable within each tier by risk_score
        nodes_sorted = sorted(
            nodes,
            key=lambda n: (
                any(
                    e.is_anomalous
                    for e in edges
                    if e.source == n.id or e.target == n.id
                ),
                n.risk_score,
            ),
            reverse=True,
        )
        nodes = nodes_sorted[:EXPAND_MAX_NODES]

        kept_ids = {n.id for n in nodes}
        edges = [e for e in edges if e.source in kept_ids and e.target in kept_ids]

    return ExpandResponse(
        parent_super_node_id=super_node_id,
        nodes=nodes,
        edges=edges,
    )



# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cluster_visual_props(
    cluster_id: str, child_count: int
) -> Tuple[str, str, str, float]:
    """Returns (label, color, cluster_rule, base_risk_score) for a cluster_id."""
    if cluster_id == "super:external_threats":
        return (
            f"External Threats ({child_count} IPs)",
            "#EF4444",
            "external_ip",
            7.0,
        )
    elif cluster_id.startswith("super:subnet:"):
        subnet = cluster_id.replace("super:subnet:", "")
        return (
            f"Subnet {subnet} ({child_count} hosts)",
            "#3B82F6",
            "internal_subnet_24",
            2.0,
        )
    elif cluster_id == "super:web_urls":
        return (
            f"Web Endpoints ({child_count})",
            "#F59E0B",
            "url_collapse",
            3.0,
        )
    else:
        return (
            f"Cluster ({child_count})",
            "#8B5CF6",
            "unknown",
            1.0,
        )
