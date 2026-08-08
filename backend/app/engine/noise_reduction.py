import polars as pl

# ─────────────────────────────────────────────────────────────────────────────
# Thresholds – tunable without touching graph_builder logic
# ─────────────────────────────────────────────────────────────────────────────
BRUTE_FORCE_MIN_ATTEMPTS      = 5
BRUTE_FORCE_FAIL_RATIO        = 0.5   # ≥50 % failures → brute force
PRIVILEGE_USERS               = {"root", "admin", "administrator", "wheel", "sudo"}
MULTI_USER_PIVOT_THRESHOLD    = 2     # ≥2 distinct users from one IP
HIGH_FREQ_COLLAPSED_THRESHOLD = 100   # pure success ≥100 hits → baseline noise

# HTTP-specific
HTTP_STATIC_EXTENSIONS = {
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Stylesheets & scripts
    ".css", ".js", ".mjs", ".map",
    # Media
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi", ".flv", ".swf",
    # Documents & data (non-API)
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".gz", ".tar",
    # Misc static
    ".txt", ".xml", ".json", ".rss", ".atom", ".manifest",
}
HTTP_SCAN_MIN_DISTINCT_PATHS  = 5    # ≥5 distinct 4xx paths from one IP → scanner
HTTP_COLLAPSE_REPEATED_MIN    = 20   # collapse repeated 200 GET to same path prefix


class AlgorithmicNoiseReducer:
    """
    Vectorised Polars noise-reduction & anomaly-scoring pipeline.

    Strategy:
    ─────────
    SSH layer
        • Aggregate raw events → 1 edge per (src_ip, dest_host).
        • Score each aggregated edge using vectorised Polars expressions
          (no Python-level row iteration).
        • Drop "HIGH_FREQUENCY_COLLAPSED" edges (pure-baseline noise) that
          are not also involved in a privilege pivot.

    HTTP layer
        • Collapse path to stem prefix (first two segments) so that
          scanner enumeration like /admin/1, /admin/2, … collapses to one
          node instead of thousands.
        • Drop static-asset GETs with 200 status (CDN / browser cache traffic).
        • Aggregate (src_ip, path_prefix, verb) → 1 edge.
        • Flag 4xx scanners, POST exploits, high-volume 2xx directories.
    """

    # ─────────────────────────────────────────────────────────────────────────
    # SSH
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def process_ssh_edges(df_events: pl.DataFrame) -> pl.DataFrame:
        """
        Input columns expected: src_ip, dest_host, auth_result, user, timestamp.
        Returns one row per unique (src_ip, dest_host) with anomaly metrics
        already computed via vectorised Polars expressions.
        """
        if df_events.is_empty():
            return pl.DataFrame()

        # ── 1. Aggregate raw events → 1 edge per pair ──────────────────────
        aggregated = (
            df_events
            .group_by(["src_ip", "dest_host"])
            .agg([
                pl.len().alias("total_attempts"),
                pl.col("auth_result").filter(pl.col("auth_result") == "SUCCESS")
                    .len().alias("successful_auths"),
                pl.col("auth_result").filter(pl.col("auth_result") == "FAILURE")
                    .len().alias("failed_auths"),
                pl.col("user").unique().alias("distinct_users"),
                pl.col("timestamp").min().alias("first_timestamp"),
                pl.col("timestamp").max().alias("last_timestamp"),
            ])
        )

        # ── 2. Vectorised feature flags ─────────────────────────────────────
        #   fail_ratio, is_brute_force, has_priv_user, is_multi_pivot, is_collapsed
        aggregated = aggregated.with_columns([
            # failure ratio – safe division
            (pl.col("failed_auths") / pl.col("total_attempts").cast(pl.Float64))
                .alias("fail_ratio"),
            # distinct_users list → len
            pl.col("distinct_users").list.len().alias("n_users"),
        ])

        aggregated = aggregated.with_columns([
            # brute-force burst
            (
                (pl.col("total_attempts") > BRUTE_FORCE_MIN_ATTEMPTS) &
                (pl.col("fail_ratio")     >= BRUTE_FORCE_FAIL_RATIO)
            ).alias("is_brute_force"),

            # privilege-user pivot (contains any sensitive username)
            pl.col("distinct_users").list.eval(
                pl.element().is_in(list(PRIVILEGE_USERS))
            ).list.any().alias("has_priv_user"),

            # multi-user pivot from single source
            (pl.col("n_users") >= MULTI_USER_PIVOT_THRESHOLD).alias("is_multi_pivot"),

            # high-frequency fully-successful (baseline noise)
            (
                (pl.col("total_attempts") >= HIGH_FREQ_COLLAPSED_THRESHOLD) &
                (pl.col("failed_auths")   == 0) &
                (pl.col("n_users")        == 1)
            ).alias("is_collapsed"),
        ])

        # ── 3. Risk score (vectorised) ──────────────────────────────────────
        aggregated = aggregated.with_columns(
            (
                pl.lit(1.0)
                + pl.col("is_brute_force").cast(pl.Float64) * 3.5
                + pl.col("has_priv_user").cast(pl.Float64) * 2.5
                + pl.col("is_multi_pivot").cast(pl.Float64) * 2.0
                # collapsed noise gets a penalty
                - pl.col("is_collapsed").cast(pl.Float64) * 2.0
            ).round(2).alias("risk_score")
        )

        # ── 4. is_anomalous flag ────────────────────────────────────────────
        aggregated = aggregated.with_columns(
            (
                (pl.col("is_brute_force") | pl.col("has_priv_user") | pl.col("is_multi_pivot")) &
                ~(pl.col("is_collapsed") & ~pl.col("has_priv_user"))
            ).alias("is_anomalous")
        )

        # ── 5. Drop pure baseline noise (collapsed & not anomalous) ─────────
        aggregated = aggregated.filter(
            ~(pl.col("is_collapsed") & ~pl.col("is_anomalous"))
        )

        return aggregated

    # keep old name for backward-compat with any test that still calls it
    @staticmethod
    def process_edge_heuristics(df_events: pl.DataFrame) -> pl.DataFrame:
        return AlgorithmicNoiseReducer.process_ssh_edges(df_events)

    # ─────────────────────────────────────────────────────────────────────────
    # HTTP
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def process_http_edges(df_events: pl.DataFrame) -> pl.DataFrame:
        """
        Input columns expected: src_ip, uri, verb, status_code, timestamp.
        Returns aggregated, noise-filtered HTTP edge topology.
        """
        if df_events.is_empty():
            return pl.DataFrame()

        # ── 1. Drop ALL requests to static assets (biggest noise source) ─────
        #   Any request to a .gif/.css/.js/etc is noise regardless of verb or
        #   status code — browsers prefetch, CDNs 404, crawlers HEAD these.
        static_ext_pattern = "(?i)\\.(" + "|".join(
            e.lstrip(".") for e in HTTP_STATIC_EXTENSIONS
        ) + ")(\\?.*)?$"

        df_events = df_events.filter(
            ~pl.col("uri").str.contains(static_ext_pattern)
        )

        if df_events.is_empty():
            return pl.DataFrame()

        # ── 2. Semantic URI collapsing ────────────────────────────────────────
        #   Step A: Strip query parameters   /item?id=1&page=2  →  /item
        #   Step B: Replace numeric & UUID path segments with '*'
        #           /api/v1/users/42/profile  →  /api/v1/users/*/profile
        #           /item/550e8400-e29b-41d4-a716-446655440000  →  /item/*
        #   Step C: Collapse to first 2 meaningful path segments
        #           /api/v1/users/*/profile   →  /api/v1
        #   This merges thousands of dynamic URL variants into a handful of
        #   semantic endpoint nodes.
        df_events = df_events.with_columns(
            pl.col("uri")
            .str.replace(r"\?.*$", "")                              # strip query string
            .str.replace(r"#.*$", "")                                # strip fragment
            .str.replace_all(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/*")  # UUIDs → *
            .str.replace_all(r"/\d+", "/*")                          # numeric segments → *
            .str.replace_all(r"(/\*)+", "/*")                        # collapse consecutive /*/*/  → /*
            .str.extract(r"^((?:/[^/]*){1,2})")                      # keep first 2 path segments
            .fill_null(pl.col("uri"))
            .alias("uri_prefix")
        )

        # ── 3. Aggregate (src_ip, uri_prefix, verb) → 1 edge ────────────────
        aggregated = (
            df_events
            .group_by(["src_ip", "uri_prefix", "verb"])
            .agg([
                pl.len().alias("total_attempts"),
                pl.col("status_code").mode().first().alias("status_code"),
                pl.col("status_code").filter(
                    (pl.col("status_code") >= 400) & (pl.col("status_code") < 500)
                ).len().alias("count_4xx"),
                pl.col("status_code").filter(
                    pl.col("status_code") >= 500
                ).len().alias("count_5xx"),
                pl.col("timestamp").min().alias("first_timestamp"),
                pl.col("timestamp").max().alias("last_timestamp"),
            ])
        )

        # ── 4. Drop high-frequency clean GETs (repeated 2xx non-anomalous) ──
        aggregated = aggregated.filter(
            ~(
                (pl.col("verb") == "GET") &
                (pl.col("count_4xx") == 0) &
                (pl.col("count_5xx") == 0) &
                (pl.col("total_attempts") >= HTTP_COLLAPSE_REPEATED_MIN)
            )
        )

        # ── 5. Vectorised anomaly scoring ────────────────────────────────────
        aggregated = aggregated.with_columns([
            (pl.col("count_4xx") > 0).alias("has_4xx"),
            (pl.col("count_5xx") > 0).alias("has_5xx"),
            (pl.col("verb") == "POST").alias("is_post"),
            (pl.col("verb").is_in(["DELETE", "PUT", "PATCH"])).alias("is_write"),
        ])

        aggregated = aggregated.with_columns(
            (
                pl.lit(1.0)
                + pl.col("is_post").cast(pl.Float64)  * 2.5
                + pl.col("is_write").cast(pl.Float64) * 1.5
                + pl.col("has_4xx").cast(pl.Float64)  * 1.5
                + pl.col("has_5xx").cast(pl.Float64)  * 2.0
            ).round(2).alias("risk_score")
        )

        aggregated = aggregated.with_columns(
            (
                pl.col("is_post") | pl.col("is_write") |
                pl.col("has_4xx") | pl.col("has_5xx")
            ).alias("is_anomalous")
        )

        return aggregated
