import re
from typing import List
import polars as pl
from app.engine.base import BaseLogParser, UNIFIED_COLUMNS

HTTP_ACCESS_PATTERN = r"(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+\"(?P<verb>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[0-9.]+\"\s+(?P<status_code>\d+)\s+(?P<bytes_sent>\d+)"
SQUID_ACCESS_PATTERN = r"^\s*(?P<timestamp>\d+\.\d+)\s+\d+\s+(?P<src_ip>\S+)\s+\S+/(?P<status_code>\d+)\s+(?P<bytes_sent>\d+)\s+(?P<verb>[A-Z]+)\s+(?P<uri>\S+)"

class HTTPWebParser(BaseLogParser):
    """Modular parser for Apache/Nginx Combined and Squid Proxy access logs."""

    @property
    def format_key(self) -> str:
        return "NCSA_SQUID_HTTP"

    def detect_score(self, sample_lines: List[str]) -> float:
        if not sample_lines:
            return 0.0

        matches = 0
        for line in sample_lines:
            if re.search(r"HTTP/1\.[01]|HTTP/2|TCP_(MISS|HIT|DENIED|REFRESH_HIT)", line) or re.search(r'GET\s+\S+|POST\s+\S+', line):
                matches += 1

        return min(1.0, matches / max(1, len(sample_lines)))

    def parse(self, df_raw: pl.DataFrame) -> pl.DataFrame:
        if df_raw.is_empty():
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        # 1. Squid Proxy Access Format
        df_squid = (
            df_raw
            .filter(pl.col("raw_line").str.contains(r"TCP_"))
            .with_columns(pl.col("raw_line").str.extract_groups(SQUID_ACCESS_PATTERN).alias("g"))
            .with_columns([
                pl.col("g").struct.field("timestamp").alias("timestamp"),
                pl.col("g").struct.field("src_ip").alias("source_ip"),
                pl.lit("HTTP").alias("protocol"),
                pl.col("g").struct.field("verb").alias("action"),
                pl.col("g").struct.field("uri").alias("target"),
                pl.struct([
                    pl.col("g").struct.field("status_code").cast(pl.Int32, strict=False).alias("status_code"),
                    pl.col("g").struct.field("bytes_sent").cast(pl.Int32, strict=False).alias("bytes_sent")
                ]).struct.json_encode().alias("metadata")
            ])
            .filter(pl.col("source_ip").is_not_null())
            .select(UNIFIED_COLUMNS)
        )

        # 2. Apache / Nginx Combined Log Format
        df_ncsa = (
            df_raw
            .filter(pl.col("raw_line").str.contains(r"\"[A-Z]+\s+\S+\s+HTTP/"))
            .with_columns(pl.col("raw_line").str.extract_groups(HTTP_ACCESS_PATTERN).alias("g"))
            .with_columns([
                pl.col("g").struct.field("timestamp").alias("timestamp"),
                pl.col("g").struct.field("src_ip").alias("source_ip"),
                pl.lit("HTTP").alias("protocol"),
                pl.col("g").struct.field("verb").alias("action"),
                pl.col("g").struct.field("uri").alias("target"),
                pl.struct([
                    pl.col("g").struct.field("status_code").cast(pl.Int32, strict=False).alias("status_code"),
                    pl.col("g").struct.field("bytes_sent").cast(pl.Int32, strict=False).alias("bytes_sent")
                ]).struct.json_encode().alias("metadata")
            ])
            .filter(pl.col("source_ip").is_not_null())
            .select(UNIFIED_COLUMNS)
        )

        dfs = [df for df in [df_squid, df_ncsa] if len(df) > 0]
        if not dfs:
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        return pl.concat(dfs, how="vertical")
