import re
from typing import List
import polars as pl
from app.engine.base import BaseLogParser, UNIFIED_COLUMNS

ACCEPTED_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
FAILED_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
INVALID_USER_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"

class SSHAuthParser(BaseLogParser):
    """Modular parser for Linux SSH Syslog authentication logs."""

    @property
    def format_key(self) -> str:
        return "SYSLOG_SSH"

    def detect_score(self, sample_lines: List[str]) -> float:
        if not sample_lines:
            return 0.0
        
        matches = 0
        keywords = [r"sshd\[\d+\]", r"pam_unix", r"Accepted", r"Failed", r"Invalid user"]
        for line in sample_lines:
            if any(re.search(kw, line) for kw in keywords):
                matches += 1

        return min(1.0, matches / max(1, len(sample_lines)))

    def parse(self, df_raw: pl.DataFrame) -> pl.DataFrame:
        if df_raw.is_empty():
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        # 1. Accepted SSH connections
        df_accepted = (
            df_raw
            .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Accepted"))
            .with_columns(pl.col("raw_line").str.extract_groups(ACCEPTED_PATTERN).alias("g"))
            .with_columns([
                pl.col("g").struct.field("timestamp").alias("timestamp"),
                pl.col("g").struct.field("src_ip").alias("source_ip"),
                pl.lit("SSH").alias("protocol"),
                pl.lit("SUCCESS").alias("action"),
                pl.col("g").struct.field("host").alias("target"),
                pl.struct([
                    pl.col("g").struct.field("user").alias("user"),
                    pl.col("g").struct.field("auth_method").alias("auth_method"),
                    pl.col("g").struct.field("host").alias("dest_host")
                ]).struct.json_encode().alias("metadata")
            ])
            .filter(pl.col("source_ip").is_not_null())
            .select(UNIFIED_COLUMNS)
        )

        # 2. Failed SSH connections
        df_failed = (
            df_raw
            .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Failed"))
            .with_columns(pl.col("raw_line").str.extract_groups(FAILED_PATTERN).alias("g"))
            .with_columns([
                pl.col("g").struct.field("timestamp").alias("timestamp"),
                pl.col("g").struct.field("src_ip").alias("source_ip"),
                pl.lit("SSH").alias("protocol"),
                pl.lit("FAILURE").alias("action"),
                pl.col("g").struct.field("host").alias("target"),
                pl.struct([
                    pl.col("g").struct.field("user").alias("user"),
                    pl.col("g").struct.field("auth_method").alias("auth_method"),
                    pl.col("g").struct.field("host").alias("dest_host")
                ]).struct.json_encode().alias("metadata")
            ])
            .filter(pl.col("source_ip").is_not_null())
            .select(UNIFIED_COLUMNS)
        )

        # 3. Invalid user SSH connections
        df_invalid = (
            df_raw
            .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Invalid user"))
            .with_columns(pl.col("raw_line").str.extract_groups(INVALID_USER_PATTERN).alias("g"))
            .with_columns([
                pl.col("g").struct.field("timestamp").alias("timestamp"),
                pl.col("g").struct.field("src_ip").alias("source_ip"),
                pl.lit("SSH").alias("protocol"),
                pl.lit("FAILURE").alias("action"),
                pl.col("g").struct.field("host").alias("target"),
                pl.struct([
                    pl.col("g").struct.field("user").alias("user"),
                    pl.lit("password").alias("auth_method"),
                    pl.col("g").struct.field("host").alias("dest_host")
                ]).struct.json_encode().alias("metadata")
            ])
            .filter(pl.col("source_ip").is_not_null())
            .select(UNIFIED_COLUMNS)
        )

        dfs = [df for df in [df_accepted, df_failed, df_invalid] if len(df) > 0]
        if not dfs:
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        return pl.concat(dfs, how="vertical")
