import re
from typing import Tuple
import polars as pl

# Regex patterns for Syslog, NCSA, and Squid
ACCEPTED_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
FAILED_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed\s+(?P<auth_method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
INVALID_USER_PATTERN = r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)"

HTTP_ACCESS_PATTERN = r"(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+\"(?P<verb>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[0-9.]+\"\s+(?P<status_code>\d+)\s+(?P<bytes_sent>\d+)"
SQUID_ACCESS_PATTERN = r"^\s*(?P<timestamp>\d+\.\d+)\s+\d+\s+(?P<src_ip>\S+)\s+\S+/(?P<status_code>\d+)\s+(?P<bytes_sent>\d+)\s+(?P<verb>[A-Z]+)\s+(?P<uri>\S+)"

MAX_PARSED_LINES = 50000

class LogParserEngine:
    """High-throughput multi-format Polars log parsing engine supporting Linux auth.log,
    Apache/Nginx access logs, Squid Proxy logs, and Zeek TSV network logs.
    """

    @staticmethod
    def parse_log_bytes(content: bytes, detected_format: str = "UNKNOWN") -> Tuple[pl.DataFrame, pl.DataFrame, int]:
        """Parses raw log bytes and returns (df_ssh_events, df_http_events, total_lines)."""
        raw_lines = content.decode("utf-8", errors="replace").splitlines()
        total_lines = len(raw_lines)

        if not raw_lines:
            return pl.DataFrame(), pl.DataFrame(), 0

        # Subsample for ultra-fast processing on multi-gigabyte log files
        sample_lines = raw_lines[:MAX_PARSED_LINES]
        df_raw = pl.DataFrame({"raw_line": sample_lines})

        df_ssh = pl.DataFrame()
        df_http = pl.DataFrame()

        # 1. ZEEK TSV LOG PARSER
        if detected_format == "ZEEK_TSV" or any("\t" in line for line in sample_lines[:5]):
            non_comment_df = df_raw.filter(~pl.col("raw_line").str.starts_with("#"))
            if not non_comment_df.is_empty():
                df_split = non_comment_df.with_columns(pl.col("raw_line").str.split("\t"))
                col_count = len(df_split["raw_line"][0]) if len(df_split) > 0 else 0

                # Zeek HTTP log
                if col_count >= 10 and any("GET" in line or "HEAD" in line or "POST" in line for line in sample_lines[:20]):
                    df_http = (
                        df_split
                        .with_columns([
                            pl.col("raw_line").list.get(0).alias("timestamp"),
                            pl.col("raw_line").list.get(2).alias("src_ip"),
                            pl.col("raw_line").list.get(7).alias("verb"),
                            pl.col("raw_line").list.get(9).alias("uri"),
                            pl.col("raw_line").list.get(14, null_on_oob=True).cast(pl.Int32, strict=False).alias("status_code"),
                            pl.lit(100).alias("bytes_sent"),
                            pl.lit("HTTP").alias("protocol")
                        ])
                        .filter(pl.col("src_ip").is_not_null() & (pl.col("src_ip") != "-"))
                    )
                # Zeek SSH log
                elif col_count >= 6:
                    df_ssh = (
                        df_split
                        .with_columns([
                            pl.col("raw_line").list.get(0).alias("timestamp"),
                            pl.col("raw_line").list.get(2).alias("src_ip"),
                            pl.col("raw_line").list.get(4).alias("dest_host"),
                            pl.col("raw_line").list.get(6, null_on_oob=True).alias("auth_result_raw"),
                            pl.lit("password").alias("auth_method"),
                            pl.lit("root").alias("user"),
                            pl.lit("SSH").alias("protocol")
                        ])
                        .with_columns(
                            pl.when(pl.col("auth_result_raw").str.contains("success"))
                            .then(pl.lit("SUCCESS"))
                            .otherwise(pl.lit("FAILURE"))
                            .alias("auth_result")
                        )
                        .filter(pl.col("src_ip").is_not_null() & (pl.col("src_ip") != "-"))
                    )

        # 2. SQUID PROXY ACCESS LOG PARSER
        if df_http.is_empty() and (detected_format == "SQUID_ACCESS" or any("TCP_" in line for line in sample_lines[:10])):
            df_http = (
                df_raw
                .filter(pl.col("raw_line").str.contains(r"TCP_"))
                .with_columns([
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 1).alias("timestamp"),
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 2).alias("src_ip"),
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 3).cast(pl.Int32, strict=False).alias("status_code"),
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 4).cast(pl.Int32, strict=False).alias("bytes_sent"),
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 5).alias("verb"),
                    pl.col("raw_line").str.extract(SQUID_ACCESS_PATTERN, 6).alias("uri"),
                    pl.lit("HTTP").alias("protocol")
                ])
                .filter(pl.col("src_ip").is_not_null())
            )

        # 3. LINUX SYSLOG SSH PARSER (Accepted + Failed + Invalid user)
        if df_ssh.is_empty():
            df_accepted = (
                df_raw
                .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Accepted"))
                .with_columns([
                    pl.col("raw_line").str.extract(ACCEPTED_PATTERN, 1).alias("timestamp"),
                    pl.col("raw_line").str.extract(ACCEPTED_PATTERN, 2).alias("dest_host"),
                    pl.col("raw_line").str.extract(ACCEPTED_PATTERN, 3).alias("auth_method"),
                    pl.col("raw_line").str.extract(ACCEPTED_PATTERN, 4).alias("user"),
                    pl.col("raw_line").str.extract(ACCEPTED_PATTERN, 5).alias("src_ip"),
                    pl.lit("SUCCESS").alias("auth_result"),
                    pl.lit("SSH").alias("protocol")
                ])
            )

            df_failed = (
                df_raw
                .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Failed"))
                .with_columns([
                    pl.col("raw_line").str.extract(FAILED_PATTERN, 1).alias("timestamp"),
                    pl.col("raw_line").str.extract(FAILED_PATTERN, 2).alias("dest_host"),
                    pl.col("raw_line").str.extract(FAILED_PATTERN, 3).alias("auth_method"),
                    pl.col("raw_line").str.extract(FAILED_PATTERN, 4).alias("user"),
                    pl.col("raw_line").str.extract(FAILED_PATTERN, 5).alias("src_ip"),
                    pl.lit("FAILURE").alias("auth_result"),
                    pl.lit("SSH").alias("protocol")
                ])
            )

            df_invalid = (
                df_raw
                .filter(pl.col("raw_line").str.contains(r"sshd\[\d+\]:\s+Invalid user"))
                .with_columns([
                    pl.col("raw_line").str.extract(INVALID_USER_PATTERN, 1).alias("timestamp"),
                    pl.col("raw_line").str.extract(INVALID_USER_PATTERN, 2).alias("dest_host"),
                    pl.lit("password").alias("auth_method"),
                    pl.col("raw_line").str.extract(INVALID_USER_PATTERN, 3).alias("user"),
                    pl.col("raw_line").str.extract(INVALID_USER_PATTERN, 4).alias("src_ip"),
                    pl.lit("FAILURE").alias("auth_result"),
                    pl.lit("SSH").alias("protocol")
                ])
            )

            ssh_dfs = [df for df in [df_accepted, df_failed, df_invalid] if len(df) > 0]
            if ssh_dfs:
                df_ssh = pl.concat(ssh_dfs, how="vertical").filter(pl.col("src_ip").is_not_null())

        # 4. APACHE/NGINX COMBINED LOG PARSER
        if df_http.is_empty():
            df_http = (
                df_raw
                .filter(pl.col("raw_line").str.contains(r"\"[A-Z]+\s+\S+\s+HTTP/"))
                .with_columns([
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 1).alias("src_ip"),
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 2).alias("timestamp"),
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 3).alias("verb"),
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 4).alias("uri"),
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 5).cast(pl.Int32, strict=False).alias("status_code"),
                    pl.col("raw_line").str.extract(HTTP_ACCESS_PATTERN, 6).cast(pl.Int32, strict=False).alias("bytes_sent"),
                    pl.lit("HTTP").alias("protocol")
                ])
                .filter(pl.col("src_ip").is_not_null())
            )

        return df_ssh, df_http, total_lines

    @staticmethod
    def parse_auth_log_bytes(content: bytes) -> Tuple[pl.DataFrame, pl.DataFrame, int]:
        """Legacy compatibility wrapper."""
        return LogParserEngine.parse_log_bytes(content, "UNKNOWN")
