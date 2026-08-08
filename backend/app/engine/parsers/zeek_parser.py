from typing import List
import polars as pl
from app.engine.base import BaseLogParser, UNIFIED_COLUMNS

class ZeekTSVParser(BaseLogParser):
    """Modular parser for Zeek / Bro tab-separated network logs (SSH & HTTP)."""

    @property
    def format_key(self) -> str:
        return "ZEEK_TSV"

    def detect_score(self, sample_lines: List[str]) -> float:
        if not sample_lines:
            return 0.0

        score = 0.0
        if any(line.startswith("#fields") or line.startswith("#types") for line in sample_lines):
            score += 0.9

        tab_count = sum(1 for line in sample_lines if "\t" in line and len(line.split("\t")) >= 6)
        if tab_count > 0:
            score += min(0.8, tab_count / max(1, len(sample_lines)))

        return min(1.0, score)

    def parse(self, df_raw: pl.DataFrame) -> pl.DataFrame:
        if df_raw.is_empty():
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        non_comment_df = df_raw.filter(~pl.col("raw_line").str.starts_with("#"))
        if non_comment_df.is_empty():
            return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})

        df_split = non_comment_df.with_columns(pl.col("raw_line").str.split("\t"))
        sample_first = df_split["raw_line"][0]
        col_count = len(sample_first)

        # 1. Zeek HTTP Log
        if col_count >= 10 and any("GET" in str(line) or "HEAD" in str(line) or "POST" in str(line) for line in sample_first):
            return (
                df_split
                .with_columns([
                    pl.col("raw_line").list.get(0).alias("timestamp"),
                    pl.col("raw_line").list.get(2).alias("source_ip"),
                    pl.lit("HTTP").alias("protocol"),
                    pl.col("raw_line").list.get(7).alias("action"),
                    pl.col("raw_line").list.get(9).alias("target"),
                    pl.struct([
                        pl.col("raw_line").list.get(14, null_on_oob=True).cast(pl.Int32, strict=False).alias("status_code"),
                        pl.lit(100).alias("bytes_sent")
                    ]).struct.json_encode().alias("metadata")
                ])
                .filter(pl.col("source_ip").is_not_null() & (pl.col("source_ip") != "-"))
                .select(UNIFIED_COLUMNS)
            )

        # 2. Zeek SSH Log
        if col_count >= 6:
            return (
                df_split
                .with_columns([
                    pl.col("raw_line").list.get(0).alias("timestamp"),
                    pl.col("raw_line").list.get(2).alias("source_ip"),
                    pl.lit("SSH").alias("protocol"),
                    pl.col("raw_line").list.get(6, null_on_oob=True).alias("auth_result_raw"),
                    pl.col("raw_line").list.get(4).alias("target"),
                    pl.struct([
                        pl.lit("root").alias("user"),
                        pl.lit("password").alias("auth_method")
                    ]).struct.json_encode().alias("metadata")
                ])
                .with_columns(
                    pl.when(pl.col("auth_result_raw").str.contains("success"))
                    .then(pl.lit("SUCCESS"))
                    .otherwise(pl.lit("FAILURE"))
                    .alias("action")
                )
                .filter(pl.col("source_ip").is_not_null() & (pl.col("source_ip") != "-"))
                .select(UNIFIED_COLUMNS)
            )

        return pl.DataFrame(schema={c: pl.Utf8 for c in UNIFIED_COLUMNS})
