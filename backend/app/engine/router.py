import logging
from typing import Tuple
import polars as pl
from app.engine.registry import ParserRegistry
import app.engine.parsers  # Ensures parsers register on import

logger = logging.getLogger(__name__)

MAX_PARSED_LINES = 50000
SNIFFER_SAMPLE_LINES = 100

class LogRouterEngine:
    """Unified file router utilizing Strategy and Registry patterns for log format
    auto-detection and Polars ETL parser dispatching.
    """

    @staticmethod
    def sniff_format(content_bytes: bytes) -> Tuple[str, float]:
        """Sniffs initial 50-100 lines of log bytes to determine log format strategy.
        
        Returns:
            Tuple of (format_key, confidence_score)
        """
        if not content_bytes:
            return "UNKNOWN", 0.0

        sample_text = content_bytes[:16384].decode("utf-8", errors="replace")
        sample_lines = [l for l in sample_text.splitlines() if l.strip()][:SNIFFER_SAMPLE_LINES]

        parser, score = ParserRegistry.sniff_and_select(sample_lines)
        return parser.format_key, score

    @staticmethod
    def route_and_parse(content_bytes: bytes) -> Tuple[pl.DataFrame, int, str]:
        """Routes uploaded log bytes to matching parser strategy based on heuristic sniffing.
        
        Returns:
            Tuple of (df_events, total_lines, detected_format_key)
        """
        raw_lines = content_bytes.decode("utf-8", errors="replace").splitlines()
        total_lines = len(raw_lines)

        if not raw_lines:
            return pl.DataFrame(), 0, "UNKNOWN"

        sample_lines = [l for l in raw_lines[:SNIFFER_SAMPLE_LINES] if l.strip()]
        parser, score = ParserRegistry.sniff_and_select(sample_lines)

        logger.info(f"Sniffed format '{parser.format_key}' with confidence {score:.2f}")

        # Parse with selected strategy
        sample_batch = raw_lines[:MAX_PARSED_LINES]
        df_raw = pl.DataFrame({"raw_line": sample_batch})
        df_events = parser.parse(df_raw)

        return df_events, total_lines, parser.format_key

    @staticmethod
    def stream_chunks(source, chunk_size: int = 1000):
        """Batch generator that breaks log payload into chunks (default 100k lines)
        and yields parsed Polars DataFrames incrementally for streaming ETL.
        Supports bytes or file-like streams (e.g. UploadFile.file).
        
        Yields:
            Tuple of (df_events_chunk, chunk_idx, total_chunks, processed_lines, total_lines, format_key)
        """
        if isinstance(source, (bytes, bytearray)):
            raw_lines = source.decode("utf-8", errors="replace").splitlines()
            total_lines = len(raw_lines)

            if not raw_lines:
                return

            sample_lines = [l for l in raw_lines[:SNIFFER_SAMPLE_LINES] if l.strip()]
            parser, score = ParserRegistry.sniff_and_select(sample_lines)

            logger.info(f"Stream sniffer detected format '{parser.format_key}' (confidence {score:.2f})")

            total_chunks = max(1, (total_lines + chunk_size - 1) // chunk_size)
            processed_lines = 0

            for chunk_idx in range(total_chunks):
                chunk_start = chunk_idx * chunk_size
                chunk_end = min(total_lines, chunk_start + chunk_size)
                batch_lines = raw_lines[chunk_start:chunk_end]
                processed_lines += len(batch_lines)

                df_raw = pl.DataFrame({"raw_line": batch_lines})
                df_events = parser.parse(df_raw)

                yield (df_events, chunk_idx, total_chunks, processed_lines, total_lines, parser.format_key)
        else:
            file_obj = source

            # 1. Get file size in O(1) via seek — no full-file scan
            if hasattr(file_obj, "seek"):
                file_obj.seek(0, 2)
                file_size = file_obj.tell()
                file_obj.seek(0)
            else:
                file_size = 0

            # 2. Read first 64KB sample for format sniffing + avg line length estimate
            sample_bytes = file_obj.read(65536) if hasattr(file_obj, "read") else b""
            if hasattr(file_obj, "seek"):
                file_obj.seek(0)

            sample_text = sample_bytes.decode("utf-8", errors="replace")
            sample_lines_raw = sample_text.splitlines()
            sample_lines = [l for l in sample_lines_raw if l.strip()][:SNIFFER_SAMPLE_LINES]

            # Estimate total lines from avg line length in the sample (never blocks on full scan)
            avg_line_len = (len(sample_bytes) / max(1, len(sample_lines_raw))) if sample_lines_raw else 120
            estimated_total_lines = max(1, int(file_size / max(1, avg_line_len))) if file_size > 0 else 0

            parser, score = ParserRegistry.sniff_and_select(sample_lines)
            logger.info(f"Stream sniffer detected format '{parser.format_key}' (confidence {score:.2f}, est. lines {estimated_total_lines:,})")

            try:
                reader = pl.read_csv_batched(
                    file_obj,
                    has_header=False,
                    new_columns=["raw_line"],
                    batch_size=chunk_size,
                    truncate_ragged_lines=True,
                    quote_char=None,
                    separator="\n"
                )
                chunk_idx = 0
                processed_lines = 0
                while True:
                    batches = reader.next_batches(1)
                    if not batches:
                        break
                    df_batch = batches[0]
                    lines_in_batch = len(df_batch)
                    if lines_in_batch == 0:
                        continue
                    processed_lines += lines_in_batch
                    # Use estimate until actual count exceeds it at the end
                    calc_total_lines = max(estimated_total_lines, processed_lines)
                    calc_total_chunks = max(1, (calc_total_lines + chunk_size - 1) // chunk_size)
                    df_events = parser.parse(df_batch)
                    yield (df_events, chunk_idx, calc_total_chunks, processed_lines, calc_total_lines, parser.format_key)
                    chunk_idx += 1
            except Exception as exc:
                logger.warning(f"Polars read_csv_batched fallback to streaming line iterator: {exc}")
                if hasattr(file_obj, "seek"):
                    file_obj.seek(0)

                batch_lines = []
                chunk_idx = 0
                processed_lines = 0

                for line in file_obj:
                    if isinstance(line, bytes):
                        line = line.decode("utf-8", errors="replace")
                    batch_lines.append(line.rstrip("\r\n"))

                    if len(batch_lines) >= chunk_size:
                        processed_lines += len(batch_lines)
                        calc_total_lines = max(estimated_total_lines, processed_lines)
                        calc_total_chunks = max(1, (calc_total_lines + chunk_size - 1) // chunk_size)
                        df_raw = pl.DataFrame({"raw_line": batch_lines})
                        df_events = parser.parse(df_raw)
                        yield (df_events, chunk_idx, calc_total_chunks, processed_lines, calc_total_lines, parser.format_key)
                        chunk_idx += 1
                        batch_lines = []

                if batch_lines:
                    processed_lines += len(batch_lines)
                    calc_total_lines = max(estimated_total_lines, processed_lines)
                    calc_total_chunks = max(1, (calc_total_lines + chunk_size - 1) // chunk_size)
                    df_raw = pl.DataFrame({"raw_line": batch_lines})
                    df_events = parser.parse(df_raw)
                    yield (df_events, chunk_idx, calc_total_chunks, processed_lines, calc_total_lines, parser.format_key)


