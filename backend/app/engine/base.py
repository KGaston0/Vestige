from abc import ABC, abstractmethod
from typing import List
import polars as pl

# Standardized Unified Schema Column Contract
UNIFIED_COLUMNS = ["timestamp", "source_ip", "protocol", "action", "target", "metadata"]

class BaseLogParser(ABC):
    """Abstract Base Class for modular log parsers (Strategy Pattern).
    
    Every concrete parser implements heuristic confidence scoring and Polars extraction
    that maps raw log lines into the standardized unified event schema:
    [timestamp, source_ip, protocol, action, target, metadata]
    """

    @property
    @abstractmethod
    def format_key(self) -> str:
        """Returns the unique format key string (e.g., 'SYSLOG_SSH', 'NCSA_HTTP')."""
        pass

    @abstractmethod
    def detect_score(self, sample_lines: List[str]) -> float:
        """Inspects sample lines and returns a confidence score between 0.0 and 1.0."""
        pass

    @abstractmethod
    def parse(self, df_raw: pl.DataFrame) -> pl.DataFrame:
        """Parses raw lines DataFrame into standardized unified schema DataFrame:
        [timestamp, source_ip, protocol, action, target, metadata]
        """
        pass
