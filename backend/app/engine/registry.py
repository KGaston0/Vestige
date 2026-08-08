import logging
from typing import Dict, List, Tuple, Optional
from app.engine.base import BaseLogParser

logger = logging.getLogger(__name__)

class ParserRegistry:
    """Central registry for modular log parser strategies (Registry Pattern).
    
    Provides heuristic sniffing over sample lines to select the best parser strategy
    and execute unified event extraction.
    """

    _parsers: Dict[str, BaseLogParser] = {}

    @classmethod
    def register(cls, parser: BaseLogParser) -> None:
        """Registers a parser strategy instance into the central registry."""
        cls._parsers[parser.format_key] = parser
        logger.info(f"Registered log parser strategy: {parser.format_key}")

    @classmethod
    def get_parser(cls, format_key: str) -> Optional[BaseLogParser]:
        """Retrieves a registered parser by format key."""
        return cls._parsers.get(format_key)

    @classmethod
    def sniff_and_select(cls, sample_lines: List[str]) -> Tuple[BaseLogParser, float]:
        """Sniffs sample lines (first 50-100 lines) across all registered parsers,
        scoring format confidence to select the best strategy.
        
        Returns:
            Tuple of (selected_parser_instance, confidence_score)
        """
        best_parser: Optional[BaseLogParser] = None
        best_score: float = 0.0

        for key, parser in cls._parsers.items():
            score = parser.detect_score(sample_lines)
            if score > best_score:
                best_score = score
                best_parser = parser

        if best_parser is None or best_score <= 0.0:
            # Return first registered parser as fallback if score is 0
            fallback = list(cls._parsers.values())[0] if cls._parsers else None
            if fallback is None:
                raise RuntimeError("No log parser strategies registered in ParserRegistry.")
            return fallback, 0.0

        return best_parser, best_score

    @classmethod
    def list_formats(cls) -> List[str]:
        """Returns list of registered format keys."""
        return list(cls._parsers.keys())
