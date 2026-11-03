"""Telemetry and structured logging configuration."""

import logging
import time
from typing import Any, Dict
import structlog


def configure_logging():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )


configure_logging()
logger = structlog.get_logger("sentinel_exfil")


class TelemetryTimer:
    """Context manager to measure latency in milliseconds."""

    def __init__(self, name: str):
        self.name = name
        self.start_time = 0.0
        self.elapsed_ms = 0.0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000.0
