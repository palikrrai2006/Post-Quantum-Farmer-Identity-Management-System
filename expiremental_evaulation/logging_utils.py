"""Structured logging utility shared across the PQC fingerprint system."""

from __future__ import annotations

import logging
from pathlib import Path

from config import LOG_FILE, LOG_LEVEL


def get_logger(name: str) -> logging.Logger:
    """Create (or fetch) a configured logger that writes to console and file.

    Args:
        name: The dotted module name, typically passed as ``__name__``.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(Path(LOG_FILE), encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger
