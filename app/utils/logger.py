"""
app/utils/logger.py
-------------------
Application-level logging setup.
Writes to console and a rotating log file.
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(name: str = "secmon", log_file: str = "secmon.log") -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # Already configured

    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler (INFO and above)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler (DEBUG and above, rotating)
    try:
        fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except PermissionError:
        logger.warning("Could not open log file %s — file logging disabled.", log_file)

    return logger


# Module-level logger for use throughout the app
log = setup_logger()
