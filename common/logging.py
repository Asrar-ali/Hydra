"""Small logger factory. Use this instead of ``print`` in committed code."""
from __future__ import annotations

import logging
import os

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        logging.basicConfig(
            level=os.environ.get("HYDRA_LOG_LEVEL", "INFO"),
            format="%(asctime)s  %(name)-18s %(levelname)-7s %(message)s",
            datefmt="%H:%M:%S",
        )
        _CONFIGURED = True
    return logging.getLogger(name)
