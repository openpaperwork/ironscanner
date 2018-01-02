#!/usr/bin/env python3

import logging
import sys

logger = logging.getLogger(__name__)


class LogTracker(logging.Handler):
    # Assuming 1KB per line, it makes about 50MB of RAM
    # (+ memory allocator overhead)
    MAX_LINES = 50 * 1000
    LOG_LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }

    def __init__(self):
        super(LogTracker, self).__init__()
        self._formatter = logging.Formatter(
            '%(levelname)-6s %(name)-30s %(message)s'
        )
        self.output = []

    def emit(self, record):
        line = self._formatter.format(record)
        self.output.append(line)
        if len(self.output) > self.MAX_LINES:
            self.output.pop(0)

    def get_logs(self):
        return "\n".join(self.output)

    def on_uncatched_exception_cb(self, exc_type, exc_value, exc_tb):
        logger.error(
            "=== UNCATCHED EXCEPTION ===",
            exc_info=(exc_type, exc_value, exc_tb)
        )
        logger.error(
            "==========================="
        )

    def init(self):
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(self._formatter)
        logger.addHandler(handler)
        logger.addHandler(self)
        sys.excepthook = self.on_uncatched_exception_cb
        logger.setLevel(logging.DEBUG)
