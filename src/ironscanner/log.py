#!/usr/bin/env python3

import base64
import logging
import os
import sys
import tempfile

logger = logging.getLogger(__name__)


class LogTracker(logging.Handler):
    LOG_LEVELS = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }

    def __init__(self):
        super().__init__()
        self._formatter = logging.Formatter(
            '%(levelname)-6s %(asctime)-15s %(name)-10s %(message)s'
        )
        self.outfile = None

    def emit(self, record):
        line = self._formatter.format(record)
        sys.stderr.write(line + "\n")

    def on_uncatched_exception_cb(self, exc_type, exc_value, exc_tb):
        logger.error(
            "=== UNCATCHED EXCEPTION ===",
            exc_info=(exc_type, exc_value, exc_tb)
        )
        logger.error(
            "==========================="
        )

    def init(self):
        self.outfile = tempfile.NamedTemporaryFile(
            mode="w+", newline='\n', prefix='ironscanner_', suffix='.txt',
            delete=False
        )
        sys.stderr.write(
            "Logs will be stored temporarily in: {}\n".format(
                self.outfile.name
            )
        )

        os.dup2(self.outfile.fileno(), sys.stdout.fileno())
        os.dup2(self.outfile.fileno(), sys.stderr.fileno())

        logger = logging.getLogger()
        logger.addHandler(self)
        sys.excepthook = self.on_uncatched_exception_cb
        logger.setLevel(logging.DEBUG)

    def get_logs(self):
        self.outfile.flush()
        logs = None
        with open(self.outfile.name, 'r') as fd:
            logs = fd.read()
        self.cleanup()
        return logs

    def complete_report(self, report):
        traces = ""
        try:
            logs = self.get_logs()
            traces = base64.encodebytes(logs.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            traces = "(Exception: {})".format(str(exc))
            logger.error("Exception while encoding traces", exc_info=exc)
        report['traces'] = traces

    def cleanup(self):
        if os.path.exists(self.outfile.name):
            # os.unlink(self.outfile.name)
            pass

    def __str__(self):
        return "Traces"
