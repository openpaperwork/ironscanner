#!/usr/bin/env python3

import logging
import sys
import threading

logger = logging.getLogger(__name__)


def _trace(frame, event, arg):
    if event == "call":
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno
        logger.debug("%s:%s() @ %s" % (filename, frame.f_code.co_name, lineno))
    return _trace


class TraceThread(threading.Thread):
    def __init__(self, func, args, kwargs, end_func):
        super().__init__(name="TraceThread({})".format(str(func)))
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.end_func = end_func
        self.ret = None
        self.exc = None

    def run(self):
        sys.settrace(_trace)
        try:
            self.ret = self.func(*self.args, **self.kwargs)
        except Exception as exc:
            self.exc = exc
            sys.settrace(None)
            logger.error("Exception while calling {}".format(str(self.func)),
                         exc_info=exc)
        finally:
            sys.settrace(None)
            self.end_func()


class TimeoutException(Exception):
    pass


def trace(func, *args, **kwargs):
    trace_timeout = kwargs.pop("trace_timeout", 120)

    condition = threading.Condition()

    def no_timeout():
        with condition:
            condition.notify_all()

    thread = TraceThread(func, args, kwargs, no_timeout)

    with condition:
        thread.start()
        if not condition.wait(trace_timeout):
            raise TimeoutException(
                "Call to {} lasted more than {} seconds !".format(
                    str(func), trace_timeout
                )
            )

    if thread.exc is not None:
        raise thread.exc
    return thread.ret


if __name__ == "__main__":
    def testC(arg):
        pass

    def testB(arg):
        testC(arg)

    def testA():
        testB("ABC")
        testB("DEF")
        testB("GEF")

    def testTooLong(lng):
        import time
        time.sleep(lng)

    import log
    log.LogTracker().init()
    trace(testA)
    trace(testTooLong, 10, trace_timeout=5)
