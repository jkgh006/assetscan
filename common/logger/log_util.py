#!/usr/bin/env python
# -*- coding:utf-8 -*-
import threading,sys,os
import log_config
LEGEND = 70
class LogUtil(object):
    import logging
    from logging import config

    logging.addLevelName(LEGEND, 'LEGEND')
    config.dictConfig(log_config.LOGGING)

    _log_server = None
    _mutex = threading.Condition()

    ERROR = logging.ERROR
    WARN = logging.WARN
    INFO = logging.INFO
    DEBUG = logging.DEBUG

    @staticmethod
    def getLogger(name=None, via_socket=True):
        import logging
        logger = logging.getLogger('mylogger')

        def findCaller():
            f = sys._getframe(2)
            rv = "(unknown file)", 0, "(unknown function)"
            while hasattr(f, "f_code"):
                co = f.f_code
                filename = os.path.normcase(co.co_filename)
                if filename == __file__:
                    f = f.f_back
                    continue
                rv = (co.co_filename, f.f_lineno, co.co_name)
                break
            return rv

        def legend(msg, *args, **kwargs):
            try:
                fn, lno, func = findCaller()
            except ValueError:
                fn, lno, func = "(unknown file)", 0, "(unknown function)"
            fn = os.path.splitext(os.path.basename(fn))[0]
            logger.log(LEGEND, '{%s.%s:%d} %s', fn, func, lno, msg, *args, **kwargs)
        logger.__setattr__('legend', legend)

        return logger