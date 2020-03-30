# coding: utf-8

import logging
import inspect
import os

DEBUG = logging.DEBUG
INFO = logging.INFO
ERROR = logging.ERROR

_null = lambda *args, **kargs: None
info = debug = error = _null


def init(level):
    global info, debug, error

    FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger('root')
    logger.setLevel(level)

    def _error(msg, *args, layer=0):
        if layer:
            func = _get_caller(layer)
            logger.error(
                "<%s:%d - %s()> " + msg, 
                os.path.basename(func.f_code.co_filename),
                func.f_lineno, 
                func.f_code.co_name,
                *args
            )
        else:
            logger.error(msg, *args)

    info = logger.info
    debug = logger.debug
    error = _error

    
def _get_caller(level):
    func = inspect.currentframe() # _get_caller
    func = func.f_back # error
    func = func.f_back # caller
    for _ in range(level):
        func = func.f_back
    return func

