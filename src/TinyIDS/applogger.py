
import sys
import os
import logging

from TinyIDS.config import cfg


DEFAULT_LOGFILE_PATH = 'tinyids.log'
DEFAULT_LOGLEVEL = 'info'

DEFAULT_LOGLEVELS = {
    "debug"         : logging.DEBUG,        # 10
    "info"          : logging.INFO,         # 20
    "warning"       : logging.WARNING,      # 30
    "error"         : logging.ERROR,        # 40
    "critical"      : logging.CRITICAL,     # 50
}

FORMATTER_DETAIL = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S'
)


class LoggerError(Exception):
    pass


def init_std_stream_loggers():
    logger = logging.getLogger('main')
    logger.setLevel(logging.DEBUG)  # Main logger's level is always DEBUG
    
    # Add the stream handler
    
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.DEBUG)
    stderr_handler.setFormatter(FORMATTER_DETAIL)
    logger.addHandler(stderr_handler)
    logger.debug('Standard stream loggers initialized successfully')


def init_file_logger():
    """Adds a file handler to the 'main' logger."""
    
    # Logger settings: path, level
    
    path = cfg.get('main', 'logfile')
    if not path:
        path = DEFAULT_LOGFILE_PATH
    # Use the absolute path to the logfile
    path = os.path.abspath(path)
    
    level = cfg.get('main', 'loglevel')
    if level.lower() not in DEFAULT_LOGLEVELS.keys():
        raise LoggerError("Invalid loglevel for logfile. Must be one of: \
            '%s'" % DEFAULT_LOGLEVELS.keys())
    
    logger = logging.getLogger('main')
    logger.setLevel(logging.DEBUG)  # Main logger's level is always DEBUG

    # Add the file handler
    
    try:
        file_handler = logging.FileHandler(path, 'a')
    except IOError, err:
        raise LoggerError("%s: '%s'" % (err[1], path))
    else:
        file_handler.setFormatter(FORMATTER_DETAIL)
        file_handler.setLevel(DEFAULT_LOGLEVELS[level])
        logger.addHandler(file_handler)

        logger.debug('Logging to file enabled successfully (%s)' % os.path.abspath(path))


