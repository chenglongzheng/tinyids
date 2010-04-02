# -*- coding: utf-8 -*-
#
#  This file is part of TinyIDS.
#
#  TinyIDS is a distributed Intrusion Detection System (IDS) for Unix systems. 
#
#  Project development web site:
#
#      http://www.codetrax.org/projects/tinyids
#
#  Copyright (c) 2010 George Notaras, G-Loaded.eu, CodeTRAX.org
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import sys
import logging


DEFAULT_LOGLEVELS = {
    'debug'         : logging.DEBUG,        # 10
    'info'          : logging.INFO,         # 20
    'warning'       : logging.WARNING,      # 30
    'error'         : logging.ERROR,        # 40
    'critical'      : logging.CRITICAL,     # 50
}

FORMATTER_MINIMAL = logging.Formatter('%(message)s')
FORMATTER_NORMAL = logging.Formatter('%(levelname)-8s %(message)s')
FORMATTER_DETAIL = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S'
)
FORMATTER_EXTRA_DETAIL = logging.Formatter(
    '%(asctime)s %(name)s:%(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S'
)


class LoggerError(Exception):
    pass


class StderrFilter(logging.Filter):
    """Stderr filter component.

    By default, permits records of all levels, except 'logging.INFO' and
    'logging.DEBUG'.
    
    If 'verbose' is True, then it also permits records with 'logging.DEBUG'
    level.

    """
    def __init__(self, verbose=False):
        self.verbose = verbose

    def filter(self, record):
        if record.levelno == logging.INFO:
            return False
        elif record.levelno == logging.DEBUG:
            if self.verbose:
                return True
        else:
            return True


class StdoutFilter(logging.Filter):
    """Stdout filter component.

    By default, permits only records with level 'logging.INFO'.
    
    If 'quiet' is True, then it does not permit any records at all.

    """
    def __init__(self, quiet=False):
        self.quiet = quiet

    def filter(self, record):
        if not self.quiet:
            return record.levelno == logging.INFO


def init_std_stream_loggers(verbose=False, quiet=False):
    """Configures two stream handlers for STDERR and STDOUT.

    Which messages finally reach STDERR and STDOUT is determined by the
    StdoutFilter and StderrFilter filters.

    Since filters are used, the logging level of each of the stream handlers
    has no effect. It is set to 'logging.DEBUG' in order to avoid any conflicts
    with the filters.

    """
    if verbose and quiet:
        raise LoggerError('Cannot be quiet and verbose at the same time')

    # Get a logger named 'main'
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # Handler that logs to STDERR
    stderr_handler = logging.StreamHandler(sys.stderr)

    # Handler that logs to STDOUT
    stdout_handler = logging.StreamHandler(sys.stdout)

    # Set the each stream handler's logging level to 'logging.DEBUG'.
    stderr_handler.setLevel(logging.DEBUG)
    stdout_handler.setLevel(logging.DEBUG)

    # Add the appropriate filter to each handler
    stderr_handler.addFilter(StderrFilter(verbose))
    stdout_handler.addFilter(StdoutFilter(quiet))

    # Add formatter to both STDOUT & STDERR handlers
    stderr_handler.setFormatter(FORMATTER_NORMAL)
    stdout_handler.setFormatter(FORMATTER_NORMAL)

    # Add the stream handlers to the main logger
    logger.addHandler(stderr_handler)
    logger.addHandler(stdout_handler)

    #logger.debug('Logging to standard streams: STDOUT, STDERR')


def init_file_logger(path, level):
    """Adds a file handler to the 'main' logger.
    
    Accepts:
    
    - path: path to log file on the filesystem.
    - level: a string (debug, info, warning, error, critical).
    
    """
    if level.lower() not in DEFAULT_LOGLEVELS.keys():
        raise LoggerError('Invalid log level: %s' % level)
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Main logger's level is always DEBUG

    try:
        file_handler = logging.FileHandler(path, 'a')
    except IOError, (errno, strerror):
        raise LoggerError("Could not open log file %s: '%s'" % (strerror, path))
    else:
        file_handler.setFormatter(FORMATTER_DETAIL)
        file_handler.setLevel(DEFAULT_LOGLEVELS[level])
        logger.addHandler(file_handler)
        
        #logger.debug('Logging to file: %s' % path)

