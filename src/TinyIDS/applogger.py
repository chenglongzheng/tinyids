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
import os
import logging


DEFAULT_LOGLEVELS = {
    'debug'         : logging.DEBUG,        # 10
    'info'          : logging.INFO,         # 20
    'warning'       : logging.WARNING,      # 30
    'error'         : logging.ERROR,        # 40
    'critical'      : logging.CRITICAL,     # 50
}

FORMATTER_DETAIL = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S'
)


class LoggerError(Exception):
    pass


def init_std_stream_loggers(level='info'):
    logger = logging.getLogger('main')
    logger.setLevel(logging.DEBUG)  # Main logger's level is always DEBUG
    
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(DEFAULT_LOGLEVELS[level])
    stderr_handler.setFormatter(FORMATTER_DETAIL)
    logger.addHandler(stderr_handler)


def init_file_logger(path, level):
    """Adds a file handler to the 'main' logger.
    
    Accepts:
        path: path to logfile
        level: a string (debug, info, warning, error, critical)
    
    """
    path = os.path.abspath(path)
    if level.lower() not in DEFAULT_LOGLEVELS.keys():
        raise LoggerError("Invalid loglevel for logfile. Must be one of: \
            '%s'" % DEFAULT_LOGLEVELS.keys())
    
    logger = logging.getLogger('main')
    logger.setLevel(logging.DEBUG)  # Main logger's level is always DEBUG

    try:
        file_handler = logging.FileHandler(path, 'a')
    except IOError, (errno, strerror):
        raise LoggerError("%s: '%s'" % (strerror, path))
    else:
        file_handler.setFormatter(FORMATTER_DETAIL)
        file_handler.setLevel(DEFAULT_LOGLEVELS[level])
        logger.addHandler(file_handler)

        
