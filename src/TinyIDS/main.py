# -*- coding: utf-8 -*-
#
#  This file is part of tinyids.
#
#  tinyids - 
#
#  Project: https://www.codetrax.org/projects/tinyids
#
#  Copyright 2010 George Notaras <gnot [at] g-loaded.eu>, CodeTRAX.org
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

from TinyIDS import applogger
from TinyIDS import cmdline
from TinyIDS import config
from TinyIDS.server import TinyIDSServer, TinyIDSCommandHandler
from TinyIDS.client import TinyIDSClient


def main():
    opts = cmdline.parse_client()
    if opts.debug:
        applogger.init_std_stream_loggers(level='debug')
    else:
        applogger.init_std_stream_loggers()
    logger = logging.getLogger('main')
    logger.debug('getting client configuration')
    try:
        cfg = config.get_client_configuration(opts.confpath)
    except config.ConfigFileNotFoundError:
        logger.critical('configuration file not found. exiting...')
        sys.exit(1)
    command = None
    if opts.test:
        command = 'TEST'
    if opts.check:
        command = 'CHECK'
    elif opts.update:
        command = 'UPDATE'
    elif opts.delete:
        command = 'DELETE'
    elif opts.changephrase:
        command = 'CHANGEPHRASE'
    client = TinyIDSClient(command)
    client.run()

def server_main():
    opts = cmdline.parse_server()
    if opts.debug:
        applogger.init_std_stream_loggers(level='debug')
    else:
        applogger.init_file_logger()
    logger = logging.getLogger('main')
    logger.debug('getting server configuration')
    try:
        cfg = config.get_server_configuration(opts.confpath)
    except config.ConfigFileNotFoundError:
        logger.critical('configuration file not found')
        sys.exit(1)
    interface = cfg.get('main', 'interface')
    port = cfg.getint('main', 'port')
    server = TinyIDSServer((interface, port), TinyIDSCommandHandler)
    server.serve_forever()
