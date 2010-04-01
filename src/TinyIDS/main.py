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

from TinyIDS import applogger
from TinyIDS import cmdline
from TinyIDS import config
from TinyIDS import info
from TinyIDS import process
from TinyIDS.server import TinyIDSServer, TinyIDSCommandHandler, InternalServerError
from TinyIDS.client import TinyIDSClient



def main():
    opts = cmdline.parse_client()
    if opts.debug:
        applogger.init_std_stream_loggers(level='debug')
    else:
        applogger.init_std_stream_loggers()
    logger = logging.getLogger('main')
    logger.debug('Getting client configuration from %s' % opts.confpath)
    try:
        cfg = config.get_client_configuration(opts.confpath)
    except config.ConfigFileNotFoundError:
        logger.critical('Configuration file not found. exiting...')
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
    config_path = os.path.abspath(opts.confpath)
    try:
        cfg = config.get_server_configuration(config_path)
    except config.ConfigFileNotFoundError:
        sys.stderr.write('ERROR: Configuration file not found: %s\n' % config_path)
        sys.stderr.flush()
        sys.exit(1)
    
    interface = cfg.get('main', 'interface')
    port = cfg.getint('main', 'port')
    user = cfg.get_or_default('main', 'user', '')
    group = cfg.get_or_default('main', 'group', '')
    logfile = os.path.abspath(
        cfg.get_or_default('main', 'logfile', config.DEFAULT_LOGFILE_PATH))
    loglevel = cfg.get_or_default('main', 'loglevel', config.DEFAULT_LOGLEVEL)
    
    # Initialize logging
    logger = logging.getLogger('main')
    if opts.debug:
        # Log to stderr
        applogger.init_std_stream_loggers(level='debug')
        logger.info('tinyidsd started in debug mode')
        logger.info('Logging to STDERR')
    else:
        # Log to file
        try:
            applogger.init_file_logger(logfile, loglevel)
        except applogger.LoggerError, strerror:
            sys.stderr.write('ERROR: Logger: %s\n' % strerror)
            sys.stderr.flush()
            sys.exit(1)
    
        # Set permissions and ownership on the logfile, if running as root
        if user:
            process.chown_chmod_path(logfile, user, group, 0600)
        
        logger.info('tinyidsd normal startup')
        logger.info('Logging to file: %s' % logfile)
    
    if not opts.debug:
        # Drop Privileges, if running as root
        if user:
            process.run_as_user(user, group)
        else:
            logger.warning('Server running as root. User not set.')
    
        # Fork into background, if running as root
        process.run_in_background()
    
    logger.info('Using server configuration from %s' % config_path)
    logger.info('TinyIDS Server v%s starting...' % info.version)
    
    try:
        service = TinyIDSServer((interface, port), TinyIDSCommandHandler)
    except InternalServerError:
        logger.debug('Terminated')
    else:
        try:
            service.serve_forever()
        except KeyboardInterrupt:
            logger.warning('Caught keyboard interrupt')
            service.server_forced_shutdown()
        except:
            import traceback
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
            message = traceback.format_exception_only(exceptionType, exceptionValue)[0]
            logger.critical('unhandled exception: %s' % message.strip())
            service.server_forced_shutdown()
            print '-'*70
            traceback.print_exc()
            print '-'*70
        else:
            logger.info('Server shutdown complete')
