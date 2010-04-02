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
from TinyIDS import crypto
from TinyIDS.server import TinyIDSServer, TinyIDSCommandHandler, InternalServerError, TerminationSignal
from TinyIDS.client import TinyIDSClient



def main():
    opts = cmdline.parse_client()
    config_path = os.path.abspath(opts.confpath)
    try:
        cfg = config.get_client_configuration(config_path)
    except config.ConfigFileNotFoundError:
        sys.stderr.write('ERROR: Configuration file not found: %s\n' % config_path)
        sys.stderr.flush()
        sys.exit(1)
    
    # Initialize logging
    logger = logging.getLogger()
    if opts.debug:
        applogger.init_std_stream_loggers(verbose=True)
        logger.debug('tinyids started in debug mode')
    else:
        applogger.init_std_stream_loggers()
    
    logger.debug('Using client configuration from: %s' % config_path)
    logger.debug('Logging to standard streams: STDOUT, STDERR')
    
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
    logger.info('TinyIDS Client v%s initialized' % info.version)
    logger.info('Running in mode: %s' % command)
    
    client.run()

    logger.debug('terminated')


def server_main():
    opts = cmdline.parse_server()
    config_path = os.path.abspath(opts.confpath)
    try:
        cfg = config.get_server_configuration(config_path)
    except config.ConfigFileNotFoundError:
        sys.stderr.write('ERROR: Configuration file not found: %s\n' % config_path)
        sys.stderr.flush()
        sys.exit(1)
    
    # Settings
    interface = cfg.get('main', 'interface')
    port = cfg.getint('main', 'port')
    user = cfg.get_or_default('main', 'user', '')
    group = cfg.get_or_default('main', 'group', '')
    logfile = os.path.abspath(
        cfg.get_or_default('main', 'logfile', config.DEFAULT_LOGFILE_PATH))
    loglevel = cfg.get_or_default('main', 'loglevel', config.DEFAULT_LOGLEVEL)
    use_keys = cfg.getboolean('main', 'use_keys')
    keys_dir = cfg.get('main', 'keys_dir')
    key_bits = cfg.getint('main', 'key_bits')
    
    # Initialize logging
    logger = logging.getLogger()
    if opts.debug:
        # Log to stderr
        applogger.init_std_stream_loggers(verbose=True)
        logger.debug('tinyidsd started in debug mode')
        logger.debug('Logging to standard streams: STDOUT, STDERR')
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
        logger.debug('Logging to file: %s' % logfile)
    
    logger.debug('Using server configuration from: %s' % config_path)
    
    # For security reason the server's PKI module is activated before the
    # server process drops privileges.
    pki = None
    if use_keys:
        pki = crypto.RSAModule(keys_dir, key_bits=key_bits)
        if not os.path.exists(pki.get_private_key_path()):
            # Create both keys if the private key is missing
            if not opts.debug:
                sys.stderr.write('Generating RSA %s-bit keypair. Please wait...\n' % key_bits)
            logger.warning('Generating RSA %s-bit keypair. Please wait...' % key_bits)
            pki.generate_keys()
            if not opts.debug:
                sys.stderr.write('Public key saved to: %s\n' % pki.get_public_key_path())
            logger.info('Public key saved to: %s' % pki.get_public_key_path())
            if not opts.debug:
                sys.stderr.write('Private key saved to: %s\n' % pki.get_private_key_path())
            logger.info('Private key saved to: %s' % pki.get_private_key_path())
            if not opts.debug:
                sys.stderr.write('Resuming server startup...\n')
                sys.stderr.flush()
        pki.load_private_key()
        logger.info('Server private key loaded successfully')
    
    if not opts.debug:
        # Drop Privileges, if running as root
        if user:
            process.run_as_user(user, group)
        else:
            logger.warning('Server running as root. User not set.')
    
        # Fork into background, if running as root
        process.run_in_background()
    
    logger.info('TinyIDS Server v%s starting...' % info.version)
    
    try:
        service = TinyIDSServer((interface, port), TinyIDSCommandHandler, pki)
    except InternalServerError:
        logger.debug('Terminated')
    else:
        try:
            service.serve_forever()
        except KeyboardInterrupt:
            logger.warning('Caught keyboard interrupt')
            service.server_forced_shutdown()
        except TerminationSignal:
            service.server_close()
            logger.info('Server shutdown complete')
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
    logger.debug('terminated')

