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

import os
import logging
import glob
import socket
import getpass
import time

import TinyIDS.backends
from TinyIDS import config
from TinyIDS import crypto
from TinyIDS.util import sha1, load_backend


logger = logging.getLogger()


class NoBackendsToRun(Exception):
    pass


class TinyIDSClient:
    """A client implementation of the TinyIDS protocol."""
    
    cmd_end = '\r\n'
    max_response_len = 1024
    
    def __init__(self, command):
        
        self.command = command  # TEST | CHECK | UPDATE | DELETE | CHANGEPHRASE
        self.hasher = sha1()
        self.cfg = config.get_client_configuration()
        
        # Default hashing delay
        self.default_hashing_delay = self._get_hashing_delay()
        
        # PKI Module
        _keys_dir = self.cfg.get('main', 'keys_dir')
        self.pki = crypto.RSAModule(_keys_dir)
        
        # This is socket.socket object while connected to server
        # Should be set to None as soon the connection is closed
        # or a socket error occurs.
        self.sock = None
        
        # Should hold the name of the server as long as there is a
        # valid connection to it.
        self.server_name = None
        
    def _close_socket(self):
        """Should be called after all socket errors."""
        if isinstance(self.sock, socket.socket):
            self.sock.close()
            if self.server_name:
                logger.info('Closed connection with server: %s' % self.server_name)
        self.sock = None
        self.server_name = None
    
    def _get_hashing_delay(self):
        """Returns the hashing delay in seconds."""
        delay_msec = self.default_hashing_delay = self.cfg.getfloat('main', 'hashing_delay')
        delay_sec = delay_msec / 1000
        logger.debug('Hashing delay set to %.3f seconds' % delay_sec)
        return delay_sec
    
    def _run_backends(self):
        # Get a list of all backend paths
        backend_paths = []
        core_backends_dir = TinyIDS.backends.__path__[0]
        backend_paths.extend(glob.glob(os.path.join(core_backends_dir, '*.py')))
        extra_backends_dir = self.cfg.get('main', 'extra_backends_dir')
        backend_paths.extend(glob.glob(os.path.join(extra_backends_dir, '*.py')))
        
        if not backend_paths:
            raise NoBackendsToRun
        
        # 
        user_defined_backend_list = self.cfg.getlist('main', 'tests')
        user_defined_backend_list_finished = [] # holds names of backends that have finished
        if user_defined_backend_list:
            logger.debug('Using user-defined list of backends')
        
        # Load all needed backends and store them in a list
        for backend_path in backend_paths:
            backend_name = os.path.basename(backend_path)[:-3]
            backend_dir = os.path.dirname(backend_path)
            if backend_name == '__init__':
                continue
            elif user_defined_backend_list:
                #print "checking user list"
                if not backend_name in user_defined_backend_list:
                    logger.debug('Skipping backend: %s' % backend_name)
                    continue
            # Load backend
            m = load_backend(backend_dir, backend_name)
            if not hasattr(m, 'Check'):
                logger.warning('Skipping invalid backend: %s' % backend_path)
                continue
            # Run backend
            logger.info('Processing backend: %s' % backend_name)
            for data in m.Check().run():
                self.hash_data(data)
            logger.info('- Complete')
            
            if user_defined_backend_list:
                # If a user-defined list of backends is used, add the name of
                # the backend that has just run to the list:
                # user_defined_backend_list_finished
                user_defined_backend_list_finished.append(backend_name)
        
        if user_defined_backend_list:
            invalid_user_defined_tests = []
            for test in user_defined_backend_list:
                if test not in user_defined_backend_list_finished:
                    invalid_user_defined_tests.append(test)
            if invalid_user_defined_tests:
                logger.warning('Invalid user-defined test(s): %s' % ', '.join(invalid_user_defined_tests))
                if not user_defined_backend_list_finished:
                    raise NoBackendsToRun
    
    def _get_server_canonical_name(self, server_name):
        """Returns the name of the server after stripping the 'server__' prefix'"""
        return server_name.split('__')[1]
    
    def _get_enabled_server_list(self):
        """Returns a list of servers that have been enabled in the
        client configuration."""
        enabled_servers = []
        for section in self.cfg.sections():
            if not section.startswith('server__'):
                continue
            server_name = self._get_server_canonical_name(section)
            if not self.cfg.has_option(section, 'host'):
                logger.warning('Misconfigured server: %s' % server_name)
                continue
            if self.cfg.has_option(section, 'enabled'):
                is_enabled = self.cfg.getboolean(section, 'enabled')
                if not is_enabled:
                    continue
                enabled_servers.append(section)
        return enabled_servers
    
    def _send(self, host, port, data):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        logger.info('- Established connection to server: %s' % self.server_name)
        if self.pki.public_key is not None:
            data = self.pki.encrypt(data)
            logger.info('- PKI: data encrypted')
        self.sock.send(data + self.cmd_end)
        logger.info('- Sent %s command to server: %s' % (self.command, self.server_name))
    
    def _get_server_response(self):
        
        response = self.sock.recv(self.max_response_len).strip()
        response = response.rstrip(self.cmd_end)
        logger.info('- Received response from server: %s' % self.server_name)
        if self.pki.public_key is not None:
            response = self.pki.verify(response)
            logger.info('- PKI: data verified')
        return response.strip()
    
    def _communicate(self, host, port, data):
        self._send(host, port, data)
        response = self._get_server_response()
        self._check_command_status(response)
    
    def _check_command_status(self, response):
        if response.startswith('20'):
            logger.info('- SUCCESS: %s complete on server: %s' % (self.command, self.server_name))
        else:
            logger.warning('- FAILURE: %s command on server: %s failed with: %s' % (self.command, self.server_name, response))
    
    def _get_passphrase(self, msg):
        data = ''
        while not data:
            data = getpass.getpass('%s: ' % msg)
        return data
    
    def _com_TEST(self, host, port):
        """
        Syntax: TEST
        """
        data = self.command
        self._communicate(host, port, data)
        
    def _com_CHECK(self, host, port):
        """
        Syntax: CHECK <hash>
        """
        data = '%s %s' % (self.command, self.get_checksum())
        self._communicate(host, port, data)
    
    def _com_UPDATE(self, host, port):
        """
        Syntax: UPDATE <hash> <passphrase>
        """
        passphrase = self._get_passphrase('Passphrase')
        data = '%s %s %s' % (self.command, self.get_checksum(), passphrase)
        self._communicate(host, port, data)
    
    def _com_DELETE(self, host, port):
        """
        Syntax: DELETE <passphrase>
        """
        passphrase = self._get_passphrase('Passphrase')
        data = '%s %s' % (self.command, passphrase)
        self._communicate(host, port, data)
    
    def _com_CHANGEPHRASE(self, host, port):
        """
        Syntax: CHANGEPHRASE <old_passphrase> <new_passphrase>
        """
        passphrase_old = self._get_passphrase('Old passphrase')
        while True:
            passphrase_new = self._get_passphrase('New passphrase')
            passphrase_new_confirm = self._get_passphrase('Confirm new passphrase')
            if passphrase_new == passphrase_new_confirm:
                break
            logger.error('passphrases do not match. try again...')
        data = '%s %s %s' % (self.command, passphrase_old, passphrase_new)
        self._communicate(host, port, data)
    
    # Public API
    
    def get_checksum(self):
        return self.hasher.hexdigest()
    
    def hash_data(self, data):
        self.hasher.update(data)
        time.sleep(self.default_hashing_delay)
    
    def run(self):
        """Main client method."""
        
        logger.info('Getting list of enabled servers')
        enabled_servers = self._get_enabled_server_list()
        if not enabled_servers:
            logger.warning('No servers configured. Shutting down...')
            self.client_close()
            return
        logger.info('Servers found. Proceeding with data hashing...')
        
        # Decide which method to execute
        func = getattr(self, '_com_%s' % self.command)
        
        # Tests are required to run only with the CHECK and UPDATE commands
        if self.command in ('CHECK', 'UPDATE'):
            logger.info('Hashing data. Please wait...')
            #self._run_checks()
            try:
                self._run_backends()
            except NoBackendsToRun:
                logger.warning('No valid backends. Shutting down...')
                self.client_close()
                return
            else:
                logger.info('Hashing complete')
        
        # Execute command on server
        logger.info('Preparing to contact servers')
        for server in enabled_servers:
            # server is in 'server__<name>' format (a section name)
            # Here we set self.server_name to the canonical server name
            self.server_name = self._get_server_canonical_name(server)
            logger.info('Contacting server: %s' % self.server_name)
            
            # Get server settings
            host = self.cfg.get(server, 'host')
            port = config.DEFAULT_PORT
            if self.cfg.has_option(server, 'port'):
                port = self.cfg.getint(server, 'port')
            if self.cfg.has_option(server, 'public_key'):
                public_key_fname = self.cfg.get(server, 'public_key')
                if public_key_fname:
                    self.pki.load_external_public_key(public_key_fname) # sets self.pki.public_key
                    
            # Run command on the server
            try:
                func(host, port)
            except socket.error, (errno, strerror):
                logger.error('Connection error: \'%s\'' % strerror)
                logger.warning('Skipping server: %s' % self.server_name)
                self.server_name = None
            except crypto.DataEncryptionError:
                logger.warning('- FAILURE: could not encrypt data for server: %s. Skipping server...' % self.server_name)
            except crypto.DataVerificationError:
                logger.warning('- FAILURE: could not verify response from server: %s' % self.server_name)
            
            self._close_socket()
            self.pki.reset()    # sets self.pki.public_key to None
        
        logger.info('Finished with servers')
        
        self.client_close()
    
    def client_close(self):
        logger.info('Client shutting down...')

