# -*- coding: utf-8 -*-
#
#  This file is part of <Project>
#
#  <Description>
#
#  <Project URL>
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

import os
import socket
import logging
import getpass

import TinyIDS.backends
from TinyIDS import config
from TinyIDS.util import sha1, load_backend


logger = logging.getLogger('main')


class TinyIDSClient:
    """A client implementation of the TinyIDS protocol."""
    
    cmd_end = '\r\n'
    
    def __init__(self, command):
        self.command = command  # TEST | CHECK | UPDATE | DELETE | CHANGEPHRASE
        self.hasher = sha1()
        self.cfg = config.get_client_configuration()
        # This is socket.socket object while connected to server
        # Should be set to None as soon the connection is closed
        # or a socket error occurs.
        self.sock = None
        # Should hold the name of the server as long as there is a
        # valid connection to it.
        self.server_name = None
        logger.debug('client initialized')
    
    def _close_socket(self):
        """Should be called after socket errors."""
        if isinstance(self.sock, socket.socket):
            self.sock.close()
        self.sock = None
        self.server_name = None
    
    def client_close(self):
        logger.debug('client closing')
        
    def _get_server_canonical_name(self, server_name):
        """Returns the name of the server after stripping the 'server__' prefix'"""
        return server_name.split('__')[1]
    
    def get_enabled_server_list(self):
        """Returns a list of servers that have been enabled in the
        client configuration."""
        enabled_servers = []
        for section in self.cfg.sections():
            if not section.startswith('server__'):
                continue
            server_name = self._get_server_canonical_name(section)
            if not self.cfg.has_option(section, 'host'):
                logger.warning('misconfigured server: %s' % server_name)
                continue
            if self.cfg.has_option(section, 'enabled'):
                is_enabled = self.cfg.getboolean(section, 'enabled')
                if not is_enabled:
                    continue
                enabled_servers.append(section)
        return enabled_servers
    
    def send(self, host, port, public_key, data):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        logger.debug('established connection to server %s' % self.server_name)
        logger.debug('sendind %s command to server: %s' % (self.command, self.server_name))
        self.sock.send(data + self.cmd_end)
    
    def get_server_response(self):
        response = self.sock.recv(1024)
        logger.debug('received response from server: %s' % self.server_name)
        self._close_socket()
        return response.strip()
    
    def hash_data(self, data):
        self.hasher.update(data)
    
    def get_checksum(self):
        return self.hasher.hexdigest()
    
    def _run_all_valid_checks(self, directory):
        pass
    
    def run_checks(self):
        backends_dir = TinyIDS.backends.__path__[0]
        #backends_glob_exp = os.path.join(backends_dir, '*.py')
    #    plugins_dir = DEFAULT_PLUGINS_DIR
        #plugins_glob_exp = os.path.join(plugins_dir, '*.py')
        # Run internal backend tests first
        for backend_fname in os.listdir(backends_dir):
            if not backend_fname.endswith('.py'):
                continue
            backend_name = backend_fname[:-3]
            # Load backend
            m = load_backend(backends_dir, backend_name)
            if not hasattr(m, 'Check'):
                continue
            print 'doing %s' % backend_name
            for data in m.Check().run():
                self.hash_data(data)
    
        print self.get_checksum()

    def run(self):
        # Decide which method to execute
        func = getattr(self, '_com_%s' % self.command)
        # Tests are required to run only with the CHECK and UPDATE commands
        if self.command in ('CHECK', 'UPDATE'):
            self.run_checks()
        enabled_servers = self.get_enabled_server_list()
        if not enabled_servers:
            logger.warning('no servers configured. aborting...')
            return
        for server in enabled_servers:
            # server is in 'server__<name>' format (a section name)
            # Here we set self.server_name to the canonical server name
            self.server_name = self._get_server_canonical_name(server)
            
            # Get server settings
            host = self.cfg.get(server, 'host')
            port = config.DEFAULT_PORT
            if self.cfg.has_option(server, 'port'):
                port = self.cfg.getint(server, 'port')
            public_key = None
            if self.cfg.has_option(server, 'public_key'):
                _pk = self.cfg.get(server, 'public_key')
                if _pk:
                    public_key = _pk
            
            # Run command on the server
            try:
                func(host, port, public_key)
            except socket.error, e:
                logger.error('connection error: "%s"' % e)
                logger.warning('skipping server: %s' % self.server_name)
                self._close_socket()
                continue
        
        self.client_close()
    
    def _communicate(self, host, port, public_key, data):
        self.send(host, port, public_key, data)
        response = self.get_server_response()
        self._check_command_status(response)
    
    def _check_command_status(self, response):
        if response.startswith('20'):
            logger.debug('%s command was successful' % self.command)
            print 'SUCCESS'
        else:
            logger.warning('%s command failed with: %s' % (self.command, response))
    
    def _get_passphrase(self, msg):
        data = ''
        while not data:
            data = getpass.getpass('%s: ' % msg)
        return data
    
    def _com_TEST(self, host, port, public_key):
        """
        Syntax: TEST
        """
        data = self.command
        self._communicate(host, port, public_key, data)
        
    def _com_CHECK(self, host, port, public_key):
        """
        Syntax: CHECK <hash>
        """
        data = '%s %s' % (self.command, self.get_checksum())
        self._communicate(host, port, public_key, data)
    
    def _com_UPDATE(self, host, port, public_key):
        """
        Syntax: UPDATE <hash> <passphrase>
        """
        while True:
            passphrase = self._get_passphrase('Passphrase')
            passphrase_confirm = self._get_passphrase('Confirm passphrase')
            if passphrase == passphrase_confirm:
                break
            logger.error('passphrases do not match. try again...')
        data = '%s %s %s' % (self.command, self.get_checksum(), passphrase)
        self._communicate(host, port, public_key, data)
    
    def _com_DELETE(self, host, port, public_key):
        """
        Syntax: DELETE <passphrase>
        """
        passphrase = self._get_passphrase('Passphrase')
        data = '%s %s' % (self.command, passphrase)
        self._communicate(host, port, public_key, data)
    
    def _com_CHANGEPHRASE(self, host, port, public_key):
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
        self._communicate(host, port, public_key, data)

