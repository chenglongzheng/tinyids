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

import TinyIDS.backends
from TinyIDS import config
from TinyIDS.util import sha1, load_backend


logger = logging.getLogger('main')


class TinyIDSClient:

    cmd_end = '\r\n'
    
    def __init__(self, command):
        self.command = command  # TEST | CHECK | UPDATE | DELETE | CHANGEPHRASE
        self.hasher = sha1()
        self.cfg = config.get_client_configuration()
        self.sock = None
        logger.debug('client initialized')
    
    def _close_socket(self):
        self.sock.close()
        self.sock = None
    
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
            if not self.cfg.has_option(section, 'host'):
                logger.warning('misconfigured server: %s' % self._get_server_canonical_name(section))
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
        self.sock.send(data + self.cmd_end)
    
    def get_server_response(self):
        response = self.sock.recv(1024)
        self.sock.close()
        self.sock = None
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
        plugins_dir = DEFAULT_PLUGINS_DIR
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
            host = self.cfg.get(server, 'host')
            port = config.DEFAULT_PORT
            if self.cfg.has_option(server, 'port'):
                port = self.cfg.getint(server, 'port')
            public_key = None
            if self.cfg.has_option(server, 'public_key'):
                _pk = self.cfg.get(server, 'public_key')
                if _pk:
                    public_key = _pk
            srv_name = self._get_server_canonical_name(server)
            
            logger.debug('sendind %s command to server: %s' % (self.command, srv_name))
            
            try:
                func(host, port, public_key)
            except socket.error, e:
                logger.error('server error: "%s"' % e)
                logger.warning('skipping server: %s' % srv_name)
                self._close_socket()
                continue
            
        
        
    def _com_TEST(self, host, port, public_key):
        data = self.command
        self.send(host, port, public_key, data)
        response = self.get_server_response()
        if response.startswith('20'):
            logger.debug('%s command was successful' % self.command)
        else:
            logger.warning('%s command failed' % self.command)
        