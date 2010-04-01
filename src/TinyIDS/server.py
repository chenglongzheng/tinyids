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
import SocketServer
import logging

from TinyIDS import database
from TinyIDS import config
from TinyIDS import crypto


logger = logging.getLogger('main')


class DataDecryptionError(Exception):
    pass

class InternalServerError(Exception):
    pass


class TinyIDSServer(SocketServer.ThreadingTCPServer):
    
    def __init__(self, server_address, RequestHandlerClass):
        """Constructor of the TinyIDS Server.
        
        Extra instance attributes:
        
        cfg - the server ConfigParser instance
        db - database.HashDatabase instance
        
        """
        # Server Configuration
        self.cfg = config.get_server_configuration()
        
        # Hash Database
        db_path = self.cfg.get_or_default('main', 'db_path', config.DEFAULT_DATABASE_PATH)
        self.db = database.HashDatabase(db_path)
        
        # PKI Module
        self.pki = None
        
        try:
            SocketServer.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)
        except InternalServerError:
            self.server_forced_shutdown()
            raise InternalServerError
        
    def database_activate(self):
        try:
            self.db.database_activate()
        except database.InitializationError, strerror:
            logger.error('Database initialization error: %s' % strerror)
            raise InternalServerError
        logger.info('Hash database activated')
    
    def database_close(self):
        if self.db is not None:
            self.db.database_close()
            logger.info('Hash database closed')
    
    def pki_activate(self):
        if not self.cfg.getboolean('main', 'use_keys'):
            return
        keys_dir = self.cfg.get('main', 'keys_dir')
        key_bits = self.cfg.getint('main', 'key_bits')
        self.pki = crypto.RSAModule(keys_dir, key_bits=key_bits)
        logger.info('PKI module activated')
        if not os.path.exists(self.pki.get_private_key_path()):
            # Create both keys if the private key is missing
            logger.warning('Generating RSA %s-bit keypair. Please wait...' % key_bits)
            self.pki.generate_keys()
            logger.info('Public key saved to: %s' % self.pki.get_public_key_path())
            logger.info('Private key saved to: %s' % self.pki.get_private_key_path())
        self.pki.load_private_key()
        logger.info('Server private key loaded successfully')
        
    def pki_close(self):
        self.pki = None
        logger.info('PKI module deactivated')
    
    def server_activate(self):
        self.database_activate()
        self.pki_activate()
        SocketServer.ThreadingTCPServer.server_activate(self)
        logger.debug('Accepting connections on %s:%s' % self.server_address)
        
    def server_close(self):
        logger.info('TinyIDS Server preparing for shutdown...')
        self.database_close()
        self.pki_close()
        SocketServer.ThreadingTCPServer.server_close(self)
    
    def server_forced_shutdown(self):
        logger.warning('Forced shutdown')
        self.server_close()
        logger.info('Forced shutdown complete')
        
    def verify_request(self, request, client_address):
        """TODO: IP-based access control."""
        return True
    
    
    



class TinyIDSCommandHandler(SocketServer.StreamRequestHandler):
    
    max_data_len = 8192
    cmd_end = '\r\n'
        
    def __init__(self, request, client_address, server):
        
        # Indicator of the command that is being processed
        self.doing_command = None
        
        # command : (<processing_method>, <number_of_args>)
        self.com2func = {
            'TEST':         (self._com_TEST, 0),          # TEST
            'CHECK':        (self._com_CHECK, 1),         # CHECK <hash>
            'UPDATE':       (self._com_UPDATE, 2),        # UPDATE <hash> <passphrase>
            'DELETE':       (self._com_DELETE, 1),        # DELETE <passphrase>
            'CHANGEPHRASE': (self._com_CHANGEPHRASE, 2),  # CHANGEPHRASE <old_passphrase> <new_passphrase>
        }
        
        # error_code : (<str_error>, <level>)
        self.errcodes = {
            20 : ('20 OK', 'info'),
            30 : ('30 MISMATCH', 'warning'),
            31 : ('31 NOT FOUND', 'warning'),
            40 : ('40 INVALID CLIENT', 'warning'),
            41 : ('41 INVALID COMMAND', 'warning'),
            42 : ('42 INVALID PASSPHRASE', 'warning'),
        }
        
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)
    
    def _client(self):
        return self.client_address[0]
    
    def _get_data(self):
        data = self.rfile.readline(self.max_data_len).strip()
        data = data.rstrip(self.cmd_end)
        if self.server.pki is not None:
            # PKI is enabled
            data = self.server.pki.decrypt(data)
        return data
    
    def _verify_grammar(self, data):
        cmd_parts = data.split()
        if not cmd_parts:
            return False
        command = cmd_parts[0].upper()
        if not self.com2func.has_key(command):
            return False
        args = cmd_parts[1:]
        if self.com2func[command][1] == len(args):
            return True
        return False
        
    def _process_command(self, data):
        cmd_parts = data.split()
        command = cmd_parts[0].upper()
        self.doing_command = command
        args = cmd_parts[1:]
        com_func = self.com2func[command][0]
        com_func(*args)
    
    def _finish_command(self):
        self.doing_command = None
        
    def _com_TEST(self):
        self._send_response(20) # OK
    
    def _com_CHECK(self, hash):
        try:
            hash_db = self.server.db.get(self._client())
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        else:
            if hash == hash_db:
                self._send_response(20) # OK
            else:
                self._send_response(30) # MISMATCH
    
    def _com_UPDATE(self, hash, passphrase):
        try:
            self.server.db.put(self._client(), hash, passphrase)
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    def _com_DELETE(self, passphrase):
        try:
            self.server.db.remove(self._client(), passphrase)
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    def _com_CHANGEPHRASE(self, passphrase_old, passphrase_new):
        try:
            self.server.db.change_passphrase(self._client(), passphrase_old, passphrase_new)
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    def _send_response(self, code, sign=True):
        msg, level = self.errcodes[code]
        
        if code == 20:
            logger.info('SUCCESS: %s ran %s successfully' % (self._client(), self.doing_command))
        else:
            logger.warning('FAILURE: %s failed with %s: %s' % (self._client(), self.doing_command, msg))
        
        if sign and self.server.pki is not None:
            # PKI is enabled
            msg = self.server.pki.sign(msg)
        
        self.wfile.write(msg + self.cmd_end)
        logger.info('Sent response to %s' % self._client())

   
    def setup(self):
        logger.debug('%s client connected' % self._client())
        SocketServer.StreamRequestHandler.setup(self)
        
    def handle(self):
        try:
            data = self._get_data()
        except DataDecryptionError:
            self._send_response(40, sign=False) # INVALID CLIENT
        else:
            if self._verify_grammar(data):
                self._process_command(data)
                self._finish_command()
            else:
                self._send_response(41)
    
    def finish(self):
        SocketServer.StreamRequestHandler.finish(self)
        logger.debug('%s client disconnected' % self._client())
        
        #self.server.db.dbprint()


