
import os
import SocketServer
import socket
import logging
import base64

from TinyIDS import database
from TinyIDS import config
from TinyIDS import rsa
from TinyIDS import util


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
        private_key - if PKI is enabled (use_keys = 1), then this should hold
        the private key. Otherwise should be None
        
        """
        # Server Configuration
        self.cfg = config.get_server_configuration()
        
        # Hash Database
        db_path = self.cfg.get_or_default('main', 'db_path', config.DEFAULT_DATABASE_PATH)
        self.db = database.HashDatabase(db_path)
        
        # Server Private Key
        self.private_key = None
        
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
    
    def server_activate(self):
        self.database_activate()
        self._load_or_create_keys()
        SocketServer.ThreadingTCPServer.server_activate(self)
        logger.debug('Accepting connections on %s:%s' % self.server_address)
        
    def server_close(self):
        logger.info('TinyIDS Server preparing for shutdown...')
        self.database_close()
        SocketServer.ThreadingTCPServer.server_close(self)
    
    def server_forced_shutdown(self):
        logger.warning('Forced shutdown')
        self.server_close()
        logger.info('Forced shutdown complete')
        
    def verify_request(self, request, client_address):
        """TODO: IP-based access control."""
        return True
    
    
    def _load_or_create_keys(self):
        """Loads the server private key. If it does not exist, it is created."""
        
        if not self.cfg.getboolean('main', 'use_keys'):
            self.private_key = None
            return
        
        logger.debug('PKI support enabled')
        keys_dir = self.cfg.get('main', 'keys_dir')
        public_key_path = '%s.pub' % os.path.join(keys_dir, self._get_key_basename())
        private_key_path = '%s.key' % os.path.join(keys_dir, self._get_key_basename())
        
        # Create both keys if the private key is missing
        if not os.path.exists(private_key_path):
            logger.warning('Generating RSA keypair. Please wait...')
            public_key, private_key = self._generate_keypair()
            util.export_key_to_file(public_key, public_key_path)
            logger.info('Public key saved to: %s' % public_key_path)
            util.export_key_to_file(private_key, private_key_path)
            logger.info('Private key saved to: %s' % private_key_path)
        
        # Load the server's private key
        self.private_key = util.import_key_from_file(private_key_path)
        logger.info('Server private key loaded successfully')
        
    def _get_key_basename(self):
        return socket.gethostname()
    
    def _generate_keypair(self):
        key_bits = self.cfg.getint('main', 'key_bits')
        public_key, private_key = rsa.gen_pubpriv_keys(key_bits)
        return public_key, private_key



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
        return '%s:%s' % self.client_address
    
    def _decrypt_data(self, data_enc_b64):
        print repr(data_enc_b64)
        data_enc = base64.b64decode(data_enc_b64)
        try:
            data = rsa.decrypt(data_enc, self.server.private_key)
        except:
            raise DataDecryptionError
        logger.debug('decrypted data')
        return data

    def _get_data(self):
        #data = self.rfile.read(self.max_data_len)
        data = self.rfile.readline(self.max_data_len).strip()
        data = data.rstrip(self.cmd_end)
        if self.server.private_key is not None:
            # PKI is enabled
            data = self._decrypt_data(data)
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
    
    
    def _sign_response(self, data_raw):
        data_signed = rsa.sign(data_raw, self.server.private_key)
        logger.debug('signed response')
        data_signed_b64 = base64.b64encode(data_signed)
        return data_signed_b64
    
    def _send_response(self, code, sign=True):
        msg, level = self.errcodes[code]
        
        if code == 20:
            logger.info('%s ran %s successfully' % (self._client(), self.doing_command))
        else:
            logger.warning('%s failed with %s: %s' % (self._client(), self.doing_command, msg))
        
        if sign and self.server.private_key is not None:
            # PKI is enabled
            msg = self._sign_response(msg)
            logger.debug('signed response')
        
        self.wfile.write(msg + self.cmd_end)
        logger.debug('sent response to %s' % self._client())
        
        #self.server.db.dbprint()
    
   
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


