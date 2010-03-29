
import os
import SocketServer
import logging

from TinyIDS import database


logger = logging.getLogger('main')


class TinyIDSServer(SocketServer.ThreadingTCPServer):
    
    def _database_activate(self):
        self.db = database.HashDatabase()
        logger.debug('hash database initialized')
    
    def _database_close(self):
        self.db.close()
        logger.debug('hash database closed')
    
    def server_activate(self):
        logger.debug('server starting')
        self._database_activate()
        SocketServer.ThreadingTCPServer.server_activate(self)
        logger.debug('server accepting connections')
    
    def server_close(self):
        logger.debug('server shutting down')
        self._database_close()
        SocketServer.ThreadingTCPServer.server_close(self)
        logger.debug('server terminated')
        
    def verify_request(self, request, client_address):
        """Should check the RSA KEY"""
        return True



class TinyIDSCommandHandler(SocketServer.StreamRequestHandler):
    
    
    
    def __init__(self, request, client_address, server):
    
        self.max_data_len = 8192
        self.cmd_end = '\r\n'
        
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
    
    #def _decrypt_command(self):
    #    pass

    def _get_data(self):
        #data = self.rfile.read(self.max_data_len)
        data = self.rfile.readline().strip()
        return data.rstrip(self.cmd_end)
    
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
        args = cmd_parts[1:]
        com_func = self.com2func[command][0]
        com_func(*args)
    
    
    def _com_TEST(self):
        logger.debug('client: %s tested connection' % repr(self.client_address))
        self._send_response(20) # OK
    
    def _com_CHECK(self, hash):
        try:
            hash_db = self.server.db.get(self.client_address[0])
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        else:
            if hash == hash_db:
                self._send_response(20) # OK
            else:
                self._send_response(30) # MISMATCH
    
    def _com_UPDATE(self, hash, passphrase):
        try:
            self.server.db.put(self.client_address[0], hash, passphrase)
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    def _com_DELETE(self, passphrase):
        try:
            self.server.db.remove(self.client_address[0], passphrase)
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    def _com_CHANGEPHRASE(self, passphrase_old, passphrase_new):
        try:
            self.server.db.change_passphrase(self.client_address[0], passphrase_old, passphrase_new)
        except database.HashDoesNotExistError:
            self._send_response(31) # NOT FOUND
        except database.InvalidPassphraseError:
            self._send_response(42) # INVALID PASSPHRASE
        else:
            self._send_response(20) # OK
    
    
    #def _sign_response(self, msg):
    #    return msg
    
    def _send_response(self, code):
        msg, level = self.errcodes[code]
        self.wfile.write(msg + self.cmd_end)
        
        self.server.db.dbprint()
    
   
    
    def handle(self):
    
        data = self._get_data()
        if self._verify_grammar(data):
            self._process_command(data)
        else:
            self._send_response(41)


            

    
    