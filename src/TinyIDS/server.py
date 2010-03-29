
import os
import SocketServer
import logging

from TinyIDS.database import ChecksumDatabase


logging.basicConfig(
    filename = os.path.abspath(os.path.join(os.path.dirname(__file__), 'tinyids.log')),
    filemode = 'a',
    level = logging.DEBUG,
    format = '%(asctime)s %(levelname)s %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
)

#logger = logging.getLogger()







class TinyIDSServer(SocketServer.ThreadingTCPServer):
    
    def _database_activate(self):
        self.db = ChecksumDatabase()
    
    def _database_close(self):
        self.db.close()
    
    def server_activate(self):
        self._database_activate()
        SocketServer.ThreadingTCPServer.server_activate(self)
    
    def server_close(self):
        self._database_close()
        SocketServer.ThreadingTCPServer.server_close(self)
        
    def verify_request(self, request, client_address):
        """Should check the RSA KEY"""
        return True



class TinyIDSCommandHandler(SocketServer.StreamRequestHandler):
    
    
    
    def __init__(self, request, client_address, server):
    
        self.max_data_len = 8192
        self.cmd_end = '\r\n'
        
        # command : (<processing_method>, <number_of_args>)
        self.com2func = {
            'CLIENT':       (self._com_CLIENT, 0),        # CLIENT
            'CHECK':        (self._com_CHECK, 1),         # CHECK <checksum>
            'UPDATE':       (self._com_UPDATE, 2),        # UPDATE <checksum> <passphrase>
            'DELETE':       (self._com_DELETE, 1),        # DELETE <passphrase>
            'CHANGEPHRASE': (self._com_CHANGEPHRASE, 2),  # CHANGEPHRASE <old_passphrase> <new_passphrase>
        }
        
        # error_code : (<str_error>, <level>)
        self.errcodes = {
            20 : ('20 OK', 'info'),
            30 : ('30 MISMATCH', 'warning'),
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
    
    
    def _com_CLIENT(self):
        self._send_response(20)
    
    def _com_CHECK(self, checksum):
        pass
    
    def _com_UPDATE(self, checksum, passphrase):
        pass
    
    def _com_DELETE(self, passphrase):
        pass
    
    def _com_CHANGEPHRASE(self, old, new):
        pass
    
    
    #def _sign_response(self, msg):
    #    return msg
    
    def _send_response(self, code):
        msg, level = self.errcodes[code]
        self.wfile.write(msg + self.cmd_end)
    
   
    
    def handle(self):
    
        data = self._get_data()
        if self._verify_grammar(data):
            self._process_command(data)
        else:
            self._send_response(41)


            

    
    