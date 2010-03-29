
import os
import anydbm

class ChecksumDatabase:
    
    def __init__(self, path=None):
        if not path:
            path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'tinyids.db'))
        self.db = anydbm.open(path, 'c', 0600)
    
    def get(self, client_ip):
        checksum, passphrase_crypted = self.db[client_ip]
    
    def put(self, client_ip, checksum, passphrase_crypted):
        self.db[client_ip] = (checksum, passphrase_crypted)
    
    def close(self):
        self.db.close()
