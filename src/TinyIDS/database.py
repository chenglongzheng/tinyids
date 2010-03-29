
import os
import anydbm


DEFAULT_DATABASE_PATH = 'tinyids.db'

class ChecksumDatabase:
    
    def __init__(self, path=None):
        if not path:
            path = DEFAULT_DATABASE_PATH
        path = os.path.abspath(path)
        self.db = anydbm.open(path, 'c', 0600)
    
    def get(self, client_ip):
        checksum, passphrase_crypted = self.db[client_ip]
    
    def put(self, client_ip, checksum, passphrase_crypted):
        self.db[client_ip] = (checksum, passphrase_crypted)
    
    def close(self):
        self.db.close()
