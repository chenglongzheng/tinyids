
import os
import anydbm
import logging

from TinyIDS.util import sha1sum


class InitializationError(Exception):
    pass

class HashDoesNotExistError(Exception):
    pass

class InvalidPassphraseError(Exception):
    pass


class HashDatabase:
    """Implements a database object, where hashes and passphrases are stored
    for each client IP address.
    
    Records are of the format:
    
    <client_ip> : <hash>____<passhphrase_crypted>
    
    """
    def __init__(self, path):
        """Database object constructor.
        
        Accepts a path to the database on the filesystem.
        
        """
        self.path = os.path.abspath(path)
        self.db = None
    
    # Private API
    
    def _get_crypted_passphrase(self, client_ip, passphrase_raw):
        """Encrypts the raw passphrase.
        
        The encryption is performed in the following way:
        
        - The client IP and the provided raw passphrase are concatenated
        - The sha1 checksum is returned for the whole string
        
        """
        concat_str = client_ip + passphrase_raw
        return sha1sum(concat_str)
    
    def _check_passphrase(self, client_ip, passphrase_raw, passphrase_db):
        passphrase_enc = self._get_crypted_passphrase(client_ip, passphrase_raw)
        return passphrase_enc == passphrase_db
    
    def _read(self, client_ip):
        """Reads the client IP's data from the database and returns a tuple:
        
            hash, passphrase
        
        """
        return self.db[client_ip].split('____')
    
    def _write(self, client_ip, hash, passphrase):
        """Writes data to the database.
        
        Data for each client is stored using the convention:
        
        <hash>____<passhphrase_crypted>
        
        """
        self.db[client_ip] = '%s____%s' % (hash, passphrase)
    
    # Public API
    
    def get(self, client_ip):
        """Returns the stored hash for the client IP or Nonee if there is
        no hash stored for the client IP."""
        if not self.db.has_key(client_ip):
            raise HashDoesNotExistError
        hash_db, passphrase_db = self._read(client_ip)
        return hash_db
    
    def put(self, client_ip, hash, passphrase_raw):
        """Stores a new hash for client IP or updates the existing one.
        
        If a hash already exists for the client IP, then it tries to verify
        the raw passphrase. If the verification succeeds, then the stored hash
        is updated.
        
        If a hash for the client IP does not exist in the database, store
        the hash and the encrypted passphrase in the db.
        
        """
        if self.db.has_key(client_ip):
            hash_db, passphrase_db = self._read(client_ip)
            if not self._check_passphrase(client_ip, passphrase_raw, passphrase_db):
                raise InvalidPassphraseError
            self._write(client_ip, hash, passphrase_db)
        else:
            passphrase_enc = self._get_crypted_passphrase(client_ip, passphrase_raw)
            self._write(client_ip, hash, passphrase_enc)
    
    def remove(self, client_ip, passphrase_raw):
        """Removes the client IP's hash from the database if passphrase is OK."""
        if not self.db.has_key(client_ip):
            raise HashDoesNotExistError

        hash_db, passphrase_db = self._read(client_ip)
        if not self._check_passphrase(client_ip, passphrase_raw, passphrase_db):
            raise InvalidPassphraseError
        del self.db[client_ip]
    
    def change_passphrase(self, client_ip, passphrase_raw_old, passphrase_raw_new):
        """Changes client IP's passphrase if passphrase_raw_old is verified."""
        if not self.db.has_key(client_ip):
            raise HashDoesNotExistError
        hash_db, passphrase_db = self._read(client_ip)
        if not self._check_passphrase(client_ip, passphrase_raw_old, passphrase_db):
            raise InvalidPassphraseError
        passphrase_enc = self._get_crypted_passphrase(client_ip, passphrase_raw_new)
        self._write(client_ip, hash_db, passphrase_enc)
    
    def dbprint(self):
        for k, v in self.db.iteritems():
            print k, '\t', repr(v)
        print '-'*40
    
    def database_activate(self):
        """Opens the database or creates it if it does not exist.
        
        On sucess sets the instance attribute: self.db
        On error InitializationError is raised.
        
        """
        try:
            self.db = anydbm.open(self.path, 'c', 0600)
        except anydbm.error, (errno, strerror):
            self.db = None
            raise InitializationError(strerror)
    
    def database_close(self):
        """Closes the database."""
        if self.db is not None:
            self.db.close()

    
    
    
