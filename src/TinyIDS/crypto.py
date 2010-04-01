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
import socket
import pickle
import base64
import zlib

from TinyIDS import rsa


class BaseCryptoError(Exception):
    pass

class PrivateKeyNotLoaded(BaseCryptoError):
    pass

class PublicKeyNotLoaded(BaseCryptoError):
    pass

class DataEncryptionError(BaseCryptoError):
    pass

class DataDecryptionError(BaseCryptoError):
    pass

class DataSigningError(BaseCryptoError):
    pass

class DataVerificationError(BaseCryptoError):
    pass


class RSAModule:
    
    def __init__(self, keys_dir, key_bits=384):
        self.keys_dir = keys_dir
        
        self.key_bits = key_bits
        self.public_key = None
        self.private_key = None
    
    def _get_key_basename(self):
        return socket.gethostname()
    
    def _import_key_from_file(self, path):
        """Imports a key from a file, where it has been stored as a base64
        encoded string."""
        f = open(path)
        data = f.read()
        f.close()
        data = pickle.loads(base64.decodestring(data))
        return data
    
    def _export_key_to_file(self, key, path):
        """Exports the provided key to a file as a base64-encoded string.
        
        key: a key as a dict as it is created by rsa.gen_pubpriv_keys
        
        """
        data = base64.encodestring(pickle.dumps(key))
        f = open(path, 'w')
        f.write(data)
        f.close()
        os.chmod(path, 0600)
    
    def _generate_rsa_keypair(self):
        public_key, private_key = rsa.gen_pubpriv_keys(self.key_bits)
        self._export_key_to_file(public_key, self.get_public_key_path())
        self._export_key_to_file(private_key, self.get_private_key_path())
    
    # Public API
    
    def generate_keys(self):
        self._generate_rsa_keypair()
        
    def load_private_key(self):
        """Loads the private keys."""
        self.private_key = self._import_key_from_file(self.get_private_key_path())
    
    def load_public_key(self):
        """Loads the public keys."""
        self.public_key = self._import_key_from_file(self.get_public_key_path())
    
    def load_external_private_key(self, filename):
        path = os.path.join(self.keys_dir, filename)
        self.private_key = self._import_key_from_file(path)
    
    def load_external_public_key(self, filename):
        path = os.path.join(self.keys_dir, filename)
        self.public_key = self._import_key_from_file(path)
    
    def get_private_key_path(self):
        return '%s.key' % os.path.join(self.keys_dir, self._get_key_basename())
    
    def get_public_key_path(self):
        return '%s.pub' % os.path.join(self.keys_dir, self._get_key_basename())
    
    def reset(self):
        self.public_key = None
        self.private_key = None
    
    def encrypt(self, data_raw):
        if self.public_key is None:
            raise PublicKeyNotLoaded
        try:
            data_enc = rsa.encrypt(data_raw, self.public_key)
            data_enc_b64 = base64.b64encode(data_enc)
        except:
            raise DataEncryptionError
        else:
            return data_enc_b64
    
    def decrypt(self, data_enc_b64):
        if self.private_key is None:
            raise PrivateKeyNotLoaded
        try:
            data_enc = base64.b64decode(data_enc_b64)
            data_raw = rsa.decrypt(data_enc, self.private_key)
        except:
            raise DataDecryptionError
        else:
            return data_raw
    
    def verify(self, data_signed_b64):
        if self.public_key is None:
            raise PublicKeyNotLoaded
        try:
            data_signed = base64.b64decode(data_signed_b64)
            data_raw = rsa.verify(data_signed, self.public_key)
        except:
            raise DataVerificationError
        else:
            return data_raw
    
    def sign(self, data_raw):
        if self.private_key is None:
            raise PrivateKeyNotLoaded
        try:
            data_signed = rsa.sign(data_raw, self.private_key)
            data_signed_b64 = base64.b64encode(data_signed)
        except:
            raise DataSigningError
        else:
            return data_signed_b64
    
    
    
    