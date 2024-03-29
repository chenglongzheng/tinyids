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

PROTOCOL_REVISION = 2
COMPATIBLE_PROTOCOL_REVISIONS = (PROTOCOL_REVISION,)
DEFAULT_SERVER_CONFIG = '/etc/tinyids/tinyidsd.conf'
DEFAULT_CLIENT_CONFIG = '/etc/tinyids/tinyids.conf'
DEFAULT_PORT = 10500
DEFAULT_DATABASE_PATH = '/var/lib/tinyids/tinyids.db'
DEFAULT_LOGFILE_PATH = '/var/log/tinyidsd.log'
DEFAULT_LOGLEVEL = 'info'


import os
import ConfigParser


class ConfigPathNotSetError(Exception):
    pass

class ConfigFileNotFoundError(Exception):
    pass

class InvalidDefaultError(Exception):
    pass


class TinyIDSConfigParser(ConfigParser.RawConfigParser):

    def getlist(self, section, option):
        """Returns a list of strings.
        
        Expects a comma-delimited list of strings as the option value.
        
        Multiline value is supported.
        
        """
        value_list = self.get(section, option)
        return [value.strip() for value in value_list.split(',') if value.strip()]
    
    def get_or_default(self, section, option, default):
        """Returns the option value.
        
        If the option is not set or the value is empty, then it returns the
        provided default value.
        
        """
        if not isinstance(default, str):
            raise InvalidDefaultError
        elif not self.has_option(section, option):
            return default
        value = self.get(section, option)
        if not value:
            value = default
        return value
    

def get_client_configuration(path=None):
    """Returns the global client configuration object 'cfg_client'.
    
    If cfg_client has not been created, this function creates it and
    reads the relevant configuration file.
    
    Accepts a path to the configuration file. If the path is missing and
    global cfg_client object has not been set, the ConfigPathNotSetError
    exception is raised.
    
    """
    global cfg_client
    if not globals().has_key('cfg_client'):
        if not path:
            raise ConfigPathNotSetError
        elif not os.path.exists(path):
            raise ConfigFileNotFoundError
        cfg_client = TinyIDSConfigParser()
        cfg_client.read(path)
        return cfg_client
    else:
        return cfg_client

def get_server_configuration(path=None):
    """Returns the global server configuration object 'cfg_server'.
    
    If cfg_server has not been created, this function creates it and
    reads the relevant configuration file.
    
    Accepts a path to the configuration file. If the path is missing and
    global cfg_server object has not been set, the ConfigPathNotSetError
    exception is raised.
    
    """
    global cfg_server
    if not globals().has_key('cfg_server'):
        if not path:
            raise ConfigPathNotSetError
        elif not os.path.exists(path):
            raise ConfigFileNotFoundError
        cfg_server = TinyIDSConfigParser()
        cfg_server.read(path)
        return cfg_server
    else:
        return cfg_server
