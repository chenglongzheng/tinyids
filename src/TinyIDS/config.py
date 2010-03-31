

DEFAULT_SERVER_CONFIG = '/etc/tinyids/tinyidsd.conf'
DEFAULT_CLIENT_CONFIG = '/etc/tinyids/tinyids.conf'
DEFAULT_PORT = 10500
DEFAULT_DATABASE_PATH = '/var/lib/tinyids/tinyids.db'
DEFAULT_LOGFILE_PATH = '/var/log/tinyids.log'


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
        value_list = self.get(section, option)
        return [value.strip() for value in value_list.split(',') if value.strip()]
    
    def get_or_default(self, section, option, default):
        if not isinstance(default, str):
            raise InvalidDefaultError
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

