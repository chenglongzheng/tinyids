

import ConfigParser


class TinyIDSConfig(ConfigParser.RawConfigParser):
    def __init__(self):
        ConfigParser.RawConfigParser.__init__(self)
        self.add_section('main')
        self.set('main', 'interface', '127.0.0.1')
        self.set('main', 'port', '9999')
        self.set('main', 'logfile', 'tinyids.log')
        self.set('main', 'loglevel', 'debug')
        self.set('main', 'datadir', 'tinyids.db')
        print 'CONFIG WAS CREATED'

cfg = TinyIDSConfig()
