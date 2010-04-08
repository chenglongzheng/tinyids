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

DEFAULT_GLOB_EXP = (
    '/usr/local/sbin/*',
    '/usr/local/bin/*',
    '/sbin/*',
    '/bin/*',
    '/usr/sbin/*',
    '/usr/bin/*',
    '/root/bin/*',
    '/lib/*',
    '/usr/lib/*',
    '/usr/local/lib/*',
)


import os
import glob
import logging
import subprocess

from TinyIDS.config import TinyIDSConfigParser


class BaseBackendError(Exception):
    pass

class InternalBackendError(BaseBackendError):
    pass

class ExternalCommandError(BaseBackendError):
    pass


class BaseCollector:
    """Base class for data collector backends.
    
    In TinyIDS terminology a 'collector backend' is a module that collects
    information from files or from the output of system commands and provides
    it to a hashing algorithm, so that a unique checksum is calculated for
    the specific piece of information.
    
    Backend Configuration
    
    Each collector backend may have its own optional configuration file. A
    very basic configuration file is shown below:
    
    [main]
    paths = 
        /usr/local/bin/*,
        /usr/local/lib/*,
    
    The 'paths' option accepts a comma-delimited list of glob expressions.
    This option is used by the file_paths() generator.
    
    Each backend configuration file may have any other option the developer
    sees fit. Even the 'paths' option is optional and the backend developer
    may uses other means to retrieve a list of file paths.  
    
    Instance Methods
    
    * file_paths(): a file path generator (helper method)
    * external_command(): executes a system command (helper method)
    * collect(): information generator. Should iterate over pieces of collected
      information. (mandatory method)
     
    """
    
    def __init__(self, config_path=None):
        """Constructor.
        
        Arguments
        
          config_path: an optional path to a configuration file.
        
        Instance attributes
        
          logger: a logging logger object.
          cfg: a ConfigParser instance containing the backend configuration.
        
        """
        self.logger = logging.getLogger()
        self.cfg = TinyIDSConfigParser()
        if config_path:
            if os.path.exists(config_path):
                self.cfg.read(config_path)
                self.logger.debug('Using configuration for %s backend from: %s' % (__name__, config_path))
        
    def file_paths(self):
        """File path generator.
        
          1. Retrieves the glob expressions from the configuration file (option
             'paths' under the [main] section). If a configuration file is not
             found or if the option is not set, then the internal default glob
             expressions (DEFAULT_GLOB_EXP) are used.
          2. Expands each glob expression.
          3. Iterates over the list of paths, which are the result of the
             glob expression expansion. 
        
        """
        if not self.cfg.has_section('main'):
            paths = DEFAULT_GLOB_EXP
        elif not self.cfg.has_option('main', 'paths'):
            paths = DEFAULT_GLOB_EXP
        else:
            paths = self.cfg.getlist('main', 'paths')
        for path in paths:
            file_list = glob.glob(path)
            for fpath in file_list:
                if os.path.isfile(fpath):   # Follows symbolic links
                    yield fpath
    
    def external_command(self, args):
        """Executes an external command.
        
        Accepts a list of command-line arguments.
        
        Returns the command output from STDOUT.
        
        On error, raises the ExternalCommandError exception containing the
        STDERR information.
        
        """
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            raise ExternalCommandError(stderr)
        return stdout
    
    def collect(self):
        """Information generator.
        
        All backends should implement a collect() generator.
        
        The yielded information will finally pass through a hashing algorithm.
        
        Should be overridden by backends that derive from the base class.
        
        """
        raise NotImplementedError

