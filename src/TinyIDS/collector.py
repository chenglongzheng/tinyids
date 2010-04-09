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
import glob
import logging
import subprocess
import shlex
import ConfigParser

from TinyIDS.config import TinyIDSConfigParser


class BaseBackendError(Exception):
    pass

class InternalBackendError(BaseBackendError):
    pass

class BackendConfigurationError(BaseBackendError):
    pass

class ExternalCommandError(BaseBackendError):
    pass


class BaseCollector:
    """Base class for data collector backends.
    
    In TinyIDS terminology a 'collector backend' is a module that collects
    information from files or from the output of system commands and provides
    it to the client.
    
    Backend Configuration
    
    Each collector backend may have its own optional configuration file.
    By convention, the basename of the backend configuration file is:
    
      <backend_name>.conf
    
    Each backend configuration file may have any option the developer
    sees fit.  
    
    Instance Helper Methods
    
    The following methods can be used by backends in order to avoid
    duplicating work between different backends. 
    
    * file_paths(): a file path generator (helper method)
    * command_args(): a command generator (helper method)
    * external_command(): executes a system command (helper method)
    
    Instance Mandatory Methods
    
    * collect(): information generator. Should iterate over pieces of
                 collected information.
    
    """
    
    name = 'OVERRIDE'
    
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
                self.logger.debug('%s: Using configuration from: %s' % (self.name, config_path))
        
    def file_paths(self, default_glob_exp):
        """File path generator.
        
        Accepts the 'default_glob_exp' list. This list should contain a
        list of glob expressions as strings.
        
        Optional configuration file.
        
        [main]
        paths = glob1, glob2, ...
        
        The file_paths() generator:
        
          1. tries to retrieve the glob expressions from the configuration
             file (option 'paths' under the [main] section).
          2. If this is not possible, then it uses the default_glob_exp list.
          3. Processes the glob expressions and yields each path to file:
            a. Expands each glob expression into a list of paths.
            b. Iterates over the list of paths and returns them one by one. 
        
        """
        paths = default_glob_exp
        try:
            paths = self.cfg.getlist('main', 'paths')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            self.logger.debug('%s: Scanning internal default paths' % self.name)
        else:
            self.logger.debug('%s: Scanning user-defined paths' % self.name)
        for path in paths:
            file_list = glob.glob(path)
            for fpath in file_list:
                if os.path.isfile(fpath):   # Follows symbolic links
                    yield fpath
    
    def command_args(self, default_commands):
        """Command generator.
        
        Each command is returned as a list of arguments.
        
        Accepts the 'default_commands' list. This list should contain a
        list of commands as strings.
        
        Optional configuration file.
        
        [main]
        commands = com1, com2, ...
        
        The command_args() generator:
        
          1. tries to retrieve a list of commands from the configuration file.
          2. If this is not possible, it uses the default_commands list.
        
        Iterates over the list of commands and returns each command as a
        list of command line arguments.

        """
        commands = default_commands
        try:
            commands = self.cfg.getlist('main', 'commands')
        except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
            if not default_commands:
                raise InternalBackendError('No commands to execute')
            self.logger.debug('%s: Executing internal default commands' % self.name)
        else:
            self.logger.debug('%s: Executing user-defined commands' % self.name)
        for command in commands:
            yield shlex.split(command)
    
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

