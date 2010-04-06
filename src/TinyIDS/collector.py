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

DEFAULT_PATHS = (
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

from TinyIDS.config import TinyIDSConfigParser


logger = logging.getLogger()


class BaseCollector:
    """
    TODO: write BaseCollector docstring
    """
    
    def __init__(self, config_path=None):
        
        self.config_path = config_path
        self.cfg = TinyIDSConfigParser()
        if self.config_path:
            if os.path.exists(self.config_path):
                self.cfg.read(self.config_path)
                logger.debug('Using configuration for %s backend from: %s' % (__name__, self.config_path))
        
    def file_paths(self):
        if not self.cfg.has_section('main'):
            paths = DEFAULT_PATHS
        elif not self.cfg.has_option('main', 'paths'):
            paths = DEFAULT_PATHS
        else:
            paths = self.cfg.getlist('main', 'paths')
        for path in paths:
            file_list = glob.glob(path)
            for fpath in file_list:
                if os.path.isfile(fpath):   # Follows symbolic links
                    yield fpath
    
    def collect(self):
        pass

