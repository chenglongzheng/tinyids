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

import sys

from TinyIDS.collector import BaseCollector


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


class CollectorBackend(BaseCollector):
    
    name = __name__
    
    def collect(self):
        for path in self.file_paths(DEFAULT_GLOB_EXP):
            #print 'checking: %s' % path
            f = open(path, 'rb')
            data = f.read()
            yield data
            f.close()

if __name__ == '__main__':
    for data in CollectorBackend().collect():
        sys.stdout.write(data)
    sys.stdout.flush()

