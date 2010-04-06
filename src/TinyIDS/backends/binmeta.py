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
import os

from TinyIDS.collector import BaseCollector


class CollectorBackend(BaseCollector):
    
    def collect(self):
        for path in self.file_paths():
            #print 'checking: %s' % path
            fst = os.stat(path)
            data = '%s %s %s %s %s %s %s\n' % (path, fst.st_mode, fst.st_ino, fst.st_uid, fst.st_gid, fst.st_size, fst.st_mtime)
            yield data

if __name__ == '__main__':
    for data in CollectorBackend().collect():
        sys.stdout.write(data)
    sys.stdout.flush()


