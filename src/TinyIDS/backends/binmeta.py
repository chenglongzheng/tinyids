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
import glob

class Check:
    name = 'Binary Hash'
    
    paths = (
        '/usr/local/sbin',
        '/usr/local/bin',
        '/sbin',
        '/bin',
        '/usr/sbin',
        '/usr/bin',
        '/root/bin',
    )
    
    def run(self):
        for path in self.paths:
            glob_exp = os.path.join(path, '*')
            #print 'checking: %s' % glob_exp
            flist = glob.glob(glob_exp)
            for fpath in flist:
                if os.path.isfile(fpath):   # Follows symbolic links
                    #print 'checking: %s' % fpath
                    fst = os.stat(fpath)
                    data = '%s %s %s %s %s %s %s\n' % (fpath, fst.st_mode, fst.st_ino, fst.st_uid, fst.st_gid, fst.st_size, fst.st_mtime)
                    yield data

if __name__ == '__main__':
    for data in Check().run():
        sys.stdout.write(data)
    sys.stdout.flush()



