#! /usr/bin/env python
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
#  NOTES
#
#  Create source distribution tarball:
#    python setup.py sdist --formats=gztar
#
#  Create binary distribution rpm:
#    python setup.py bdist --formats=rpm
#
#  Create binary distribution rpm with being able to change an option:
#    python setup.py bdist_rpm --release 7
#
#  Test installation:
#    python setup.py install --prefix=/usr --root=/tmp
#
#  Install:
#    python setup.py install
#  Or:
#    python setup.py install --prefix=/usr
#


import sys
sys.path = ['src/'] + sys.path

from distutils.core import setup
from TinyIDS import info

if __name__=='__main__':
    setup(
        name = info.name,
        version = info.version,
        description = info.description,
        long_description = info.long_description,
        author = info.author,
        author_email = info.author_email,
        url = info.url,
        download_url = info.download_url,
        license = info.license,
        classifiers = info.classifiers,
        packages = [
            'TinyIDS',
            'TinyIDS.backends',
            'TinyIDS.rsa',
        ],
        package_dir = {'': 'src'},
        data_files = [
            ('/etc/tinyids', [
                'etc/tinyids.conf.default',
                'etc/tinyidsd.conf.default',
            ]),
            ('/etc/tinyids/backends', [
                'etc/backends/custom.py.example',
            ]),
            #('/etc/tinyids/backends', []),
            ('/etc/tinyids/keys', []),
            ('/var/lib/tinyids', []),
        ],
        scripts = ['scripts/tinyids', 'scripts/tinyidsd']
    )
