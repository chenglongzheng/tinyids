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

version = '0.1.1'
status = 'beta'
name = 'tinyids'
description = """TinyIDS is a distributed Intrusion Detection System (IDS) for Unix systems."""
long_description = """TinyIDS is a distributed Intrusion Detection System (IDS) for Unix systems. It is based on client/server architecture. The client, tinyids, runs its hashing backends on the local system and calculates a hash of the file contents and their metadata. It then compares this hash with one that has been previously stored on the server counterpart of TinyIDS, tinyidsd, which runs on a remote system. Management of the remotely stored hash is possible through the client's command line interface. Communication between the client and the server counterparts can be encrypted using RSA public key infrastructure (PKI). TinyIDS is written in Python and is released as open-source software under the terms of the Apache license version 2."""
author = 'George Notaras'
author_email = 'gnot@g-loaded.eu'
url = 'http://www.codetrax.org/projects/tinyids'
download_url = 'http://www.codetrax.org/attachments/download/21/' + name + "-" + version + ".tar.gz"
license = "Apache License version 2"

# Automate the development status for classifiers
devel_status = ''
if status == 'pre-alpha':
    devel_status = 'Development Status :: 2 - Pre-Alpha'
if status == 'alpha':
    devel_status = 'Development Status :: 3 - Alpha'
if status == 'beta':
    devel_status = 'Development Status :: 4 - Beta'
if status == 'stable':
    devel_status = 'Development Status :: 5 - Production/Stable'

# For a list of classifiers check: http://www.python.org/pypi/
# (http://pypi.python.org/pypi?:action=list_classifiers)

classifiers = [
    devel_status,
    'Environment :: No Input/Output (Daemon)',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Operating System :: POSIX',
    'Programming Language :: Python',
    'Topic :: Security',
    'Topic :: System',
    'Topic :: System :: Monitoring',
    'Topic :: Utilities',
    ]

def get_version():
    return name + ' v' + version + '/' + status
