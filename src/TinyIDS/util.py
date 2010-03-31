# -*- coding: utf-8 -*-
#
#  This file is part of <Project>
#
#  <Description>
#
#  <Project URL>
#
#  Copyright 2010 George Notaras <gnot [at] g-loaded.eu>, CodeTRAX.org
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

import imp

try:
    import hashlib
    sha1 = hashlib.sha1
except ImportError:
    import sha
    sha1 = sha.new


def sha1sum(data):
    """Returns the sha1 checksum of the provided data."""
    s = sha1()
    s.update(data)
    return s.hexdigest()

def load_backend(base_dir, name):
    """Loads the backend module and returns it."""
    name = name.strip()
    fp, pathname, desc = imp.find_module(name, [base_dir])
    try:
        x = imp.load_module(name, fp, pathname, desc)
    finally:
        if fp:
            fp.close()
    return x


