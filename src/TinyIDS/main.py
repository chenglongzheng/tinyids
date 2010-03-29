# -*- coding: utf-8 -*-
#
#  This file is part of tinyids.
#
#  tinyids - 
#
#  Project: https://www.codetrax.org/projects/tinyids
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

from TinyIDS.config import cfg
from TinyIDS import applogger
from TinyIDS import cmdline
from TinyIDS.server import TinyIDSServer, TinyIDSCommandHandler


def main():
    opts = cmdline.parse_client()
    if opts.debug:
        applogger.init_std_stream_loggers(level='debug')
    else:
        applogger.init_std_stream_loggers()

def server_main():
    opts = cmdline.parse_server()
    if opts.debug:
        applogger.init_std_stream_loggers(level='debug')
    else:
        applogger.init_file_logger()
    
    interface = cfg.get('main', 'interface')
    port = cfg.getint('main', 'port')
    server = TinyIDSServer((interface, port), TinyIDSCommandHandler)
    server.serve_forever()
