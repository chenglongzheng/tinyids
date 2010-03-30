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


DEFAULT_SERVER_CONFIG = '/etc/tinyids/tinyidsd.conf'
DEFAULT_CLIENT_CONFIG = '/etc/tinyids/tinyids.conf'

USAGE_CLIENT = """

%prog -h, --help

%prog --version

%prog [options]

%prog [--config PATH]

Only one of the following can be used at a time:

    [--test] [--check] [--update] [--delete] [--change-phrase]
    
"""

USAGE_SERVER = """

%prog -h, --help

%prog --version

%prog [options]

%prog [--config PATH] [--debug]

"""


import sys

from optparse import OptionParser

from TinyIDS import info


def parse_client():
    
    parser = OptionParser(
        prog = info.name,
        usage = USAGE_CLIENT,
        version = info.version,
        description = info.long_description,
    )

    parser.set_defaults(
        confpath = DEFAULT_CLIENT_CONFIG,
        test = False,
        check = False,
        update = False,
        delete = False,
        changephrase = False,
        debug = False,
    )

    parser.add_option('-c', '--config', action='store', type='string',
            dest='confpath', metavar='PATH', help="""Sets the path to the \
configuration file. If a path is not set, the configuration file will be \
searched at the default location. [Default: %s]""" % (DEFAULT_CLIENT_CONFIG))
    
    parser.add_option('--test', action='store_true', dest='test',
        help="""Tests communications with the remote servers.""")
    
    parser.add_option('--check', action='store_true', dest='check',
        help="""Checks the calculated hash with the one that is stored at the \
        remote servers.""")
    
    parser.add_option('--update', action='store_true', dest='update',
        help="""Updates the hash at the remote servers with the calculated one. \
You will be prompted for the passphrase.""")

    parser.add_option('--delete', action='store_true', dest='delete',
            help="""Delete the hash that is stored at the remote servers. \
You will be prompted for the passphrase.""")
    
    parser.add_option('--changephrase', action='store_true', dest='changephrase',
            help="""Change the passphrase on the remote servers. \
You will be prompted for the current and the new passphrase.""")
    
    parser.add_option('--debug', action='store_true', dest='debug',
            help="""Run in debug mode. All messages will be printed to stdout.""")
    
    opts, args = parser.parse_args()
    if args:
        parser.error('invalid number of arguments')
    # Only one of the following options can be used at a time:
    # --check, --update, --delete, --change-phrase
    nr = [opts.test, opts.check, opts.update, opts.delete, opts.changephrase].count(True)
    if nr == 0:
        parser.error('a command must be run: --test, --check, --update, --delete, --change-phrase')
    elif nr != 1:
        parser.error('only one of the following options can be used at a time: --test, --check, --update, --delete, --change-phrase')
    
    return opts


def parse_server():
    
    parser = OptionParser(
        prog = info.name,
        usage = USAGE_SERVER,
        version = info.version,
        description = info.long_description,
    )

    parser.set_defaults(
        confpath = DEFAULT_SERVER_CONFIG,
        debug = False,
    )

    parser.add_option('-c', '--config', action='store', type='string',
            dest='confpath', metavar='PATH', help="""Sets the path to the \
configuration file. If a path is not set, the configuration file will be \
searched at the default location. [Default: %s]""" % (DEFAULT_CLIENT_CONFIG))
    
    parser.add_option('--debug', action='store_true', dest='debug',
            help="""Run in debug mode. In this mode the server will not fork \
into the background, will not drop privileges and all messages will be printed \
to stderr. The logfile is not used.""")
    
    opts, args = parser.parse_args()
    if args:
        parser.error("invalid number of arguments")
    return opts


