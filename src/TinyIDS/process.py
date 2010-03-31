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

UMASK = 022

import sys
import os
import grp
import pwd


class ProcessError(Exception):
    pass

class UserError(Exception):
    pass


def run_in_background_as_user(user, group):
    """Runs the current process as a background process.

    Based on the http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66012
    Python CookBook recipe, named "fork a daemon process on UNIX", which is
    based on the UNIX double-fork magic described in "Advanced Programming
    in the Unix Environment" W. Richard Stevens, 1992, Addison-Wesley,
    ISBN 0-201-56317-7
    
    Further Reading:
        http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66012
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
    
    Returns the PID number as string.
    
    This implementation is borrowed from DictExpress by George Notaras.
    
    """
    
    # Two forks are needed in order to prevent zombie processes.
    
    # First fork
    try:
        pid = os.fork()         # Fork first child
        if pid > 0:
            sys.exit(0)         # Exit the first parent.
    except OSError, (errno, strerror):
        raise ProcessError('Failed to fork child #1. %s' % strerror)
    
    # Decouple from parent environment.
    os.umask(UMASK)             # Set umask 022
    try:
        os.chdir('/')           # Change to root dir
    except OSError, (errno, strerror):
        raise ProcessError('Could not change to %s. %s' % strerror)
    os.setsid()
    
    # Second fork
    try:
        pid = os.fork()         # Fork second child.
        if pid > 0:
            sys.exit(0)         # Exit second parent.
    except OSError, (errno, strerror):
        raise ProcessError('Failed to fork child #2. %s' % strerror)
    
    # The process now runs in the background.
    
    # Redirect standard file descriptors to /dev/null
    
#    stdin = open('/dev/null', 'r')
#    stdout = open('/dev/null', 'a+')
#    stderr = open('/dev/null', 'a+', 0)
#    
#    sys.stdin.flush()
#    sys.stdout.flush()
#    sys.stderr.flush()
#    
#    os.close(sys.stdin.fileno())
#    os.close(sys.stdout.fileno())
#    os.close(sys.stderr.fileno())
#    
#    os.dup2(stdin.fileno(), sys.stdin.fileno())
#    os.dup2(stdout.fileno(), sys.stdout.fileno())
#    os.dup2(stderr.fileno(), sys.stderr.fileno())
    
    # Drop root privileges
    # If the program has been started as root, drop privileges
    # and run as user/group.
    #
    # groupadd -r tinyids
    # useradd -r -g tinyids tinyids
    #
    if os.getuid() == 0:
        # Get the UID/GID for the option-defined User/Group
        new_gid = grp.getgrnam(group)[2]
        new_uid = pwd.getpwnam(user)[2]
        
        # The new GID should be set first
        try:
            os.setgid(new_gid)
            #os.setegid(new_gid)    # Not needed. setgid sets also the effective GID
        except KeyError:
            raise UserError('Group not found: %s' % group)
        # Then the new UID
        try:
            os.setuid(new_uid)
            #os.seteuid(new_uid)    # Not needed. setuid sets also the effective UID
        except KeyError:
            raise UserError('User not found: %s' % user)
    
    # Return PID
    return os.getpid()


# TODO: logfile should change permissions

