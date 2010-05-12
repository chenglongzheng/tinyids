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

UMASK = 022

import sys
import os
import grp
import pwd


class ProcessError(Exception):
    pass

class UserError(Exception):
    pass


def run_in_background():
    """Runs the current process in the background.

    Based on the recipe:
    
        http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66012
    
    Note: Two forks are needed in order to prevent zombie processes.
    
    Returns the PID number as string.
    
    """
    # Perform first fork
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
    
    # Perform second fork
    try:
        pid = os.fork()         # Fork second child.
        if pid > 0:
            sys.exit(0)         # Exit second parent.
    except OSError, (errno, strerror):
        raise ProcessError('Failed to fork child #2. %s' % strerror)
    
    # The process now runs in the background.
    
    # Redirect standard file descriptors to /dev/null
    stdin = open('/dev/null', 'r')
    stdout = open('/dev/null', 'a+')
    stderr = open('/dev/null', 'a+', 0)
    
    sys.stdin.flush()
    sys.stdout.flush()
    sys.stderr.flush()
    
    os.dup2(stdin.fileno(), sys.stdin.fileno())
    os.dup2(stdout.fileno(), sys.stdout.fileno())
    os.dup2(stderr.fileno(), sys.stderr.fileno())
    
    # Return PID
    return os.getpid()

    
def run_as_user(user, group):
    """The current process drops root privileges and runs as user/group.
    
    Create a user with:
    
        groupadd -r tinyids
        useradd -r -g tinyids tinyids
    
    If the process is not run as root, then this function does nothing.
    
    """
    if os.getuid() != 0:
        return
    
    # Get the UID/GID of the provided used/group
    new_gid = grp.getgrnam(group)[2]
    new_uid = pwd.getpwnam(user)[2]
    
    # The new GID should be set first
    try:
        os.setgid(new_gid)
    except KeyError:
        raise UserError('Group not found: %s' % group)
    
    # Then the new UID
    try:
        os.setuid(new_uid)
    except KeyError:
        raise UserError('User not found: %s' % user)


def set_fs_permissions(path, user, group, mode):
    """Sets permissions and ownership on path.
    
    This can only work only if the process has been started with root
    privileges. If this is not the case, it does nothing.
    
    """
    if os.getuid() != 0:
        return

    uid = pwd.getpwnam(user)[2]
    gid = grp.getgrnam(group)[2]
    
    os.chmod(path, mode)
    os.chown(path, uid, gid)
    
