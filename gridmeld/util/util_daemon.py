#!/usr/bin/env python

#
# Copyright (c) 2013 Kevin Steves <kevin.steves@pobox.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

from __future__ import print_function
import os


# Mimics OpenSSH openbsd-compat/daemon.c
# Detach from the controlling terminal and run in the background.

def daemon(nochdir=False, noclose=False):
    try:
        pid = os.fork()
    except OSError:
        raise
    if pid:
        # parent
        os._exit(0)

    # child
    try:
        os.setsid()
    except OSError:
        raise

    if not nochdir:
        os.chdir('/')

    if noclose:
        return

    try:
        fd = os.open('/dev/null', os.O_RDWR)
        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        if fd > 2:
            os.close(fd)
    except OSError:
        raise


if __name__ == '__main__':
    import sys
    import time
    from util_daemon import daemon as Daemon

    try:
        if len(sys.argv) == 1 or sys.argv[1] == 'test1':
            print("test1: should see 'hello' only")
            print('hello')
            Daemon()
            print('world')
            time.sleep(10)

        elif sys.argv[1] == 'test2':
            print("test2: should see 'hello world'")
            print('hello ', end='')
            Daemon(noclose=True)
            print('world')
            time.sleep(10)

        elif sys.argv[1] == 'test3':
            print('test3: daemon-test3 should be created in the '
                  'current directory')
            Daemon(nochdir=True)
            fd = os.open('daemon-test3', os.O_WRONLY | os.O_CREAT)
            os.close(fd)
            print('done')
            time.sleep(10)

        else:
            print('Invalid argument:', sys.argv[1], file=sys.stderr)

    except OSError as e:
        print('daemon:', e, file=sys.stderr)
