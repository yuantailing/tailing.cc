# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import signal
import socket
import subprocess
import time

from six.moves import urllib


def pick_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_until_listening(p, port, timeout=30.):
    deadline = time.time() + timeout
    while time.time() < deadline:
        assert p.poll() is None, 'server exited with {:d}'.format(p.returncode)
        try:
            socket.create_connection(('127.0.0.1', port), 1.).close()
            return
        except socket.error:
            time.sleep(.05)
    raise AssertionError('server is not listening on port {:d}'.format(port))


def main():
    port = pick_port()
    p = subprocess.Popen([os.path.join('build', 'run'), '{:d}'.format(port)])
    wait_until_listening(p, port)
    baseurl = 'http://localhost:{:d}/'.format(port)
    www_root = 'www'

    def assertEqual(uri, filepath):
        request = urllib.request.Request('{:s}{:s}'.format(baseurl, uri))
        response = urllib.request.urlopen(request)
        page_content = response.read()
        with open(filepath, 'rb') as f:
            file_content = f.read()
        assert page_content == file_content, uri

    for dirpath, dirnames, filenames in os.walk(www_root, followlinks=True):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            uri = os.path.relpath(filepath, www_root).replace('\\', '/')
            assertEqual(uri, filepath)
    assertEqual('', os.path.join(www_root, 'index.html'))
    assertEqual('tailing.cc', os.path.join('build', 'tailing.cc'))
    p.terminate()
    # cpp-httplib installs no signal handler, so SIGTERM ends the process.
    assert p.wait() in (0, -signal.SIGTERM), p.returncode


if __name__ == '__main__':
    main()
