# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import socket
import subprocess

from six.moves import urllib


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    p = subprocess.Popen([os.path.join('build', 'run'), '{:d}'.format(port)])
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
    assertEqual('tailing.cc', os.path.join('build', 'tailing.cc'))
    p.terminate()
    assert 0 == p.wait()


if __name__ == '__main__':
    main()
