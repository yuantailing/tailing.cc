#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import base64
import functools
import os
import re
import shutil
import subprocess
import sys


CC = 'g++'
CPP = 'cpp'
src_dir = 'src'
dist_dir = 'dist'
src_filename = 'tailing.cc'
TARGET = 'run'

CROW_INCLUDE_DIR = os.path.join('crow', 'include')
MIDPRODUCTS_ROOT = '.midproducts'
LICENSES = ['LICENSE', os.path.join('crow', 'LICENSE')]

v0_dir = 'simple'


def mkdirs(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        mkdirs(parent)
    if not os.path.isdir(path):
        os.mkdir(path)


def replace():
    mkdirs(os.path.join(MIDPRODUCTS_ROOT, v0_dir))
    with open(os.path.join(src_dir, src_filename), 'r') as f:
        lines = f.read().encode('utf-8').splitlines()
    template = []
    in_template = False
    for i, line in enumerate(lines):
        if line.strip() == b'TEMPLATE_FILERESPONSE_START':
            lines[i] = b''
            in_template = True
        elif line.strip() == b'TEMPLATE_FILERESPONSE_END':
            lines[i] = b''
            break
        elif in_template:
            lines[i] = b''
            template.append(line)
    filled = []

    def quote(b):
        def quote0(b):
            assert b')***' not in b
            assert b'int STDINCLUDE_' not in b
            return b'R"***(' + b + b')***"'
        l = b.split(b'\r')
        return b'"\\r" '.join(map(lambda b: quote0(b), l))

    def walk(base, d):
        for filename in sorted(os.listdir(os.path.join(base, d))):
            filepath = os.path.join(base, d, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    file_content = f.read()
                t = {
                     b'TEMPLATE_URI': '"{}"'.format(os.path.join(d, filename).replace('\\', '/')).encode('utf-8'),
                     b'TEMPLATE_CONTENT': quote(file_content),
                     b'TEMPLATE_LENGTH': '{:d}'.format(len(file_content)).encode('utf-8'),
                    }
                for line in template:
                    for k, v in t.items():
                        line = line.replace(k, v)
                    filled.append(line)
            elif os.path.isdir(filepath):
                walk(base, os.path.join(d, filename))
    walk('html', '')
    for i, line in enumerate(lines):
        if line.strip() == b'TEMPLATE_FILERESPONSE_LIST':
            lines = lines[:i] + filled + lines[i + 1:]
            break
    with open(os.path.join(MIDPRODUCTS_ROOT, v0_dir, src_filename), 'wb') as f:
        for line in lines:
            f.write(line)
            f.write(b'\n')


def merge():
    def walk(din, dout, dmid):
        for filename in os.listdir(os.path.join(din, dmid)):
            filepath = os.path.join(din, dmid, filename)
            if os.path.isfile(filepath):
                fakepath = os.path.join(dout, dmid, filename)
                mkdirs(os.path.dirname(fakepath))
                with open(filepath, 'rb') as fin:
                    with open(fakepath, 'wb') as fout:
                        for line in fin.read().splitlines():
                            s = line
                            if s.startswith(b'#include <'):
                                s = b'int STDINCLUDE_' + base64.b16encode(s) + b' = 0;'
                            fout.write(s)
                            fout.write(b'\n')
            elif os.path.isdir(filepath):
                walk(din, dout, os.path.join(dmid, filename))
    mkdirs(os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR))
    walk(CROW_INCLUDE_DIR, os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR), '')
    walk(os.path.join(MIDPRODUCTS_ROOT, v0_dir), os.path.join(MIDPRODUCTS_ROOT, src_dir), '')
    p = subprocess.Popen([CPP, os.path.join(MIDPRODUCTS_ROOT, src_dir, src_filename), '-nostdinc',
                          '-I{}'.format(os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR)), '-std=c++11'],
                         stdin=None, stdout=subprocess.PIPE, stderr=sys.stderr)
    out, _ = p.communicate()
    assert 0 == p.wait()
    lines = out.splitlines()

    required_stdheaders = []
    filter0 = re.compile(b'# \d+ ')
    filter1 = re.compile(b'int STDINCLUDE_([a-zA-Z0-9]+) = 0;$')
    for i, line in enumerate(lines):
        if filter0.match(line) or not line.strip():
            lines[i] = b''
        elif filter1.match(line):
            m = filter1.match(line)
            sbase = m.group(1)
            s = base64.b16decode(sbase.decode('utf-8'))
            if s not in required_stdheaders:
                required_stdheaders.append(s)
            lines[i] = b''
    lines = required_stdheaders + [b''] + lines
    mkdirs(dist_dir)
    with open(os.path.join(dist_dir, src_filename), 'wb') as f:
        for license in LICENSES:
            with open(license, 'r') as flincense:
                for line in flincense.read().splitlines():
                    f.write(b'// ')
                    f.write(line.encode('utf-8'))
                    f.write(b'\n')
                f.write(b'\n\n')
        for i, line in enumerate(lines):
            if i == 0 or lines[i - 1] != b'' or line != b'':
                f.write(line)
                f.write(b'\n')


def compile_simple():
    ARGS = [CC, os.path.join(MIDPRODUCTS_ROOT, v0_dir, src_filename), '-I{}'.format(CROW_INCLUDE_DIR), '-pipe', '-std=c++11', '-O2', '-lpthread', '-lboost_system',
            '-o{}'.format(os.path.join(dist_dir, TARGET))]
    print(' '.join(ARGS))
    p = subprocess.Popen(ARGS, stdin=None, stdout=sys.stdout, stderr=sys.stderr)
    assert 0 == p.wait()


def compile():
    ARGS = [CC, os.path.join(dist_dir, src_filename), '-pipe', '-std=c++11', '-O2', '-lpthread', '-lboost_system',
            '-o{}'.format(os.path.join(dist_dir, TARGET))]
    print(' '.join(ARGS))
    p = subprocess.Popen(ARGS, stdin=None, stdout=sys.stdout, stderr=sys.stderr)
    assert 0 == p.wait()


def main():
    replace()
    merge()
    shutil.rmtree(MIDPRODUCTS_ROOT)
    compile()


if __name__ == '__main__':
    main()
