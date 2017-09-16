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


def mkdirs(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        mkdirs(parent)
    if not os.path.isdir(path):
        os.mkdir(path)

def merge():
    mkdirs(os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR))
    def walk(din, dout, dmid):
        for filename in os.listdir(os.path.join(din, dmid)):
            filepath = os.path.join(din, dmid, filename)
            if os.path.isfile(filepath):
                fakepath = os.path.join(dout, dmid, filename)
                mkdirs(os.path.dirname(fakepath))
                with open(filepath, 'r') as fin:
                    with open(fakepath, 'w') as fout:
                        for line in fin:
                            s = line
                            if s.startswith('#include <'):
                                s = 'int STDINCLUDE_{} = 0;\n'.format(base64.b16encode(s))
                            fout.write(s)
            elif os.path.isdir(filepath):
                walk(din, dout, os.path.join(dmid, filename))
    walk(CROW_INCLUDE_DIR, os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR), '')
    walk(os.path.join(src_dir), os.path.join(MIDPRODUCTS_ROOT, src_dir), '')
    p = subprocess.Popen([CPP, os.path.join(MIDPRODUCTS_ROOT, src_dir, src_filename), '-nostdinc', '-I{}'.format(os.path.join(MIDPRODUCTS_ROOT, CROW_INCLUDE_DIR)), '-std=c++11'],
                         stdout=subprocess.PIPE)
    out, _ = p.communicate()
    assert 0 == p.wait()
    lines = out.splitlines()
    
    required_stdheaders = []
    filter0 = re.compile('# \d+ ')
    filter1 = re.compile('int STDINCLUDE_([a-zA-Z0-9]+) = 0;$')
    for i, line in enumerate(lines):
        if filter0.match(line) or not line.strip():
            lines[i] = ''
        elif filter1.match(line):
            m = filter1.match(line)
            sbase = m.group(1)
            s = base64.b16decode(sbase).strip()
            if s not in required_stdheaders:
                required_stdheaders.append(s)
            lines[i] = ''
    lines = required_stdheaders + [''] + lines
    mkdirs(dist_dir)
    with open(os.path.join(dist_dir, src_filename), 'w') as f:
        for license in LICENSES:
            with open(license) as flincense:
                for line in flincense:
                    f.write('// ')
                    f.write(line)
                f.write('\n\n')
        for i, line in enumerate(lines):
            if i == 0 or lines[i - 1] != '' or line != '':
                f.write(line)
                f.write('\n')
    shutil.rmtree(MIDPRODUCTS_ROOT)

def compile():
    ARGS = [CC, os.path.join(dist_dir, src_filename), '-pipe', '-std=c++11', '-lpthread', '-lboost_system',
            '-o{}'.format(os.path.join(dist_dir, TARGET))]
    print(' '.join(ARGS))
    p = subprocess.Popen(ARGS, stdin=None, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()

def main():
    merge()
    compile()

if __name__ == '__main__':
    main()
