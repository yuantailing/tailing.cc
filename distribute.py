#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hashlib
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import time


# Nothing but the compiler is needed to build, so take whichever one the
# platform comes with unless told otherwise.
CXX = os.environ.get('CXX', 'cl' if os.name == 'nt' else 'g++')
MSVC = os.path.splitext(os.path.basename(CXX))[0].lower() == 'cl'
src_dir = 'src'
dist_dir = 'build'
src_filename = 'tailing.cc'
TARGET = 'run'

HTTPLIB_DIR = 'cpp-httplib'
HTTPLIB_HEADER = 'httplib.h'
MIDPRODUCTS_ROOT = '.midproducts'
LICENSES = ['LICENSE', os.path.join(HTTPLIB_DIR, 'LICENSE')]

# The source file is an ordinary program that keeps its own source in a string.
# This declaration is the only seam it has to offer; everything that fills the
# string lives here.
SOURCE_PLACEHOLDER = b'std::string HACK_SOURCECODE("NOT FOUND");'
# Stands in for the copy while the file is being written.
SOURCE_MARKER = b'@SELF_SOURCE@'
# MSVC rejects a string literal longer than 16380 bytes, so they are split.
ESCAPE_WIDTH = 8000

# The C++ half of escape(), emitted in place of the declaration above with the
# escaped source as its argument. What the compiler hands it is the file with
# the marker still standing in; escaping that back and dropping it where the
# marker sits reproduces the file. The two escapers have to agree byte for
# byte, so they are kept next to each other.
SOURCE_EXPANSION = r'''std::string HACK_SOURCECODE = [](const std::string &t) -> std::string {
        std::string e;
        std::string::size_type c = 0;
        bool o = false;
        for (std::string::size_type i = 0; i < t.size(); i++) {
            unsigned char x = static_cast<unsigned char>(t[i]);
            char b[4];
            std::string::size_type n;
            if (x == '\\' || x == '"' || x == '?') {
                b[0] = '\\'; b[1] = static_cast<char>(x); n = 2; o = false;
            } else if (x == '\n') {
                b[0] = '\\'; b[1] = 'n'; n = 2; o = false;
            } else if (0x20 <= x && x <= 0x7e && !(o && '0' <= x && x <= '9')) {
                b[0] = static_cast<char>(x); n = 1; o = false;
            } else {
                b[0] = '\\';
                b[1] = static_cast<char>('0' + ((x >> 6) & 7));
                b[2] = static_cast<char>('0' + ((x >> 3) & 7));
                b[3] = static_cast<char>('0' + (x & 7));
                n = 4; o = true;
            }
            if (c != 0 && c + n > WIDTHu) { e += "\"\n\""; c = 0; }
            e.append(b, n);
            c += n;
        }
        std::string r(t);
        return r.replace(r.find("@" "MARKERTAIL"), MARKERLEN, e);
    }("PAYLOAD");'''

SOURCE_EXPANSION_HEAD, SOURCE_EXPANSION_TAIL = (SOURCE_EXPANSION
    .replace('WIDTH', '{:d}'.format(ESCAPE_WIDTH))
    .replace('MARKERTAIL', SOURCE_MARKER[1:].decode('ascii'))
    .replace('MARKERLEN', '{:d}'.format(len(SOURCE_MARKER)))
    .encode('ascii').split(b'PAYLOAD'))

v0_dir = 'simple'


def mkdirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def escape(data):
    """Render bytes as the inside of a C++ string literal.

    Escaping instead of picking a raw-string delimiter no byte sequence happens
    to contain keeps the output pure ASCII, so no compiler has to guess the
    encoding of the source file, and no literal outgrows what MSVC parses.
    Must agree byte for byte with SOURCE_EXPANSION, which does the same thing
    at run time.
    """
    out = []
    column = 0
    after_octal = False
    for i in range(len(data)):
        c = ord(data[i:i + 1])
        if c in (0x5c, 0x22, 0x3f):
            # '?' is escaped because trigraphs are still live under -std=c++11.
            token = '\\' + chr(c)
            after_octal = False
        elif c == 0x0a:
            token = '\\n'
            after_octal = False
        elif 0x20 <= c <= 0x7e and not (after_octal and 0x30 <= c <= 0x39):
            token = chr(c)
            after_octal = False
        else:
            # Octal, not hex: \x swallows every hex digit that follows it. A
            # digit right after an octal escape reads as part of it, and MSVC
            # warns about that (C4125), so those get escaped too.
            token = '\\{:03o}'.format(c)
            after_octal = True
        if column and column + len(token) > ESCAPE_WIDTH:
            out.append('"\n"')
            column = 0
        out.append(token)
        column += len(token)
    return ''.join(out).encode('ascii')


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
    def fill_next(context):
        for line in template:
            for k, v in context.items():
                line = line.replace(k, v)
            filled.append(line)

    def quote(b):
        return b'"' + escape(b) + b'"'

    www_root = 'www'
    for dirpath, dirnames, filenames in os.walk(www_root, followlinks=True):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            uri = os.path.relpath(filepath, www_root).replace('\\', '/')
            with open(filepath, 'rb') as f:
                file_content = f.read()
            mime_type = mimetypes.guess_type(uri)
            context = {
                b'TEMPLATE_CONTENT_TYPE': '"{}; charset=UTF-8"'.format(mimetypes.guess_type(uri)[0] or 'text/plain').encode('utf-8'),
                b'TEMPLATE_ETAG': '"\\"md5/{}\\""'.format(hashlib.md5(file_content).hexdigest()).encode('utf-8'),
                b'TEMPLATE_LAST_MODIFIED': '"{}"'.format(time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(os.path.getmtime(filepath)))).encode('utf-8'),
                b'TEMPLATE_URI': '"{}"'.format(uri).encode('utf-8'),
                b'TEMPLATE_CONTENT_STR': quote(file_content),
                b'TEMPLATE_LENGTH': '{:d}'.format(len(file_content)).encode('utf-8'),
            }
            fill_next(context)
            m =  re.match('^(.*)index\.s?html?$', uri)
            if m:
                prefix = m.group(1)
                if prefix == '' or prefix.endswith('/'):
                    context[b'TEMPLATE_URI'] = '"{}"'.format(prefix).encode('utf-8')
                    fill_next(context)

    for i, line in enumerate(lines):
        if line.strip() == b'TEMPLATE_FILERESPONSE_LIST':
            lines = lines[:i] + filled + lines[i + 1:]
            break
    with open(os.path.join(MIDPRODUCTS_ROOT, v0_dir, src_filename), 'wb') as f:
        for line in lines:
            f.write(line)
            f.write(b'\n')


def copy_quoted(data, i, out):
    """Copy a "..." or '...' literal whole, and answer where it ended.

    A literal that does not close on its line is not one: that leading quote is
    an ordinary character, so copy just it and carry on.
    """
    quote = data[i:i + 1]
    j = i + 1
    while j < len(data):
        c = data[j:j + 1]
        if c == b'\\':
            j += 2
            continue
        if c == quote:
            j += 1
            break
        if c == b'\n':
            j = i + 1
            break
        j += 1
    else:
        j = i + 1
    out.append(data[i:j])
    return j


def copy_raw(data, i, out):
    """Copy an R"delim( ... )delim" literal whole, and answer where it ended."""
    opening = data.find(b'(', i + 2)
    assert opening >= 0, 'unterminated raw string literal'
    closing = b')' + data[i + 2:opening] + b'"'
    end = data.find(closing, opening + 1)
    assert end >= 0, 'unterminated raw string literal'
    end += len(closing)
    out.append(data[i:end])
    return end


def strip_comments(filepath):
    """Drop the comments and leave every other byte where it was.

    Done here rather than by the compiler so that the build needs no particular
    one: MSVC has no counterpart to the GCC flags that strip comments while
    leaving the directives alone, and both platforms have to produce the same
    file anyway. Everything else survives, so the merged file keeps the
    platform #ifdefs and compiles wherever the header does.
    """
    with open(filepath, 'rb') as f:
        data = f.read().replace(b'\r\n', b'\n')
    identifier = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
    out = []
    i = 0
    while i < len(data):
        pair = data[i:i + 2]
        if pair == b'//':
            i += 2
            while i < len(data):
                if data[i:i + 2] == b'\\\n':
                    i += 2          # the comment goes on into the next line
                    continue
                if data[i:i + 1] == b'\n':
                    break
                i += 1
            out.append(b' ')        # a comment stands for one space
        elif pair == b'/*':
            end = data.find(b'*/', i + 2)
            assert end >= 0, 'unterminated block comment'
            i = end + 2
            out.append(b' ')
        elif pair[1:2] == b'"' and pair[0:1] == b'R' and data[i - 1:i] not in identifier:
            i = copy_raw(data, i, out)
        elif pair[0:1] in (b'"', b"'"):
            i = copy_quoted(data, i, out)
        else:
            out.append(data[i:i + 1])
            i += 1
    return b''.join(out)


def merge():
    header = strip_comments(os.path.join(HTTPLIB_DIR, HTTPLIB_HEADER))

    # cpp-httplib ships as one header, so merging is a concatenation: the
    # library takes the place of the #include that pulled it in.
    with open(os.path.join(MIDPRODUCTS_ROOT, v0_dir, src_filename), 'rb') as f:
        source = f.read().replace(b'\r\n', b'\n')
    include_line = '#include "{}"\n'.format(HTTPLIB_HEADER).encode('utf-8')
    assert include_line in source
    source = source.replace(include_line, b'')

    lines = header.split(b'\n') + [b''] + source.split(b'\n')
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
            f.write(line)
            f.write(b'\n')


def hack(filepath):
    """Put a copy of the file into the file.

    No fixed point to search for: the marker stands in for the copy while the
    escaping runs, and what it stands for never changes its length.
    """
    with open(filepath, 'rb') as f:
        merged = f.read()
    assert merged.count(SOURCE_PLACEHOLDER) == 1, 'the placeholder must occur exactly once'
    assert SOURCE_MARKER not in merged, 'the marker must not occur in the source'

    def expand(literal):
        return SOURCE_EXPANSION_HEAD + literal + SOURCE_EXPANSION_TAIL

    # What the compiler will hand back at run time: this file, marker and all.
    staged = merged.replace(SOURCE_PLACEHOLDER, expand(SOURCE_MARKER))
    with open(filepath, 'wb') as f:
        f.write(merged.replace(SOURCE_PLACEHOLDER, expand(escape(staged))))


def compile_simple():
    source = os.path.join(MIDPRODUCTS_ROOT, v0_dir, src_filename)
    target = os.path.join(dist_dir, TARGET)
    if MSVC:
        ARGS = [CXX, '/nologo', '/EHsc', '/O2', '/I{}'.format(HTTPLIB_DIR), source,
                '/Fe{}.exe'.format(target), '/Fo{}{}'.format(dist_dir, os.sep)]
    else:
        ARGS = [CXX, source, '-I{}'.format(HTTPLIB_DIR), '-pipe', '-std=c++11', '-O2', '-Wall', '-lpthread']
        if os.name == 'nt':
            ARGS.append('-lws2_32')
        ARGS.append('-o{}'.format(target))
    print(' '.join(ARGS))
    p = subprocess.Popen(ARGS, stdin=None, stdout=sys.stdout, stderr=sys.stderr)
    assert 0 == p.wait()


def compile():
    source = os.path.join(dist_dir, src_filename)
    target = os.path.join(dist_dir, TARGET)
    if MSVC:
        # cl links the sockets library itself, through a pragma in the header.
        ARGS = [CXX, '/nologo', '/EHsc', '/O2', source,
                '/Fe{}.exe'.format(target), '/Fo{}{}'.format(dist_dir, os.sep)]
    else:
        ARGS = [CXX, source, '-pipe', '-std=c++11', '-O2', '-Wall', '-lpthread']
        if os.name == 'nt':
            ARGS.append('-lws2_32')
        ARGS.append('-o{}'.format(target))
    print(' '.join(ARGS))
    p = subprocess.Popen(ARGS, stdin=None, stdout=sys.stdout, stderr=sys.stderr)
    assert 0 == p.wait()


def main():
    replace()
    # compile_simple()
    merge()
    shutil.rmtree(MIDPRODUCTS_ROOT)
    hack(os.path.join(dist_dir, src_filename))
    compile()


if __name__ == '__main__':
    main()
