# TaiLing.cc

[![CI](https://github.com/yuantailing/tailing.cc/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/yuantailing/tailing.cc/actions/workflows/ci.yml)

[TaiLing.cc](http://tailing.cc/) is compiled from [single C++ file](http://tailing.cc/tailing.cc), and produces source code itself.

## Usage

```bash
git clone https://github.com/yuantailing/tailing.cc.git
cd tailing.cc
git submodule update --init --recursive
python distribute.py
g++ build/tailing.cc -std=c++11 -O2 -lpthread -obuild/run
build/run 8888
```

Then you can browse `localhost:8888`.

On Windows, build with MSYS2/MinGW:

```bash
g++ build/tailing.cc -std=c++11 -O2 -lpthread -lws2_32 -obuild/run
```

or with MSVC, which links the sockets library on its own:

```bat
cl /EHsc /O2 build\tailing.cc /Febuild\run.exe
```

## Requirements

 - At least 1024 MB RAM is required to compile.
 - GCC, Clang and MSVC all work, from `-std=c++11` (`/std:c++14`) up, with the
   GNU dialects included.
