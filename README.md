# TaiLing.cc

[![CI](https://github.com/yuantailing/tailing.cc/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/yuantailing/tailing.cc/actions/workflows/ci.yml)

[TaiLing.cc](http://tailing.cc/) is compiled from [single C++ file](http://tailing.cc/tailing.cc), and produces source code itself.

## Usage

```console
$ git clone https://github.com/yuantailing/tailing.cc.git
$ cd tailing.cc
$ git submodule update --init --recursive
$ python distribute.py
$ g++ build/tailing.cc -std=c++11 -O2 -lpthread -obuild/run
$ build/run 8888
```

Then you can browse `localhost:8888`.

## Requirements

 - At least 1024 MB RAM is required to compile.
