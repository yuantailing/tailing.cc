# TaiLing.cc

[![Build Status](https://travis-ci.com/yuantailing/tailing.cc.svg?branch=master)](https://travis-ci.com/yuantailing/tailing.cc)

[TaiLing.cc](http://tailing.cc/) is compiled from [single C++ file](http://tailing.cc/tailing.cc), and produces source code itself.

## Usage

```console
$ git clone https://github.com/yuantailing/tailing.cc.git
$ cd tailing.cc
$ git submodule update --init --recursive
$ sudo apt install libboost-system-dev
$ python distribute.py
$ g++ dist/tailing.cc -std=c++11 -O2 -lpthread -lboost_system -odist/run
$ dist/run 8888
```

Then you can browse `localhost:8888`.

## Requirements

 - At least 1024 MB RAM is required to compile.
