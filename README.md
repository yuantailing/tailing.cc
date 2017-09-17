# TaiLing.cc
[TaiLing.cc](http://tailing.cc/) is compiled from [single C++](http://tailing.cc/tailing.cc) file, and produces sourcecode itself.

## Usage

```
$ git clone https://github.com/yuantailing/tailing.cc.git
$ cd tailing.cc
$ git submodule update --init --recursive
$ sudo apt install libboost-system-dev
$ python distribute.py
$ g++ dist/tailing.cc -std=c++11 -O2 -lpthread -lboost_system -odist/run
$ dist/run
```

Then you can browse `localhost:18080`.
