# TaiLing.cc
Website compiled with single C++ file.

## Usage

```
$ sudo apt install libboost-system-dev
$ python distribute.py
$ g++ dist/tailing.cc -pipe -std=c++11 -O2 -lpthread -lboost_system -odist/run
$ dist/run
```

Then you can browse `localhost:18080`.
