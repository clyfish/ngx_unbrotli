#!/bin/bash

cd "$(dirname "$0")" || exit 1

wget https://github.com/google/brotli/archive/refs/tags/v1.0.9.tar.gz -O brotli-1.0.9.tar.gz
tar xf brotli-1.0.9.tar.gz
cd brotli-1.0.9 || exit 1
rm -r out
mkdir out
cd out
cmake -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local/brotli ..
cmake --build . --config Release --target install
