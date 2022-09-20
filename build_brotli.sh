#!/bin/bash

cd "$(dirname "$0")" || exit 1

git clone https://github.com/google/brotli
cd brotli || exit 1
rm -r out
mkdir out
cd out
cmake3 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=~/local/brotli ..
cmake3 --build . --config Release --target install
