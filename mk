#!/bin/bash

rm -f ./src/release/onionity
rm -f ./src/release/ecc_scan.o
#export PATH=/usr/local/cuda/bin:$PATH
make -j$(nproc)
