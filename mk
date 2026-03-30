#!/bin/bash

rm -f ./src/release/onionity
rm -f ./src/release/ecc_scan.o

# Run configure if config.mk doesn't exist
if [ ! -f config.mk ]; then
    echo "No config.mk found, running ./configure..."
    ./configure || exit 1
    echo ""
fi

make -j$(nproc)
