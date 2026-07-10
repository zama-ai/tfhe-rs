#!/usr/bin/env bash

for w in 8 16 32 64 128; do
    mv mhmul${w}f*.asm integer_w_${w}
done
