#!/bin/bash

./bin/python3 external_product_correction.py --chunks 192 --rust-toolchain nightly-2024-08-19 --analysis-only --dir multi-bit-sampling/gf2/ -- --algorithm multi-bit-ext-prod --multi-bit-grouping-factor 2 > log-real-to-pred-2.dat
