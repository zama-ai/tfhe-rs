#!/usr/bin/env bash

set -e

toolchain=$(cat toolchain.txt)
source venv/bin/activate
cd tfhe-rs-cost-model/src/

python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir ext_prod_no_fft -- \
    --algorithm ext-prod \
    --sample-size 100

python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir multi_bit_gf_2_ext_prod_no_fft -- \
    --algorithm multi-bit-ext-prod \
    --multi-bit-grouping-factor 2 \
    --sample-size 100

python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir multi_bit_gf3_ext_prod_no_fft -- \
    --algorithm multi-bit-ext-prod \
    --multi-bit-grouping-factor 3 \
    --sample-size 100


python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir ext_prod_fft -- \
    --algorithm ext-prod \
    --sample-size 100 \
    --use-fft

python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir multi_bit_gf_2_ext_prod_fft -- \
    --algorithm multi-bit-ext-prod \
    --multi-bit-grouping-factor 2 \
    --sample-size 100 \
    --use-fft

python3 external_product_correction.py \
    --rust-toolchain "${toolchain}" \
    --chunks "$(nproc)" \
    --dir multi_bit_gf3_ext_prod_fft -- \
    --algorithm multi-bit-ext-prod \
    --multi-bit-grouping-factor 3 \
    --sample-size 100 \
    --use-fft
