#!/usr/bin/env bash

exp_time=$(date '+%Y-%m-%d_%H-%M-%S')

RUSTFLAGS="-C target-cpu=native" cargo +$(cat toolchain.txt) test --profile=release --tests \
--features=shortint,nightly-avx512 -p tfhe -- br_dp_ks_ms:: --test-threads=1 --nocapture | \
tee log_"${exp_time}".log