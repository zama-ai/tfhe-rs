#!/usr/bin/env bash

CURR_DATE=$(date +%Y_%m_%d)

echo "date: ${CURR_DATE}"

RUSTFLAGS="-C target-cpu=native" cargo +$(cat toolchain.txt) test --tests --profile release \
--features=shortint,nightly-avx512 -p tfhe -- \
noise_check_shortint_classic_pbs_atomic_pattern_noise \
noise_check_shortint_classic_pbs_atomic_pattern_pfail \
--nocapture --test-threads=1 2>&1 | tee quick_pfail_tests_${CURR_DATE}.log

NOISE_MEASUREMENT_USE_PER_SAMPLE_KEY=1 NOISE_MEASUREMENT_LONG_PFAIL_TESTS=1 \
RUSTFLAGS="-C target-cpu=native" cargo +$(cat toolchain.txt) test --tests --profile release \
--features=shortint,nightly-avx512 -p tfhe -- \
test_noise_check_shortint_classic_pbs_atomic_pattern_noise_v1_2_param_message_2_carry_2_ks32_pbs_tuniform_2m128 \
test_noise_check_shortint_classic_pbs_atomic_pattern_pfail_v1_2_param_message_2_carry_2_ks32_pbs_tuniform_2m128 \
--nocapture --test-threads=1 2>&1 | tee long_pfail_tests_${CURR_DATE}.log