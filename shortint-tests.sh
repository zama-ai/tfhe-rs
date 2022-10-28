#!/bin/bash

set -e

nproc_bin=nproc

arch_feature=x86_64-unix

# macOS detects CPUs differently
if [[ $(uname) == "Darwin" ]]; then
    nproc_bin="sysctl -n hw.logicalcpu"
fi

if uname -a | grep "arm64"; then
    arch_feature=aarch64-unix
fi

filter_expression=''\
'('\
'   test(/^shortint::server_key::.*_param_message_1_carry_1$/)'\
'or test(/^shortint::server_key::.*_param_message_1_carry_2$/)'\
'or test(/^shortint::server_key::.*_param_message_1_carry_3$/)'\
'or test(/^shortint::server_key::.*_param_message_1_carry_4$/)'\
'or test(/^shortint::server_key::.*_param_message_1_carry_5$/)'\
'or test(/^shortint::server_key::.*_param_message_1_carry_6$/)'\
'or test(/^shortint::server_key::.*_param_message_2_carry_2$/)'\
'or test(/^shortint::server_key::.*_param_message_2_carry_2$/)'\
'or test(/^shortint::server_key::.*_param_message_3_carry_3$/)'\
'or test(/^shortint::server_key::.*_param_message_4_carry_4$/)'\
')'\
'and not test(~smart_add_and_mul)' # This test is too slow

export RUSTFLAGS="-C target-cpu=native"

# Run tests only no examples or benches
cargo nextest run \
    --tests \
    --release \
    --package tfhe \
    --profile ci \
    --features="${arch_feature}",shortints,internal-keycache \
    --test-threads "$(${nproc_bin})" \
    -E "${filter_expression}"

cargo test \
    --release \
    --package tfhe \
    --features="${arch_feature}",shortints,internal-keycache \
    --doc \
    shortint::

echo "Test ran in $SECONDS seconds"
