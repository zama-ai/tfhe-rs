
SHELL := `/usr/bin/env which bash`

set shell := ["bash", "-c"]

default:
 @just --list

OS := `uname`
RS_CHECK_TOOLCHAIN := `cat toolchain.txt | tr -d '\n'`
CARGO_RS_CHECK_TOOLCHAIN := "+" + RS_CHECK_TOOLCHAIN
TARGET_ARCH_FEATURE:=`./scripts/get_arch_feature.sh`
RS_BUILD_TOOLCHAIN := "stable"
CARGO_PROFILE := "release"
MIN_RUST_VERSION := `grep rust-version tfhe/Cargo.toml | cut -d '=' -f 2 | xargs`
AVX512_SUPPORT := "OFF"
WASM_RUSTFLAGS := ""
BIG_TESTS_INSTANCE := "FALSE"
GEN_KEY_CACHE_MULTI_BIT_ONLY := "FALSE"
PARSE_INTEGER_BENCH_CSV_FILE := "tfhe_rs_integer_benches.csv"
export FAST_TESTS := "FALSE"
export __TFHE_RS_FAST_BENCH := "FALSE"
export __TFHE_RS_BENCH_OP_FLAVOR := "DEFAULT"
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS := "-C target-cpu=native"


CARGO := "cargo +" + RS_CHECK_TOOLCHAIN

CARGO_BUILD := CARGO + " build --profile " + CARGO_PROFILE + " "
CARGO_TEST := CARGO + " test --profile " + CARGO_PROFILE + " "
CARGO_RUN := CARGO + " run --profile " + CARGO_PROFILE + " "
CARGO_CHECK := CARGO + " check "
CARGO_CLIPPY := CARGO + " clippy "
CARGO_DOC := CARGO + " doc "
CARGO_FMT := CARGO + " fmt "
CARGO_BENCH := CARGO + " bench "



AVX512_FEATURE := if AVX512_SUPPORT == "ON" {
    "nightly-avx512"
} else {
    ""
}

FEATURES := "--features=" + TARGET_ARCH_FEATURE + "," + AVX512_FEATURE + ","



MULTI_BIT_ONLY := if GEN_KEY_CACHE_MULTI_BIT_ONLY == "TRUE" {
	"--multi-bit-only"
} else {
    ""
}

# Variables used only for regex_engine example
REGEX_STRING := ''
REGEX_PATTERN := ''

rs_check_toolchain:
	@echo {{RS_CHECK_TOOLCHAIN}}


rs_build_toolchain:
	@echo {{RS_BUILD_TOOLCHAIN}}


install_rs_check_toolchain:
	@rustup toolchain list | grep -q "{{RS_CHECK_TOOLCHAIN}}" || \
	rustup toolchain install --profile default "{{RS_CHECK_TOOLCHAIN}}" || \
	( echo "Unable to install {{RS_CHECK_TOOLCHAIN}} toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )


install_rs_build_toolchain:
	@( rustup toolchain list | grep -q "{{RS_BUILD_TOOLCHAIN}}" && \
	./scripts/check_cargo_min_ver.sh \
	--rust-toolchain "{{RS_BUILD_TOOLCHAIN}}" \
	--min-rust-version "{{MIN_RUST_VERSION}}" ) || \
	rustup toolchain install --profile default "{{RS_BUILD_TOOLCHAIN}}" || \
	( echo "Unable to install {{RS_BUILD_TOOLCHAIN}} toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )


install_cargo_nextest: install_rs_build_toolchain
	@cargo nextest --version > /dev/null 2>&1 || \
	{{CARGO}} install cargo-nextest --locked || \
	( echo "Unable to install cargo nextest, unknown error." && exit 1 )


install_wasm_pack: install_rs_build_toolchain
	@wasm-pack --version > /dev/null 2>&1 || \
	{{CARGO}} install wasm-pack || \
	( echo "Unable to install cargo wasm-pack, unknown error." && exit 1 )


install_node:
	curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | {{SHELL}}
	source ~/.bashrc
	{{SHELL}} -i -c 'nvm install node' || \
	( echo "Unable to install node, unknown error." && exit 1 )


install_dieharder:
	@dieharder -h > /dev/null 2>&1 || \
	if [[ "{{OS}}" == "Linux" ]]; then \
		sudo apt update && sudo apt install -y dieharder; \
	elif [[ "{{OS}}" == "Darwin" ]]; then\
		brew install dieharder; \
	fi || ( echo "Unable to install dieharder, unknown error." && exit 1 )


fmt: install_rs_check_toolchain
	{{CARGO_FMT}}

check_fmt: 
	{{CARGO_FMT}} --check


clippy_core: install_rs_check_toolchain
	{{CARGO_CLIPPY}} {{FEATURES}} -p tfhe -- --no-deps -D warnings
	{{CARGO_CLIPPY}} {{FEATURES}},experimental  -p tfhe -- --no-deps -D warnings


clippy_boolean: install_rs_check_toolchain
	{{CARGO_CLIPPY}} {{FEATURES}},boolean -p tfhe -- --no-deps -D warnings

clippy_shortint: install_rs_check_toolchain
	{{CARGO_CLIPPY}} {{FEATURES}},shortint \
		-p tfhe -- --no-deps -D warnings


clippy_integer: install_rs_check_toolchain
	{{CARGO_CLIPPY}} {{FEATURES}},integer \
		-p tfhe -- --no-deps -D warnings

clippy: install_rs_check_toolchain
	{{CARGO_CLIPPY}} --all-targets \
		{{FEATURES}},boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings


clippy_c_api: install_rs_check_toolchain
	{{CARGO_CLIPPY}} {{FEATURES}},boolean-c-api,shortint-c-api \
		-p tfhe -- --no-deps -D warnings


clippy_js_wasm_api: install_rs_check_toolchain
	{{CARGO_CLIPPY}} --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api \
		-p tfhe -- --no-deps -D warnings


clippy_tasks:
	{{CARGO_CLIPPY}} \
		-p tasks -- --no-deps -D warnings


clippy_trivium: install_rs_check_toolchain
	{{CARGO_CLIPPY}} -p tfhe-trivium \
		{{FEATURES}},boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings


clippy_all_targets:
	{{CARGO_CLIPPY}} --all-targets \
		{{FEATURES}},boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings


clippy_concrete_csprng:
	{{CARGO_CLIPPY}} --all-targets \
		{{FEATURES}} \
		-p concrete-csprng -- --no-deps -D warnings


clippy_all: clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core clippy_concrete_csprng clippy_trivium


clippy_fast: clippy clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core clippy_concrete_csprng


gen_key_cache: install_rs_build_toolchain
	{{CARGO_RUN}} \
		--example generates_test_keys \
		{{FEATURES}},shortint,internal-keycache -p tfhe -- \
		{{MULTI_BIT_ONLY}}


build_core: install_rs_build_toolchain install_rs_check_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}} -p tfhe
	@if [[ "{{AVX512_SUPPORT}}" == "ON" ]]; then \
		{{CARGO_BUILD}} \
			{{FEATURES}},{{AVX512_FEATURE}} -p tfhe; \
	fi


build_core_experimental: install_rs_build_toolchain install_rs_check_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},experimental -p tfhe
	@if [[ "{{AVX512_SUPPORT}}" == "ON" ]]; then \
		{{CARGO_BUILD}} \
			{{FEATURES}},experimental,{{AVX512_FEATURE}} -p tfhe; \
	fi


build_boolean: install_rs_build_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},boolean -p tfhe --all-targets


build_shortint: install_rs_build_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},shortint -p tfhe --all-targets


build_integer: install_rs_build_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},integer -p tfhe --all-targets


build_tfhe_full: install_rs_build_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},boolean,shortint,integer -p tfhe --all-targets


build_c_api: install_rs_check_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},boolean-c-api,shortint-c-api,high-level-c-api, \
		-p tfhe


build_c_api_experimental_deterministic_fft: install_rs_check_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}},boolean-c-api,shortint-c-api,high-level-c-api,experimental-force_fft_algo_dif4 \
		-p tfhe


build_web_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="{{WASM_RUSTFLAGS}}" rustup run "{{RS_BUILD_TOOLCHAIN}}" \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api


build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack
	cd tfhe && \
	rustup component add rust-src --toolchain {{RS_CHECK_TOOLCHAIN}} && \
	RUSTFLAGS="{{WASM_RUSTFLAGS}} -C target-feature=+atomics,+bulk-memory,+mutable-globals" rustup run {{RS_CHECK_TOOLCHAIN}} \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,parallel-wasm-api \
		-Z build-std=panic_abort,std


build_node_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="{{WASM_RUSTFLAGS}}" rustup run "{{RS_BUILD_TOOLCHAIN}}" \
		wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api


build_concrete_csprng: install_rs_build_toolchain
	{{CARGO_BUILD}} \
		{{FEATURES}} -p concrete-csprng --all-targets


test_core_crypto: install_rs_build_toolchain install_rs_check_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},experimental -p tfhe -- core_crypto::
	@if [[ "{{AVX512_SUPPORT}}" == "ON" ]]; then \
		{{CARGO_TEST}} \
			{{FEATURES}},experimental,{{AVX512_FEATURE}} -p tfhe -- core_crypto::; \
	fi


test_boolean: install_rs_build_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},boolean -p tfhe -- boolean::


test_c_api_rs: install_rs_check_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},boolean-c-api,shortint-c-api,high-level-c-api \
		-p tfhe \
		c_api


test_c_api_c: build_c_api
	./scripts/c_api_tests.sh


test_c_api: test_c_api_rs test_c_api_c


test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="{{BIG_TESTS_INSTANCE}}" \
		./scripts/shortint-tests.sh --rust-toolchain {{RS_BUILD_TOOLCHAIN}} \
		--cargo-profile "{{CARGO_PROFILE}}"


test_shortint_multi_bit_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="{{BIG_TESTS_INSTANCE}}" \
		./scripts/shortint-tests.sh --rust-toolchain {{RS_BUILD_TOOLCHAIN}} \
		--cargo-profile "{{CARGO_PROFILE}}" --multi-bit


test_shortint: install_rs_build_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},shortint,internal-keycache -p tfhe -- shortint::


test_integer_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="{{BIG_TESTS_INSTANCE}}" \
		./scripts/integer-tests.sh --rust-toolchain {{RS_BUILD_TOOLCHAIN}} \
		--cargo-profile "{{CARGO_PROFILE}}"


test_integer_multi_bit_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="{{BIG_TESTS_INSTANCE}}" \
		./scripts/integer-tests.sh --rust-toolchain {{RS_BUILD_TOOLCHAIN}} \
		--cargo-profile "{{CARGO_PROFILE}}" --multi-bit


test_integer: install_rs_build_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},integer,internal-keycache -p tfhe -- integer::


test_high_level_api: install_rs_build_toolchain
	{{CARGO_TEST}} \
		{{FEATURES}},boolean,shortint,integer,internal-keycache -p tfhe \
		-- high_level_api::


test_user_doc: install_rs_build_toolchain
	{{CARGO_TEST}} --doc \
		{{FEATURES}},boolean,shortint,integer,internal-keycache -p tfhe \
		-- test_user_docs::


test_regex_engine: install_rs_build_toolchain
	{{CARGO_TEST}} \
		--example regex_engine \
		{{FEATURES}},integer


test_sha256_bool: install_rs_build_toolchain
	{{CARGO_TEST}} \
		--example sha256_bool \
		{{FEATURES}},boolean


test_examples: test_sha256_bool test_regex_engine


test_trivium: install_rs_build_toolchain
	{{CARGO_TEST}} \
		trivium {{FEATURES}},boolean,shortint,integer \
		-- --test-threads=1


test_kreyvium: install_rs_build_toolchain
	{{CARGO_TEST}} \
		kreyvium {{FEATURES}},boolean,shortint,integer \
		-- --test-threads=1


test_concrete_csprng:
	{{CARGO_TEST}} \
		{{FEATURES}} -p concrete-csprng


doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	{{CARGO_DOC}} \
		{{FEATURES}},boolean,shortint,integer --no-deps


docs: doc


lint_doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	{{CARGO_DOC}} \
		{{FEATURES}},boolean,shortint,integer --no-deps


lint_docs: lint_doc


format_doc_latex:
	cargo xtask format_latex_doc
	@just --no-print-directory fmt
	@printf "\n===============================\n\n"
	@printf "Please manually inspect changes made by format_latex_doc, rustfmt can break equations \
	if the line length is exceeded\n"
	@printf "\n===============================\n"


check_compile_tests:
	{{CARGO}} test --no-run \
		{{FEATURES}},experimental,boolean,shortint,integer,internal-keycache \
		-p tfhe

	@if [[ "{{OS}}" == "Linux" || "{{OS}}" == "Darwin" ]]; then \
		just build_c_api; \
		./scripts/c_api_tests.sh --build-only; \
	fi


build_nodejs_test_docker:
	DOCKER_BUILDKIT=1 docker build --build-arg RUST_TOOLCHAIN="{{RS_BUILD_TOOLCHAIN}}" \
		-f docker/Dockerfile.wasm_tests -t tfhe-wasm-tests .


test_nodejs_wasm_api_in_docker: build_nodejs_test_docker
	if [[ -t 1 ]]; then RUN_FLAGS="-it"; else RUN_FLAGS="-i"; fi && \
	docker run --rm "$${RUN_FLAGS}" \
		-v "$$(pwd)":/tfhe-wasm-tests/tfhe-rs \
		-v tfhe-rs-root-target-cache:/root/tfhe-rs-target \
		-v tfhe-rs-pkg-cache:/tfhe-wasm-tests/tfhe-rs/tfhe/pkg \
		-v tfhe-rs-root-cargo-registry-cache:/root/.cargo/registry \
		-v tfhe-rs-root-cache:/root/.cache \
		tfhe-wasm-tests /bin/bash -i -c 'make test_nodejs_wasm_api'


test_nodejs_wasm_api: build_node_js_api
	cd tfhe && node --test js_on_wasm_tests


test_web_js_api_parallel: build_web_js_api_parallel
	just -C tfhe/web_wasm_parallel_tests test


ci_test_web_js_api_parallel: build_web_js_api_parallel
	source ~/.nvm/nvm.sh && \
	nvm use node && \
	just -C tfhe/web_wasm_parallel_tests test-ci


no_tfhe_typo:
	@./scripts/no_tfhe_typo.sh


no_dbg_log:
	@./scripts/no_dbg_calls.sh


dieharder_csprng: install_dieharder build_concrete_csprng
	./scripts/dieharder_test.sh

#
# Benchmarks
#


bench_integer: install_rs_check_toolchain
	{{CARGO_BENCH}} \
	--bench integer-bench \
	{{FEATURES}},integer,internal-keycache,{{AVX512_FEATURE}} -p tfhe --


bench_integer_multi_bit: install_rs_check_toolchain
	__TFHE_RS_BENCH_TYPE=MULTI_BIT \
	{{CARGO_BENCH}} \
	--bench integer-bench \
	{{FEATURES}},integer,internal-keycache,{{AVX512_FEATURE}} -p tfhe --


bench_shortint: install_rs_check_toolchain
	{{CARGO_BENCH}} \
	--bench shortint-bench \
	{{FEATURES}},shortint,internal-keycache,{{AVX512_FEATURE}} -p tfhe


bench_shortint_multi_bit: install_rs_check_toolchain
	__TFHE_RS_BENCH_TYPE=MULTI_BIT \
	{{CARGO_BENCH}} \
	--bench shortint-bench \
	{{FEATURES}},shortint,internal-keycache,{{AVX512_FEATURE}} -p tfhe --



bench_boolean: install_rs_check_toolchain
	{{CARGO_BENCH}} \
	--bench boolean-bench \
	{{FEATURES}},boolean,internal-keycache,{{AVX512_FEATURE}} -p tfhe


bench_pbs: install_rs_check_toolchain
	{{CARGO_BENCH}} \
	--bench pbs-bench \
	{{FEATURES}},boolean,shortint,internal-keycache,{{AVX512_FEATURE}} -p tfhe


bench_web_js_api_parallel: build_web_js_api_parallel
	just -C tfhe/web_wasm_parallel_tests bench


ci_bench_web_js_api_parallel: build_web_js_api_parallel
	source ~/.nvm/nvm.sh && \
	nvm use node && \
	just -C tfhe/web_wasm_parallel_tests bench-ci

#
# Utility tools
#


measure_hlapi_compact_pk_ct_sizes: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example hlapi_compact_pk_ct_sizes \
	{{FEATURES}},integer,internal-keycache


measure_shortint_key_sizes: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example shortint_key_sizes \
	{{FEATURES}},shortint,internal-keycache


measure_boolean_key_sizes: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example boolean_key_sizes \
	{{FEATURES}},boolean,internal-keycache


parse_integer_benches:
	python3 ./ci/parse_integer_benches_to_csv.py \
		--criterion-dir target/criterion \
		--output-file "{{PARSE_INTEGER_BENCH_CSV_FILE}}"


parse_wasm_benchmarks: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example wasm_benchmarks_parser \
	{{FEATURES}},shortint,internal-keycache \
	-- web_wasm_parallel_tests/test/benchmark_results


write_params_to_file: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example write_params_to_file \
	{{FEATURES}},boolean,shortint,internal-keycache

#
# Real use case examples
#


regex_engine: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example regex_engine \
	{{FEATURES}},integer \
	-- {{REGEX_STRING}} {{REGEX_PATTERN}}


dark_market: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example dark_market \
	{{FEATURES}},integer,internal-keycache \
	-- fhe-modified fhe-parallel plain fhe


sha256_bool: install_rs_check_toolchain
	{{CARGO_RUN}} \
	--example sha256_bool \
	{{FEATURES}},boolean


pcc: no_tfhe_typo no_dbg_log check_fmt lint_doc clippy_all check_compile_tests


fpcc: no_tfhe_typo no_dbg_log check_fmt lint_doc clippy_fast check_compile_tests

conformance: fmt
