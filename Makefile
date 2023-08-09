SHELL:=$(shell /usr/bin/env which bash)
OS:=$(shell uname)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
RS_BUILD_TOOLCHAIN:=$(shell \
	( (echo $(TARGET_ARCH_FEATURE) | grep -q x86) && echo stable) || echo $(RS_CHECK_TOOLCHAIN))
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
CARGO_PROFILE?=release
MIN_RUST_VERSION:=$(shell grep rust-version tfhe/Cargo.toml | cut -d '=' -f 2 | xargs)
AVX512_SUPPORT?=OFF
WASM_RUSTFLAGS:=
BIG_TESTS_INSTANCE?=FALSE
GEN_KEY_CACHE_MULTI_BIT_ONLY?=FALSE
PARSE_INTEGER_BENCH_CSV_FILE?=tfhe_rs_integer_benches.csv
FAST_TESTS?=FALSE
FAST_BENCH?=FALSE
BENCH_OP_FLAVOR?=DEFAULT
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS?=-C target-cpu=native

ifeq ($(AVX512_SUPPORT),ON)
		AVX512_FEATURE=nightly-avx512
else
		AVX512_FEATURE=
endif

ifeq ($(GEN_KEY_CACHE_MULTI_BIT_ONLY),TRUE)
		MULTI_BIT_ONLY=--multi-bit-only
else
		MULTI_BIT_ONLY=
endif

# Variables used only for regex_engine example
REGEX_STRING?=''
REGEX_PATTERN?=''

.PHONY: rs_check_toolchain # Echo the rust toolchain used for checks
rs_check_toolchain:
	@echo $(RS_CHECK_TOOLCHAIN)

.PHONY: rs_build_toolchain # Echo the rust toolchain used for builds
rs_build_toolchain:
	@echo $(RS_BUILD_TOOLCHAIN)

.PHONY: install_rs_check_toolchain # Install the toolchain used for checks
install_rs_check_toolchain:
	@rustup toolchain list | grep -q "$(RS_CHECK_TOOLCHAIN)" || \
	rustup toolchain install --profile default "$(RS_CHECK_TOOLCHAIN)" || \
	( echo "Unable to install $(RS_CHECK_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_rs_build_toolchain # Install the toolchain used for builds
install_rs_build_toolchain:
	@( rustup toolchain list | grep -q "$(RS_BUILD_TOOLCHAIN)" && \
	./scripts/check_cargo_min_ver.sh \
	--rust-toolchain "$(CARGO_RS_BUILD_TOOLCHAIN)" \
	--min-rust-version "$(MIN_RUST_VERSION)" ) || \
	rustup toolchain install --profile default "$(RS_BUILD_TOOLCHAIN)" || \
	( echo "Unable to install $(RS_BUILD_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_cargo_nextest # Install cargo nextest used for shortint tests
install_cargo_nextest: install_rs_build_toolchain
	@cargo nextest --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install cargo-nextest --locked || \
	( echo "Unable to install cargo nextest, unknown error." && exit 1 )

.PHONY: install_wasm_pack # Install wasm-pack to build JS packages
install_wasm_pack: install_rs_build_toolchain
	@wasm-pack --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install wasm-pack || \
	( echo "Unable to install cargo wasm-pack, unknown error." && exit 1 )

.PHONY: install_node # Install last version of NodeJS via nvm
install_node:
	curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | $(SHELL)
	source ~/.bashrc
	$(SHELL) -i -c 'nvm install node' || \
	( echo "Unable to install node, unknown error." && exit 1 )

.PHONY: fmt # Format rust code
fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt

.PHONT: check_fmt # Check rust code format
check_fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check

.PHONY: clippy_core # Run clippy lints on core_crypto with and without experimental features
clippy_core: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE) \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),experimental \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortint features
clippy_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),shortint \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_integer # Run clippy lints enabling the integer features
clippy_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),integer \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the boolean, shortint, integer
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_c_api # Run clippy lints enabling the boolean, shortint and the C API
clippy_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_js_wasm_api # Run clippy lints enabling the boolean, shortint, integer and the js wasm API
clippy_js_wasm_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_tasks # Run clippy lints on helper tasks crate.
clippy_tasks:
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		-p tasks -- --no-deps -D warnings

.PHONY: clippy_all_targets # Run clippy lints on all targets (benches, examples, etc.)
clippy_all_targets:
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets clippy_c_api \
clippy_js_wasm_api clippy_tasks clippy_core

.PHONY: clippy_fast # Run main clippy targets
clippy_fast: clippy clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
		--example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe -- \
		$(MULTI_BIT_ONLY)

.PHONY: build_core # Build core_crypto without experimental features
build_core: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE) -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),$(AVX512_FEATURE) -p tfhe; \
	fi

.PHONY: build_core_experimental # Build core_crypto with experimental features
build_core_experimental: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),experimental -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),experimental,$(AVX512_FEATURE) -p tfhe; \
	fi

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe --all-targets

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),shortint -p tfhe --all-targets

.PHONY: build_integer # Build with integer enabled
build_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer -p tfhe --all-targets

.PHONY: build_tfhe_full # Build with boolean, shortint and integer enabled
build_tfhe_full: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer -p tfhe --all-targets

.PHONY: build_c_api # Build the C API for boolean, shortint and integer
build_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api, \
		-p tfhe

.PHONY: build_c_api_experimental_deterministic_fft # Build the C API for boolean, shortint and integer with experimental deterministic FFT
build_c_api_experimental_deterministic_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api,experimental-force_fft_algo_dif4 \
		-p tfhe

.PHONY: build_web_js_api # Build the js API targeting the web browser
build_web_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) -C target-feature=+atomics,+bulk-memory,+mutable-globals" rustup run $(RS_CHECK_TOOLCHAIN) \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,parallel-wasm-api \
		-Z build-std=panic_abort,std

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api

.PHONY: test_core_crypto # Run the tests of the core_crypto module including experimental ones
test_core_crypto: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),experimental -p tfhe -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),experimental,$(AVX512_FEATURE) -p tfhe -- core_crypto::; \
	fi

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe -- boolean::

.PHONY: test_c_api_rs # Run the rust tests for the C API
test_c_api_rs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api \
		-p tfhe \
		c_api

.PHONY: test_c_api_c # Run the C tests for the C API
test_c_api_c: build_c_api
	./scripts/c_api_tests.sh

.PHONY: test_c_api # Run all the tests for the C API
test_c_api: test_c_api_rs test_c_api_c

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)"

.PHONY: test_shortint_multi_bit_ci # Run the tests for shortint ci running only multibit tests
test_shortint_multi_bit_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit

.PHONY: test_shortint # Run all the tests for shortint
test_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe -- shortint::

.PHONY: test_integer_ci # Run the tests for integer ci
test_integer_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)"

.PHONY: test_integer_multi_bit_ci # Run the tests for integer ci running only multibit tests
test_integer_multi_bit_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit

.PHONY: test_integer # Run all the tests for integer
test_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache -p tfhe -- integer::

.PHONY: test_high_level_api # Run all the tests for high_level_api
test_high_level_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p tfhe \
		-- high_level_api::

.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p tfhe \
		-- test_user_docs::

.PHONY: test_regex_engine # Run tests for regex_engine example
test_regex_engine: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--example regex_engine \
		--features=$(TARGET_ARCH_FEATURE),integer

.PHONY: test_sha256_bool # Run tests for sha256_bool example
test_sha256_bool: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--example sha256_bool \
		--features=$(TARGET_ARCH_FEATURE),boolean

.PHONY: test_examples # Run tests for examples
test_examples: test_sha256_bool test_regex_engine

.PHONY: test_trivium # Run tests for trivium
test_trivium: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		trivium --features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer \
		-- --test-threads=1

.PHONY: test_kreyvium # Run tests for kreyvium
test_kreyvium: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		kreyvium --features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer \
		-- --test-threads=1

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer --no-deps

.PHONY: docs # Build rust doc alias for doc
docs: doc

.PHONY: lint_doc # Build rust doc with linting enabled
lint_doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer --no-deps

.PHONY: lint_docs # Build rust doc with linting enabled alias for lint_doc
lint_docs: lint_doc

.PHONY: format_doc_latex # Format the documentation latex equations to avoid broken rendering.
format_doc_latex:
	cargo xtask format_latex_doc
	@"$(MAKE)" --no-print-directory fmt
	@printf "\n===============================\n\n"
	@printf "Please manually inspect changes made by format_latex_doc, rustfmt can break equations \
	if the line length is exceeded\n"
	@printf "\n===============================\n"

.PHONY: check_compile_tests # Build tests in debug without running them
check_compile_tests:
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=$(TARGET_ARCH_FEATURE),experimental,boolean,shortint,integer,internal-keycache \
		-p tfhe

	@if [[ "$(OS)" == "Linux" || "$(OS)" == "Darwin" ]]; then \
		"$(MAKE)" build_c_api; \
		./scripts/c_api_tests.sh --build-only; \
	fi

.PHONY: build_nodejs_test_docker # Build a docker image with tools to run nodejs tests for wasm API
build_nodejs_test_docker:
	DOCKER_BUILDKIT=1 docker build --build-arg RUST_TOOLCHAIN="$(RS_BUILD_TOOLCHAIN)" \
		-f docker/Dockerfile.wasm_tests -t tfhe-wasm-tests .

.PHONY: test_nodejs_wasm_api_in_docker # Run tests for the nodejs on wasm API in a docker container
test_nodejs_wasm_api_in_docker: build_nodejs_test_docker
	if [[ -t 1 ]]; then RUN_FLAGS="-it"; else RUN_FLAGS="-i"; fi && \
	docker run --rm "$${RUN_FLAGS}" \
		-v "$$(pwd)":/tfhe-wasm-tests/tfhe-rs \
		-v tfhe-rs-root-target-cache:/root/tfhe-rs-target \
		-v tfhe-rs-pkg-cache:/tfhe-wasm-tests/tfhe-rs/tfhe/pkg \
		-v tfhe-rs-root-cargo-registry-cache:/root/.cargo/registry \
		-v tfhe-rs-root-cache:/root/.cache \
		tfhe-wasm-tests /bin/bash -i -c 'make test_nodejs_wasm_api'

.PHONY: test_nodejs_wasm_api # Run tests for the nodejs on wasm API
test_nodejs_wasm_api: build_node_js_api
	cd tfhe && node --test js_on_wasm_tests

.PHONY: test_web_js_api_parallel # Run tests for the web wasm api
test_web_js_api_parallel: build_web_js_api_parallel
	$(MAKE) -C tfhe/web_wasm_parallel_tests test

.PHONY: ci_test_web_js_api_parallel # Run tests for the web wasm api
ci_test_web_js_api_parallel: build_web_js_api_parallel
	source ~/.nvm/nvm.sh && \
	nvm use node && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests test-ci

.PHONY: no_tfhe_typo # Check we did not invert the h and f in tfhe
no_tfhe_typo:
	@./scripts/no_tfhe_typo.sh

.PHONY: no_dbg_log # Check we did not leave dbg macro calls in the rust code
no_dbg_log:
	@./scripts/no_dbg_calls.sh

#
# Benchmarks
#

.PHONY: bench_integer # Run benchmarks for integer
bench_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,$(AVX512_FEATURE) -p tfhe --

.PHONY: bench_integer_multi_bit # Run benchmarks for integer using multi-bit parameters
bench_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,$(AVX512_FEATURE) -p tfhe --

.PHONY: bench_shortint # Run benchmarks for shortint
bench_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint-bench \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache,$(AVX512_FEATURE) -p tfhe

.PHONY: bench_boolean # Run benchmarks for boolean
bench_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench boolean-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,internal-keycache,$(AVX512_FEATURE) -p tfhe

.PHONY: bench_pbs # Run benchmarks for PBS
bench_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,internal-keycache,$(AVX512_FEATURE) -p tfhe

.PHONY: bench_web_js_api_parallel # Run benchmarks for the web wasm api
bench_web_js_api_parallel: build_web_js_api_parallel
	$(MAKE) -C tfhe/web_wasm_parallel_tests bench

.PHONY: ci_bench_web_js_api_parallel # Run benchmarks for the web wasm api
ci_bench_web_js_api_parallel: build_web_js_api_parallel
	source ~/.nvm/nvm.sh && \
	nvm use node && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests bench-ci

#
# Utility tools
#

.PHONY: measure_hlapi_compact_pk_ct_sizes # Measure sizes of public keys and ciphertext for high-level API
measure_hlapi_compact_pk_ct_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example hlapi_compact_pk_ct_sizes \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache

.PHONY: measure_shortint_key_sizes # Measure sizes of bootstrapping and key switching keys for shortint
measure_shortint_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example shortint_key_sizes \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache

.PHONY: measure_boolean_key_sizes # Measure sizes of bootstrapping and key switching keys for boolean
measure_boolean_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example boolean_key_sizes \
	--features=$(TARGET_ARCH_FEATURE),boolean,internal-keycache

.PHONY: parse_integer_benches # Run python parser to output a csv containing integer benches data
parse_integer_benches:
	python3 ./ci/parse_integer_benches_to_csv.py \
		--criterion-dir target/criterion \
		--output-file "$(PARSE_INTEGER_BENCH_CSV_FILE)"

.PHONY: parse_wasm_benchmarks # Parse benchmarks performed with WASM web client into a CSV file
parse_wasm_benchmarks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example wasm_benchmarks_parser \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache \
	-- web_wasm_parallel_tests/test/benchmark_results

.PHONY: write_params_to_file # Gather all crypto parameters into a file with a Sage readable format.
write_params_to_file: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example write_params_to_file \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,internal-keycache

#
# Real use case examples
#

.PHONY: regex_engine # Run regex_engine example
regex_engine: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example regex_engine \
	--features=$(TARGET_ARCH_FEATURE),integer \
	-- $(REGEX_STRING) $(REGEX_PATTERN)

.PHONY: dark_market # Run dark market example
dark_market: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example dark_market \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache \
	-- fhe-modified fhe-parallel plain fhe

.PHONY: sha256_bool # Run sha256_bool example
sha256_bool: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example sha256_bool \
	--features=$(TARGET_ARCH_FEATURE),boolean

.PHONY: pcc # pcc stands for pre commit checks
pcc: no_tfhe_typo no_dbg_log check_fmt lint_doc clippy_all check_compile_tests

.PHONY: fpcc # pcc stands for pre commit checks, the f stands for fast
fpcc: no_tfhe_typo no_dbg_log check_fmt lint_doc clippy_fast check_compile_tests

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fmt

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
