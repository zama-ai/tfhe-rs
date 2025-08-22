SHELL:=$(shell /usr/bin/env which bash)
OS:=$(shell uname)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
RS_BUILD_TOOLCHAIN:=$(shell \
	( (echo $(TARGET_ARCH_FEATURE) | grep -q x86) && echo stable) || echo $(RS_CHECK_TOOLCHAIN))
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
MIN_RUST_VERSION:=1.65
AVX512_SUPPORT?=OFF
WASM_RUSTFLAGS:=
BIG_TESTS_INSTANCE?=FALSE
GEN_KEY_CACHE_MULTI_BIT_ONLY?=FALSE
PARSE_INTEGER_BENCH_CSV_FILE?=tfhe_rs_integer_benches.csv
FAST_TESTS?=FALSE
FAST_BENCH?=FALSE
BENCH_OP_FLAVOR?=DEFAULT
BENCH_TYPE?=latency
NODE_VERSION=20
# sed: -n, do not print input stream, -e means a script/expression
# 1,/version/ indicates from the first line, to the line matching version at the start of the line
# p indicates to print, so we keep only the start of the Cargo.toml until we hit the first version
# entry which should be the version of tfhe
TFHE_CURRENT_VERSION:=\
$(shell sed -n -e '1,/^version/p' tfhe/Cargo.toml | \
grep '^version[[:space:]]*=' | cut -d '=' -f 2 | xargs)
# Cargo has a hard time distinguishing between our package from the workspace and a package that
# could be a dependency, so we build an unambiguous spec here
TFHE_SPEC:=tfhe@$(TFHE_CURRENT_VERSION)
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS?=-C target-cpu=native

ifeq ($(AVX512_SUPPORT),ON)
		AVX512_FEATURE=nightly-avx512
else
		AVX512_FEATURE=
endif

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

.PHONY: clippy_js_wasm_api # Run clippy lints enabling the boolean, shortint and the js wasm API
clippy_js_wasm_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_tasks # Run clippy lints on helper tasks crate.
clippy_tasks:
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		-p tasks -- --no-deps -D warnings

.PHONY: clippy_all_targets # Run clippy lints on all targets (benches, examples, etc.)
clippy_all_targets:
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets clippy_c_api \
clippy_js_wasm_api clippy_tasks clippy_core

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --release \
		--example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe

.PHONY: build_core # Build core_crypto without experimental features
build_core: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE) -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --release \
			--features=$(TARGET_ARCH_FEATURE),$(AVX512_FEATURE) -p tfhe; \
	fi

.PHONY: build_core_experimental # Build core_crypto with experimental features
build_core_experimental: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),experimental -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --release \
			--features=$(TARGET_ARCH_FEATURE),experimental,$(AVX512_FEATURE) -p tfhe; \
	fi

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe --all-targets

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),shortint -p tfhe --all-targets

.PHONY: build_integer # Build with integer enabled
build_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),integer -p tfhe --all-targets

.PHONY: build_tfhe_full # Build with boolean, shortint and integer enabled
build_tfhe_full: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer -p tfhe --all-targets

.PHONY: build_c_api # Build the C API for boolean and shortint
build_c_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api -p tfhe --all-targets

.PHONY: build_web_js_api # Build the js API targeting the web browser
build_web_js_api: install_rs_build_toolchain
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_rs_build_toolchain
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api

.PHONY: test_core_crypto # Run the tests of the core_crypto module including experimental ones
test_core_crypto: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),experimental -p tfhe -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release \
			--features=$(TARGET_ARCH_FEATURE),experimental,$(AVX512_FEATURE) -p tfhe -- core_crypto::; \
	fi

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe -- boolean::

.PHONY: test_c_api # Run the tests for the C API
test_c_api: build_c_api
	./scripts/c_api_tests.sh

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
		./scripts/shortint-tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_shortint # Run all the tests for shortint
test_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe -- shortint::

.PHONY: test_integer_ci # Run the tests for integer ci
test_integer_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
		./scripts/integer-tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_integer # Run all the tests for integer
test_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache -p tfhe -- integer::

.PHONY: test_typed_api # Run all the tests for typed_api
test_typed_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p tfhe -- typed_api::

.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release --doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p tfhe \
		-- test_user_docs::

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer --no-deps

.PHONY: format_doc_latex # Format the documentation latex equations to avoid broken rendering.
format_doc_latex:
	cargo xtask format_latex_doc
	@"$(MAKE)" --no-print-directory fmt
	@printf "\n===============================\n\n"
	@printf "Please manually inspect changes made by format_latex_doc, rustfmt can break equations \
	if the line length is exceeded\n"
	@printf "\n===============================\n"

.PHONY: check_compile_tests # Build tests in debug without running them
check_compile_tests: build_c_api
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=$(TARGET_ARCH_FEATURE),experimental,boolean,shortint,integer,internal-keycache \
		-p tfhe
		@if [[ "$(OS)" == "Linux" || "$(OS)" == "Darwin" ]]; then \
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

.PHONY: no_tfhe_typo # Check we did not invert the h and f in tfhe
no_tfhe_typo:
	@./scripts/no_tfhe_typo.sh

#
# Benchmarks
#

.PHONY: bench_integer # Run benchmarks for integer
bench_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,$(AVX512_FEATURE) -p tfhe --

.PHONY: bench_integer_multi_bit # Run benchmarks for integer using multi-bit parameters
bench_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,$(AVX512_FEATURE) -p tfhe --

.PHONY: bench_shortint # Run benchmarks for shortint
bench_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
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

.PHONY: measure_shortint_key_sizes # Measure sizes of bootstrapping and key switching keys for shortint
measure_shortint_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run \
	--example shortint_key_sizes \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache

.PHONY: measure_boolean_key_sizes # Measure sizes of bootstrapping and key switching keys for boolean
measure_boolean_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run \
	--example boolean_key_sizes \
	--features=$(TARGET_ARCH_FEATURE),boolean,internal-keycache

.PHONY: pcc # pcc stands for pre commit checks
pcc: no_tfhe_typo check_fmt doc clippy_all check_compile_tests

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fmt

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
