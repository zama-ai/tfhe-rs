SHELL:=$(shell /usr/bin/env which bash)
OS:=$(shell uname)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
CPU_COUNT=$(shell ./scripts/cpu_count.sh)
RS_BUILD_TOOLCHAIN:=stable
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
CARGO_PROFILE?=release
MIN_RUST_VERSION:=$(shell grep '^rust-version[[:space:]]*=' tfhe/Cargo.toml | cut -d '=' -f 2 | xargs)
AVX512_SUPPORT?=OFF
WASM_RUSTFLAGS:=
BIG_TESTS_INSTANCE?=FALSE
GEN_KEY_CACHE_MULTI_BIT_ONLY?=FALSE
GEN_KEY_CACHE_COVERAGE_ONLY?=FALSE
PARSE_INTEGER_BENCH_CSV_FILE?=tfhe_rs_integer_benches.csv
FAST_TESTS?=FALSE
FAST_BENCH?=FALSE
BENCH_OP_FLAVOR?=DEFAULT
NODE_VERSION=20
FORWARD_COMPAT?=OFF
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

ifeq ($(GEN_KEY_CACHE_MULTI_BIT_ONLY),TRUE)
		MULTI_BIT_ONLY=--multi-bit-only
else
		MULTI_BIT_ONLY=
endif

ifeq ($(GEN_KEY_CACHE_COVERAGE_ONLY),TRUE)
		COVERAGE_ONLY=--coverage-only
else
		COVERAGE_ONLY=
endif

ifeq ($(FORWARD_COMPAT),ON)
		FORWARD_COMPAT_FEATURE=forward_compatibility
else
		FORWARD_COMPAT_FEATURE=
endif

# Variables used only for regex_engine example
REGEX_STRING?=''
REGEX_PATTERN?=''

# tfhe-cuda-backend
TFHECUDA_SRC=backends/tfhe-cuda-backend/cuda
TFHECUDA_BUILD=$(TFHECUDA_SRC)/build

# Exclude these files from coverage reports
define COVERAGE_EXCLUDED_FILES
--exclude-files apps/trivium/src/trivium/* \
--exclude-files apps/trivium/src/kreyvium/* \
--exclude-files apps/trivium/src/static_deque/* \
--exclude-files apps/trivium/src/trans_ciphering/* \
--exclude-files tasks/src/* \
--exclude-files tfhe/benches/boolean/* \
--exclude-files tfhe/benches/core_crypto/* \
--exclude-files tfhe/benches/shortint/* \
--exclude-files tfhe/benches/integer/* \
--exclude-files tfhe/benches/* \
--exclude-files tfhe/examples/regex_engine/* \
--exclude-files tfhe/examples/utilities/*
endef

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
	curl -o nvm_install.sh https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh
	@echo "2ed5e94ba12434370f0358800deb69f514e8bce90f13beb0e1b241d42c6abafd nvm_install.sh" > nvm_checksum
	@sha256sum -c nvm_checksum
	@rm nvm_checksum
	$(SHELL) nvm_install.sh
	@rm nvm_install.sh
	source ~/.bashrc
	$(SHELL) -i -c 'nvm install $(NODE_VERSION)' || \
	( echo "Unable to install node, unknown error." && exit 1 )

.PHONY: install_dieharder # Install dieharder for apt distributions or macOS
install_dieharder:
	@dieharder -h > /dev/null 2>&1 || \
	if [[ "$(OS)" == "Linux" ]]; then \
		sudo apt update && sudo apt install -y dieharder; \
	elif [[ "$(OS)" == "Darwin" ]]; then\
		brew install dieharder; \
	fi || ( echo "Unable to install dieharder, unknown error." && exit 1 )

.PHONY: install_tarpaulin # Install tarpaulin to perform code coverage
install_tarpaulin: install_rs_build_toolchain
	@cargo tarpaulin --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install cargo-tarpaulin --locked || \
	( echo "Unable to install cargo tarpaulin, unknown error." && exit 1 )

.PHONY: check_linelint_installed # Check if linelint newline linter is installed
check_linelint_installed:
	@printf "\n" | linelint - > /dev/null 2>&1 || \
	( echo "Unable to locate linelint. Try installing it: https://github.com/fernandrone/linelint/releases" && exit 1 )

.PHONY: check_actionlint_installed # Check if actionlint workflow linter is installed
check_actionlint_installed:
	@actionlint --version > /dev/null 2>&1 || \
	( echo "Unable to locate actionlint. Try installing it: https://github.com/rhysd/actionlint/releases" && exit 1 )

.PHONY: check_nvm_installed # Check if Node Version Manager is installed
check_nvm_installed:
	@source ~/.nvm/nvm.sh && nvm --version > /dev/null 2>&1 || \
	( echo "Unable to locate Node. Run 'make install_node'" && exit 1 )

.PHONY: install_mlc # Install mlc (Markup Link Checker)
install_mlc: install_rs_build_toolchain
	@mlc --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install mlc --locked || \
	( echo "Unable to install mlc, unknown error." && exit 1 )

.PHONY: fmt # Format rust code
fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt

.PHONY: fmt_js # Format javascript code
fmt_js: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests fmt

.PHONY: fmt_gpu # Format rust and cuda code
fmt_gpu: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt
	cd "$(TFHECUDA_SRC)" && ./format_tfhe_cuda_backend.sh

.PHONY: fmt_c_tests # Format c tests
fmt_c_tests:
	find tfhe/c_api_tests/ -regex '.*\.\(cpp\|hpp\|cu\|c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: check_fmt # Check rust code format
check_fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check

.PHONY: check_fmt_c_tests  # Check C tests format
check_fmt_c_tests:
	find tfhe/c_api_tests/ -regex '.*\.\(cpp\|hpp\|cu\|c\|h\)' -exec clang-format --dry-run --Werror -style=file {} \;

.PHONY: check_fmt_gpu # Check rust and cuda code format
check_fmt_gpu: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check
	cd "$(TFHECUDA_SRC)" && ./format_tfhe_cuda_backend.sh -c

.PHONY: check_fmt_js # Check javascript code format
check_fmt_js: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests check_fmt

.PHONY: clippy_gpu # Run clippy lints on tfhe with "gpu" enabled
clippy_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache,gpu \
		--all-targets \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: fix_newline # Fix newline at end of file issues to be UNIX compliant
fix_newline: check_linelint_installed
	linelint -a .

.PHONY: check_newline # Check for newline at end of file to be UNIX compliant
check_newline: check_linelint_installed
	linelint .

.PHONY: lint_workflow # Run static linter on GitHub workflows
lint_workflow: check_actionlint_installed
	actionlint

.PHONY: clippy_core # Run clippy lints on core_crypto with and without experimental features
clippy_core: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE) \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),nightly-avx512 \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),experimental,nightly-avx512 \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortint features
clippy_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),shortint \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_integer # Run clippy lints enabling the integer features
clippy_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),integer \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the boolean, shortint, integer
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_c_api # Run clippy lints enabling the boolean, shortint and the C API
clippy_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_js_wasm_api # Run clippy lints enabling the boolean, shortint, integer and the js wasm API
clippy_js_wasm_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_tasks # Run clippy lints on helper tasks crate.
clippy_tasks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		-p tasks -- --no-deps -D warnings

.PHONY: clippy_trivium # Run clippy lints on Trivium app
clippy_trivium: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-trivium -- --no-deps -D warnings

.PHONY: clippy_all_targets # Run clippy lints on all targets (benches, examples, etc.)
clippy_all_targets: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache,zk-pok-experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_concrete_csprng # Run clippy lints on concrete-csprng
clippy_concrete_csprng: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=$(TARGET_ARCH_FEATURE) \
		-p concrete-csprng -- --no-deps -D warnings

.PHONY: clippy_zk_pok # Run clippy lints on tfhe-zk-pok
clippy_zk_pok: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-zk-pok -- --no-deps -D warnings

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets clippy_c_api \
clippy_js_wasm_api clippy_tasks clippy_core clippy_concrete_csprng clippy_zk_pok clippy_trivium

.PHONY: clippy_fast # Run main clippy targets
clippy_fast: clippy clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core \
clippy_concrete_csprng

.PHONY: clippy_cuda_backend # Run clippy lints on the tfhe-cuda-backend
clippy_cuda_backend: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-cuda-backend -- --no-deps -D warnings

.PHONY: build_core # Build core_crypto without experimental features
build_core: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE) -p $(TFHE_SPEC)
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),$(AVX512_FEATURE) -p $(TFHE_SPEC); \
	fi

.PHONY: build_core_experimental # Build core_crypto with experimental features
build_core_experimental: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),experimental -p $(TFHE_SPEC)
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),experimental,$(AVX512_FEATURE) -p $(TFHE_SPEC); \
	fi

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean -p $(TFHE_SPEC) --all-targets

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),shortint -p $(TFHE_SPEC) --all-targets

.PHONY: build_integer # Build with integer enabled
build_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer -p $(TFHE_SPEC) --all-targets

.PHONY: build_tfhe_full # Build with boolean, shortint and integer enabled
build_tfhe_full: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer -p $(TFHE_SPEC) --all-targets

.PHONY: build_tfhe_coverage # Build with test coverage enabled
build_tfhe_coverage: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p $(TFHE_SPEC) --tests

.PHONY: symlink_c_libs_without_fingerprint # Link the .a and .so files without the changing hash part in target
symlink_c_libs_without_fingerprint:
	@./scripts/symlink_c_libs_without_fingerprint.sh \
		--cargo-profile "$(CARGO_PROFILE)" \
		--lib-name tfhe-c-api-dynamic-buffer

.PHONY: build_c_api # Build the C API for boolean, shortint and integer
build_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api,zk-pok-experimental,$(FORWARD_COMPAT_FEATURE) \
		-p $(TFHE_SPEC)
	@"$(MAKE)" symlink_c_libs_without_fingerprint

.PHONY: build_c_api_gpu # Build the C API for boolean, shortint and integer
build_c_api_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api,zk-pok-experimental,gpu \
		-p $(TFHE_SPEC)
	@"$(MAKE)" symlink_c_libs_without_fingerprint

.PHONY: build_c_api_experimental_deterministic_fft # Build the C API for boolean, shortint and integer with experimental deterministic FFT
build_c_api_experimental_deterministic_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api,zk-pok-experimental,experimental-force_fft_algo_dif4,$(FORWARD_COMPAT_FEATURE) \
		-p $(TFHE_SPEC)
	@"$(MAKE)" symlink_c_libs_without_fingerprint

.PHONY: build_web_js_api # Build the js API targeting the web browser
build_web_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok-experimental

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) -C target-feature=+atomics,+bulk-memory,+mutable-globals" rustup run $(RS_CHECK_TOOLCHAIN) \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,parallel-wasm-api,zk-pok-experimental \
		-Z build-std=panic_abort,std

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok-experimental

.PHONY: build_concrete_csprng # Build concrete_csprng
build_concrete_csprng: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE) -p concrete-csprng --all-targets

.PHONY: test_core_crypto # Run the tests of the core_crypto module including experimental ones
test_core_crypto: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),experimental,zk-pok-experimental -p $(TFHE_SPEC) -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
			--features=$(TARGET_ARCH_FEATURE),experimental,zk-pok-experimental,$(AVX512_FEATURE) -p $(TFHE_SPEC) -- core_crypto::; \
	fi

.PHONY: test_core_crypto_cov # Run the tests of the core_crypto module with code coverage
test_core_crypto_cov: install_rs_build_toolchain install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/core_crypto --line --engine llvm --timeout 500 \
		--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
		--features=$(TARGET_ARCH_FEATURE),experimental,internal-keycache \
		-p $(TFHE_SPEC) -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
			--out xml --output-dir coverage/core_crypto_avx512 --line --engine llvm --timeout 500 \
			--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
			--features=$(TARGET_ARCH_FEATURE),experimental,internal-keycache,$(AVX512_FEATURE) \
			-p $(TFHE_SPEC) -- -Z unstable-options --report-time core_crypto::; \
	fi

.PHONY: test_cuda_backend # Run the internal tests of the CUDA backend
test_cuda_backend:
	mkdir -p "$(TFHECUDA_BUILD)" && \
		cd "$(TFHECUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Release -DTFHE_CUDA_BACKEND_BUILD_TESTS=ON && \
		make -j "$(CPU_COUNT)" && \
		make test

.PHONY: test_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_gpu: test_core_crypto_gpu test_integer_gpu test_cuda_backend

.PHONY: test_core_crypto_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_core_crypto_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),gpu -p $(TFHE_SPEC) -- core_crypto::gpu::
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),gpu -p $(TFHE_SPEC) -- core_crypto::gpu::

.PHONY: test_integer_gpu # Run the tests of the integer module including experimental on the gpu backend
test_integer_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer,gpu -p $(TFHE_SPEC) -- integer::gpu::server_key::
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer,gpu -p $(TFHE_SPEC) -- integer::gpu::server_key::

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean -p $(TFHE_SPEC) -- boolean::

.PHONY: test_boolean_cov # Run the tests of the boolean module with code coverage
test_boolean_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/boolean --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=$(TARGET_ARCH_FEATURE),boolean,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time boolean::

.PHONY: test_c_api_rs # Run the rust tests for the C API
test_c_api_rs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api,high-level-c-api \
		-p $(TFHE_SPEC) \
		c_api

.PHONY: test_c_api_c # Run the C tests for the C API
test_c_api_c: build_c_api
	./scripts/c_api_tests.sh --cargo-profile "$(CARGO_PROFILE)"

.PHONY: test_c_api # Run all the tests for the C API
test_c_api: test_c_api_rs test_c_api_c

.PHONY: test_c_api_gpu # Run the C tests for the C API
test_c_api_gpu: build_c_api_gpu
	./scripts/c_api_tests.sh --gpu --cargo-profile "$(CARGO_PROFILE)"

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_shortint_multi_bit_ci # Run the tests for shortint ci running only multibit tests
test_shortint_multi_bit_ci: install_rs_build_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_shortint # Run all the tests for shortint
test_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p $(TFHE_SPEC) -- shortint::

.PHONY: test_shortint_cov # Run the tests of the shortint module with code coverage
test_shortint_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/shortint --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time shortint::

.PHONY: test_integer_ci # Run the tests for integer ci
test_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_ci # Run the tests for unsigned integer ci
test_unsigned_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_ci # Run the tests for signed integer ci
test_signed_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_integer_multi_bit_ci # Run the tests for integer ci running only multibit tests
test_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_multi_bit_ci # Run the tests for nsigned integer ci running only multibit tests
test_unsigned_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_multi_bit_ci # Run the tests for nsigned integer ci running only multibit tests
test_signed_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_safe_deserialization # Run the tests for safe deserialization
test_safe_deserialization: install_rs_build_toolchain install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache -p $(TFHE_SPEC) -- safe_deserialization::

.PHONY: test_integer # Run all the tests for integer
test_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache -p $(TFHE_SPEC) -- integer::

.PHONY: test_integer_cov # Run the tests of the integer module with code coverage
test_integer_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/integer --line --engine llvm --timeout 500 \
		--implicit-test-threads \
		--exclude-files $(COVERAGE_EXCLUDED_FILES) \
		--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time integer::

.PHONY: test_high_level_api # Run all the tests for high_level_api
test_high_level_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache,zk-pok-experimental -p $(TFHE_SPEC) \
		-- high_level_api::

test_high_level_api_gpu: install_rs_build_toolchain install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) nextest run --cargo-profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,gpu -p $(TFHE_SPEC) \
		-E "test(/high_level_api::.*gpu.*/)"

.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache,pbs-stats,zk-pok-experimental \
		-p $(TFHE_SPEC) \
		-- test_user_docs::

.PHONY: test_user_doc_gpu # Run tests for GPU from the .md documentation
test_user_doc_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,internal-keycache,gpu,zk-pok-experimental -p $(TFHE_SPEC) \
		-- test_user_docs::

.PHONY: test_fhe_strings # Run tests for fhe_strings example
test_fhe_strings: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--example fhe_strings \
		--features=$(TARGET_ARCH_FEATURE),integer

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
		-p tfhe-trivium -- --test-threads=1 trivium::

.PHONY: test_kreyvium # Run tests for kreyvium
test_kreyvium: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-trivium -- --test-threads=1 kreyvium::

.PHONY: test_concrete_csprng # Run concrete-csprng tests
test_concrete_csprng: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE) -p concrete-csprng

.PHONY: test_zk_pok # Run tfhe-zk-pok-experimental tests
test_zk_pok: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-zk-pok

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,gpu,internal-keycache,experimental --no-deps -p $(TFHE_SPEC)

.PHONY: docs # Build rust doc alias for doc
docs: doc

.PHONY: lint_doc # Build rust doc with linting enabled
lint_doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,integer,gpu,internal-keycache,experimental -p $(TFHE_SPEC) --no-deps

.PHONY: lint_docs # Build rust doc with linting enabled alias for lint_doc
lint_docs: lint_doc

.PHONY: format_doc_latex # Format the documentation latex equations to avoid broken rendering.
format_doc_latex:
	RUSTFLAGS="" cargo xtask format_latex_doc
	@"$(MAKE)" --no-print-directory fmt
	@printf "\n===============================\n\n"
	@printf "Please manually inspect changes made by format_latex_doc, rustfmt can break equations \
	if the line length is exceeded\n"
	@printf "\n===============================\n"

.PHONY: check_md_docs_are_tested # Checks that the rust codeblocks in our .md files are tested
check_md_docs_are_tested:
	RUSTFLAGS="" cargo xtask check_tfhe_docs_are_tested

.PHONY: check_intra_md_links # Checks broken internal links in Markdown docs
check_intra_md_links: install_mlc
	mlc --offline --match-file-extension tfhe/docs

.PHONY: check_md_links # Checks all broken links in Markdown docs
check_md_links: install_mlc
	mlc --match-file-extension tfhe/docs

.PHONY: check_compile_tests # Build tests in debug without running them
check_compile_tests: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=$(TARGET_ARCH_FEATURE),experimental,boolean,shortint,integer,internal-keycache \
		-p $(TFHE_SPEC)

	@if [[ "$(OS)" == "Linux" || "$(OS)" == "Darwin" ]]; then \
		"$(MAKE)" build_c_api && \
		./scripts/c_api_tests.sh --build-only --cargo-profile "$(CARGO_PROFILE)"; \
	fi

.PHONY: check_compile_tests_benches_gpu # Build tests in debug without running them
check_compile_tests_benches_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=$(TARGET_ARCH_FEATURE),experimental,boolean,shortint,integer,internal-keycache,gpu \
		-p $(TFHE_SPEC)
	mkdir -p "$(TFHECUDA_BUILD)" && \
		cd "$(TFHECUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Debug -DTFHE_CUDA_BACKEND_BUILD_TESTS=ON -DTFHE_CUDA_BACKEND_BUILD_BENCHMARKS=ON && \
		make -j "$(CPU_COUNT)"

.PHONY: build_nodejs_test_docker # Build a docker image with tools to run nodejs tests for wasm API
build_nodejs_test_docker:
	DOCKER_BUILDKIT=1 docker build --build-arg RUST_TOOLCHAIN="$(RS_BUILD_TOOLCHAIN)" \
		-f docker/Dockerfile.wasm_tests --build-arg NODE_VERSION=$(NODE_VERSION) -t tfhe-wasm-tests .

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
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests test-ci

.PHONY: no_tfhe_typo # Check we did not invert the h and f in tfhe
no_tfhe_typo:
	@./scripts/no_tfhe_typo.sh

.PHONY: no_dbg_log # Check we did not leave dbg macro calls in the rust code
no_dbg_log:
	@./scripts/no_dbg_calls.sh

.PHONY: dieharder_csprng # Run the dieharder test suite on our CSPRNG implementation
dieharder_csprng: install_dieharder build_concrete_csprng
	./scripts/dieharder_test.sh

#
# Benchmarks
#

.PHONY: bench_integer # Run benchmarks for unsigned integer
bench_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_signed_integer # Run benchmarks for signed integer
bench_signed_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_integer_gpu # Run benchmarks for integer on GPU backend
bench_integer_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,gpu,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_integer_multi_bit # Run benchmarks for unsigned integer using multi-bit parameters
bench_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_signed_integer_multi_bit # Run benchmarks for signed integer using multi-bit parameters
bench_signed_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_integer_multi_bit_gpu # Run benchmarks for integer on GPU backend using multi-bit parameters
bench_integer_multi_bit_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,gpu,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_shortint # Run benchmarks for shortint
bench_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint-bench \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_oprf # Run benchmarks for shortint
bench_oprf: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench oprf-shortint-bench \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench oprf-integer-bench \
	--features=$(TARGET_ARCH_FEATURE),integer,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_shortint_multi_bit # Run benchmarks for shortint using multi-bit parameters
bench_shortint_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint-bench \
	--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache,nightly-avx512 -p $(TFHE_SPEC) --

.PHONY: bench_boolean # Run benchmarks for boolean
bench_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench boolean-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_pbs # Run benchmarks for PBS
bench_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_pbs_gpu # Run benchmarks for PBS on GPU backend
bench_pbs_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,gpu,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_ks # Run benchmarks for keyswitch
bench_ks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

.PHONY: bench_ks_gpu # Run benchmarks for PBS on GPU backend
bench_ks_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-bench \
	--features=$(TARGET_ARCH_FEATURE),boolean,shortint,gpu,internal-keycache,nightly-avx512 -p $(TFHE_SPEC)

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

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
		--example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint,internal-keycache -- \
		$(MULTI_BIT_ONLY) $(COVERAGE_ONLY)

.PHONY: gen_key_cache_core_crypto # Run function to generate keys and cache them for core_crypto tests
gen_key_cache_core_crypto: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --tests --profile $(CARGO_PROFILE) \
		--features=$(TARGET_ARCH_FEATURE),experimental,internal-keycache -p $(TFHE_SPEC) -- --nocapture \
		core_crypto::keycache::generate_keys

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

.PHONY: pcc # pcc stands for pre commit checks (except GPU)
pcc: no_tfhe_typo no_dbg_log check_fmt lint_doc check_md_docs_are_tested check_intra_md_links \
clippy_all check_compile_tests

.PHONY: pcc_gpu # pcc stands for pre commit checks for GPU compilation
pcc_gpu: clippy_gpu clippy_cuda_backend check_compile_tests_benches_gpu

.PHONY: fpcc # pcc stands for pre commit checks, the f stands for fast
fpcc: no_tfhe_typo no_dbg_log check_fmt lint_doc check_md_docs_are_tested clippy_fast \
check_compile_tests

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fix_newline fmt

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
