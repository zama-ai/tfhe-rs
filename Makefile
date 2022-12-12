SHELL:=$(shell /usr/bin/env which bash)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt)
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
RS_BUILD_TOOLCHAIN:=$(shell \
	( (echo $(TARGET_ARCH_FEATURE) | grep -q x86) && echo stable) || echo $(RS_CHECK_TOOLCHAIN))
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
MIN_RUST_VERSION:=1.65
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the termianl and change them if required without forgetting the flags
export RUSTFLAGS:=-C target-cpu=native

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

.PHONY: clippy # Run clippy lints enabling the boolean, shortint
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint \
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

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy clippy_boolean clippy_shortint clippy_c_api clippy_js_wasm_api clippy_tasks

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --release \
		--example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),shortint -p tfhe

.PHONY: build_boolean_and_shortint # Build with boolean and shortint enabled
build_boolean_and_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint -p tfhe

.PHONY: build_c_api # Build the C API for boolean and shortint
build_c_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),boolean-c-api,shortint-c-api -p tfhe

.PHONY: test_core_crypto # Run the tests of the core_crypto module
test_core_crypto: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE) -p tfhe -- core_crypto::

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),boolean -p tfhe -- boolean::

.PHONY: test_c_api # Run the tests for the C API
test_c_api: install_rs_build_toolchain
	./scripts/c_api_tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	./scripts/shortint-tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_shortint # Run all the tests for shortint
test_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),shortint,internal-keycache -p tfhe -- shortint::

.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release --doc \
		--features=$(TARGET_ARCH_FEATURE),shortint,boolean,internal-keycache -p tfhe \
		-- test_user_docs::

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),boolean,shortint --no-deps

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
		--features=$(TARGET_ARCH_FEATURE),shortint,boolean,internal-keycache -p tfhe

.PHONY: pcc # pcc stands for pre commit checks
pcc: check_fmt doc clippy_all check_compile_tests

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fmt

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
