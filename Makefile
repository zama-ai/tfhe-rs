SHELL:=$(shell /usr/bin/env which bash)
RS_TOOLCHAIN:=$(shell cat toolchain.txt)
CARGO_RS_TOOLCHAIN:=+$(RS_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the termianl and change them if required without forgetting the flags
export RUSTFLAGS:=-C target-cpu=native

.PHONY: rs_toolchain # Echo the used rust toolchain for checks
rs_toolchain:
	@echo $(RS_TOOLCHAIN)

.PHONY: install_rs_toolchain # Install the toolchain used for checks
install_rs_toolchain:
	@rustup toolchain list | grep "$(RS_TOOLCHAIN)" > /dev/null || \
	rustup toolchain install "$(RS_TOOLCHAIN)" || \
	echo "Unable to install $(RS_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/"

.PHONY: fmt # Format rust code
fmt: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" fmt

.PHONT: check_fmt # Check rust code format
check_fmt: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" fmt --check

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortints features
clippy_shortint: install_rs_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the booleans, shortints
clippy: install_rs_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_c_api # Run clippy lints enabling the booleans, shortints and the C API
clippy_c_api: install_rs_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_cuda # Run clippy lints enabling the booleans, shortints, cuda and c API features
clippy_cuda: install_rs_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),cuda,booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --release --example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),shortints,internal-keycache -p tfhe

.PHONY: build_boolean # Build with boolean enabled
build_boolean:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release \
		--features=$(TARGET_ARCH_FEATURE),booleans -p tfhe

.PHONY: build_shortint # Build with shortint enabled
build_shortint:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release \
		--features=$(TARGET_ARCH_FEATURE),shortints -p tfhe

.PHONY: build_boolean_and_shortint # Build with boolean and shortint enabled
build_boolean_and_shortint:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints -p tfhe

.PHONY: build_c_api # Build the C API for boolean and shortint
build_c_api:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release
		--features=$(TARGET_ARCH_FEATURE),booleans-c-api,shortints-c-api -p tfhe

.PHONY: test_core_crypto # Run the tests of the core_crypto module
test_core_crypto:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release \
		--features=$(TARGET_ARCH_FEATURE) -p tfhe -- core_crypto::

.PHONY: test_core_crypto_cuda # Run the tests of the core_crypto module with cuda enabled
test_core_crypto_cuda:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release \
		--features=$(TARGET_ARCH_FEATURE),cuda -p tfhe -- core_crypto::backends::cuda::

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release \
		--features=$(TARGET_ARCH_FEATURE),booleans -p tfhe -- boolean::

.PHONY: test_boolean_cuda # Run the tests of the boolean module with cuda enabled
test_boolean_cuda:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release \
		--features=$(TARGET_ARCH_FEATURE),booleans,cuda -p tfhe -- boolean::

.PHONY: test_c_api # Run the tests for the C API
test_c_api:
	./scripts/c_api_tests.sh

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci:
	./scripts/shortint-tests.sh

.PHONY: test_shortint # Run all the tests for shortint
test_shortint:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release \
		--features=$(TARGET_ARCH_FEATURE),shortints -p tfhe -- shortint::

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
