SHELL:=$(shell /usr/bin/env which bash)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt)
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
RS_BUILD_TOOLCHAIN:=$(shell \
	( (echo $(TARGET_ARCH_FEATURE) | grep -q x86) && echo stable) || echo $(RS_CHECK_TOOLCHAIN))
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
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
	echo "Unable to install $(RS_CHECK_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/"

.PHONY: install_rs_build_toolchain # Install the toolchain used for builds
install_rs_build_toolchain:
	@rustup toolchain list | grep -q "$(RS_BUILD_TOOLCHAIN)" || \
	rustup toolchain install --profile default "$(RS_BUILD_TOOLCHAIN)" || \
	echo "Unable to install $(RS_BUILD_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/"

.PHONY: install_cargo_nextest # Install cargo nextest used for shortint tests
install_cargo_nextest: install_rs_build_toolchain
	@cargo nextest --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install cargo-nextest --locked || \
	echo "Unable to install cargo nextest, unknown error."

.PHONY: fmt # Format rust code
fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt

.PHONT: check_fmt # Check rust code format
check_fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortints features
clippy_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the booleans, shortints
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_c_api # Run clippy lints enabling the booleans, shortints and the C API
clippy_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_cuda # Run clippy lints enabling the booleans, shortints, cuda and c API features
clippy_cuda: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),cuda,booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --release \
		--example generates_test_keys \
		--features=$(TARGET_ARCH_FEATURE),shortints,internal-keycache -p tfhe

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),booleans -p tfhe

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),shortints -p tfhe

.PHONY: build_boolean_and_shortint # Build with boolean and shortint enabled
build_boolean_and_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints -p tfhe

.PHONY: build_c_api # Build the C API for boolean and shortint
build_c_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release
		--features=$(TARGET_ARCH_FEATURE),booleans-c-api,shortints-c-api -p tfhe

.PHONY: test_core_crypto # Run the tests of the core_crypto module
test_core_crypto: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE) -p tfhe -- core_crypto::

.PHONY: test_core_crypto_cuda # Run the tests of the core_crypto module with cuda enabled
test_core_crypto_cuda: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),cuda -p tfhe -- core_crypto::backends::cuda::

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),booleans -p tfhe -- boolean::

.PHONY: test_boolean_cuda # Run the tests of the boolean module with cuda enabled
test_boolean_cuda: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),booleans,cuda -p tfhe -- boolean::

.PHONY: test_c_api # Run the tests for the C API
test_c_api: install_rs_build_toolchain
	./scripts/c_api_tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_shortint_ci # Run the tests for shortint ci
test_shortint_ci: install_rs_build_toolchain install_cargo_nextest
	./scripts/shortint-tests.sh $(CARGO_RS_BUILD_TOOLCHAIN)

.PHONY: test_shortint # Run all the tests for shortint
test_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(TARGET_ARCH_FEATURE),shortints,internal-keycache -p tfhe -- shortint::

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints --no-deps

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
