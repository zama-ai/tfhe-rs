SHELL:=$(shell /usr/bin/env which bash)
RS_TOOLCHAIN:=$(shell cat toolchain.txt)
CARGO_RS_TOOLCHAIN:=+$(RS_TOOLCHAIN)
TARGET_ARCH_FEATURE:=$(shell ./scripts/get_arch_feature.sh)
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
	cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortints features
clippy_shortint: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the booleans, shortints
clippy: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans,shortints \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_c_api # Run clippy lints enabling the booleans, shortints and the C API
clippy_c_api: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_cuda # Run clippy lints enabling the booleans, shortints, cuda and c API features
clippy_cuda: install_rs_toolchain
	cargo "$(CARGO_RS_TOOLCHAIN)" clippy \
		--features=$(TARGET_ARCH_FEATURE),cuda,booleans-c-api,shortints-c-api \
		-p tfhe -- --no-deps -D warnings

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
