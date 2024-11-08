SHELL:=$(shell /usr/bin/env which bash)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
RS_BUILD_TOOLCHAIN:=stable
CARGO_RS_BUILD_TOOLCHAIN:=+$(RS_BUILD_TOOLCHAIN)
MIN_RUST_VERSION:=1.65
WASM_BINDGEN_VERSION:=$(shell grep '^wasm-bindgen[[:space:]]*=' Cargo.toml | cut -d '=' -f 2 | xargs)
NODE_VERSION=22.6
AVX512_SUPPORT?=OFF
FFT128_SUPPORT?=OFF
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS?=-C target-cpu=native

ifeq ($(AVX512_SUPPORT),ON)
		AVX512_FEATURE=nightly
else
		AVX512_FEATURE=
endif

ifeq ($(FFT128_SUPPORT),ON)
		FFT128_FEATURE=fft128
else
		FFT128_FEATURE=
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

.PHONY: install_build_wasm32_target # Install the wasm32 toolchain used for builds
install_build_wasm32_target: install_rs_build_toolchain
	rustup +$(RS_BUILD_TOOLCHAIN) target add wasm32-unknown-unknown || \
	( echo "Unable to install wasm32-unknown-unknown target toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

# The installation uses the ^ symbol because we need the matching version of wasm-bindgen in the
# Cargo.toml, as we don't lock those dependencies, this allows to get the matching CLI
.PHONY: install_wasm_bindgen_cli # Install wasm-bindgen-cli to get access to the test runner
install_wasm_bindgen_cli: install_rs_build_toolchain
	cargo +$(RS_BUILD_TOOLCHAIN) install --locked wasm-bindgen-cli --version ^$(WASM_BINDGEN_VERSION)

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

.PHONY: check_nvm_installed # Check if Node Version Manager is installed
check_nvm_installed:
	@source ~/.nvm/nvm.sh && nvm --version > /dev/null 2>&1 || \
	( echo "Unable to locate Node. Run 'make install_node'" && exit 1 )

.PHONY: check_actionlint_installed # Check if actionlint workflow linter is installed
check_actionlint_installed:
	@actionlint --version > /dev/null 2>&1 || \
	( echo "Unable to locate actionlint. Try installing it: https://github.com/rhysd/actionlint/releases" && exit 1 )

.PHONY: fmt # Format rust code
fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt

.PHONY: check_fmt # Check rust code format
check_fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check

.PHONY: lint_workflow # Run static linter on GitHub workflows
lint_workflow: check_actionlint_installed
	@actionlint

.PHONY: clippy # Run clippy lints
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=serde -- --no-deps -D warnings

.PHONY: build
build: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--features=$(FFT128_FEATURE)

.PHONY: build_no_std
build_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release \
		--no-default-features \
		--features=$(FFT128_FEATURE)

.PHONY: build_bench
build_bench: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
		--no-run \
		--features=serde \
		--features=$(FFT128_FEATURE)

.PHONY: test
test: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=$(FFT128_FEATURE)

.PHONY: test_serde
test_serde: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=serde

.PHONY: test_nightly
test_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release \
		--features=nightly,$(FFT128_FEATURE)

.PHONY: test_no_std
test_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--no-default-features \
		--features=$(FFT128_FEATURE)

.PHONY: test_no_std_nightly
test_no_std_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release \
		--no-default-features \
		--features=nightly,$(FFT128_FEATURE)

.PHONY: test_node_js
test_node_js: install_rs_build_toolchain install_build_wasm32_target install_wasm_bindgen_cli check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	RUSTFLAGS="" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=serde --target wasm32-unknown-unknown

.PHONY: test_all
test_all: test test_serde test_nightly test_no_std test_no_std_nightly test_node_js

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc --no-deps

.PHONY: bench # Run benchmarks
bench: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench --bench fft \
		--features=serde \
		--features=$(AVX512_FEATURE) \
		--features=$(FFT128_FEATURE)

.PHONY: pcc # pcc stands for pre commit checks
pcc: check_fmt doc clippy

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fmt

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
