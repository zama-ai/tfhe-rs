SHELL:=$(shell /usr/bin/env which bash)
OS:=$(shell uname)
RS_CHECK_TOOLCHAIN:=$(shell cat toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
CARGO_BUILD_JOBS=default
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
NIGHTLY_TESTS?=FALSE
BENCH_OP_FLAVOR?=DEFAULT
BENCH_TYPE?=latency
BENCH_PARAM_TYPE?=classical
BENCH_PARAMS_SET?=default
NODE_VERSION=22.6
BACKWARD_COMPAT_DATA_URL=https://github.com/zama-ai/tfhe-backward-compat-data.git
BACKWARD_COMPAT_DATA_BRANCH?=$(shell ./scripts/backward_compat_data_version.py)
BACKWARD_COMPAT_DATA_PROJECT=tfhe-backward-compat-data
BACKWARD_COMPAT_DATA_DIR=$(BACKWARD_COMPAT_DATA_PROJECT)
TFHE_SPEC:=tfhe
WASM_PACK_VERSION="0.13.1"
# We are kind of hacking the cut here, the version cannot contain a quote '"'
WASM_BINDGEN_VERSION:=$(shell grep '^wasm-bindgen[[:space:]]*=' Cargo.toml | cut -d '"' -f 2 | xargs)
WEB_RUNNER_DIR=web-test-runner
WEB_SERVER_DIR=tfhe/web_wasm_parallel_tests
# This is done to avoid forgetting it, we still precise the RUSTFLAGS in the commands to be able to
# copy paste the command in the terminal and change them if required without forgetting the flags
export RUSTFLAGS?=-C target-cpu=native

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

# Variables used only for regex_engine example
REGEX_STRING?=''
REGEX_PATTERN?=''

# tfhe-cuda-backend
TFHECUDA_SRC=backends/tfhe-cuda-backend/cuda
TFHECUDA_BUILD=$(TFHECUDA_SRC)/build

# tfhe-hpu-backend
HPU_CONFIG=v80

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

.PHONY: install_build_wasm32_target # Install the wasm32 toolchain used for builds
install_build_wasm32_target: install_rs_build_toolchain
	rustup +$(RS_BUILD_TOOLCHAIN) target add wasm32-unknown-unknown || \
	( echo "Unable to install wasm32-unknown-unknown target toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_cargo_nextest # Install cargo nextest used for shortint tests
install_cargo_nextest: install_rs_build_toolchain
	@cargo nextest --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install cargo-nextest --locked || \
	( echo "Unable to install cargo nextest, unknown error." && exit 1 )

# The installation should use the ^ symbol if the specified version in the root Cargo.toml is of the
# form "0.2.96" then we get ^0.2.96 e.g., as we don't lock those dependencies
# this allows to get the matching CLI
# If a version range is specified no need to add the leading ^
.PHONY: install_wasm_bindgen_cli # Install wasm-bindgen-cli to get access to the test runner
install_wasm_bindgen_cli: install_rs_build_toolchain
	cargo +$(RS_BUILD_TOOLCHAIN) install --locked wasm-bindgen-cli --version "$(WASM_BINDGEN_VERSION)"

.PHONY: install_wasm_pack # Install wasm-pack to build JS packages
install_wasm_pack: install_rs_build_toolchain
	@wasm-pack --version | grep "$(WASM_PACK_VERSION)" > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install --locked wasm-pack@$(WASM_PACK_VERSION) || \
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

.PHONY: node_version  # Return Node version that will be installed
node_version:
	@echo "$(NODE_VERSION)"

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

.PHONY: install_cargo_dylint # Install custom tfhe-rs lints
install_cargo_dylint:
	cargo install cargo-dylint dylint-link

.PHONY: install_typos_checker # Install typos checker
install_typos_checker: install_rs_build_toolchain
	@typos --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install typos-cli || \
	( echo "Unable to install typos-cli, unknown error." && exit 1 )

.PHONY: install_zizmor # Install zizmor workflow security checker
install_zizmor: install_rs_build_toolchain
	@zizmor --version > /dev/null 2>&1 || \
	cargo $(CARGO_RS_BUILD_TOOLCHAIN) install zizmor --version ~1.9 || \
	( echo "Unable to install zizmor, unknown error." && exit 1 )

.PHONY: setup_venv # Setup Python virtualenv for wasm tests
setup_venv:
	python3 -m venv venv
	@source venv/bin/activate && \
	pip3 install -r ci/webdriver_requirements.txt

# This is an internal target, not meant to be called on its own.
install_web_resource:
	wget -P $(dest) $(url)
	@cd $(dest) && \
	echo "$(checksum) $(filename)" > checksum && \
	sha256sum -c checksum && \
	rm checksum && \
	$(decompress_cmd) $(filename)

install_chrome_browser: url = "https://storage.googleapis.com/chrome-for-testing-public/130.0.6723.69/linux64/chrome-linux64.zip"
install_chrome_browser: checksum = "f789d53911a50cfa4a2bc1f09cde57567247f52515436d92b1aa9de93c2787d0"
install_chrome_browser: dest = "$(WEB_RUNNER_DIR)/chrome"
install_chrome_browser: filename = "chrome-linux64.zip"
install_chrome_browser: decompress_cmd = unzip

.PHONY: install_chrome_browser # Install Chrome browser for Linux
install_chrome_browser: install_web_resource

install_chrome_web_driver: url = "https://storage.googleapis.com/chrome-for-testing-public/130.0.6723.69/linux64/chromedriver-linux64.zip"
install_chrome_web_driver: checksum = "90fe8dedf33eefe4b72704f626fa9f5834427c042235cfeb4251f18c9f0336ea"
install_chrome_web_driver: dest = "$(WEB_RUNNER_DIR)/chrome"
install_chrome_web_driver: filename = "chromedriver-linux64.zip"
install_chrome_web_driver: decompress_cmd = unzip

.PHONY: install_chrome_web_driver # Install Chrome web driver for Linux
install_chrome_web_driver: install_web_resource

install_firefox_browser: url = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/131.0/linux-x86_64/en-US/firefox-131.0.tar.bz2"
install_firefox_browser: checksum = "4ca8504a62a31472ecb8c3a769d4301dd4ac692d4cc5d51b8fe2cf41e7b11106"
install_firefox_browser: dest = "$(WEB_RUNNER_DIR)/firefox"
install_firefox_browser: filename = "firefox-131.0.tar.bz2"
install_firefox_browser: decompress_cmd = tar -xvf

.PHONY: install_firefox_browser # Install firefox browser for Linux
install_firefox_browser: install_web_resource

install_firefox_web_driver: url = "https://github.com/mozilla/geckodriver/releases/download/v0.35.0/geckodriver-v0.35.0-linux64.tar.gz"
install_firefox_web_driver: checksum = "ac26e9ba8f3b8ce0fbf7339b9c9020192f6dcfcbf04a2bcd2af80dfe6bb24260"
install_firefox_web_driver: dest = "$(WEB_RUNNER_DIR)/firefox"
install_firefox_web_driver: filename = "geckodriver-v0.35.0-linux64.tar.gz"
install_firefox_web_driver: decompress_cmd = tar -xvf

.PHONY: install_firefox_web_driver # Install firefox web driver for Linux
install_firefox_web_driver: install_web_resource

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
	$(MAKE) -C tfhe/web_wasm_parallel_tests fmt && \
	$(MAKE) -C tfhe/js_on_wasm_tests fmt

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
	$(MAKE) -C tfhe/web_wasm_parallel_tests check_fmt && \
	$(MAKE) -C tfhe/js_on_wasm_tests check_fmt

.PHONY: check_typos # Check for typos in codebase
check_typos: install_typos_checker
	@typos && echo "No typos found"

.PHONY: clippy_gpu # Run clippy lints on tfhe with "gpu" enabled
clippy_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,gpu,pbs-stats,extended-types,zk-pok \
		--all-targets \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: check_gpu # Run check on tfhe with "gpu" enabled
check_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" check \
		--features=boolean,shortint,integer,internal-keycache,gpu,pbs-stats \
		--all-targets \
		-p $(TFHE_SPEC)

.PHONY: clippy_hpu # Run clippy lints on tfhe with "hpu" enabled
clippy_hpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,hpu,pbs-stats,extended-types \
		--all-targets \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_gpu_hpu # Run clippy lints on tfhe with "gpu" and "hpu" enabled
clippy_gpu_hpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,gpu,hpu,pbs-stats,extended-types,zk-pok \
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

.PHONY: check_workflow_security # Run zizmor security checker on GitHub workflows
check_workflow_security: install_zizmor
	zizmor --persona pedantic .

.PHONY: clippy_core # Run clippy lints on core_crypto with and without experimental features
clippy_core: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=nightly-avx512 \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=experimental,nightly-avx512 \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=zk-pok \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortint features
clippy_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=shortint \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=shortint,experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=zk-pok,shortint \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_integer # Run clippy lints enabling the integer features
clippy_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer,experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer,experimental,extended-types \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the boolean, shortint, integer
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_rustdoc # Run clippy lints on doctests enabling the boolean, shortint, integer and zk-pok
clippy_rustdoc: install_rs_check_toolchain
	if [[ "$(OS)" != "Linux" && "$(OS)" != "Darwin" ]]; then \
		echo "WARNING: skipped clippy_rustdoc, unsupported OS $(OS)"; \
		exit 0; \
	fi && \
	CARGO_TERM_QUIET=true CLIPPYFLAGS="-D warnings" RUSTDOCFLAGS="--no-run --nocapture --test-builder ./scripts/clippy_driver.sh -Z unstable-options" \
		cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" test --doc \
		--features=boolean,shortint,integer,zk-pok,pbs-stats,strings,experimental \
		-p $(TFHE_SPEC)

.PHONY: clippy_rustdoc_gpu # Run clippy lints on doctests enabling the boolean, shortint, integer and zk-pok
clippy_rustdoc_gpu: install_rs_check_toolchain
	if [[ "$(OS)" != "Linux" ]]; then \
		echo "WARNING: skipped clippy_rustdoc_gpu, unsupported OS $(OS)"; \
		exit 0; \
	fi && \
	CARGO_TERM_QUIET=true CLIPPYFLAGS="-D warnings" RUSTDOCFLAGS="--no-run --nocapture --test-builder ./scripts/clippy_driver.sh -Z unstable-options" \
		cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" test --doc \
		--features=boolean,shortint,integer,zk-pok,pbs-stats,strings,experimental,gpu \
		-p $(TFHE_SPEC)

.PHONY: clippy_c_api # Run clippy lints enabling the boolean, shortint and the C API
clippy_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,extended-types \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_js_wasm_api # Run clippy lints enabling the boolean, shortint, integer and the js wasm API
clippy_js_wasm_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,high-level-client-js-wasm-api,zk-pok,extended-types \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,high-level-client-js-wasm-api,extended-types \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_tasks # Run clippy lints on helper tasks crate.
clippy_tasks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		-p tasks -- --no-deps -D warnings

.PHONY: clippy_trivium # Run clippy lints on Trivium app
clippy_trivium: install_rs_check_toolchain
	cd apps/trivium; RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-trivium -- --no-deps -D warnings

.PHONY: clippy_ws_tests # Run clippy on the workspace level tests
clippy_ws_tests: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --tests \
		-p tests --features=shortint,integer,zk-pok -- --no-deps -D warnings

.PHONY: clippy_all_targets # Run clippy lints on all targets (benches, examples, etc.)
clippy_all_targets: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer,internal-keycache,zk-pok,strings,pbs-stats,extended-types \
		-p $(TFHE_SPEC) -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer,internal-keycache,zk-pok,strings,pbs-stats,extended-types,experimental \
		-p $(TFHE_SPEC) -- --no-deps -D warnings

.PHONY: clippy_tfhe_csprng # Run clippy lints on tfhe-csprng
clippy_tfhe_csprng: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=parallel,software-prng -p tfhe-csprng -- --no-deps -D warnings

.PHONY: clippy_zk_pok # Run clippy lints on tfhe-zk-pok
clippy_zk_pok: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-zk-pok -- --no-deps -D warnings

.PHONY: clippy_versionable # Run clippy lints on tfhe-versionable
clippy_versionable: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-versionable-derive -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-versionable -- --no-deps -D warnings

.PHONY: clippy_tfhe_lints # Run clippy lints on tfhe-lints
clippy_tfhe_lints: install_cargo_dylint # the toolchain is selected with toolchain.toml
	cd utils/tfhe-lints && \
	rustup toolchain install && \
	cargo clippy --all-targets -- --no-deps -D warnings

.PHONY: clippy_param_dedup # Run clippy lints on param_dedup tool
clippy_param_dedup: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p param_dedup -- --no-deps -D warnings

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy_rustdoc clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets \
clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core clippy_tfhe_csprng clippy_zk_pok clippy_trivium \
clippy_versionable clippy_tfhe_lints clippy_ws_tests clippy_bench clippy_param_dedup

.PHONY: clippy_fast # Run main clippy targets
clippy_fast: clippy_rustdoc clippy clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks \
clippy_core clippy_tfhe_csprng

.PHONY: clippy_cuda_backend # Run clippy lints on the tfhe-cuda-backend
clippy_cuda_backend: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-cuda-backend -- --no-deps -D warnings

.PHONY: clippy_hpu_backend # Run clippy lints on the tfhe-hpu-backend
clippy_hpu_backend: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-hpu-backend -- --no-deps -D warnings

.PHONY: check_rust_bindings_did_not_change # Check rust bindings are up to date for tfhe-cuda-backend
check_rust_bindings_did_not_change:
	cargo build -p tfhe-cuda-backend && "$(MAKE)" fmt_gpu && \
	git diff --quiet HEAD -- backends/tfhe-cuda-backend/src/bindings.rs || \
	( echo "Generated bindings have changed! Please run 'git add backends/tfhe-cuda-backend/src/bindings.rs' \
	and commit the changes." && exit 1 )


.PHONY: tfhe_lints # Run custom tfhe-rs lints
tfhe_lints: install_cargo_dylint
	RUSTFLAGS="$(RUSTFLAGS)" cargo dylint --all -p tfhe --no-deps -- \
		--features=boolean,shortint,integer,strings,zk-pok

.PHONY: build_core # Build core_crypto without experimental features
build_core: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		-p $(TFHE_SPEC)
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=nightly-avx512 -p $(TFHE_SPEC); \
	fi

.PHONY: build_core_experimental # Build core_crypto with experimental features
build_core_experimental: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=experimental -p $(TFHE_SPEC)
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
			--features=experimental,nightly-avx512 -p $(TFHE_SPEC); \
	fi

.PHONY: build_boolean # Build with boolean enabled
build_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean -p $(TFHE_SPEC) --all-targets

.PHONY: build_shortint # Build with shortint enabled
build_shortint: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=shortint -p $(TFHE_SPEC) --all-targets

.PHONY: build_integer # Build with integer enabled
build_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=integer -p $(TFHE_SPEC) --all-targets

.PHONY: build_tfhe_full # Build with boolean, shortint and integer enabled
build_tfhe_full: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer -p $(TFHE_SPEC) --all-targets

.PHONY: build_tfhe_coverage # Build with test coverage enabled
build_tfhe_coverage: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache -p $(TFHE_SPEC) --tests

.PHONY: build_c_api # Build the C API for boolean, shortint and integer
build_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,extended-types \
		-p $(TFHE_SPEC)

.PHONY: build_c_api_gpu # Build the C API for boolean, shortint and integer
build_c_api_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,extended-types,gpu \
		-p $(TFHE_SPEC)

.PHONY: build_c_api_experimental_deterministic_fft # Build the C API for boolean, shortint and integer with experimental deterministic FFT
build_c_api_experimental_deterministic_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,experimental-force_fft_algo_dif4 \
		-p $(TFHE_SPEC)

.PHONY: build_web_js_api # Build the js API targeting the web browser
build_web_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok,extended-types

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) -C target-feature=+atomics,+bulk-memory" rustup run $(RS_CHECK_TOOLCHAIN) \
		wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,parallel-wasm-api,zk-pok,extended-types \
		-Z build-std=panic_abort,std && \
	find pkg/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_rs_build_toolchain install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" rustup run "$(RS_BUILD_TOOLCHAIN)" \
		wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok,extended-types

.PHONY: build_tfhe_csprng # Build tfhe_csprng
build_tfhe_csprng: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		-p tfhe-csprng --all-targets

.PHONY: test_core_crypto # Run the tests of the core_crypto module including experimental ones
test_core_crypto: install_rs_build_toolchain install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=experimental,zk-pok -p $(TFHE_SPEC) -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
			--features=experimental,zk-pok,nightly-avx512 -p $(TFHE_SPEC) -- core_crypto::; \
	fi

.PHONY: test_core_crypto_cov # Run the tests of the core_crypto module with code coverage
test_core_crypto_cov: install_rs_build_toolchain install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/core_crypto --line --engine llvm --timeout 500 \
		--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
		--features=experimental,internal-keycache \
		-p $(TFHE_SPEC) -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
			--out xml --output-dir coverage/core_crypto_avx512 --line --engine llvm --timeout 500 \
			--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
			--features=experimental,internal-keycache,nightly-avx512 \
			-p $(TFHE_SPEC) -- -Z unstable-options --report-time core_crypto::; \
	fi

.PHONY: test_cuda_backend # Run the internal tests of the CUDA backend
test_cuda_backend:
	mkdir -p "$(TFHECUDA_BUILD)" && \
		cd "$(TFHECUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Release -DTFHE_CUDA_BACKEND_BUILD_TESTS=ON && \
		"$(MAKE)" -j "$(CPU_COUNT)" && \
		"$(MAKE)" test

.PHONY: test_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_gpu: test_core_crypto_gpu test_integer_gpu test_cuda_backend

.PHONY: test_core_crypto_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_core_crypto_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=gpu -p $(TFHE_SPEC) -- core_crypto::gpu::
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=gpu -p $(TFHE_SPEC) -- core_crypto::gpu::

.PHONY: test_integer_gpu # Run the tests of the integer module including experimental on the gpu backend
test_integer_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p $(TFHE_SPEC) -- integer::gpu::server_key:: --test-threads=4
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p $(TFHE_SPEC) -- integer::gpu::server_key::

.PHONY: test_integer_long_run_gpu # Run the long run integer tests on the gpu backend
test_integer_long_run_gpu: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	LONG_TESTS=TRUE \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)" --backend "gpu"

.PHONY: test_integer_compression
test_integer_compression: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=integer -p $(TFHE_SPEC) -- integer::ciphertext::compressed_ciphertext_list::tests::
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=integer -p $(TFHE_SPEC) -- integer::ciphertext::compress

.PHONY: test_integer_compression_gpu
test_integer_compression_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p $(TFHE_SPEC) -- integer::gpu::ciphertext::compressed_ciphertext_list::tests::
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --doc --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p $(TFHE_SPEC) -- integer::gpu::ciphertext::compress

.PHONY: test_integer_gpu_ci # Run the tests for integer ci on gpu backend
test_integer_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_gpu_ci # Run the tests for unsigned integer ci on gpu backend
test_unsigned_integer_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_gpu_ci # Run the tests for signed integer ci on gpu backend
test_signed_integer_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_integer_multi_bit_gpu_ci # Run the tests for integer ci on gpu backend running only multibit tests
test_integer_multi_bit_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_multi_bit_gpu_ci # Run the tests for unsigned integer ci on gpu backend running only multibit tests
test_unsigned_integer_multi_bit_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_multi_bit_gpu_ci # Run the tests for signed integer ci on gpu backend running only multibit tests
test_signed_integer_multi_bit_gpu_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_integer_hpu_ci # Run the tests for integer ci on hpu backend
test_integer_hpu_ci: install_rs_check_toolchain install_cargo_nextest
	cargo test --release -p $(TFHE_SPEC) --features hpu-v80 --test hpu

.PHONY: test_integer_hpu_mockup_ci # Run the tests for integer ci on hpu backend and mockup
test_integer_hpu_mockup_ci: install_rs_check_toolchain install_cargo_nextest
	source ./setup_hpu.sh --config sim ; \
	cargo build --release --bin hpu_mockup; \
    coproc target/release/hpu_mockup --params mockups/tfhe-hpu-mockup/params/tuniform_64b_pfail64_psi64.toml > mockup.log; \
	HPU_TEST_ITER=1 \
	cargo test --profile devo -p $(TFHE_SPEC) --features hpu --test hpu -- u32 && \
	kill %1

.PHONY: test_integer_hpu_mockup_ci_fast # Run the quick tests for integer ci on hpu backend and mockup.
test_integer_hpu_mockup_ci_fast: install_rs_check_toolchain install_cargo_nextest
	source ./setup_hpu.sh --config sim ; \
	cargo build --profile devo --bin hpu_mockup; \
    coproc target/devo/hpu_mockup --params mockups/tfhe-hpu-mockup/params/tuniform_64b_fast.toml > mockup.log; \
	HPU_TEST_ITER=1 \
	cargo test --profile devo -p $(TFHE_SPEC) --features hpu --test hpu -- u32 && \
	kill %1

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=boolean -p $(TFHE_SPEC) -- boolean::

.PHONY: test_boolean_cov # Run the tests of the boolean module with code coverage
test_boolean_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/boolean --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=boolean,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time boolean::

.PHONY: test_c_api_rs # Run the rust tests for the C API
test_c_api_rs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api \
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
		--features=shortint,internal-keycache -p $(TFHE_SPEC) -- shortint::

.PHONY: test_shortint_cov # Run the tests of the shortint module with code coverage
test_shortint_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/shortint --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=shortint,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time shortint::

.PHONY: test_integer_ci # Run the tests for integer ci
test_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_ci # Run the tests for unsigned integer ci
test_unsigned_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_ci # Run the tests for signed integer ci
test_signed_integer_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_integer_multi_bit_ci # Run the tests for integer ci running only multibit tests
test_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_unsigned_integer_multi_bit_ci # Run the tests for unsigned integer ci running only multibit tests
test_unsigned_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_signed_integer_multi_bit_ci # Run the tests for signed integer ci running only multibit tests
test_signed_integer_multi_bit_ci: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_CHECK_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "$(TFHE_SPEC)"

.PHONY: test_integer_long_run # Run the long run integer tests
test_integer_long_run: install_rs_check_toolchain install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	LONG_TESTS=TRUE \
		./scripts/integer-tests.sh --rust-toolchain $(CARGO_RS_BUILD_TOOLCHAIN) \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "$(TFHE_SPEC)"

.PHONY: test_safe_serialization # Run the tests for safe serialization
test_safe_serialization: install_rs_build_toolchain install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache -p $(TFHE_SPEC) -- safe_serialization::

.PHONY: test_zk # Run the tests for the zk module of the TFHE-rs crate
test_zk: install_rs_build_toolchain install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=shortint,zk-pok -p $(TFHE_SPEC) -- zk::

.PHONY: test_integer # Run all the tests for integer
test_integer: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=integer,internal-keycache -p $(TFHE_SPEC) -- integer::

.PHONY: test_integer_cov # Run the tests of the integer module with code coverage
test_integer_cov: install_rs_check_toolchain install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/integer --line --engine llvm --timeout 500 \
		--implicit-test-threads \
		--exclude-files $(COVERAGE_EXCLUDED_FILES) \
		--features=integer,internal-keycache \
		-p $(TFHE_SPEC) -- -Z unstable-options --report-time integer::

.PHONY: test_high_level_api # Run all the tests for high_level_api
test_high_level_api: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache,zk-pok,strings -p $(TFHE_SPEC) \
		-- high_level_api::

test_high_level_api_gpu: install_rs_build_toolchain install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) nextest run --cargo-profile $(CARGO_PROFILE) \
		--test-threads=4 --features=integer,internal-keycache,gpu,zk-pok -p $(TFHE_SPEC) \
		-E "test(/high_level_api::.*gpu.*/)"

test_high_level_api_hpu: install_rs_build_toolchain install_cargo_nextest
ifeq ($(HPU_CONFIG), v80)
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) nextest run --cargo-profile $(CARGO_PROFILE) \
		--build-jobs=$(CARGO_BUILD_JOBS) \
		--test-threads=1 \
		--features=integer,internal-keycache,hpu,hpu-v80 -p $(TFHE_SPEC) \
		-E "test(/high_level_api::.*hpu.*/)"
else
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) nextest run --cargo-profile $(CARGO_PROFILE) \
		--build-jobs=$(CARGO_BUILD_JOBS) \
		--test-threads=1 \
		--features=integer,internal-keycache,hpu -p $(TFHE_SPEC) \
		-E "test(/high_level_api::.*hpu.*/)"
endif


.PHONY: test_strings # Run the tests for strings ci
test_strings: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=shortint,integer,strings -p $(TFHE_SPEC) \
		-- strings::


.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=boolean,shortint,integer,internal-keycache,pbs-stats,zk-pok,strings \
		-p $(TFHE_SPEC) \
		-- test_user_docs::

.PHONY: test_user_doc_gpu # Run tests for GPU from the .md documentation
test_user_doc_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,zk-pok,gpu -p $(TFHE_SPEC) \
		-- test_user_docs::

.PHONY: test_user_doc_hpu # Run tests for HPU from the .md documentation
test_user_doc_hpu: install_rs_build_toolchain
ifeq ($(HPU_CONFIG), v80)
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,hpu,hpu-v80 -p $(TFHE_SPEC) \
		-- test_user_docs::
else
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,hpu -p $(TFHE_SPEC) \
		-- test_user_docs::
endif



.PHONY: test_regex_engine # Run tests for regex_engine example
test_regex_engine: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--example regex_engine --features=integer

.PHONY: test_sha256_bool # Run tests for sha256_bool example
test_sha256_bool: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--example sha256_bool --features=boolean

.PHONY: test_examples # Run tests for examples
test_examples: test_sha256_bool test_regex_engine

.PHONY: test_trivium # Run tests for trivium
test_trivium: install_rs_build_toolchain
	cd apps/trivium; RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-trivium -- --test-threads=1 trivium::

.PHONY: test_kreyvium # Run tests for kreyvium
test_kreyvium: install_rs_build_toolchain
	cd apps/trivium; RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-trivium -- --test-threads=1 kreyvium::

.PHONY: test_tfhe_csprng # Run tfhe-csprng tests
test_tfhe_csprng: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-csprng

.PHONY: test_zk_pok # Run tfhe-zk-pok tests
test_zk_pok: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe-zk-pok

.PHONY: test_zk_wasm_x86_compat_ci
test_zk_wasm_x86_compat_ci: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_zk_wasm_x86_compat

.PHONY: test_zk_wasm_x86_compat # Check compatibility between wasm and x86_64 proofs
test_zk_wasm_x86_compat: install_rs_build_toolchain build_node_js_api
	cd tfhe/tests/zk_wasm_x86_test && npm install
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		-p tfhe --test zk_wasm_x86_test --features=integer,zk-pok

.PHONY: test_versionable # Run tests for tfhe-versionable subcrate
test_versionable: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--all-targets -p tfhe-versionable

.PHONY: test_tfhe_lints # Run test on tfhe-lints
test_tfhe_lints: install_cargo_dylint
	cd utils/tfhe-lints && \
	rustup toolchain install && \
	cargo test

# The backward compat data repo holds historical binary data but also rust code to generate and load them.
# Here we use the "patch" functionality of Cargo to make sure the repo used for the data is the same as the one used for the code.
.PHONY: test_backward_compatibility_ci
test_backward_compatibility_ci: install_rs_build_toolchain
	TFHE_BACKWARD_COMPAT_DATA_DIR="$(BACKWARD_COMPAT_DATA_DIR)" RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--config "patch.'$(BACKWARD_COMPAT_DATA_URL)'.$(BACKWARD_COMPAT_DATA_PROJECT).path=\"tests/$(BACKWARD_COMPAT_DATA_DIR)\"" \
		--features=shortint,integer,zk-pok -p tests test_backward_compatibility -- --nocapture

.PHONY: test_backward_compatibility # Same as test_backward_compatibility_ci but tries to clone the data repo first if needed
test_backward_compatibility: tests/$(BACKWARD_COMPAT_DATA_DIR) test_backward_compatibility_ci

.PHONY: backward_compat_branch # Prints the required backward compatibility branch
backward_compat_branch:
	@echo "$(BACKWARD_COMPAT_DATA_BRANCH)"

.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=boolean,shortint,integer,strings,gpu,internal-keycache,experimental,zk-pok --no-deps -p $(TFHE_SPEC)

.PHONY: docs # Build rust doc alias for doc
docs: doc

.PHONY: lint_doc # Build rust doc with linting enabled
lint_doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=boolean,shortint,integer,strings,gpu,internal-keycache,experimental,zk-pok -p $(TFHE_SPEC) --no-deps

.PHONY: lint_docs # Build rust doc with linting enabled alias for lint_doc
lint_docs: lint_doc

.PHONY: format_doc_latex # Format the documentation latex equations to avoid broken rendering.
format_doc_latex: install_rs_build_toolchain
	RUSTFLAGS="" cargo "$(CARGO_RS_BUILD_TOOLCHAIN)" xtask format_latex_doc
	@"$(MAKE)" --no-print-directory fmt
	@printf "\n===============================\n\n"
	@printf "Please manually inspect changes made by format_latex_doc, rustfmt can break equations \
	if the line length is exceeded\n"
	@printf "\n===============================\n"

.PHONY: check_md_docs_are_tested # Checks that the rust codeblocks in our .md files are tested
check_md_docs_are_tested: install_rs_build_toolchain
	RUSTFLAGS="" cargo "$(CARGO_RS_BUILD_TOOLCHAIN)" xtask check_tfhe_docs_are_tested

.PHONY: check_intra_md_links # Checks broken internal links in Markdown docs
check_intra_md_links: install_mlc
	mlc --offline --match-file-extension tfhe/docs

.PHONY: check_md_links # Checks all broken links in Markdown docs
check_md_links: install_mlc
	mlc --match-file-extension tfhe/docs

.PHONY: check_parameter_export_ok # Checks exported "current" shortint parameter module is correct
check_parameter_export_ok:
	python3 ./scripts/check_current_param_export.py

.PHONY: check_compile_tests # Build tests in debug without running them
check_compile_tests: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=experimental,boolean,shortint,integer,internal-keycache \
		-p $(TFHE_SPEC)

	@if [[ "$(OS)" == "Linux" || "$(OS)" == "Darwin" ]]; then \
		"$(MAKE)" build_c_api && \
		./scripts/c_api_tests.sh --build-only --cargo-profile "$(CARGO_PROFILE)"; \
	fi

.PHONY: check_compile_tests_benches_gpu # Build tests in debug without running them
check_compile_tests_benches_gpu: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --no-run \
		--features=experimental,boolean,shortint,integer,internal-keycache,gpu,zk-pok \
		-p $(TFHE_SPEC)
	mkdir -p "$(TFHECUDA_BUILD)" && \
		cd "$(TFHECUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Debug -DTFHE_CUDA_BACKEND_BUILD_TESTS=ON -DTFHE_CUDA_BACKEND_BUILD_BENCHMARKS=ON && \
		"$(MAKE)" -j "$(CPU_COUNT)"

.PHONY: test_nodejs_wasm_api # Run tests for the nodejs on wasm API
test_nodejs_wasm_api: build_node_js_api
	cd tfhe/js_on_wasm_tests && npm install && npm run test

.PHONY: test_nodejs_wasm_api_ci # Run tests for the nodejs on wasm API
test_nodejs_wasm_api_ci: build_node_js_api
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_nodejs_wasm_api

# This is an internal target, not meant to be called on its own.
run_web_js_api_parallel: build_web_js_api_parallel setup_venv
	cd $(WEB_SERVER_DIR) && npm install && npm run build
	source venv/bin/activate && \
	python ci/webdriver.py \
	--browser-path $(browser_path) \
	--driver-path $(driver_path) \
	--browser-kind  $(browser_kind) \
	--server-cmd "npm run server" \
	--server-workdir "$(WEB_SERVER_DIR)" \
	--id-pattern $(filter)

test_web_js_api_parallel_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
test_web_js_api_parallel_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
test_web_js_api_parallel_chrome: browser_kind = chrome
test_web_js_api_parallel_chrome: filter = Test

.PHONY: test_web_js_api_parallel_chrome # Run tests for the web wasm api on Chrome
test_web_js_api_parallel_chrome: run_web_js_api_parallel

.PHONY: test_web_js_api_parallel_chrome_ci # Run tests for the web wasm api on Chrome
test_web_js_api_parallel_chrome_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_parallel_chrome

test_web_js_api_parallel_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
test_web_js_api_parallel_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
test_web_js_api_parallel_firefox: browser_kind = firefox
test_web_js_api_parallel_firefox: filter = Test

.PHONY: test_web_js_api_parallel_firefox # Run tests for the web wasm api on Firefox
test_web_js_api_parallel_firefox: run_web_js_api_parallel

.PHONY: test_web_js_api_parallel_firefox_ci # Run tests for the web wasm api on Firefox
test_web_js_api_parallel_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_parallel_firefox

.PHONY: no_tfhe_typo # Check we did not invert the h and f in tfhe
no_tfhe_typo:
	@./scripts/no_tfhe_typo.sh

.PHONY: no_dbg_log # Check we did not leave dbg macro calls in the rust code
no_dbg_log:
	@./scripts/no_dbg_calls.sh

.PHONY: dieharder_csprng # Run the dieharder test suite on our CSPRNG implementation
dieharder_csprng: install_dieharder build_tfhe_csprng
	./scripts/dieharder_test.sh

#
# Benchmarks
#

.PHONY: clippy_bench # Run clippy lints on tfhe-benchmark
clippy_bench: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer,internal-keycache,nightly-avx512,pbs-stats,zk-pok \
		-p tfhe-benchmark -- --no-deps -D warnings

.PHONY: clippy_bench_gpu # Run clippy lints on tfhe-benchmark
clippy_bench_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=gpu,shortint,integer,internal-keycache,nightly-avx512,pbs-stats,zk-pok \
		-p tfhe-benchmark -- --no-deps -D warnings

.PHONY: clippy_bench_hpu # Run clippy lints on tfhe-benchmark
clippy_bench_hpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=hpu,shortint,integer,internal-keycache,pbs-stats\
		-p tfhe-benchmark -- --no-deps -D warnings

.PHONY: print_doc_bench_parameters # Print parameters used in doc benchmarks
print_doc_bench_parameters:
	RUSTFLAGS="" cargo run --example print_doc_bench_parameters \
	--features=shortint,internal-keycache -p tfhe

.PHONY: bench_integer # Run benchmarks for unsigned integer
bench_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=integer,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer # Run benchmarks for signed integer
bench_signed_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=integer,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_gpu # Run benchmarks for integer on GPU backend
bench_integer_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=integer,gpu,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer_gpu # Run benchmarks for signed integer on GPU backend
bench_signed_integer_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=integer,gpu,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_hpu # Run benchmarks for integer on HPU backend
bench_integer_hpu: install_rs_check_toolchain
	source ./setup_hpu.sh --config $(HPU_CONFIG) ; \
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=integer,internal-keycache,pbs-stats,hpu,hpu-v80 -p tfhe-benchmark -- --quick

.PHONY: bench_integer_compression # Run benchmarks for unsigned integer compression
bench_integer_compression: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench	glwe_packing_compression-integer-bench \
	--features=integer,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_compression_gpu
bench_integer_compression_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench	glwe_packing_compression-integer-bench \
	--features=integer,internal-keycache,gpu,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_zk_gpu
bench_integer_zk_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench zk-pke-bench \
	--features=integer,internal-keycache,gpu,pbs-stats,zk-pok -p tfhe-benchmark --

.PHONY: bench_integer_multi_bit # Run benchmarks for unsigned integer using multi-bit parameters
bench_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=integer,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer_multi_bit # Run benchmarks for signed integer using multi-bit parameters
bench_signed_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=integer,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_multi_bit_gpu # Run benchmarks for integer on GPU backend using multi-bit parameters
bench_integer_multi_bit_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-bench \
	--features=integer,gpu,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer_multi_bit_gpu # Run benchmarks for signed integer on GPU backend using multi-bit parameters
bench_signed_integer_multi_bit_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed-bench \
	--features=integer,gpu,internal-keycache,nightly-avx512,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_zk # Run benchmarks for integer encryption with ZK proofs
bench_integer_zk: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench zk-pke-bench \
	--features=integer,internal-keycache,zk-pok,nightly-avx512,pbs-stats \
	-p tfhe-benchmark --

.PHONY: bench_shortint # Run benchmarks for shortint
bench_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint-bench \
	--features=shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_shortint_oprf # Run benchmarks for shortint
bench_shortint_oprf: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench oprf-shortint-bench \
	--features=shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_boolean # Run benchmarks for boolean
bench_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench boolean-bench \
	--features=boolean,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_ks # Run benchmarks for keyswitch
bench_ks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-bench \
	--features=boolean,shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_ks_gpu # Run benchmarks for keyswitch on GPU backend
bench_ks_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-bench \
	--features=boolean,shortint,gpu,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_pbs # Run benchmarks for PBS
bench_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs-bench \
	--features=boolean,shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_pbs_gpu # Run benchmarks for PBS on GPU backend
bench_pbs_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_FAST_BENCH=$(FAST_BENCH) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs-bench \
	--features=boolean,shortint,gpu,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_ks_pbs # Run benchmarks for KS-PBS
bench_ks_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-pbs-bench \
	--features=boolean,shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_ks_pbs_gpu # Run benchmarks for KS-PBS on GPU backend
bench_ks_pbs_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench ks-pbs-bench \
	--features=boolean,shortint,gpu,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_pbs128 # Run benchmarks for PBS using FFT 128 bits
bench_pbs128: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs128-bench \
	--features=boolean,shortint,internal-keycache,nightly-avx512 -p tfhe-benchmark

.PHONY: bench_pbs128_gpu # Run benchmarks for PBS using FFT 128 bits on GPU
bench_pbs128_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench pbs128-bench \
	--features=boolean,shortint,gpu,internal-keycache,nightly-avx512 -p tfhe-benchmark

bench_web_js_api_parallel_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
bench_web_js_api_parallel_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
bench_web_js_api_parallel_chrome: browser_kind = chrome
bench_web_js_api_parallel_chrome: filter = Bench

.PHONY: bench_web_js_api_parallel_chrome # Run benchmarks for the web wasm api
bench_web_js_api_parallel_chrome: run_web_js_api_parallel

.PHONY: bench_web_js_api_parallel_chrome_ci # Run benchmarks for the web wasm api
bench_web_js_api_parallel_chrome_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_parallel_chrome

bench_web_js_api_parallel_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
bench_web_js_api_parallel_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
bench_web_js_api_parallel_firefox: browser_kind = firefox
bench_web_js_api_parallel_firefox: filter = Bench

.PHONY: bench_web_js_api_parallel_firefox # Run benchmarks for the web wasm api
bench_web_js_api_parallel_firefox: run_web_js_api_parallel

.PHONY: bench_web_js_api_parallel_firefox_ci # Run benchmarks for the web wasm api
bench_web_js_api_parallel_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_parallel_firefox

.PHONY: bench_hlapi_erc20 # Run benchmarks for ERC20 operations
bench_hlapi_erc20: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,internal-keycache,pbs-stats,nightly-avx512 -p tfhe-benchmark --

.PHONY: bench_hlapi_erc20_gpu # Run benchmarks for ERC20 operations on GPU
bench_hlapi_erc20_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,gpu,internal-keycache,pbs-stats,nightly-avx512 -p tfhe-benchmark --

.PHONY: bench_hlapi_dex # Run benchmarks for DEX operations
bench_hlapi_dex: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-dex \
	--features=integer,internal-keycache,pbs-stats,nightly-avx512 -p tfhe-benchmark --

.PHONY: bench_hlapi_dex_gpu # Run benchmarks for DEX operations on GPU
bench_hlapi_dex_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-dex \
	--features=integer,gpu,internal-keycache,pbs-stats,nightly-avx512 -p tfhe-benchmark --

.PHONY: bench_hlapi_erc20_hpu # Run benchmarks for ECR20 operations on HPU
bench_hlapi_erc20_hpu: install_rs_check_toolchain
	source ./setup_hpu.sh --config $(HPU_CONFIG) ; \
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,internal-keycache,hpu,hpu-v80 -p tfhe-benchmark -- --quick

.PHONY: bench_tfhe_zk_pok # Run benchmarks for the tfhe_zk_pok crate
bench_tfhe_zk_pok: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench -p tfhe-zk-pok --

#
# Utility tools
#

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo $(CARGO_RS_BUILD_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
		--example generates_test_keys \
		--features=boolean,shortint,experimental,internal-keycache -p $(TFHE_SPEC) \
		-- $(MULTI_BIT_ONLY) $(COVERAGE_ONLY)

.PHONY: gen_key_cache_core_crypto # Run function to generate keys and cache them for core_crypto tests
gen_key_cache_core_crypto: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --tests --profile $(CARGO_PROFILE) \
		--features=experimental,internal-keycache -p $(TFHE_SPEC) -- --nocapture \
		core_crypto::keycache::generate_keys

.PHONY: measure_hlapi_compact_pk_ct_sizes # Measure sizes of public keys and ciphertext for high-level API
measure_hlapi_compact_pk_ct_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--bin hlapi_compact_pk_ct_sizes \
	--features=integer,internal-keycache \
	-p tfhe-benchmark

.PHONY: measure_shortint_key_sizes # Measure sizes of bootstrapping and key switching keys for shortint
measure_shortint_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--bin shortint_key_sizes \
	--features=shortint,internal-keycache \
	-p tfhe-benchmark

.PHONY: measure_boolean_key_sizes # Measure sizes of bootstrapping and key switching keys for boolean
measure_boolean_key_sizes: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--bin boolean_key_sizes \
	--features=boolean,internal-keycache \
	-p tfhe-benchmark

.PHONY: parse_integer_benches # Run python parser to output a csv containing integer benches data
parse_integer_benches:
	python3 ./ci/parse_integer_benches_to_csv.py \
		--criterion-dir target/criterion \
		--output-file "$(PARSE_INTEGER_BENCH_CSV_FILE)"

.PHONY: parse_wasm_benchmarks # Parse benchmarks performed with WASM web client into a CSV file
parse_wasm_benchmarks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--bin wasm_benchmarks_parser \
	--features=shortint,internal-keycache \
	-p tfhe-benchmark \
	-- wasm_benchmark_results.json

.PHONY: write_params_to_file # Gather all crypto parameters into a file with a Sage readable format.
write_params_to_file: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run \
	--example write_params_to_file --features=boolean,shortint,internal-keycache

.PHONY: clone_backward_compat_data # Clone the data repo needed for backward compatibility tests
clone_backward_compat_data:
	./scripts/clone_backward_compat_data.sh $(BACKWARD_COMPAT_DATA_URL) $(BACKWARD_COMPAT_DATA_BRANCH) tests/$(BACKWARD_COMPAT_DATA_DIR)

tests/$(BACKWARD_COMPAT_DATA_DIR): clone_backward_compat_data

#
# Real use case examples
#

.PHONY: regex_engine # Run regex_engine example
regex_engine: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example regex_engine --features=integer \
	-- $(REGEX_STRING) $(REGEX_PATTERN)

.PHONY: dark_market # Run dark market example
dark_market: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example dark_market \
	--features=integer,internal-keycache \
	-- fhe-modified fhe-parallel plain fhe

.PHONY: sha256_bool # Run sha256_bool example
sha256_bool: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--example sha256_bool --features=boolean

.PHONY: pcc # pcc stands for pre commit checks (except GPU)
pcc: no_tfhe_typo no_dbg_log check_parameter_export_ok check_fmt check_typos lint_doc \
check_md_docs_are_tested check_intra_md_links clippy_all check_compile_tests test_tfhe_lints \
tfhe_lints

.PHONY: pcc_gpu # pcc stands for pre commit checks for GPU compilation
pcc_gpu: check_rust_bindings_did_not_change clippy_rustdoc_gpu \
clippy_gpu clippy_cuda_backend clippy_bench_gpu check_compile_tests_benches_gpu

.PHONY: pcc_hpu # pcc stands for pre commit checks for HPU compilation
pcc_hpu: clippy_hpu clippy_hpu_backend test_integer_hpu_mockup_ci_fast

.PHONY: fpcc # pcc stands for pre commit checks, the f stands for fast
fpcc: no_tfhe_typo no_dbg_log check_parameter_export_ok check_fmt check_typos lint_doc \
check_md_docs_are_tested clippy_fast check_compile_tests

.PHONY: conformance # Automatically fix problems that can be fixed
conformance: fix_newline fmt fmt_js

#=============================== FFT Section ==================================
.PHONY: doc_fft # Build rust doc for tfhe-fft
doc_fft: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--all-features --no-deps -p tfhe-fft

.PHONY: docs_fft # Build rust doc tfhe-fft, alias for doc
docs_fft: doc_fft

.PHONY: lint_doc_fft # Build rust doc for tfhe-fft with linting enabled
lint_doc_fft: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--all-features --no-deps -p tfhe-fft

.PHONY: lint_docs_fft # Build rust doc for tfhe-fft with linting enabled, alias for lint_doc
lint_docs_fft: lint_doc_fft

.PHONY: clippy_fft # Run clippy lints on tfhe-fft
clippy_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--all-features -p tfhe-fft -- --no-deps -D warnings

.PHONY: pcc_fft # pcc stands for pre commit checks
pcc_fft: check_fmt lint_doc_fft clippy_fft

.PHONY: build_fft
build_fft: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-fft
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-fft \
		--features=fft128

.PHONY: build_fft_no_std
build_fft_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-fft \
		--no-default-features
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-fft \
		--no-default-features \
		--features=fft128

##### Tests #####

.PHONY: test_fft
test_fft: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft \
		--features=fft128

.PHONY: test_fft_serde
test_fft_serde: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft \
		--features=serde
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft \
		--features=serde,fft128

.PHONY: test_fft_nightly
test_fft_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-fft \
		--features=nightly
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-fft \
		--features=nightly,fft128

.PHONY: test_fft_no_std
test_fft_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft \
		--no-default-features
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-fft \
		--no-default-features \
		--features=fft128

.PHONY: test_fft_no_std_nightly
test_fft_no_std_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-fft \
		--no-default-features \
		--features=nightly
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-fft \
		--no-default-features \
		--features=nightly,fft128

.PHONY: test_fft_node_js
test_fft_node_js: install_rs_build_toolchain install_build_wasm32_target install_wasm_bindgen_cli
	RUSTFLAGS="" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release \
		--features=serde --target wasm32-unknown-unknown -p tfhe-fft

.PHONY: test_fft_node_js_ci
test_fft_node_js_ci: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	"$(MAKE)" test_fft_node_js

.PHONY: test_fft_all
test_fft_all: test_fft test_fft_serde test_fft_nightly test_fft_no_std test_fft_no_std_nightly \
test_fft_node_js_ci

##### Bench #####

.PHONY: bench_fft # Run FFT benchmarks
bench_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" bench --bench fft -p tfhe-fft \
		--features=serde \
		--features=nightly \
		--features=fft128
#============================End FFT Section ==================================

#=============================== NTT Section ==================================
.PHONY: doc_ntt # Build rust doc for tfhe-ntt
doc_ntt: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--all-features --no-deps -p tfhe-ntt

.PHONY: docs_ntt # Build rust doc tfhe-ntt, alias for doc
docs_ntt: doc_ntt

.PHONY: lint_doc_ntt # Build rust doc for tfhe-ntt with linting enabled
lint_doc_ntt: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--all-features --no-deps -p tfhe-ntt

.PHONY: lint_docs_ntt # Build rust doc for tfhe-ntt with linting enabled, alias for lint_doc
lint_docs_ntt: lint_doc_ntt

.PHONY: clippy_ntt # Run clippy lints on tfhe-ntt
clippy_ntt: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--all-features -p tfhe-ntt -- --no-deps -D warnings

.PHONY: pcc_ntt # pcc stands for pre commit checks
pcc_ntt: check_fmt lint_doc_ntt clippy_ntt

.PHONY: build_ntt
build_ntt: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-ntt

.PHONY: build_ntt_no_std
build_ntt_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) build --release -p tfhe-ntt \
		--no-default-features

##### Tests #####

.PHONY: test_ntt
test_ntt: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-ntt

.PHONY: test_ntt_nightly
test_ntt_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-ntt \
		--features=nightly

.PHONY: test_ntt_no_std
test_ntt_no_std: install_rs_build_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_BUILD_TOOLCHAIN) test --release -p tfhe-ntt \
		--no-default-features

.PHONY: test_ntt_no_std_nightly
test_ntt_no_std_nightly: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --release -p tfhe-ntt \
		--no-default-features \
		--features=nightly

.PHONY: test_ntt_all
test_ntt_all: test_ntt test_ntt_no_std test_ntt_nightly test_ntt_no_std_nightly

##### Bench #####

.PHONY: bench_ntt # Run NTT benchmarks
bench_ntt: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" bench --bench ntt -p tfhe-ntt \
		--features=nightly
#============================End NTT Section ==================================

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
