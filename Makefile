SHELL:=$(shell /usr/bin/env which bash)
OS:=$(shell uname)
RS_CHECK_TOOLCHAIN:=$(shell cat nightly-toolchain.txt | tr -d '\n')
CARGO_RS_CHECK_TOOLCHAIN:=+$(RS_CHECK_TOOLCHAIN)
CARGO_BUILD_JOBS=default
CPU_COUNT=$(shell ./scripts/cpu_count.sh)
CARGO_PROFILE?=release
MIN_RUST_VERSION:=$(shell grep '^rust-version[[:space:]]*=' Cargo.toml | cut -d '=' -f 2 | xargs)
AVX512_SUPPORT?=OFF
WASM_RUSTFLAGS:=
BIG_TESTS_INSTANCE?=FALSE
GEN_KEY_CACHE_MULTI_BIT_ONLY?=FALSE
GEN_KEY_CACHE_COVERAGE_ONLY?=FALSE
PARSE_INTEGER_BENCH_CSV_FILE?=tfhe_rs_integer_benches.csv
FAST_TESTS?=FALSE
BIT_SIZES_SET?=ALL
NIGHTLY_TESTS?=FALSE
BENCH_OP_FLAVOR?=DEFAULT
BENCH_TYPE?=latency
BENCH_PARAM_TYPE?=classical
BENCH_PARAMS_SET?=default
BENCH_CUSTOM_COMMAND:=
NODE_VERSION=24.12
BACKWARD_COMPAT_DATA_DIR=utils/tfhe-backward-compat-data
BACKWARD_COMPAT_DATA_GEN_VERSION:=$(TFHE_VERSION)
TEST_VECTORS_DIR=apps/test-vectors
CURRENT_TFHE_VERSION:=$(shell grep '^version[[:space:]]*=' tfhe/Cargo.toml | cut -d '=' -f 2 | xargs)
WASM_PACK_VERSION="0.13.1"
WASM_BINDGEN_VERSION:=$(shell cargo tree --target wasm32-unknown-unknown -e all --prefix none | grep "wasm-bindgen v" | head -n 1 | cut -d 'v' -f2)
WEB_RUNNER_DIR=web-test-runner
WEB_SERVER_DIR=tfhe/web_wasm_parallel_tests
TAPLO_VERSION=0.10.0
TYPOS_VERSION=1.42.0
ZIZMOR_VERSION=1.20.0
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
ZKCUDA_SRC=backends/zk-cuda-backend/cuda
ZKCUDA_BUILD=$(ZKCUDA_SRC)/build
ZKCUDARS_SRC=backends/zk-cuda-backend/src

# tfhe-hpu-backend
HPU_CONFIG=v80
V80_PCIE_DEV?=01

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

# Prints out recipe name at the beginning of the execution and print it out again at the end if a failure occurs.
define run_recipe_with_details
	@echo "Running recipe: $1"
	@$(MAKE) $1 --no-print-directory || { echo "Recipe '$@' failed"; exit 1; }
endef

.PHONY: rs_check_toolchain # Echo the rust toolchain used for checks
rs_check_toolchain:
	@echo $(RS_CHECK_TOOLCHAIN)

.PHONY: install_rs_check_toolchain # Install the toolchain used for checks
install_rs_check_toolchain:
	@rustup toolchain list | grep -q "$(RS_CHECK_TOOLCHAIN)" || \
	rustup toolchain install --profile default "$(RS_CHECK_TOOLCHAIN)" || \
	( echo "Unable to install $(RS_CHECK_TOOLCHAIN) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_rs_latest_nightly_toolchain # Install the nightly toolchain used to build docs using same version as docs.rs
# We don't check that it exists, because we always want the latest
# and the command below will install/update
install_rs_latest_nightly_toolchain:
	rustup toolchain install --profile default nightly  || \
	( echo "Unable to install nightly  toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_rs_msrv_toolchain # Install the msrv toolchain
install_rs_msrv_toolchain:
	@rustup toolchain install --profile default "$(MIN_RUST_VERSION)" || \
	( echo "Unable to install $(MIN_RUST_VERSION) toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_build_wasm32_target # Install the wasm32 toolchain used for builds
install_build_wasm32_target:
	rustup target add wasm32-unknown-unknown || \
	( echo "Unable to install wasm32-unknown-unknown target toolchain, check your rustup installation. \
	Rustup can be downloaded at https://rustup.rs/" && exit 1 )

.PHONY: install_cargo_nextest # Install cargo nextest used for shortint tests
install_cargo_nextest:
	@cargo nextest --version > /dev/null 2>&1 || \
	cargo install cargo-nextest --locked || \
	( echo "Unable to install cargo nextest, unknown error." && exit 1 )

.PHONY: install_wasm_bindgen_cli # Install wasm-bindgen-cli to get access to the test runner
install_wasm_bindgen_cli:
	cargo install --locked wasm-bindgen-cli --version "$(WASM_BINDGEN_VERSION)"

.PHONY: check_default_toolchain_msrv # Check that the toolchain in `rust-toolchain.toml` matches the MSRV
check_default_toolchain_msrv:
	./scripts/check_default_toolchain_msrv.sh

.PHONY: install_wasm_pack # Install wasm-pack to build JS packages
install_wasm_pack:
	@wasm-pack --version | grep "$(WASM_PACK_VERSION)" > /dev/null 2>&1 || \
	cargo install --locked wasm-pack@$(WASM_PACK_VERSION) || \
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
install_tarpaulin:
	@cargo tarpaulin --version > /dev/null 2>&1 || \
	cargo install cargo-tarpaulin --locked || \
	( echo "Unable to install cargo tarpaulin, unknown error." && exit 1 )

.PHONY: install_cargo_dylint # Install custom tfhe-rs lints
install_cargo_dylint:
	cargo install --locked cargo-dylint dylint-link

.PHONY: install_cargo_audit # Check dependencies
install_cargo_audit:
	cargo install --locked cargo-audit

.PHONY: install_taplo # Check Cargo.toml format
install_taplo:
	@./scripts/install_taplo.sh --taplo-version $(TAPLO_VERSION)

.PHONY: install_typos_checker # Install typos checker
install_typos_checker:
	@./scripts/install_typos.sh --typos-version $(TYPOS_VERSION)

.PHONY: install_zizmor # Install zizmor workflow security checker
install_zizmor:
	@./scripts/install_zizmor.sh --zizmor-version $(ZIZMOR_VERSION)

.PHONY: zizmor_version  # Return zizmor version that will be installed
zizmor_version:
	@echo "$(ZIZMOR_VERSION)"

.PHONY: install_cargo_cross # Install cross for big endian tests
install_cargo_cross:
	cargo install --locked cross

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
install_mlc:
	@mlc --version > /dev/null 2>&1 || \
	cargo install mlc --locked || \
	( echo "Unable to install mlc, unknown error." && exit 1 )

.PHONY: fmt # Format rust code
fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C $(BACKWARD_COMPAT_DATA_DIR) fmt
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C utils/tfhe-lints fmt
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C apps/trivium fmt

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
	cd "$(ZKCUDA_SRC)" && ./format_zk_cuda_backend.sh

.PHONY: fmt_c_tests # Format c tests
fmt_c_tests:
	find tfhe/c_api_tests/ -regex '.*\.\(cpp\|hpp\|cu\|c\|h\)' -exec clang-format -style=file -i {} \;

.PHONY: fmt_toml # Format TOML files
fmt_toml: install_taplo
	taplo fmt

.PHONY: check_fmt # Check rust code format
check_fmt: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C $(BACKWARD_COMPAT_DATA_DIR) fmt --check
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C utils/tfhe-lints fmt --check
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options -C apps/trivium fmt --check

.PHONY: check_fmt_c_tests  # Check C tests format
check_fmt_c_tests:
	find tfhe/c_api_tests/ -regex '.*\.\(cpp\|hpp\|cu\|c\|h\)' -exec clang-format --dry-run --Werror -style=file {} \;

.PHONY: check_fmt_gpu # Check rust and cuda code format
check_fmt_gpu: install_rs_check_toolchain
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" fmt --check
	cd "$(TFHECUDA_SRC)" && ./format_tfhe_cuda_backend.sh -c
	cd "$(ZKCUDA_SRC)" && ./format_zk_cuda_backend.sh -c

.PHONY: check_fmt_js # Check javascript code format
check_fmt_js: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) -C tfhe/web_wasm_parallel_tests check_fmt && \
	$(MAKE) -C tfhe/js_on_wasm_tests check_fmt

.PHONY: check_fmt_toml # Check TOML files format
check_fmt_toml: install_taplo
	@RUST_LOG=warn taplo fmt --check || \
	echo "TOML files format check failed. Please run 'make fmt_toml'"

.PHONY: check_typos # Check for typos in codebase
check_typos: install_typos_checker
	@typos && echo "No typos found"

.PHONY: clippy_gpu # Run clippy lints on tfhe with "gpu" enabled
clippy_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,gpu,pbs-stats,extended-types,zk-pok \
		--all-targets \
		-p tfhe -- --no-deps -D warnings

.PHONY: check_gpu # Run check on tfhe with "gpu" enabled
check_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" check \
		--features=boolean,shortint,integer,internal-keycache,gpu,pbs-stats \
		--all-targets \
		-p tfhe

.PHONY: clippy_hpu # Run clippy lints on tfhe with "hpu" enabled
clippy_hpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,hpu,pbs-stats,extended-types \
		--all-targets \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_gpu_hpu # Run clippy lints on tfhe with "gpu" and "hpu" enabled
clippy_gpu_hpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean,shortint,integer,internal-keycache,gpu,hpu,pbs-stats,extended-types,zk-pok \
		--all-targets \
		-p tfhe -- --no-deps -D warnings

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
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=experimental \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--no-default-features \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--no-default-features \
		--features=experimental \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=zk-pok \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_boolean # Run clippy lints enabling the boolean features
clippy_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_shortint # Run clippy lints enabling the shortint features
clippy_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=shortint \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=shortint,experimental \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=zk-pok,shortint \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_integer # Run clippy lints enabling the integer features
clippy_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer,experimental \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=integer,experimental,extended-types \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy # Run clippy lints enabling the boolean, shortint, integer
clippy: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_rustdoc # Run clippy lints on doctests enabling the boolean, shortint, integer and zk-pok
clippy_rustdoc: install_rs_check_toolchain
	if [[ "$(OS)" != "Linux" && "$(OS)" != "Darwin" ]]; then \
		echo "WARNING: skipped clippy_rustdoc, unsupported OS $(OS)"; \
		exit 0; \
	fi && \
	CARGO_TERM_QUIET=true CLIPPYFLAGS="-D warnings" RUSTDOCFLAGS="--no-run --test-builder ./scripts/clippy_driver.sh -Z unstable-options" \
		cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" test --doc \
		--features=boolean,shortint,integer,zk-pok,pbs-stats,strings,experimental \
		-p tfhe -- --nocapture

.PHONY: clippy_rustdoc_gpu # Run clippy lints on doctests enabling the boolean, shortint, integer and zk-pok
clippy_rustdoc_gpu: install_rs_check_toolchain
	if [[ "$(OS)" != "Linux" ]]; then \
		echo "WARNING: skipped clippy_rustdoc_gpu, unsupported OS $(OS)"; \
		exit 0; \
	fi && \
	CARGO_TERM_QUIET=true CLIPPYFLAGS="-D warnings" RUSTDOCFLAGS="--no-run --test-builder ./scripts/clippy_driver.sh -Z unstable-options" \
		cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" test --doc \
		--features=boolean,shortint,integer,zk-pok,pbs-stats,strings,experimental,gpu \
		-p tfhe -- --nocapture

.PHONY: clippy_c_api # Run clippy lints enabling the boolean, shortint and the C API
clippy_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,extended-types \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_js_wasm_api # Run clippy lints enabling the boolean, shortint, integer and the js wasm API
clippy_js_wasm_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,high-level-client-js-wasm-api,zk-pok,extended-types \
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,high-level-client-js-wasm-api,extended-types \
		-p tfhe -- --no-deps -D warnings

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
		-p tfhe -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=boolean,shortint,integer,internal-keycache,zk-pok,strings,pbs-stats,extended-types,experimental \
		-p tfhe -- --no-deps -D warnings

.PHONY: clippy_tfhe_csprng # Run clippy lints on tfhe-csprng
clippy_tfhe_csprng: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=parallel,software-prng -p tfhe-csprng -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=parallel -p tfhe-csprng -- --no-deps -D warnings

.PHONY: clippy_zk_pok # Run clippy lints on tfhe-zk-pok
clippy_zk_pok: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-zk-pok -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-zk-pok --features=experimental -- --no-deps -D warnings

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

.PHONY: clippy_wasm_par_mq # Run clippy lints on wasm-par-mq and its examples
clippy_wasm_par_mq: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets --all-features \
		-p wasm-par-mq -p wasm-par-mq-web-tests -p wasm-par-mq-example-msm -- --no-deps -D warnings

.PHONY: clippy_backward_compat_data # Run clippy lints on tfhe-backward-compat-data
clippy_backward_compat_data: install_rs_check_toolchain # the toolchain is selected with toolchain.toml
	@# Some old crates are x86 specific, only run in that case
	@if uname -a | grep -q x86; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options \
			-C $(BACKWARD_COMPAT_DATA_DIR) clippy --all --all-targets \
			-- --no-deps -D warnings; \
		for crate in `ls -1 $(BACKWARD_COMPAT_DATA_DIR)/crates/ | grep generate_`; do \
			echo "checking $$crate"; \
			RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" -Z unstable-options \
				-C $(BACKWARD_COMPAT_DATA_DIR)/crates/$$crate clippy --all --all-targets -- --no-deps -D warnings; \
		done \
	else \
		echo "Cannot run clippy for backward compat crate on non x86 platform for now."; \
	fi

.PHONY: clippy_test_vectors # Run clippy lints on the test vectors app
clippy_test_vectors: install_rs_check_toolchain
	cd apps/test-vectors; RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-test-vectors -- --no-deps -D warnings

.PHONY: clippy_all # Run all clippy targets
clippy_all: clippy_rustdoc clippy clippy_boolean clippy_shortint clippy_integer clippy_all_targets \
clippy_c_api clippy_js_wasm_api clippy_tasks clippy_core clippy_tfhe_csprng clippy_zk_pok clippy_trivium \
clippy_versionable clippy_tfhe_lints clippy_ws_tests clippy_bench clippy_param_dedup \
clippy_test_vectors clippy_backward_compat_data clippy_wasm_par_mq

.PHONY: clippy_fast # Run main clippy targets
clippy_fast: clippy_rustdoc clippy clippy_all_targets clippy_c_api clippy_js_wasm_api clippy_tasks \
clippy_core clippy_tfhe_csprng

.PHONY: clippy_cuda_backend # Run clippy lints on the tfhe-cuda-backend
clippy_cuda_backend: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-cuda-backend -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p zk-cuda-backend -- --no-deps -D warnings

.PHONY: clippy_hpu_backend # Run clippy lints on the tfhe-hpu-backend
clippy_hpu_backend: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-hpu-backend -- --no-deps -D warnings

.PHONY: clippy_hpu_mockup # Run clippy lints on tfhe-hpu-mockup
clippy_hpu_mockup: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy \
		--all-targets \
		-p tfhe-hpu-mockup -- --no-deps -D warnings

.PHONY: check_rust_bindings_did_not_change # Check rust bindings are up to date for tfhe-cuda-backend
check_rust_bindings_did_not_change:
	cargo build -p tfhe-cuda-backend && "$(MAKE)" fmt_gpu && \
	git diff --quiet HEAD -- backends/tfhe-cuda-backend/src/bindings.rs || \
	( echo "Generated bindings have changed! Please run 'git add backends/tfhe-cuda-backend/src/bindings.rs' \
	and commit the changes." && exit 1 )


.PHONY: tfhe_lints # Run custom tfhe-rs lints
tfhe_lints: install_cargo_dylint
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo dylint --all -p tfhe --no-deps -- \
		--features=boolean,shortint,integer,strings,zk-pok
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo dylint --all -p tfhe-zk-pok --no-deps -- \
		--features=experimental

.PHONY: audit_dependencies # Run cargo audit to check vulnerable dependencies
audit_dependencies: install_cargo_audit
	cargo audit


.PHONY: build_core # Build core_crypto without experimental features
build_core:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--no-default-features -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
			--features=avx512 -p tfhe; \
	fi

.PHONY: build_core_experimental # Build core_crypto with experimental features
build_core_experimental:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--no-default-features --features=experimental -p tfhe
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
			--features=experimental,avx512 -p tfhe; \
	fi

.PHONY: build_boolean # Build with boolean enabled
build_boolean:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--features=boolean -p tfhe --all-targets

.PHONY: build_shortint # Build with shortint enabled
build_shortint:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --all-targets

.PHONY: build_integer # Build with integer enabled
build_integer:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--features=integer -p tfhe --all-targets

.PHONY: build_tfhe_full # Build with boolean, shortint and integer enabled
build_tfhe_full:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer -p tfhe --all-targets

.PHONY: build_tfhe_coverage # Build with test coverage enabled
build_tfhe_coverage:
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo build --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache -p tfhe --tests

# As of 05/08/2025 this is the set of features that can be easily compiled without additional
# toolkits
.PHONY: build_tfhe_msrv # Build with msrv compiler
build_tfhe_msrv:
	RUSTFLAGS="$(RUSTFLAGS)" cargo +$(MIN_RUST_VERSION) build --profile dev \
		--features=boolean,extended-types,hpu,hpu-debug \
		--features=hpu-v80,integer,noise-asserts \
		--features=pbs-stats,shortint,strings,zk-pok -p tfhe

.PHONY: build_c_api # Build the C API for boolean, shortint and integer
build_c_api: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,extended-types \
		-p tfhe

.PHONY: build_c_api_gpu # Build the C API for boolean, shortint and integer
build_c_api_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,extended-types,gpu \
		-p tfhe

.PHONY: build_c_api_experimental_deterministic_fft # Build the C API for boolean, shortint and integer with experimental deterministic FFT
build_c_api_experimental_deterministic_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) build --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api,zk-pok,experimental-force_fft_algo_dif4 \
		-p tfhe

.PHONY: build_web_js_api # Build the js API targeting the web browser
build_web_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok,extended-types

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
# parallel wasm requires specific build options, see https://github.com/rust-lang/rust/pull/147225
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) -C target-feature=+atomics,+bulk-memory \
		-Clink-arg=--shared-memory \
		-Clink-arg=--max-memory=1073741824 \
		-Clink-arg=--import-memory \
		-Clink-arg=--export=__wasm_init_tls \
		-Clink-arg=--export=__tls_size \
		-Clink-arg=--export=__tls_align \
		-Clink-arg=--export=__tls_base" \
		rustup run $(RS_CHECK_TOOLCHAIN) wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,parallel-wasm-api,zk-pok,extended-types \
		-Z build-std=panic_abort,std && \
	find pkg/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=nodejs \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok,extended-types

.PHONY: build_tfhe_csprng # Build tfhe_csprng
build_tfhe_csprng:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --profile $(CARGO_PROFILE) \
		-p tfhe-csprng --all-targets

.PHONY: test_core_crypto # Run the tests of the core_crypto module including experimental ones
test_core_crypto:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--no-default-features --features=experimental,zk-pok -p tfhe -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
			--features=experimental,zk-pok -p tfhe -- core_crypto::; \
	fi

.PHONY: test_core_crypto_cov # Run the tests of the core_crypto module with code coverage
test_core_crypto_cov: install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/core_crypto --line --engine llvm --timeout 500 \
		--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
		--no-default-features \
		--features=experimental,internal-keycache \
		-p tfhe -- core_crypto::
	@if [[ "$(AVX512_SUPPORT)" == "ON" ]]; then \
		RUSTFLAGS="$(RUSTFLAGS)" cargo tarpaulin --profile $(CARGO_PROFILE) \
			--out xml --output-dir coverage/core_crypto_avx512 --line --engine llvm --timeout 500 \
			--implicit-test-threads $(COVERAGE_EXCLUDED_FILES) \
			--features=experimental,internal-keycache,avx512 \
			-p tfhe -- -Z unstable-options --report-time core_crypto::; \
	fi

.PHONY: test_cuda_backend # Run the internal tests of the CUDA backend
test_cuda_backend:
	mkdir -p "$(TFHECUDA_BUILD)" && \
		cd "$(TFHECUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Release -DTFHE_CUDA_BACKEND_BUILD_TESTS=ON && \
		"$(MAKE)" -j "$(CPU_COUNT)" && \
		"$(MAKE)" test

.PHONY: test_zk_cuda_backend # Run the internal tests of the CUDA ZK backend
test_zk_cuda_backend:
	mkdir -p "$(ZKCUDA_BUILD)" && \
		cd "$(ZKCUDA_BUILD)" && \
		cmake .. -DCMAKE_BUILD_TYPE=Release -DZK_CUDA_BACKEND_BUILD_TESTS=ON && \
		"$(MAKE)" -j "$(CPU_COUNT)" && \
		"$(MAKE)" test
	cd "$(ZKCUDARS_SRC)" && \
		cargo test --release


.PHONY: test_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_gpu: test_core_crypto_gpu test_integer_gpu test_cuda_backend

.PHONY: test_core_crypto_gpu # Run the tests of the core_crypto module including experimental on the gpu backend
test_core_crypto_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=gpu -p tfhe -- core_crypto::gpu::
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --doc --profile $(CARGO_PROFILE) \
		--features=gpu -p tfhe -- core_crypto::gpu::

.PHONY: test_integer_gpu # Run the tests of the integer module including experimental on the gpu backend
test_integer_gpu: install_cargo_nextest
	TEST_THREADS=2 \
	DOCTEST_THREADS=4 \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--tfhe-package "tfhe" --all-but-noise

.PHONY: test_integer_gpu_debug # Run the tests of the integer module with Debug flags for CUDA
test_integer_gpu_debug:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile release_lto_off \
		--features=integer,gpu-debug -vv -p tfhe -- integer::gpu::server_key:: --test-threads=1 --nocapture
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --doc --profile release_lto_off \
		--features=integer,gpu-debug -p tfhe -- integer::gpu::server_key::

.PHONY: test_high_level_api_gpu_valgrind # Run the tests of the integer module with Debug flags for CUDA
test_high_level_api_gpu_valgrind: install_cargo_nextest
	export RUSTFLAGS="-C target-cpu=x86-64" && \
	export CARGO_PROFILE="$(CARGO_PROFILE)" &&	scripts/check_memory_errors.sh --cpu

.PHONY: test_high_level_api_gpu_sanitizer # Run the tests of the integer module with Debug flags for CUDA
test_high_level_api_gpu_sanitizer: install_cargo_nextest
	export RUSTFLAGS="-C target-cpu=x86-64" && \
	export CARGO_PROFILE="$(CARGO_PROFILE)" &&	scripts/check_memory_errors.sh --gpu

.PHONY: test_integer_hl_test_gpu_check_warnings
test_integer_hl_test_gpu_check_warnings:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build \
		--features=integer,internal-keycache,gpu-debug,zk-pok -vv -p tfhe &> /tmp/gpu_compile_output
	WARNINGS=$$(cat /tmp/gpu_compile_output | grep ": warning #" | grep "\[tfhe-cuda-backend" | grep -v "inline qualifier" || true) && \
	if [[ "$${WARNINGS}" != "" ]]; then \
	    echo "FAILING BECAUSE CUDA COMPILATION WARNINGS WERE DETECTED: " && \
		echo "$${WARNINGS}" && exit 1; \
	fi


.PHONY: test_integer_long_run_gpu # Run the long run integer tests on the gpu backend
test_integer_long_run_gpu: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	LONG_TESTS=TRUE \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "tfhe" --backend "gpu"

.PHONY: test_integer_short_run_gpu # Run the long run integer tests on the gpu backend
test_integer_short_run_gpu: install_cargo_nextest
	TFHE_RS_TEST_LONG_TESTS_MINIMAL=TRUE \
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p tfhe -- integer::gpu::server_key::radix::tests_long_run::test_random_op_sequence integer::gpu::server_key::radix::tests_long_run::test_signed_random_op_sequence --test-threads=1 --nocapture

.PHONY: build_debug_integer_short_run_gpu # Run the long run integer tests on the gpu backend
build_debug_integer_short_run_gpu: install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo test -vv --no-run --profile debug_lto_off \
		--features=integer,gpu-debug-fake-multi-gpu -p tfhe
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile debug_lto_off \
		--features=integer,gpu-debug-fake-multi-gpu -p tfhe -- integer::gpu::server_key::radix::tests_long_run::test_random_op_sequence::test_gpu_short_random --list
	@echo "To debug fake-multi-gpu short run tests run:"
	@echo "TFHE_RS_LONGRUN_TESTS_SEED=<SEED_FROM_CI> TFHE_RS_TEST_LONG_TESTS_MINIMAL=TRUE <executable> integer::gpu::server_key::radix::tests_long_run::test_random_op_sequence::test_gpu_short_random_op_sequence_param_gpu_multi_bit_group_4_message_2_carry_2_ks_pbs_tuniform_2m128 --nocapture"
	@echo "Where <executable> = the one printed in the () in the 'Running unittests src/lib.rs ()' line above"

.PHONY: test_integer_compression
test_integer_compression:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=integer -p tfhe -- integer::ciphertext::compressed_ciphertext_list::tests::
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --doc --profile $(CARGO_PROFILE) \
		--features=integer -p tfhe -- integer::ciphertext::compress

.PHONY: test_integer_compression_gpu
test_integer_compression_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p tfhe -- integer::gpu::ciphertext::compressed_ciphertext_list::tests::
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --doc --profile $(CARGO_PROFILE) \
		--features=integer,gpu -p tfhe -- integer::gpu::ciphertext::compress

.PHONY: test_integer_gpu_ci # Run the tests for integer ci on gpu backend
test_integer_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--tfhe-package "tfhe"

.PHONY: test_unsigned_integer_gpu_ci # Run the tests for unsigned integer ci on gpu backend
test_unsigned_integer_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--unsigned-only --tfhe-package "tfhe"

.PHONY: test_signed_integer_gpu_ci # Run the tests for signed integer ci on gpu backend
test_signed_integer_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --backend "gpu" \
		--signed-only --tfhe-package "tfhe"

.PHONY: test_integer_multi_bit_gpu_ci # Run the tests for integer ci on gpu backend running only multibit tests
test_integer_multi_bit_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--tfhe-package "tfhe"

.PHONY: test_unsigned_integer_multi_bit_gpu_ci # Run the tests for unsigned integer ci on gpu backend running only multibit tests
test_unsigned_integer_multi_bit_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--unsigned-only --tfhe-package "tfhe"

.PHONY: test_signed_integer_multi_bit_gpu_ci # Run the tests for signed integer ci on gpu backend running only multibit tests
test_signed_integer_multi_bit_gpu_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --backend "gpu" \
		--signed-only --tfhe-package "tfhe"

.PHONY: test_integer_hpu_ci # Run the tests for integer ci on hpu backend
test_integer_hpu_ci: install_cargo_nextest
	cargo test --release -p tfhe --features hpu-v80 --test hpu

.PHONY: test_integer_hpu_mockup_ci # Run the tests for integer ci on hpu backend and mockup
test_integer_hpu_mockup_ci: install_cargo_nextest
	source ./setup_hpu.sh --config sim ; \
	cargo build --release --bin hpu_mockup; \
	coproc target/release/hpu_mockup --params mockups/tfhe-hpu-mockup/params/tuniform_64b_pfail64_psi64.toml > mockup.log; \
	HPU_TEST_ITER=1 \
	cargo test --profile devo -p tfhe --features hpu --test hpu -- u32 && \
	kill %1

.PHONY: test_integer_hpu_mockup_ci_fast # Run the quick tests for integer ci on hpu backend and mockup.
test_integer_hpu_mockup_ci_fast: install_cargo_nextest
	source ./setup_hpu.sh --config sim ; \
	cargo build --profile devo --bin hpu_mockup; \
	coproc target/devo/hpu_mockup --params mockups/tfhe-hpu-mockup/params/tuniform_64b_fast.toml > mockup.log; \
	HPU_TEST_ITER=1 \
	cargo test --profile devo -p tfhe --features hpu --test hpu -- u32 && \
	kill %1

.PHONY: test_boolean # Run the tests of the boolean module
test_boolean:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean -p tfhe -- boolean::

.PHONY: test_boolean_cov # Run the tests of the boolean module with code coverage
test_boolean_cov: install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/boolean --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=boolean,internal-keycache \
		-p tfhe -- -Z unstable-options --report-time boolean::

.PHONY: test_c_api_rs # Run the rust tests for the C API
test_c_api_rs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) test --profile $(CARGO_PROFILE) \
		--features=boolean-c-api,shortint-c-api,high-level-c-api \
		-p tfhe \
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
test_shortint_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --tfhe-package "tfhe"

.PHONY: test_shortint_multi_bit_ci # Run the tests for shortint ci running only multibit tests
test_shortint_multi_bit_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
		./scripts/shortint-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --tfhe-package "tfhe"

.PHONY: test_shortint # Run all the tests for shortint
test_shortint:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint,internal-keycache -p tfhe -- shortint::

.PHONY: test_shortint_cov # Run the tests of the shortint module with code coverage
test_shortint_cov: install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/shortint --line --engine llvm --timeout 500 \
		$(COVERAGE_EXCLUDED_FILES) \
		--features=shortint,internal-keycache \
		-p tfhe -- -Z unstable-options --report-time shortint::

.PHONY: test_integer_ci # Run the tests for integer ci
test_integer_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "tfhe"

.PHONY: test_unsigned_integer_ci # Run the tests for unsigned integer ci
test_unsigned_integer_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "tfhe"

.PHONY: test_signed_integer_ci # Run the tests for signed integer ci
test_signed_integer_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "tfhe"

.PHONY: test_integer_multi_bit_ci # Run the tests for integer ci running only multibit tests
test_integer_multi_bit_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "tfhe"

.PHONY: test_unsigned_integer_multi_bit_ci # Run the tests for unsigned integer ci running only multibit tests
test_unsigned_integer_multi_bit_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--unsigned-only --tfhe-package "tfhe"

.PHONY: test_signed_integer_multi_bit_ci # Run the tests for signed integer ci running only multibit tests
test_signed_integer_multi_bit_ci: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	FAST_TESTS="$(FAST_TESTS)" \
	NIGHTLY_TESTS="$(NIGHTLY_TESTS)" \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --multi-bit --avx512-support "$(AVX512_SUPPORT)" \
		--signed-only --tfhe-package "tfhe"

.PHONY: test_integer_long_run # Run the long run integer tests
test_integer_long_run: install_cargo_nextest
	BIG_TESTS_INSTANCE="$(BIG_TESTS_INSTANCE)" \
	LONG_TESTS=TRUE \
		./scripts/integer-tests.sh \
		--cargo-profile "$(CARGO_PROFILE)" --avx512-support "$(AVX512_SUPPORT)" \
		--tfhe-package "tfhe"

.PHONY: test_noise_check # Run dedicated noise and pfail check tests
test_noise_check:
	@# First run the sanity checks to make sure the atomic patterns are correct
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer -p tfhe -- sanity_check
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer -p tfhe -- noise_check \
		--test-threads=1 --nocapture

.PHONY: test_noise_check_gpu # Run dedicated noise and pfail check tests on gpu backend
test_noise_check_gpu:
	@# First run the sanity checks to make sure the atomic patterns are correct
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,gpu -p tfhe -- gpu_sanity_check
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,gpu -p tfhe -- gpu_noise_check \
		--test-threads=1 --nocapture

.PHONY: test_safe_serialization # Run the tests for safe serialization
test_safe_serialization: install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache -p tfhe -- safe_serialization::

.PHONY: test_zk # Run the tests for the zk module of the TFHE-rs crate
test_zk: install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint,zk-pok -p tfhe -- zk::

.PHONY: test_integer # Run all the tests for integer
test_integer:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=integer,internal-keycache -p tfhe -- integer::

.PHONY: test_integer_cov # Run the tests of the integer module with code coverage
test_integer_cov: install_tarpaulin
	RUSTFLAGS="$(RUSTFLAGS)" cargo tarpaulin --profile $(CARGO_PROFILE) \
		--out xml --output-dir coverage/integer --line --engine llvm --timeout 500 \
		--implicit-test-threads \
		--exclude-files $(COVERAGE_EXCLUDED_FILES) \
		--features=integer,internal-keycache \
		-p tfhe -- -Z unstable-options --report-time integer::

.PHONY: test_high_level_api # Run all the tests for high_level_api
test_high_level_api:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,internal-keycache,zk-pok,strings -p tfhe \
		-- high_level_api::

test_high_level_api_gpu_fast: install_cargo_nextest # Run all the GPU tests for high_level_api except test_uniformity for oprf which is too long
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--test-threads=4 --features=integer,internal-keycache,gpu,zk-pok -p tfhe \
	  -E "test(/high_level_api::.*gpu.*/) and not test(/uniformity/)"


test_high_level_api_gpu: install_cargo_nextest # Run all the GPU tests for high_level_api
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--test-threads=4 --features=integer,internal-keycache,gpu,zk-pok -p tfhe \
		-E "test(/high_level_api::.*gpu.*/)"

test_list_gpu: install_cargo_nextest
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest list --cargo-profile $(CARGO_PROFILE) \
		--features=integer,internal-keycache,gpu,zk-pok -p tfhe \
		-E "test(/.*gpu.*/)"

.PHONY: build_one_hl_api_test_gpu
build_one_hl_api_test_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --no-run \
		   --features=integer,gpu-debug -vv -p tfhe -- "$${TEST}" --test-threads=1 --nocapture

.PHONY: build_one_hl_api_test_fake_multi_gpu
build_one_hl_api_test_fake_multi_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --no-run \
		   --features=integer,gpu-debug-fake-multi-gpu -vv -p tfhe -- "$${TEST}" --test-threads=1 --nocapture

test_high_level_api_hpu: install_cargo_nextest
ifeq ($(HPU_CONFIG), v80)
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--build-jobs=$(CARGO_BUILD_JOBS) \
		--test-threads=1 \
		--features=integer,internal-keycache,hpu,hpu-v80 -p tfhe \
		-E "test(/high_level_api::.*hpu.*/)"
else
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--build-jobs=$(CARGO_BUILD_JOBS) \
		--test-threads=1 \
		--features=integer,internal-keycache,hpu -p tfhe \
		-E "test(/high_level_api::.*hpu.*/)"
endif


.PHONY: test_strings # Run the tests for strings ci
test_strings:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint,integer,strings -p tfhe \
		-- strings::


.PHONY: test_user_doc # Run tests from the .md documentation
test_user_doc:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) --doc \
		--features=boolean,shortint,integer,internal-keycache,pbs-stats,zk-pok,strings \
		-p tfhe \
		-- test_user_docs::

.PHONY: test_user_doc_gpu # Run tests for GPU from the .md documentation
test_user_doc_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,zk-pok,gpu -p tfhe \
		-- test_user_docs::

.PHONY: test_user_doc_hpu # Run tests for HPU from the .md documentation
test_user_doc_hpu:
ifeq ($(HPU_CONFIG), v80)
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,hpu,hpu-v80 -p tfhe \
		-- test_user_docs::
else
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) --doc \
		--features=internal-keycache,integer,hpu -p tfhe \
		-- test_user_docs::
endif



.PHONY: test_regex_engine # Run tests for regex_engine example
test_regex_engine:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--example regex_engine --features=integer

.PHONY: test_sha256_bool # Run tests for sha256_bool example
test_sha256_bool:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--example sha256_bool --features=boolean

.PHONY: test_examples # Run tests for examples
test_examples: test_sha256_bool test_regex_engine

.PHONY: test_trivium # Run tests for trivium
test_trivium:
	cd apps/trivium; RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe-trivium -- --test-threads=1 trivium::

.PHONY: test_kreyvium # Run tests for kreyvium
test_kreyvium:
	cd apps/trivium; RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe-trivium -- --test-threads=1 kreyvium::

.PHONY: test_tfhe_csprng # Run tfhe-csprng tests
test_tfhe_csprng:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe-csprng

.PHONY: test_tfhe_csprng_big_endian # Run tfhe-csprng tests on an emulated big endian system
test_tfhe_csprng_big_endian: install_cargo_cross
	RUSTFLAGS="" cross test --profile $(CARGO_PROFILE) \
		-p tfhe-csprng --target=powerpc64-unknown-linux-gnu


.PHONY: test_zk_pok # Run tfhe-zk-pok tests
test_zk_pok:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe-zk-pok --features experimental

.PHONY: test_zk_wasm_x86_compat_ci
test_zk_wasm_x86_compat_ci: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_zk_wasm_x86_compat

.PHONY: test_zk_wasm_x86_compat # Check compatibility between wasm and x86_64 proofs
test_zk_wasm_x86_compat: build_node_js_api
	cd tfhe/tests/zk_wasm_x86_test && npm install
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe --test zk_wasm_x86_test --features=integer,zk-pok

.PHONY: test_versionable # Run tests for tfhe-versionable subcrate
test_versionable:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--all-targets -p tfhe-versionable

.PHONY: test_tfhe_lints # Run test on tfhe-lints
test_tfhe_lints: install_cargo_dylint
	cd utils/tfhe-lints && \
	rustup toolchain install && \
	cargo test

# The backward compat data folder holds historical binary data but also rust code to generate and load them.
.PHONY: gen_backward_compat_data # Re-generate backward compatibility data
gen_backward_compat_data:
	$(BACKWARD_COMPAT_DATA_DIR)/gen_data.sh $(BACKWARD_COMPAT_DATA_GEN_VERSION)

# Instantiate a new backward data crate for the current TFHE-rs version, if it does not already exists
.PHONY: new_backward_compat_crate
new_backward_compat_crate:
	cd $(BACKWARD_COMPAT_DATA_DIR) && cargo run -p add_new_version -- --tfhe-version $(CURRENT_TFHE_VERSION)

.PHONY: test_backward_compatibility_ci
test_backward_compatibility_ci:
	TFHE_BACKWARD_COMPAT_DATA_DIR="../$(BACKWARD_COMPAT_DATA_DIR)" RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint,integer,zk-pok -p tests test_backward_compatibility -- --nocapture

.PHONY: test_backward_compatibility # Same as test_backward_compatibility_ci but tries to clone the data repo first if needed
test_backward_compatibility: pull_backward_compat_data test_backward_compatibility_ci

# Generate the test vectors and update the hash file
.PHONY: gen_test_vectors
gen_test_vectors:
	./scripts/test_vectors.sh generate apps/test-vectors

# Generate the test vectors and check that the content matches the hash file
# `comm` is used to compare the checksums, and will also notify of any added file
.PHONY: check_test_vectors
check_test_vectors:
	@# Test vectors are not compatible between architectures
	@if uname -a | grep -q x86; then \
		./scripts/test_vectors.sh check apps/test-vectors; \
	else \
		echo "Cannot check test vectors on non x86 platform for now."; \
	fi


.PHONY: doc # Build rust doc
doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=boolean,shortint,integer,strings,gpu,internal-keycache,experimental,zk-pok --no-deps -p tfhe

.PHONY: docs # Build rust doc alias for doc
docs: doc

.PHONY: lint_doc # Build rust doc with linting enabled
lint_doc: install_rs_check_toolchain
	@# Even though we are not in docs.rs, this allows to "just" build the doc
	DOCS_RS=1 \
	RUSTDOCFLAGS="--html-in-header katex-header.html -Dwarnings" \
	cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" doc \
		--features=boolean,shortint,integer,strings,gpu,internal-keycache,experimental,zk-pok -p tfhe --no-deps

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

.PHONY: check_main_readme_links # Check main README links
check_main_readme_links: install_mlc
	mlc README.md

.PHONY: check_doc_paths_use_dash # Check paths use "-" instead of "_" in docs for gitbook compatibility
check_doc_paths_use_dash:
	python3 ./scripts/check_doc_paths_use_dash.py

.PHONY: check_parameter_export_ok # Checks exported "current" shortint parameter module is correct
check_parameter_export_ok:
	python3 ./scripts/check_current_param_export.py

.PHONY: check_compile_tests # Build tests in debug without running them
check_compile_tests:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --no-run \
		--features=experimental,boolean,shortint,integer,internal-keycache \
		-p tfhe

.PHONY: check_compile_tests_c_api # Build C API tests without running them
check_compile_tests_c_api:
	@if [[ "$(OS)" == "Linux" || "$(OS)" == "Darwin" ]]; then \
		"$(MAKE)" build_c_api && \
		./scripts/c_api_tests.sh --build-only --cargo-profile "$(CARGO_PROFILE)"; \
	fi

.PHONY: check_compile_tests_benches_gpu # Build tests in debug without running them
check_compile_tests_benches_gpu:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --no-run \
		--features=experimental,boolean,shortint,integer,internal-keycache,gpu,zk-pok \
		-p tfhe
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
	--server-cmd $(server_cmd) \
	--server-workdir "$(WEB_SERVER_DIR)" \
	--id-pattern $(filter)

test_web_js_api_parallel_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
test_web_js_api_parallel_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
test_web_js_api_parallel_chrome: browser_kind = chrome
test_web_js_api_parallel_chrome: server_cmd = "npm run server:multithreaded"
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
test_web_js_api_parallel_firefox: server_cmd = "npm run server:multithreaded"
test_web_js_api_parallel_firefox: filter = Test

.PHONY: test_web_js_api_parallel_firefox # Run tests for the web wasm api on Firefox
test_web_js_api_parallel_firefox: run_web_js_api_parallel

.PHONY: test_web_js_api_parallel_firefox_ci # Run tests for the web wasm api on Firefox
test_web_js_api_parallel_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_parallel_firefox

WASM_PAR_MQ_TEST_DIR=utils/wasm-par-mq/web_tests

.PHONY: build_wasm_par_mq_tests # Build the wasm-par-mq test WASM package
build_wasm_par_mq_tests: install_wasm_pack
	cd $(WASM_PAR_MQ_TEST_DIR) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --target=web --out-dir pkg

# This is an internal target, not meant to be called on its own.
run_wasm_par_mq_tests: build_wasm_par_mq_tests setup_venv
	cd $(WASM_PAR_MQ_TEST_DIR) && npm install && npm run build
	source venv/bin/activate && \
	python ci/webdriver.py \
	--browser-path $(browser_path) \
	--driver-path $(driver_path) \
	--browser-kind $(browser_kind) \
	--server-cmd "npm run server" \
	--server-workdir "$(WASM_PAR_MQ_TEST_DIR)" \
	--index-path "$(WASM_PAR_MQ_TEST_DIR)/index.html" \
	--id-pattern Test

test_wasm_par_mq_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
test_wasm_par_mq_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
test_wasm_par_mq_chrome: browser_kind = chrome

.PHONY: test_wasm_par_mq_chrome # Run wasm-par-mq tests on Chrome
test_wasm_par_mq_chrome: run_wasm_par_mq_tests

.PHONY: test_wasm_par_mq_chrome_ci # Run wasm-par-mq tests on Chrome in CI
test_wasm_par_mq_chrome_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_wasm_par_mq_chrome

test_wasm_par_mq_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
test_wasm_par_mq_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
test_wasm_par_mq_firefox: browser_kind = firefox

.PHONY: test_wasm_par_mq_firefox # Run wasm-par-mq tests on Firefox
test_wasm_par_mq_firefox: run_wasm_par_mq_tests

.PHONY: test_wasm_par_mq_firefox_ci # Run wasm-par-mq tests on Firefox in CI
test_wasm_par_mq_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_wasm_par_mq_firefox

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
		--features=boolean,shortint,integer,internal-keycache,pbs-stats,zk-pok \
		-p tfhe-benchmark -- --no-deps -D warnings
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
	  --features=shortint,internal-keycache \
		-p tfhe-benchmark -- --no-deps -D warnings

.PHONY: clippy_bench_gpu # Run clippy lints on tfhe-benchmark
clippy_bench_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		--features=gpu,shortint,integer,internal-keycache,pbs-stats,zk-pok \
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
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer # Run benchmarks for signed integer
bench_signed_integer: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_gpu # Run benchmarks for integer on GPU backend
bench_integer_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_signed_integer_gpu # Run benchmarks for signed integer on GPU backend
bench_signed_integer_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_hpu # Run benchmarks for integer on HPU backend
bench_integer_hpu: install_rs_check_toolchain
	source ./setup_hpu.sh --config $(HPU_CONFIG); \
	export V80_PCIE_DEV=${V80_PCIE_DEV}; \
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer \
	--features=integer,internal-keycache,pbs-stats,hpu,hpu-v80 -p tfhe-benchmark -- --quick

.PHONY: bench_integer_compression # Run benchmarks for unsigned integer compression
bench_integer_compression: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-glwe_packing_compression \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_compression_gpu
bench_integer_compression_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-glwe_packing_compression \
	--features=integer,internal-keycache,gpu,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_compression_128b_gpu
bench_integer_compression_128b_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench	glwe_packing_compression_128b-integer-bench \
	--features=integer,internal-keycache,gpu,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_zk_gpu
bench_integer_zk_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-zk-pke \
	--features=integer,internal-keycache,gpu,pbs-stats,zk-pok -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_aes_gpu # Run benchmarks for AES on GPU backend
bench_integer_aes_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-aes \
	--features=integer,internal-keycache,gpu, -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_aes256_gpu # Run benchmarks for AES256 on GPU backend
bench_integer_aes256_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-aes256 \
	--features=integer,internal-keycache,gpu, -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_trivium_gpu # Run benchmarks for trivium on GPU backend
bench_integer_trivium_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-trivium \
	--features=integer,internal-keycache,gpu, -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_kreyvium_gpu # Run benchmarks for kreyvium on GPU backend
bench_integer_kreyvium_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-kreyvium \
	--features=integer,internal-keycache,gpu, -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_multi_bit # Run benchmarks for unsigned integer using multi-bit parameters
bench_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_signed_integer_multi_bit # Run benchmarks for signed integer using multi-bit parameters
bench_signed_integer_multi_bit: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_integer_multi_bit_gpu # Run benchmarks for integer on GPU backend using multi-bit parameters
bench_integer_multi_bit_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_signed_integer_multi_bit_gpu # Run benchmarks for signed integer on GPU backend using multi-bit parameters
bench_signed_integer_multi_bit_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=MULTI_BIT \
	__TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-signed \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_integer_zk # Run benchmarks for integer encryption with ZK proofs
bench_integer_zk: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench integer-zk-pke \
	--features=integer,internal-keycache,zk-pok,pbs-stats \
	-p tfhe-benchmark --

.PHONY: bench_shortint # Run benchmarks for shortint
bench_shortint: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint \
	--features=shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_shortint_oprf # Run benchmarks for shortint
bench_shortint_oprf: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench shortint-oprf \
	--features=shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_boolean # Run benchmarks for boolean
bench_boolean: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench boolean \
	--features=boolean,internal-keycache -p tfhe-benchmark

.PHONY: bench_ks # Run benchmarks for keyswitch
bench_ks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-ks \
	--features=boolean,shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_ks_gpu # Run benchmarks for keyswitch on GPU backend
bench_ks_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-ks \
	--features=boolean,shortint,gpu,internal-keycache -p tfhe-benchmark --profile release_lto_off

.PHONY: bench_pbs # Run benchmarks for PBS
bench_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-pbs \
	--features=boolean,shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_pbs_gpu # Run benchmarks for PBS on GPU backend
bench_pbs_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-pbs \
	--features=boolean,shortint,gpu,internal-keycache -p tfhe-benchmark --profile release_lto_off

.PHONY: bench_ks_pbs # Run benchmarks for KS-PBS
bench_ks_pbs: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-ks-pbs \
	--features=boolean,shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_ks_pbs_gpu # Run benchmarks for KS-PBS on GPU backend
bench_ks_pbs_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) __TFHE_RS_PARAMS_SET=$(BENCH_PARAMS_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-ks-pbs \
	--features=boolean,shortint,gpu,internal-keycache -p tfhe-benchmark --profile release_lto_off

.PHONY: bench_pbs128 # Run benchmarks for PBS using FFT 128 bits
bench_pbs128: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-pbs128 \
	--features=boolean,shortint,internal-keycache -p tfhe-benchmark

.PHONY: bench_pbs128_gpu # Run benchmarks for PBS using FFT 128 bits on GPU
bench_pbs128_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench core_crypto-pbs128 \
	--features=boolean,shortint,gpu,internal-keycache -p tfhe-benchmark --profile release_lto_off

bench_web_js_api_parallel_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
bench_web_js_api_parallel_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
bench_web_js_api_parallel_chrome: browser_kind = chrome
bench_web_js_api_parallel_chrome: server_cmd = "npm run server:multithreaded"
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
bench_web_js_api_parallel_firefox: server_cmd = "npm run server:multithreaded"
bench_web_js_api_parallel_firefox: filter = Bench

.PHONY: bench_web_js_api_parallel_firefox # Run benchmarks for the web wasm api
bench_web_js_api_parallel_firefox: run_web_js_api_parallel

.PHONY: bench_web_js_api_parallel_firefox_ci # Run benchmarks for the web wasm api
bench_web_js_api_parallel_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_parallel_firefox

bench_web_js_api_cross_origin_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
bench_web_js_api_cross_origin_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
bench_web_js_api_cross_origin_chrome: browser_kind = chrome
bench_web_js_api_cross_origin_chrome: server_cmd = "npm run server:cross-origin"
bench_web_js_api_cross_origin_chrome: filter = ZeroKnowledgeBench # Only bench zk with cross-origin workers

.PHONY: bench_web_js_api_cross_origin_chrome # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_chrome: run_web_js_api_parallel

.PHONY: bench_web_js_api_cross_origin_chrome_ci # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_chrome_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_cross_origin_chrome

bench_web_js_api_cross_origin_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
bench_web_js_api_cross_origin_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
bench_web_js_api_cross_origin_firefox: browser_kind = firefox
bench_web_js_api_cross_origin_firefox: server_cmd = "npm run server:cross-origin"
bench_web_js_api_cross_origin_firefox: filter = ZeroKnowledgeBench # Only bench zk with cross-origin workers

.PHONY: bench_web_js_api_cross_origin_firefox # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_firefox: run_web_js_api_parallel

.PHONY: bench_web_js_api_cross_origin_firefox_ci # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_cross_origin_firefox

.PHONY: bench_hlapi_unsigned # Run benchmarks for integer operations
bench_hlapi_unsigned: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi_unsigned \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_signed # Run benchmarks for signed integer operations
bench_hlapi_signed: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_OP_FLAVOR=$(BENCH_OP_FLAVOR) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi_signed \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_gpu # Run benchmarks for integer operations on GPU
bench_hlapi_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_hpu # Run benchmarks for HLAPI operations on HPU
bench_hlapi_hpu: install_rs_check_toolchain
	source ./setup_hpu.sh --config $(HPU_CONFIG); \
	export V80_PCIE_DEV=${V80_PCIE_DEV}; \
	RUSTFLAGS="$(RUSTFLAGS)" \
	__TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi \
	--features=integer,internal-keycache,hpu,hpu-v80,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_erc20 # Run benchmarks for ERC20 operations
bench_hlapi_erc20: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_erc20_gpu # Run benchmarks for ERC20 operations on GPU
bench_hlapi_erc20_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) \
    cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_erc20_gpu_classical # Run benchmarks for ERC20 operations on GPU with classical parameters
bench_hlapi_erc20_gpu_classical: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_PARAM_TYPE=classical \
    cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_dex # Run benchmarks for DEX operations
bench_hlapi_dex: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-dex \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_dex_gpu # Run benchmarks for DEX operations on GPU
bench_hlapi_dex_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE)  __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-dex \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_dex_gpu_classical # Run benchmarks for DEX operations on GPU with classical parameters
bench_hlapi_dex_gpu_classical: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE)  __TFHE_RS_PARAM_TYPE=$(BENCH_PARAM_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-dex \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_erc20_hpu # Run benchmarks for ECR20 operations on HPU
bench_hlapi_erc20_hpu: install_rs_check_toolchain
	source ./setup_hpu.sh --config $(HPU_CONFIG); \
	export V80_PCIE_DEV=${V80_PCIE_DEV}; \
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-erc20 \
	--features=integer,internal-keycache,hpu,hpu-v80,pbs-stats -p tfhe-benchmark --

.PHONY: bench_tfhe_zk_pok # Run benchmarks for the tfhe_zk_pok crate
bench_tfhe_zk_pok: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench -p tfhe-zk-pok --

.PHONY: bench_hlapi_noise_squash # Run benchmarks for noise squash operation
bench_hlapi_noise_squash: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-noise-squash \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --

.PHONY: bench_hlapi_noise_squash_gpu # Run benchmarks for noise squash operation on GPU
bench_hlapi_noise_squash_gpu: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) __TFHE_RS_BENCH_BIT_SIZES_SET=$(BIT_SIZES_SET) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-noise-squash \
	--features=integer,gpu,internal-keycache,pbs-stats -p tfhe-benchmark --profile release_lto_off --

.PHONY: bench_hlapi_kvstore # Run benchmarks for Key-Value Store operations
bench_hlapi_kvstore: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench \
	--bench hlapi-kvstore \
	--features=integer,internal-keycache,pbs-stats -p tfhe-benchmark --


.PHONY: bench_custom # Run benchmarks with a user-defined command
bench_custom: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) bench -p tfhe-benchmark $(BENCH_CUSTOM_COMMAND)

#
# Utility tools
#

.PHONY: gen_key_cache # Run the script to generate keys and cache them for shortint tests
gen_key_cache:
	RUSTFLAGS="$(RUSTFLAGS) --cfg tarpaulin" cargo run --profile $(CARGO_PROFILE) \
		--example generates_test_keys \
		--features=boolean,shortint,experimental,internal-keycache -p tfhe \
		-- $(MULTI_BIT_ONLY) $(COVERAGE_ONLY)

.PHONY: gen_key_cache_core_crypto # Run function to generate keys and cache them for core_crypto tests
gen_key_cache_core_crypto:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --tests --profile $(CARGO_PROFILE) \
		--features=experimental,internal-keycache -p tfhe -- --nocapture \
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
	--example write_params_to_file --features=boolean,shortint,hpu,internal-keycache

.PHONY: pull_backward_compat_data # Pull the data files needed for backward compatibility tests
pull_backward_compat_data:
	./scripts/pull_lfs_data.sh $(BACKWARD_COMPAT_DATA_DIR)

.PHONY: pull_hpu_files # Pull the hpu files
pull_hpu_files:
	./scripts/pull_lfs_data.sh backends/tfhe-hpu-backend/

.PHONY: pull_test_vectors # Pull the data files needed for backward compatibility tests
pull_test_vectors:
	./scripts/pull_lfs_data.sh $(TEST_VECTORS_DIR)

#
# Real use case examples
#

.PHONY: regex_engine # Run regex_engine example
regex_engine:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --profile $(CARGO_PROFILE) \
	--example regex_engine --features=integer \
	-- $(REGEX_STRING) $(REGEX_PATTERN)

.PHONY: dark_market # Run dark market example
dark_market:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --profile $(CARGO_PROFILE) \
	--example dark_market \
	--features=integer,internal-keycache \
	-- fhe-modified fhe-parallel plain fhe

.PHONY: sha256_bool # Run sha256_bool example
sha256_bool:
	RUSTFLAGS="$(RUSTFLAGS)" cargo run --profile $(CARGO_PROFILE) \
	--example sha256_bool --features=boolean

.PHONY: pcc # pcc stands for pre commit checks for CPU compilation
pcc: pcc_batch_1 pcc_batch_2 pcc_batch_3 pcc_batch_4 pcc_batch_5 pcc_batch_6 pcc_batch_7

#
# PCC split into several batches to speed-up CI feedback.
# Each batch have roughly the same execution time.
# Durations are given from GitHub Ubuntu large runner with 16 CPU.
#

.PHONY: pcc_batch_1 # duration: 6'10''
pcc_batch_1:
	$(call run_recipe_with_details,no_tfhe_typo)
	$(call run_recipe_with_details,no_dbg_log)
	$(call run_recipe_with_details,check_parameter_export_ok)
	$(call run_recipe_with_details,check_fmt)
	$(call run_recipe_with_details,check_fmt_toml)
	$(call run_recipe_with_details,check_typos)
	$(call run_recipe_with_details,lint_doc)
	$(call run_recipe_with_details,check_md_docs_are_tested)
	$(call run_recipe_with_details,check_intra_md_links)
	$(call run_recipe_with_details,check_doc_paths_use_dash)
	$(call run_recipe_with_details,test_tfhe_lints)
	$(call run_recipe_with_details,tfhe_lints)
	$(call run_recipe_with_details,clippy_rustdoc)
	$(call run_recipe_with_details,check_default_toolchain_msrv)

.PHONY: pcc_batch_2 # duration: 6'10'' (shortest one, extend it with further checks)
pcc_batch_2:
	$(call run_recipe_with_details,clippy)
	$(call run_recipe_with_details,clippy_all_targets)
	$(call run_recipe_with_details,check_fmt_js)
	$(call run_recipe_with_details,clippy_test_vectors)
	$(call run_recipe_with_details,check_test_vectors)
	$(call run_recipe_with_details,clippy_wasm_par_mq)

.PHONY: pcc_batch_3 # duration: 6'50''
pcc_batch_3:
	$(call run_recipe_with_details,clippy_shortint)
	$(call run_recipe_with_details,clippy_integer)

.PHONY: pcc_batch_4 # duration: 7'40''
pcc_batch_4:
	$(call run_recipe_with_details,clippy_core)
	$(call run_recipe_with_details,clippy_js_wasm_api)
	$(call run_recipe_with_details,clippy_ws_tests)
	$(call run_recipe_with_details,clippy_bench)

.PHONY: pcc_batch_5 # duration: 7'20''
pcc_batch_5:
	$(call run_recipe_with_details,clippy_tfhe_lints)
	$(call run_recipe_with_details,check_compile_tests)
	$(call run_recipe_with_details,clippy_backward_compat_data)

.PHONY: pcc_batch_6  # duration: 6'32''
pcc_batch_6:
	$(call run_recipe_with_details,clippy_boolean)
	$(call run_recipe_with_details,clippy_c_api)
	$(call run_recipe_with_details,clippy_tasks)
	$(call run_recipe_with_details,clippy_tfhe_csprng)
	$(call run_recipe_with_details,clippy_zk_pok)
	$(call run_recipe_with_details,clippy_trivium)
	$(call run_recipe_with_details,clippy_versionable)
	$(call run_recipe_with_details,clippy_param_dedup)
	$(call run_recipe_with_details,docs)

.PHONY: pcc_batch_7 # duration: 7'50'' (currently PCC execution bottleneck)
pcc_batch_7:
	$(call run_recipe_with_details,check_compile_tests_c_api)

.PHONY: pcc_gpu # pcc stands for pre commit checks for GPU compilation
pcc_gpu:
	$(call run_recipe_with_details,check_rust_bindings_did_not_change)
	$(call run_recipe_with_details,clippy_rustdoc_gpu)
	$(call run_recipe_with_details,clippy_gpu)
	$(call run_recipe_with_details,clippy_cuda_backend)
	$(call run_recipe_with_details,clippy_bench_gpu)
	$(call run_recipe_with_details,check_compile_tests_benches_gpu)
	$(call run_recipe_with_details,test_integer_hl_test_gpu_check_warnings)

.PHONY: pcc_hpu # pcc stands for pre commit checks for HPU compilation
pcc_hpu:
	$(call run_recipe_with_details,clippy_hpu)
	$(call run_recipe_with_details,clippy_hpu_backend)
	$(call run_recipe_with_details,clippy_hpu_mockup)
	$(call run_recipe_with_details,test_integer_hpu_mockup_ci_fast)

.PHONY: fpcc # pcc stands for pre commit checks, the f stands for fast
fpcc:
	$(call run_recipe_with_details,no_tfhe_typo)
	$(call run_recipe_with_details,no_dbg_log)
	$(call run_recipe_with_details,check_parameter_export_ok)
	$(call run_recipe_with_details,check_fmt)
	$(call run_recipe_with_details,check_fmt_toml)
	$(call run_recipe_with_details,check_typos)
	$(call run_recipe_with_details,lint_doc)
	$(call run_recipe_with_details,check_md_docs_are_tested)
	$(call run_recipe_with_details,check_intra_md_links)
	$(call run_recipe_with_details,check_doc_paths_use_dash)
	$(call run_recipe_with_details,check_main_readme_links)

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
build_fft:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-fft
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-fft \
		--features=fft128

.PHONY: build_fft_no_std
build_fft_no_std:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-fft \
		--no-default-features
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-fft \
		--no-default-features \
		--features=fft128

##### Tests #####

.PHONY: test_fft
test_fft:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-fft \
		--no-default-features \
		--features=std,fft128

.PHONY: test_fft_serde
test_fft_serde:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-fft \
		--features=serde,fft128

.PHONY: test_fft_avx512
test_fft_avx512:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-fft \
		--features=avx512,fft128

.PHONY: test_fft_no_std
test_fft_no_std:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-fft \
		--no-default-features \
		--features=fft128

.PHONY: test_fft_no_std_avx512
test_fft_no_std_avx512:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-fft \
		--no-default-features \
		--features=avx512,fft128

.PHONY: test_fft_node_js
test_fft_node_js: install_build_wasm32_target install_wasm_bindgen_cli
	RUSTFLAGS="" cargo test --release \
		--features=serde --target wasm32-unknown-unknown -p tfhe-fft

.PHONY: test_fft_node_js_ci
test_fft_node_js_ci: check_nvm_installed
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	"$(MAKE)" test_fft_node_js

.PHONY: test_fft_all
test_fft_all: test_fft test_fft_serde test_fft_avx512 test_fft_no_std test_fft_no_std_avx512 \
test_fft_node_js_ci

##### Bench #####

.PHONY: bench_fft # Run FFT benchmarks
bench_fft: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" bench --bench fft -p tfhe-fft \
		--features=serde \
		--features=avx512 \
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
build_ntt:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-ntt

.PHONY: build_ntt_no_std
build_ntt_no_std:
	RUSTFLAGS="$(RUSTFLAGS)" cargo build --release -p tfhe-ntt \
		--no-default-features

##### Tests #####

.PHONY: test_ntt
test_ntt:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-ntt \
		--no-default-features \
		--features=std

.PHONY: test_ntt_avx512
test_ntt_avx512:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-ntt \
		--features=avx512

.PHONY: test_ntt_no_std
test_ntt_no_std:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-ntt \
		--no-default-features

.PHONY: test_ntt_no_std_avx512
test_ntt_no_std_avx512:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --release -p tfhe-ntt \
		--no-default-features \
		--features=avx512

.PHONY: test_ntt_all
test_ntt_all: test_ntt test_ntt_no_std test_ntt_avx512 test_ntt_no_std_avx512

##### Bench #####

.PHONY: bench_ntt # Run NTT benchmarks
bench_ntt: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" bench --bench ntt -p tfhe-ntt

#============================End NTT Section ==================================

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^\.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
