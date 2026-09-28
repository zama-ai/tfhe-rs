WEB_CLIENT_OUT_DIR ?= pkg

# Extra RUSTFLAGS required for the parallel (multi-threaded) wasm build.
# See https://github.com/rust-lang/rust/pull/147225 and https://github.com/rust-lang/rust/pull/156174
WASM_PARALLEL_RUSTFLAGS := -C target-feature=+atomics,+bulk-memory \
	-Clink-arg=--shared-memory \
	-Clink-arg=--max-memory=1073741824 \
	-Clink-arg=--import-memory \
	-Clink-arg=--export=__heap_base \
	-Clink-arg=--export=__wasm_init_tls \
	-Clink-arg=--export=__tls_size \
	-Clink-arg=--export=__tls_align \
	-Clink-arg=--export=__tls_base

.PHONY: build_web_js_api # Build the js API targeting the web browser, in sequential or cross origin parallelism modes.
build_web_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		-- --features=boolean-js-wasm-api,integer-js-wasm-api,zk-pok,extended-types,cross-origin-wasm-api && \
	find pkg/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/pkg/
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) $(WASM_PARALLEL_RUSTFLAGS)" \
		rustup run $(RS_CHECK_TOOLCHAIN) wasm-pack build --release --target=web \
		-- --features=boolean-js-wasm-api,integer-js-wasm-api,parallel-wasm-api,zk-pok,extended-types \
		-Z build-std=panic_abort,std && \
	find pkg/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_benchmark_spec_js # Build the benchmark id builders used by the web bench harness
build_benchmark_spec_js: install_wasm_pack
	cd utils/benchmark-spec-js && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=nodejs \
		-- --features=boolean-js-wasm-api,integer-js-wasm-api,zk-pok,extended-types

.PHONY: build_node_js_api_client # Build the client js API targeting nodejs (compact encryption + ZK proofs only)
build_node_js_api_client: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=nodejs \
		-- --no-default-features \
		--features=integer-client-js-wasm-api,zk-pok

.PHONY: build_web_js_api_client # Build the client js API (compact encryption + ZK proofs only), in sequential or cross origin parallelism modes.
build_web_js_api_client: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=integer-client-js-wasm-api,zk-pok,cross-origin-wasm-api && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/$(WEB_CLIENT_OUT_DIR)/
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json

.PHONY: build_web_js_api_parallel_client # Build the client js API with parallelism support
build_web_js_api_parallel_client: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) $(WASM_PARALLEL_RUSTFLAGS)" \
		rustup run $(RS_CHECK_TOOLCHAIN) wasm-pack build --release --target=web \
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=integer-client-js-wasm-api,zk-pok,parallel-wasm-api \
		-Z build-std=panic_abort,std && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json

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

install_firefox_browser: url = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/147.0/linux-x86_64/en-US/firefox-147.0.tar.xz"
install_firefox_browser: checksum = "f055b9c0d7346a10d22edc7f10e08679af2ea495367381ab2be9cab3ec6add97"
install_firefox_browser: dest = "$(WEB_RUNNER_DIR)/firefox"
install_firefox_browser: filename = "firefox-147.0.tar.xz"
install_firefox_browser: decompress_cmd = tar -xvf

.PHONY: install_firefox_browser # Install firefox browser for Linux
install_firefox_browser: install_web_resource

install_firefox_web_driver: url = "https://github.com/mozilla/geckodriver/releases/download/v0.36.0/geckodriver-v0.36.0-linux64.tar.gz"
install_firefox_web_driver: checksum = "0bde38707eb0a686a20c6bd50f4adcc7d60d4f73c60eb83ee9e0db8f65823e04"
install_firefox_web_driver: dest = "$(WEB_RUNNER_DIR)/firefox"
install_firefox_web_driver: filename = "geckodriver-v0.36.0-linux64.tar.gz"
install_firefox_web_driver: decompress_cmd = tar -xvf

.PHONY: install_firefox_web_driver # Install firefox web driver for Linux
install_firefox_web_driver: install_web_resource

# This is an internal target, not meant to be called on its own.
run_web_js_api_parallel: build_web_js_api_parallel build_benchmark_spec_js setup_venv
	cd $(WEB_SERVER_DIR) && npm install && npm run build
	source venv/bin/activate && \
	python ci/webdriver.py \
	--browser-path $(browser_path) \
	--driver-path $(driver_path) \
	--browser-kind $(browser_kind) \
	--server-cmd $(server_cmd) \
	--server-workdir "$(WEB_SERVER_DIR)" \
	--id-pattern $(filter) \
	--id-exclude-pattern asyncMainThread

# This is an internal target, not meant to be called on its own.
run_web_js_api_cross_origin: build_web_js_api build_benchmark_spec_js setup_venv
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
	source "$(NVM_DIR)"/nvm.sh && \
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
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_parallel_firefox

# Cross-origin runs only cover the zk cases.
test_web_js_api_cross_origin_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
test_web_js_api_cross_origin_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
test_web_js_api_cross_origin_chrome: browser_kind = chrome
test_web_js_api_cross_origin_chrome: server_cmd = "npm run server:cross-origin"
test_web_js_api_cross_origin_chrome: filter = ZeroKnowledgeTest

.PHONY: test_web_js_api_cross_origin_chrome # Run tests for the web wasm api in cross-origin mode on Chrome
test_web_js_api_cross_origin_chrome: run_web_js_api_cross_origin

.PHONY: test_web_js_api_cross_origin_chrome_ci # Run tests for the web wasm api in cross-origin mode on Chrome
test_web_js_api_cross_origin_chrome_ci: setup_venv
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_cross_origin_chrome

test_web_js_api_cross_origin_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
test_web_js_api_cross_origin_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
test_web_js_api_cross_origin_firefox: browser_kind = firefox
test_web_js_api_cross_origin_firefox: server_cmd = "npm run server:cross-origin"
test_web_js_api_cross_origin_firefox: filter = ZeroKnowledgeTest

.PHONY: test_web_js_api_cross_origin_firefox # Run tests for the web wasm api in cross-origin mode on Firefox
test_web_js_api_cross_origin_firefox: run_web_js_api_cross_origin

.PHONY: test_web_js_api_cross_origin_firefox_ci # Run tests for the web wasm api in cross-origin mode on Firefox
test_web_js_api_cross_origin_firefox_ci: setup_venv
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_cross_origin_firefox

bench_web_js_api_parallel_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
bench_web_js_api_parallel_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
bench_web_js_api_parallel_chrome: browser_kind = chrome
bench_web_js_api_parallel_chrome: server_cmd = "npm run server:multithreaded"
bench_web_js_api_parallel_chrome: filter = Bench

.PHONY: bench_web_js_api_parallel_chrome # Run benchmarks for the web wasm api
bench_web_js_api_parallel_chrome: run_web_js_api_parallel

.PHONY: bench_web_js_api_parallel_chrome_ci # Run benchmarks for the web wasm api
bench_web_js_api_parallel_chrome_ci: setup_venv
	source "$(NVM_DIR)"/nvm.sh && \
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
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_parallel_firefox

# Cross-origin runs only cover the zk cases.
bench_web_js_api_cross_origin_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
bench_web_js_api_cross_origin_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
bench_web_js_api_cross_origin_chrome: browser_kind = chrome
bench_web_js_api_cross_origin_chrome: server_cmd = "npm run server:cross-origin"
bench_web_js_api_cross_origin_chrome: filter = ZeroKnowledgeBench

.PHONY: bench_web_js_api_cross_origin_chrome # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_chrome: run_web_js_api_cross_origin

.PHONY: bench_web_js_api_cross_origin_chrome_ci # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_chrome_ci: setup_venv
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_cross_origin_chrome

bench_web_js_api_cross_origin_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
bench_web_js_api_cross_origin_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
bench_web_js_api_cross_origin_firefox: browser_kind = firefox
bench_web_js_api_cross_origin_firefox: server_cmd = "npm run server:cross-origin"
bench_web_js_api_cross_origin_firefox: filter = ZeroKnowledgeBench

.PHONY: bench_web_js_api_cross_origin_firefox # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_firefox: run_web_js_api_cross_origin

.PHONY: bench_web_js_api_cross_origin_firefox_ci # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_firefox_ci: setup_venv
	source "$(NVM_DIR)"/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_cross_origin_firefox

.PHONY: parse_wasm_benchmarks # Parse benchmarks performed with WASM web client into a CSV file
parse_wasm_benchmarks: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo $(CARGO_RS_CHECK_TOOLCHAIN) run --profile $(CARGO_PROFILE) \
	--bin wasm_benchmarks_parser \
	--features=shortint,internal-keycache \
	-p tfhe-benchmark \
	-- wasm_benchmark_results.json
