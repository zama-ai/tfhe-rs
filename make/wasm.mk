WEB_CLIENT_OUT_DIR ?= pkg
# Browser test runner install dir, web test server dir, and the x86/wasm zk
# compat fixtures dir (public_key.bin/crs.bin + browser-produced proof.bin).
WEB_RUNNER_DIR=web-test-runner
WEB_SERVER_DIR=tfhe/web_wasm_parallel_tests
WASM_ZK_FIXTURES_DIR=tfhe/tests/zk_wasm_x86_test
# webdriver.py args to capture fixtureEncryptProveTest's proof into proof.bin.
ZK_CAPTURE_ARGS=--capture-key proof_b64 --capture-out "$(WASM_ZK_FIXTURES_DIR)/proof.bin"

# -----------------------------------------------------------------------------
# Full web/node pkgs
# -----------------------------------------------------------------------------

.PHONY: build_web_js_api # Build the js API targeting the web browser, in sequential or cross origin parallelism modes.
build_web_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		-- --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api,integer-client-js-wasm-api,zk-pok,extended-types,cross-origin-wasm-api && \
	find pkg/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/pkg/
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

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

# -----------------------------------------------------------------------------
# Client (lightweight) pkgs — compact encryption + ZK proofs only
# -----------------------------------------------------------------------------

.PHONY: build_web_js_api_client # Build the client js API (compact encryption + ZK proofs only), in sequential or cross origin parallelism modes.
build_web_js_api_client: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=__wasm_api,zk-pok,integer,extended-types,cross-origin-wasm-api && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/$(WEB_CLIENT_OUT_DIR)/
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json

.PHONY: build_web_js_api_parallel_client # Build the client js API with parallelism support
# parallel wasm requires specific build options, see https://github.com/rust-lang/rust/pull/147225
build_web_js_api_parallel_client: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
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
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=__wasm_api,zk-pok,integer,extended-types,parallel-wasm-api \
		-Z build-std=panic_abort,std && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json

# ===== Browser / driver / venv setup =====

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

.PHONY: ensure_chrome_web_runner # Install chrome browser + driver only if missing (install_web_resource always re-downloads)
ensure_chrome_web_runner:
	@if [ ! -f "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome" ]; then \
		echo "==> Chrome browser missing, installing..."; \
		$(MAKE) install_chrome_browser; \
	fi
	@if [ ! -f "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver" ]; then \
		echo "==> Chrome web driver missing, installing..."; \
		$(MAKE) install_chrome_web_driver; \
	fi

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

# ===== nodejs wasm API tests =====

.PHONY: test_nodejs_wasm_api # Run tests for the nodejs on wasm API
test_nodejs_wasm_api: build_node_js_api
	cd tfhe/js_on_wasm_tests && npm install && npm run test

.PHONY: test_nodejs_wasm_api_ci # Run tests for the nodejs on wasm API
test_nodejs_wasm_api_ci: build_node_js_api
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_nodejs_wasm_api

# ===== web wasm API tests (parallel + cross-origin) =====

# This is an internal target, not meant to be called on its own.
# `capture_args` is empty by default; the chrome target sets it to capture the
# proof into proof.bin (no-op when the fixtures aren't served).
run_web_js_api_parallel: build_web_js_api_parallel setup_venv ensure_zk_wasm_fixtures
	cd $(WEB_SERVER_DIR) && npm install && npm run build
	source venv/bin/activate && \
	python ci/webdriver.py \
	--browser-path $(browser_path) \
	--driver-path $(driver_path) \
	--browser-kind $(browser_kind) \
	--server-cmd $(server_cmd) \
	--server-workdir "$(WEB_SERVER_DIR)" \
	--id-pattern $(filter) \
	--id-exclude-pattern asyncMainThread \
	$(capture_args)

# This is an internal target, not meant to be called on its own.
run_web_js_api_cross_origin: build_web_js_api setup_venv
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
test_web_js_api_parallel_chrome: capture_args = $(ZK_CAPTURE_ARGS)

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

.PHONY: test_web_js_api_parallel # Run the full web wasm parallel suite (chrome + firefox) then verify the x86 zk proof
# One-shot: fresh fixtures -> chrome (captures proof.bin) -> firefox -> x86 verify.
test_web_js_api_parallel:
	$(MAKE) gen_zk_wasm_fixtures
	$(MAKE) test_web_js_api_parallel_chrome
	$(MAKE) test_web_js_api_parallel_firefox
	$(MAKE) verify_zk_wasm_proof

.PHONY: test_web_js_api_parallel_ci # Same as test_web_js_api_parallel, CI entrypoint (with nvm)
test_web_js_api_parallel_ci:
	$(MAKE) gen_zk_wasm_fixtures
	$(MAKE) test_web_js_api_parallel_chrome_ci
	$(MAKE) test_web_js_api_parallel_firefox_ci
	$(MAKE) verify_zk_wasm_proof

test_web_js_api_cross_origin_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
test_web_js_api_cross_origin_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
test_web_js_api_cross_origin_chrome: browser_kind = chrome
test_web_js_api_cross_origin_chrome: server_cmd = "npm run server:cross-origin"
test_web_js_api_cross_origin_chrome: filter = ZeroKnowledgeTest # Only run zk proof tests in cross-origin mode

.PHONY: test_web_js_api_cross_origin_chrome # Run tests for the web wasm api in cross-origin mode on Chrome
test_web_js_api_cross_origin_chrome: run_web_js_api_cross_origin

.PHONY: test_web_js_api_cross_origin_chrome_ci # Run tests for the web wasm api in cross-origin mode on Chrome
test_web_js_api_cross_origin_chrome_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_cross_origin_chrome

test_web_js_api_cross_origin_firefox: browser_path = "$(WEB_RUNNER_DIR)/firefox/firefox/firefox"
test_web_js_api_cross_origin_firefox: driver_path = "$(WEB_RUNNER_DIR)/firefox/geckodriver"
test_web_js_api_cross_origin_firefox: browser_kind = firefox
test_web_js_api_cross_origin_firefox: server_cmd = "npm run server:cross-origin"
test_web_js_api_cross_origin_firefox: filter = ZeroKnowledgeTest  # Only run zk proof tests in cross-origin mode

.PHONY: test_web_js_api_cross_origin_firefox # Run tests for the web wasm api in cross-origin mode on Firefox
test_web_js_api_cross_origin_firefox: run_web_js_api_cross_origin

.PHONY: test_web_js_api_cross_origin_firefox_ci # Run tests for the web wasm api in cross-origin mode on Firefox
test_web_js_api_cross_origin_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) test_web_js_api_cross_origin_firefox

# ===== wasm-par-mq tests =====

WASM_PAR_MQ_TEST_DIR=utils/wasm-par-mq/web_tests

.PHONY: build_wasm_par_mq_tests # Build the wasm-par-mq test WASM package
build_wasm_par_mq_tests: install_wasm_pack
	cd $(WASM_PAR_MQ_TEST_DIR) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --target=web --out-dir pkg && \
	find pkg/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../wasm_par_mq_web_tests.js")|g' {} \;

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

# ===== x86/wasm ZK proof compatibility =====

.PHONY: gen_zk_wasm_fixtures # Generate the public_key.bin + crs.bin fixtures for the wasm zk compat check
gen_zk_wasm_fixtures:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe --test zk_wasm_x86_test --features=integer,zk-pok -- --ignored --exact gen_zk_wasm_fixtures

.PHONY: ensure_zk_wasm_fixtures # Generate the zk fixtures only if missing (gen always regenerates)
ensure_zk_wasm_fixtures:
	@if [ -f "$(WASM_ZK_FIXTURES_DIR)/public_key.bin" ] && [ -f "$(WASM_ZK_FIXTURES_DIR)/crs.bin" ]; then \
		echo "==> zk wasm fixtures present in $(WASM_ZK_FIXTURES_DIR)/"; \
	else \
		echo "==> zk wasm fixtures missing, generating..."; \
		$(MAKE) gen_zk_wasm_fixtures; \
	fi

.PHONY: verify_zk_wasm_proof # Verify on x86 the proof.bin produced by the wasm fixtureEncryptProveTest (no browser)
verify_zk_wasm_proof:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		-p tfhe --test zk_wasm_x86_test --features=integer,zk-pok -- --ignored --exact verify_zk_wasm_proof

# Internal: run only fixtureEncryptProveTest in chrome and capture proof.bin
# (consumed by verify_zk_wasm_proof). Assumes fixtures + browser already present.
capture_zk_wasm_proof_chrome: capture_args = $(ZK_CAPTURE_ARGS)
capture_zk_wasm_proof_chrome: filter = fixtureEncryptProveTest
capture_zk_wasm_proof_chrome: browser_path = "$(WEB_RUNNER_DIR)/chrome/chrome-linux64/chrome"
capture_zk_wasm_proof_chrome: driver_path = "$(WEB_RUNNER_DIR)/chrome/chromedriver-linux64/chromedriver"
capture_zk_wasm_proof_chrome: browser_kind = chrome
capture_zk_wasm_proof_chrome: server_cmd = "npm run server:multithreaded"
capture_zk_wasm_proof_chrome: run_web_js_api_parallel

.PHONY: test_zk_wasm_x86_compat # Check compatibility between wasm and x86_64 proofs (self-contained, runs its own browser)
# Dev convenience: gen fixtures (x86) -> encrypt+prove in chrome -> verify (x86).
# Cascade of sub-makes (not prerequisites) so the steps stay ordered even under `make -j`.
test_zk_wasm_x86_compat:
	$(MAKE) gen_zk_wasm_fixtures
	$(MAKE) ensure_chrome_web_runner
	$(MAKE) capture_zk_wasm_proof_chrome
	$(MAKE) verify_zk_wasm_proof

# ===== web wasm API benchmarks =====

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
bench_web_js_api_cross_origin_chrome: run_web_js_api_cross_origin

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
bench_web_js_api_cross_origin_firefox: run_web_js_api_cross_origin

.PHONY: bench_web_js_api_cross_origin_firefox_ci # Run benchmarks for the web wasm api without cross-origin isolation
bench_web_js_api_cross_origin_firefox_ci: setup_venv
	source ~/.nvm/nvm.sh && \
	nvm install $(NODE_VERSION) && \
	nvm use $(NODE_VERSION) && \
	$(MAKE) bench_web_js_api_cross_origin_firefox
