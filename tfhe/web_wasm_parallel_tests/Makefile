FIXTURES_DIR := ../tests/zk_wasm_x86_test
FIXTURES_FILES := $(FIXTURES_DIR)/public_key.bin $(FIXTURES_DIR)/crs.bin

.PHONY: ensure_fixtures # Generate the x86-compat fixtures if they don't exist
ensure_fixtures:
	@if [ -f "$(FIXTURES_DIR)/public_key.bin" ] && [ -f "$(FIXTURES_DIR)/crs.bin" ]; then \
		echo "==> Fixtures already present in $(FIXTURES_DIR)/"; \
	else \
		echo "==> Fixtures missing, generating via 'make test_zk_wasm_x86_compat'..."; \
		$(MAKE) -C ../.. test_zk_wasm_x86_compat; \
	fi

.PHONY: run_server # Build and run the web server in multithreaded mode (production bundle)
run_server: ensure_fixtures
	npm install
	npm run build
	npm run server:multithreaded

.PHONY: run_server_dev # Build and run the web server in multithreaded mode (development bundle with source maps)
run_server_dev: ensure_fixtures
	npm install
	npm run build:dev
	npm run server:multithreaded

.PHONY: run_server_cross_origin # Build and run the web server in cross-origin mode (production bundle)
run_server_cross_origin: ensure_fixtures
	npm install
	npm run build
	npm run server:cross-origin

.PHONY: run_server_cross_origin_dev # Build and run the web server in cross-origin mode (development bundle with source maps)
run_server_cross_origin_dev: ensure_fixtures
	npm install
	npm run build:dev
	npm run server:cross-origin

.PHONY: fmt # Format Javascript code
fmt:
	npm install
	npm run format

.PHONY: check_fmt # Check Javascript code format
check_fmt:
	npm install
	npm run check-format
