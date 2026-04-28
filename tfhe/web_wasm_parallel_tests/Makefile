FIXTURES_DIR := ../tests/zk_wasm_x86_test
DIST_FIXTURES_DIR := dist/fixtures

.PHONY: ensure_fixtures # Generate the encrypt+prove fixtures if they don't exist
ensure_fixtures:
	@if [ -f "$(FIXTURES_DIR)/public_key.bin" ] && [ -f "$(FIXTURES_DIR)/crs.bin" ]; then \
		echo "==> Fixtures already present in $(FIXTURES_DIR)/"; \
	else \
		echo "==> Fixtures missing, generating via 'make gen_zk_wasm_fixtures'..."; \
		$(MAKE) -C ../.. gen_zk_wasm_fixtures; \
	fi

.PHONY: prepare_fixtures # Generate (if needed) + copy the encrypt+prove fixtures into dist/. Run this after `npm run build` if you want the fixture-based bench buttons to work.
prepare_fixtures: ensure_fixtures
	@if [ ! -d dist ]; then \
		echo "==> dist/ not built yet. Run 'npm run build' (or 'make run_server*') first."; \
		exit 1; \
	fi
	mkdir -p $(DIST_FIXTURES_DIR)
	cp $(FIXTURES_DIR)/public_key.bin $(FIXTURES_DIR)/crs.bin $(DIST_FIXTURES_DIR)/
	@echo "==> Fixtures copied into $(DIST_FIXTURES_DIR)/"

.PHONY: run_server # Build and run the web server in multithreaded mode (production bundle)
run_server:
	npm install
	npm run build
	npm run server:multithreaded

.PHONY: run_server_dev # Build and run the web server in multithreaded mode (development bundle with source maps)
run_server_dev:
	npm install
	npm run build:dev
	npm run server:multithreaded

.PHONY: run_server_cross_origin # Build and run the web server in cross-origin mode (production bundle)
run_server_cross_origin:
	npm install
	npm run build
	npm run server:cross-origin

.PHONY: run_server_cross_origin_dev # Build and run the web server in cross-origin mode (development bundle with source maps)
run_server_cross_origin_dev:
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
