WEB_CLIENT_OUT_DIR ?= pkg

# Extra RUSTFLAGS required for the parallel (multi-threaded) wasm build.
# See https://github.com/rust-lang/rust/pull/147225
WASM_PARALLEL_RUSTFLAGS := -C target-feature=+atomics,+bulk-memory \
	-Clink-arg=--shared-memory \
	-Clink-arg=--max-memory=1073741824 \
	-Clink-arg=--import-memory \
	-Clink-arg=--export=__wasm_init_tls \
	-Clink-arg=--export=__tls_size \
	-Clink-arg=--export=__tls_align \
	-Clink-arg=--export=__tls_base

.PHONY: build_web_js_api # Build the js API targeting the web browser, in sequential or cross origin parallelism modes.
build_web_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		-- --features=high-level-client-js-wasm-api,zk-pok,extended-types,cross-origin-wasm-api && \
	find pkg/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/pkg/
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_web_js_api_parallel # Build the js API targeting the web browser with parallelism support
# parallel wasm requires specific build options, see https://github.com/rust-lang/rust/pull/147225
build_web_js_api_parallel: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) $(WASM_PARALLEL_RUSTFLAGS)" \
		rustup run $(RS_CHECK_TOOLCHAIN) wasm-pack build --release --target=web \
		-- --features=high-level-client-js-wasm-api,parallel-wasm-api,zk-pok,extended-types \
		-Z build-std=panic_abort,std && \
	find pkg/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/pkg/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/pkg/package.json

.PHONY: build_node_js_api # Build the js API targeting nodejs
build_node_js_api: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=nodejs \
		-- --features=high-level-client-js-wasm-api,zk-pok,extended-types

.PHONY: build_node_js_api_client # Build the client js API targeting nodejs (compact encryption + ZK proofs only)
build_node_js_api_client: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=nodejs \
		-- --no-default-features \
		--features=client-js-wasm-api,zk-pok

.PHONY: build_web_js_api_client # Build the client js API (compact encryption + ZK proofs only), in sequential or cross origin parallelism modes.
build_web_js_api_client: install_wasm_pack
	cd tfhe && \
	RUSTFLAGS="$(WASM_RUSTFLAGS)" wasm-pack build --release --target=web \
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=client-js-wasm-api,zk-pok,cross-origin-wasm-api && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname worker_helpers.js -exec sed -i 's|import("../../..")|import("../../../tfhe.js")|g' {} \;
	cp utils/wasm-par-mq/js/coordinator.js tfhe/$(WEB_CLIENT_OUT_DIR)/
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json

.PHONY: build_web_js_api_parallel_client # Build the client js API with parallelism support
# parallel wasm requires specific build options, see https://github.com/rust-lang/rust/pull/147225
build_web_js_api_parallel_client: install_rs_check_toolchain install_wasm_pack install_wasm_bindgen_cli
	cd tfhe && \
	rustup component add rust-src --toolchain $(RS_CHECK_TOOLCHAIN) && \
	RUSTFLAGS="$(WASM_RUSTFLAGS) $(WASM_PARALLEL_RUSTFLAGS)" \
		rustup run $(RS_CHECK_TOOLCHAIN) wasm-pack build --release --target=web \
		--out-dir $(WEB_CLIENT_OUT_DIR) \
		-- --no-default-features \
		--features=client-js-wasm-api,zk-pok,parallel-wasm-api \
		-Z build-std=panic_abort,std && \
	find $(WEB_CLIENT_OUT_DIR)/snippets -type f -iname workerHelpers.js -exec sed -i "s|const pkg = await import('..\/..\/..');|const pkg = await import('..\/..\/..\/tfhe.js');|" {} \;
	jq '.files += ["snippets"]' tfhe/$(WEB_CLIENT_OUT_DIR)/package.json > tmp_pkg.json && mv -f tmp_pkg.json tfhe/$(WEB_CLIENT_OUT_DIR)/package.json
