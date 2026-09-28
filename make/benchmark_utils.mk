.PHONY: clippy_benchmark_spec # Run clippy lints on benchmark_spec
clippy_benchmark_spec: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p benchmark_spec -- --no-deps -D warnings

.PHONY: clippy_benchmark_spec_js # Run clippy lints on benchmark-spec-js
clippy_benchmark_spec_js: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p benchmark-spec-js -- --no-deps -D warnings

.PHONY: clippy_benchmark_parser # Run clippy lints on tfhe-benchmark-parser
clippy_benchmark_parser: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-benchmark-parser -- --no-deps -D warnings

.PHONY: clippy_data_extractor # Run clippy lints on tfhe-data-extractor
clippy_data_extractor: install_rs_check_toolchain
	RUSTFLAGS="$(RUSTFLAGS)" cargo "$(CARGO_RS_CHECK_TOOLCHAIN)" clippy --all-targets \
		-p tfhe-data-extractor -- --no-deps -D warnings

# No database needed, the extractor's profile test reads ci/regression.toml.
.PHONY: test_benchmark_utils # Run tests for benchmark_spec, the browser ids, the bench parser and the data extractor
test_benchmark_utils:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--all-targets -p benchmark_spec -p benchmark-spec-js -p tfhe-benchmark-parser \
		-p tfhe-data-extractor
