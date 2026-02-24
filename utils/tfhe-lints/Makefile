SNAPSHOT_DIR := utils/tfhe-lints/snapshots

# Guard macro: fails with a clear message if a variable is not set
# Usage: $(call require,VAR_NAME)
require = $(if $($(1)),,$(error $(1) is required. Usage: make $@ $(1)=<value>))

# Crate targets: -p <crate> -- <features>
LINT_TFHE_ARGS        := -p tfhe -- --features=boolean,shortint,integer,strings,zk-pok
LINT_TFHE_ZK_POK_ARGS := -p tfhe-zk-pok -- --features=experimental
LINT_TFHE_CSPRNG_ARGS := -p tfhe-csprng -- --all-features

# $(1) = dylint lib name, $(2) = optional TFHE_BACKWARD_COMPAT_DATA_DIR
run-dylint = $(if $(2),TFHE_BACKWARD_COMPAT_DATA_DIR=$(2)) \
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" \
	cargo dylint --lib $(1) --no-deps

# Run all crates with a given dylint lib, $(1) = lib name, $(2) = optional data dir
define run-all-crates
	$(call run-dylint,$(1),$(2)) $(LINT_TFHE_ARGS)
	$(call run-dylint,$(1),$(2)) $(LINT_TFHE_ZK_POK_ARGS)
	$(call run-dylint,$(1),$(2)) $(LINT_TFHE_CSPRNG_ARGS)
endef

.PHONY: install_cargo_dylint # Install custom tfhe-rs lints
install_cargo_dylint:
	cargo install --locked cargo-dylint dylint-link

.PHONY: install_tfhe_lints_toolchain # Install the nightly toolchain required by tfhe-lints (from utils/tfhe-lints/rust-toolchain)
install_tfhe_lints_toolchain:
	cd utils/tfhe-lints && rustup toolchain install

.PHONY: clippy_tfhe_lints # Run clippy lints on tfhe-lints
clippy_tfhe_lints: install_cargo_dylint install_tfhe_lints_toolchain
	cd utils/tfhe-lints && \
	cargo clippy --all-targets -- --no-deps -D warnings

.PHONY: test_tfhe_lints # Run test on tfhe-lints
test_tfhe_lints: install_cargo_dylint install_tfhe_lints_toolchain
	cd utils/tfhe-lints && \
	cargo test

.PHONY: tfhe_lints # Run custom tfhe-rs lints
tfhe_lints: install_cargo_dylint install_tfhe_lints_toolchain
	$(call run-all-crates,tfhe_lints)

.PHONY: backward-snapshot-base # Generate the base snapshot. Should be called when you modified enums, structs or upgrade related to Versioned types
backward-snapshot-base: install_cargo_dylint install_tfhe_lints_toolchain
	@echo "Generating base snapshot"
	$(call run-all-crates,tfhe_lints_snapshot,$(SNAPSHOT_DIR))

.PHONY: backward-snapshot-head # Generate the head snapshot. This is mostly used by the CI
backward-snapshot-head: install_cargo_dylint install_tfhe_lints_toolchain
	@echo "Generating head snapshot"
	@rm -rf $(SNAPSHOT_DIR)/head
	@mkdir -p $(SNAPSHOT_DIR)/head
	$(call run-all-crates,tfhe_lints_snapshot,$(SNAPSHOT_DIR)/head)

.PHONY: backward-snapshot-report # Generate a diff report. Required: BASE_SNAPSHOT_DIR, HEAD_SNAPSHOT_DIR, OUTPUT_FILE
backward-snapshot-report:
	$(call require,BASE_SNAPSHOT_DIR)
	$(call require,HEAD_SNAPSHOT_DIR)
	$(call require,OUTPUT_FILE)
	cargo run -p tfhe-backward-compat-checker -- diff-report \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR) \
		--output $(OUTPUT_FILE)

.PHONY: backward-snapshot-check # Check backward compat. Required: BASE_SNAPSHOT_DIR, HEAD_SNAPSHOT_DIR. Optional: ALLOW_ADDITIONAL_ENUMS=true
backward-snapshot-check:
	$(call require,BASE_SNAPSHOT_DIR)
	$(call require,HEAD_SNAPSHOT_DIR)
	cargo run -p tfhe-backward-compat-checker -- check \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR) \
		$(if $(filter true,$(ALLOW_ADDITIONAL_ENUMS)),--allow-additional-enums)
