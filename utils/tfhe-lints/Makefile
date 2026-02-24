SNAPSHOT_DIR := utils/tfhe-lints/snapshots

DYLINT_CMD = TFHE_BACKWARD_COMPAT_DATA_DIR=$(1) \
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" \
	cargo dylint --lib tfhe_lints_snapshot --no-deps

lint-tfhe = $(call DYLINT_CMD,$(1)) -p tfhe -- --features=boolean,shortint,integer,strings,zk-pok
lint-tfhe-zk-pok = $(call DYLINT_CMD,$(1)) -p tfhe-zk-pok -- --features=experimental
lint-tfhe-csprng = $(call DYLINT_CMD,$(1)) -p tfhe-csprng -- --all-features

# Run all snapshot lints for a given directory
define run-all-snapshot-lints
	$(call lint-tfhe,$(1))
	$(call lint-tfhe-zk-pok,$(1))
	$(call lint-tfhe-csprng,$(1))
endef

# Run all regular lints (non-snapshot)
define run-all-lints
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo dylint --lib tfhe_lints -p tfhe --no-deps -- \
		--features=boolean,shortint,integer,strings,zk-pok
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo dylint --lib tfhe_lints -p tfhe-zk-pok --no-deps -- \
		--features=experimental
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" cargo dylint --lib tfhe_lints -p tfhe-csprng --no-deps -- --all-features
endef

.PHONY: install_cargo_dylint # Install custom tfhe-rs lints
install_cargo_dylint:
	cargo install --locked cargo-dylint dylint-link

.PHONY: clippy_tfhe_lints # Run clippy lints on tfhe-lints
clippy_tfhe_lints: install_cargo_dylint # the toolchain is selected with toolchain.toml
	cd utils/tfhe-lints && \
	rustup toolchain install && \
	cargo clippy --all-targets -- --no-deps -D warnings

.PHONY: test_tfhe_lints # Run test on tfhe-lints
test_tfhe_lints: install_cargo_dylint
	cd utils/tfhe-lints && \
	rustup toolchain install && \
	cargo test

.PHONY: tfhe_lints # Run custom tfhe-rs lints
tfhe_lints: install_cargo_dylint
	$(run-all-lints)

.PHONY: backward-snapshot-base # Generate the base snapshot. Should be called when you modified enums, structs or upgrade related to Versioned traits
backward-snapshot-base: install_cargo_dylint
	@echo "Generating base snapshot"
	$(call run-all-snapshot-lints,$(SNAPSHOT_DIR))

.PHONY: backward-snapshot-head # Generate the head snapshot. This is mostly used by the CI
backward-snapshot-head: install_cargo_dylint
	@echo "Generating head snapshot"
	@rm -rf $(SNAPSHOT_DIR)/head
	@mkdir -p $(SNAPSHOT_DIR)/head
	$(call run-all-snapshot-lints,$(SNAPSHOT_DIR)/head)

# This variable is set for the CI
# You might need to change it for a local usage
BASE_SNAPSHOT_DIR ?= ../base/$(SNAPSHOT_DIR)
HEAD_SNAPSHOT_DIR ?= $(SNAPSHOT_DIR)/head
OUTPUT_FILE ?= ../report.md

.PHONY: backward-snapshot-report # Generate a report comparing the base and head snapshots. This should be run on the feature branch after generating the head snapshot.
backward-snapshot-report:
	cargo run -p tfhe-backward-compat-checker -- diff-report \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR) \
		--output $(OUTPUT_FILE)

ALLOW_ADDITIONAL_ENUMS ?= false

.PHONY: backward-snapshot-check # Check for backward compatibility issues between the base and head snapshots. This should be run on the feature branch after generating the head snapshot. By default, this will fail if there are any new enums in the head snapshot that were not present in the base snapshot, but this can be overridden with the ALLOW_ADDITIONAL_ENUMS variable.
backward-snapshot-check:
	cargo run -p tfhe-backward-compat-checker -- check \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR) \
		$(if $(filter true,$(ALLOW_ADDITIONAL_ENUMS)),--allow-additional-enums)
