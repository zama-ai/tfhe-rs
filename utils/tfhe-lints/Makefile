# Guard macro: fails with a clear message if a variable is not set
# Usage: $(call require,VAR_NAME)
require = $(if $($(1)),,$(error $(1) is required. Usage: make $@ $(1)=<value>))

# Crate targets: -p <crate> -- <features>
LINT_TFHE_ARGS        := -p tfhe -- --features=boolean,shortint,integer,strings,zk-pok
LINT_TFHE_ZK_POK_ARGS := -p tfhe-zk-pok -- --features=experimental
LINT_TFHE_CSPRNG_ARGS := -p tfhe-csprng -- --all-features
LINT_TFHE_SAFE_SERIALIZE_ARGS := -p tfhe-safe-serialize

# Lookup crate args from CRATE name, $(1) = crate name
crate-args = $(if $(filter tfhe,$(1)),$(LINT_TFHE_ARGS),\
             $(if $(filter tfhe-zk-pok,$(1)),$(LINT_TFHE_ZK_POK_ARGS),\
             $(if $(filter tfhe-csprng,$(1)),$(LINT_TFHE_CSPRNG_ARGS),\
             $(if $(filter tfhe-safe-serialize,$(1)),$(LINT_TFHE_SAFE_SERIALIZE_ARGS),\
             $(error Unknown crate: $(1). Expected: tfhe, tfhe-zk-pok, tfhe-csprng, tfhe-safe-serialize))))

# $(1) = dylint lib name, $(2) = optional TFHE_BACKWARD_COMPAT_DATA_DIR
run-dylint = $(if $(2),TFHE_BACKWARD_COMPAT_DATA_DIR=$(2)) \
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" \
	cargo dylint --lib $(1) --no-deps

# Run all crates with a given dylint lib, $(1) = lib name, $(2) = optional data dir, $(3) = optional working dir
define run-all-crates
	$(if $(3),cd $(3) && )$(call run-dylint,$(1),$(2)) $(LINT_TFHE_ARGS)
	$(if $(3),cd $(3) && )$(call run-dylint,$(1),$(2)) $(LINT_TFHE_ZK_POK_ARGS)
	$(if $(3),cd $(3) && )$(call run-dylint,$(1),$(2)) $(LINT_TFHE_CSPRNG_ARGS)
	$(if $(3),cd $(3) && )$(call run-dylint,$(1),$(2)) $(LINT_TFHE_SAFE_SERIALIZE_ARGS)
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

.PHONY: tfhe_lints # Run custom tfhe-rs lints on all crates
tfhe_lints: install_cargo_dylint install_tfhe_lints_toolchain
	$(call run-all-crates,tfhe_lints)

.PHONY: tfhe_lints_crate # Run custom tfhe-rs lints on a single crate. Required: CRATE (tfhe, tfhe-zk-pok, tfhe-csprng)
tfhe_lints_crate: install_cargo_dylint install_tfhe_lints_toolchain
	$(call require,CRATE)
	$(call run-dylint,tfhe_lints) $(call crate-args,$(CRATE))

.PHONY: backward_snapshot # Generate snapshots for all crates. Required: SNAPSHOT_OUTPUT_DIR
backward_snapshot: install_cargo_dylint install_tfhe_lints_toolchain
	$(call require,SNAPSHOT_OUTPUT_DIR)
	@mkdir -p $(SNAPSHOT_OUTPUT_DIR)
	$(call run-all-crates,tfhe_lints_snapshot,$(SNAPSHOT_OUTPUT_DIR))

.PHONY: backward_snapshot_worktree # Generate snapshots from a worktree at BASE_REF. Required: BASE_REF, SNAPSHOT_OUTPUT_DIR
backward_snapshot_worktree: install_cargo_dylint install_tfhe_lints_toolchain
	$(call require,BASE_REF)
	$(call require,SNAPSHOT_OUTPUT_DIR)
	$(eval WORKTREE_DIR := $(shell mktemp -u))
	git worktree add $(WORKTREE_DIR) $(BASE_REF)
	@mkdir -p $(SNAPSHOT_OUTPUT_DIR)
	$(call run-all-crates,tfhe_lints_snapshot,$(abspath $(SNAPSHOT_OUTPUT_DIR)),$(WORKTREE_DIR))
	git worktree remove --force $(WORKTREE_DIR)

.PHONY: backward_snapshot_report # Generate a diff report. Required: BASE_SNAPSHOT_DIR, HEAD_SNAPSHOT_DIR, OUTPUT_FILE
backward_snapshot_report:
	$(call require,BASE_SNAPSHOT_DIR)
	$(call require,HEAD_SNAPSHOT_DIR)
	$(call require,OUTPUT_FILE)
	cargo run -p tfhe-backward-compat-checker -- diff-report \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR) \
		--output $(OUTPUT_FILE)

.PHONY: backward_snapshot_check # Check backward compat. Required: BASE_SNAPSHOT_DIR, HEAD_SNAPSHOT_DIR
backward_snapshot_check:
	$(call require,BASE_SNAPSHOT_DIR)
	$(call require,HEAD_SNAPSHOT_DIR)
	cargo run -p tfhe-backward-compat-checker -- check \
		--base-dir $(BASE_SNAPSHOT_DIR) \
		--head-dir $(HEAD_SNAPSHOT_DIR)

.PHONY: backward_correctness # Check backward compat of current code against BASE_REF. Required: BASE_REF
backward_correctness:
	$(call require,BASE_REF)
	$(eval _BASE_DIR := $(shell mktemp -d))
	$(eval _HEAD_DIR := $(shell mktemp -d))
	$(MAKE) backward_snapshot_worktree BASE_REF=$(BASE_REF) SNAPSHOT_OUTPUT_DIR=$(_BASE_DIR)
	$(MAKE) backward_snapshot SNAPSHOT_OUTPUT_DIR=$(_HEAD_DIR)
	$(MAKE) backward_snapshot_check BASE_SNAPSHOT_DIR=$(_BASE_DIR) HEAD_SNAPSHOT_DIR=$(_HEAD_DIR)

.PHONY: backward_report # Generate a backward compat diff report against BASE_REF. Required: BASE_REF, OUTPUT_FILE
backward_report:
	$(call require,BASE_REF)
	$(call require,OUTPUT_FILE)
	$(eval _BASE_DIR := $(shell mktemp -d))
	$(eval _HEAD_DIR := $(shell mktemp -d))
	$(MAKE) backward_snapshot_worktree BASE_REF=$(BASE_REF) SNAPSHOT_OUTPUT_DIR=$(_BASE_DIR)
	$(MAKE) backward_snapshot SNAPSHOT_OUTPUT_DIR=$(_HEAD_DIR)
	$(MAKE) backward_snapshot_report BASE_SNAPSHOT_DIR=$(_BASE_DIR) HEAD_SNAPSHOT_DIR=$(_HEAD_DIR) OUTPUT_FILE=$(OUTPUT_FILE)
