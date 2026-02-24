SNAPSHOT_DIR := utils/tfhe-lints/snapshots

DYLINT_CMD = TFHE_BACKWARD_COMPAT_DATA_DIR=$(1) \
	TFHE_BACKWARD_COMPAT_FILE_SUFFIX=$(2) \
	RUSTFLAGS="$(RUSTFLAGS) -Dwarnings" \
	cargo dylint --lib tfhe_lints_snapshot --no-deps

lint-tfhe = $(call DYLINT_CMD,$(1),$(2)) -p tfhe -- --features=boolean,shortint,integer,strings,zk-pok
lint-tfhe-zk-pok = $(call DYLINT_CMD,$(1),$(2)) -p tfhe-zk-pok -- --features=experimental
lint-tfhe-csprng = $(call DYLINT_CMD,$(1),$(2)) -p tfhe-csprng --


.PHONY: backward-snapshot-generate # Generate the base snapshot. This should be run on the main branch and the generated files should be committed.
backward-snapshot-base: install_cargo_dylint
	@echo "Generating base snapshot"
	$(call lint-tfhe,$(SNAPSHOT_DIR),base)
	$(call lint-tfhe-zk-pok,$(SNAPSHOT_DIR),base)
	$(call lint-tfhe-csprng,$(SNAPSHOT_DIR),base)

.PHONY: backward-snapshot-head # Generate the head snapshot. This should be run on the feature branch before generating the report.
backward-snapshot-head: install_cargo_dylint
	@echo "Generating head snapshot"
	@rm -rf $(SNAPSHOT_DIR)/head
	@mkdir -p $(SNAPSHOT_DIR)/head
	$(call lint-tfhe,$(SNAPSHOT_DIR)/head,head)
	$(call lint-tfhe-zk-pok,$(SNAPSHOT_DIR)/head,head)
	$(call lint-tfhe-csprng,$(SNAPSHOT_DIR)/head,head)

BASE_DIR ?= ../base/utils/tfhe-lints/snapshots
BASE_FILE ?= base
HEAD_DIR ?= $(SNAPSHOT_DIR)/head
HEAD_FILE ?= head
OUTPUT_FILE ?= ../report.md

.PHONY: backward-snapshot-generate # Generate a report comparing the base and head snapshots. This should be run on the feature branch after generating the head snapshot.
backward-snapshot-generate:
	cargo run -p tfhe-backward-compat-checker -- diff-report \
    --base-dir $(BASE_DIR) --base-suffix $(BASE_FILE) \
    --head-dir $(SNAPSHOT_DIR) --head-suffix $(HEAD_FILE) \
    --output $(OUTPUT_FILE)

ALLOW_ADDITIONAL_ENUMS ?= false

.PHONY: backward-snapshot-check # Check for backward compatibility issues between the base and head snapshots. This should be run on the feature branch after generating the head snapshot. By default, this will fail if there are any new enums in the head snapshot that were not present in the base snapshot, but this can be overridden with the ALLOW_ADDITIONAL_ENUMS variable.
backward-snapshot-check:
	cargo run -p tfhe-backward-compat-checker -- check \
		--base-dir $(SNAPSHOT_DIR) --base-suffix $(BASE_FILE) \
		--head-dir $(HEAD_DIR) --head-suffix $(HEAD_FILE) \
		$(if $(filter true,$(ALLOW_ADDITIONAL_ENUMS)),--allow-additional-enums)
