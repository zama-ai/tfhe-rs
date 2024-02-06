LATTICE_ESTIMATOR_DIR=$(PWD)/../../third_party/lattice-estimator
SECURITY_LEVELS=80 112 128 192
SAGE_OBJECT_DIR=sage-object
SAGE_SECURITY_CURVES=$(SECURITY_LEVELS:%=$(SAGE_OBJECT_DIR)/%.sobj)
SAGE_VERIFIED_CURVES=$(SAGE_OBJECT_DIR)/verified_curves.sobj
CURVES_JSON_PATH=json/curves.json
CURVES_CPP_GEN_H=concrete-security-curves-cpp/include/concrete/curves.gen.h
CURVES_RUST_GEN_TXT=concrete-security-curves-rust/src/gaussian/curves_gen.rs

generate-code: generate-cpp generate-rust

# Generate CPP ########################

$(CURVES_CPP_GEN_H): concrete-security-curves-cpp/gen_header.py $(CURVES_JSON_PATH)
	cat $(CURVES_JSON_PATH) | python3 concrete-security-curves-cpp/gen_header.py > $(CURVES_CPP_GEN_H)

generate-cpp: $(CURVES_CPP_GEN_H)

# Generate RUST ########################

$(CURVES_RUST_GEN_TXT): concrete-security-curves-rust/gen_table.py $(CURVES_JSON_PATH)
	cat $(CURVES_JSON_PATH) | python3 concrete-security-curves-rust/gen_table.py > $(CURVES_RUST_GEN_TXT)

generate-rust: $(CURVES_RUST_GEN_TXT)

# Compare curves #######################

$(SAGE_OBJECT_DIR)/outdated_curves.timestamp: ./lattice-scripts/compare_curves_and_estimator.py
	PYTHONPATH=$(LATTICE_ESTIMATOR_DIR) python3 ./lattice-scripts/compare_curves_and_estimator.py \
	--curves-dir $(SAGE_OBJECT_DIR) --security-levels $(SECURITY_LEVELS) --log-q 64 \
	&& touch $(SAGE_OBJECT_DIR)/outdated_curves.timestamp

compare-curves: $(SAGE_OBJECT_DIR)/outdated_curves.timestamp

# Compare curves custom q #######################
# run via e.g:
# logq=128 make compare-curves-custom-q
# for q = 2**(128)

$(SAGE_OBJECT_DIR)/outdated_curves.timestamp: ./lattice-scripts/compare_curves_and_estimator.py
	PYTHONPATH=$(LATTICE_ESTIMATOR_DIR) python3 ./lattice-scripts/compare_curves_and_estimator.py \
	--curves-dir $(SAGE_OBJECT_DIR) --security-levels $(SECURITY_LEVELS) --log-q $(logq) \
	&& touch $(SAGE_OBJECT_DIR)/outdated_curves.timestamp

compare-curves-custom-q: $(SAGE_OBJECT_DIR)/outdated_curves.timestamp

# Generate curves ######################

$(SAGE_OBJECT_DIR)/%.sobj: $(SAGE_OBJECT_DIR)/outdated_curves.timestamp ./lattice-scripts/generate_data.sh ./lattice-scripts/generate_data.py
	PYTHONPATH=$(LATTICE_ESTIMATOR_DIR) ./lattice-scripts/generate_data.sh \
	$* --output $(SAGE_OBJECT_DIR) --old-models $(SAGE_VERIFIED_CURVES)

generate-curves: $(SAGE_SECURITY_CURVES)

# Verify curves #######################

$(CURVES_JSON_PATH) $(SAGE_VERIFIED_CURVES): ./lattice-scripts/verify_curves.py #$(SAGE_SECURITY_CURVES)
	python3 ./lattice-scripts/verify_curves.py \
	--curves-dir $(SAGE_OBJECT_DIR) --verified-curves-path $(SAGE_VERIFIED_CURVES) \
	--security-levels $(SECURITY_LEVELS) --log-q 64 > $(CURVES_JSON_PATH)

verify-curves: $(CURVES_JSON_PATH)

.PHONY: generate-cpp \
	generate-rust \
	generate-code \
	compare-curves \
	generate-curves \
	verify-curves
