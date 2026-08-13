MATRIX_DIR ?= utils/tfhe-forward-compat-matrices

.PHONY: generate_forward_compat_matrix # Generate the forward compatibility matrices
generate_forward_compat_matrix:
	cargo run --release --manifest-path "${MATRIX_DIR}/orchestrator/Cargo.toml"

.PHONY: test_forward_compat_report # Test the matrix report and baseline handling
test_forward_compat_report:
	cargo test --manifest-path "${MATRIX_DIR}/forward-common/Cargo.toml"
