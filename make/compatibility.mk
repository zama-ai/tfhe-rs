MATRIX_DIR ?= utils/tfhe-forward-compat-matrices

.PHONY: generate_forward_compat_matrix # Generate the forward compatibility matrices
generate_forward_compat_matrix:
	cargo run --release --manifest-path "${MATRIX_DIR}/orchestrator/Cargo.toml"
