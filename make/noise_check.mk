# Make rules for the noise and pfail checks whose results are recorded in database.
#
# Optional variables:
#   NOISE_CHECK_RECORDED_PARAM  Lowercase name of the parameter set to run the checks on.

NOISE_CHECK_RECORDED_PARAM ?= test_meta_param_cpu_2_2_ks_pbs_pke_to_small_zkv2_tuniform_2m128

.PHONY: test_noise_check_recorded # Run shortint noise and pfail check tests on the parameter set recorded in database
test_noise_check_recorded: install_cargo_nextest
	@# First run the sanity checks to make sure the atomic patterns are correct
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,experimental -p tfhe \
		-E "test(/^shortint::.*::test_sanity_check_.*_$(NOISE_CHECK_RECORDED_PARAM)$$/)"
	RUSTFLAGS="$(RUSTFLAGS)" cargo nextest run --cargo-profile $(CARGO_PROFILE) \
		--features=boolean,shortint,integer,experimental -p tfhe --no-capture \
		-E "test(/^shortint::.*::test_noise_check_.*_$(NOISE_CHECK_RECORDED_PARAM)$$/)"
