# Test rules for ciphers under tfhe/src/transciphering/ciphers/.
# Note: --test-threads=1 keeps tests sequential so each one gets full rayon
# parallelism (the FHE AES blocks are parallelized internally).

.PHONY: test_aes_transciphering # Run unit tests for the FHE AES-128 (CTR) implementation
test_aes_transciphering:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		transciphering::ciphers::aes -- --test-threads=1

.PHONY: test_aes_transciphering_fast # Same as above but only the non-FHE tests (plain helpers + skip)
test_aes_transciphering_fast:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::aes::test::plain_aes" -- --test-threads=1
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::aes::test::aes_fhe_skip" -- --test-threads=1
