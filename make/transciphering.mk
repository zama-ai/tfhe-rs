.PHONY: test_aes_transciphering # Run unit tests for the FHE AES-128 (CTR) implementation
test_aes_transciphering:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		transciphering::ciphers::aes

.PHONY: test_aes_transciphering_fast # Same as above but only the non-FHE tests (plain helpers + skip)
test_aes_transciphering_fast:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::aes::test::plain_aes"
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::aes::test::aes_fhe_skip"
