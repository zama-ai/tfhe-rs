# Make rules for the FHE transciphering ciphers (tfhe/src/transciphering/ciphers/).
#
# Optional variables:
#   BENCH_FILTER  Criterion regex selecting which sub-benchmarks to run
#                 (default: run all). Examples:
#                   make bench_aes_transciphering BENCH_FILTER=key_expansion
#                   make bench_aes_transciphering BENCH_FILTER=keystream_16
#                   make bench_aes_transciphering BENCH_FILTER='keystream_(1|16)'

BENCH_FILTER ?=

#
# Tests
#

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

.PHONY: test_kreyvium_transciphering # Run unit tests for the FHE Kreyvium implementation
test_kreyvium_transciphering:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		transciphering::ciphers::kreyvium

.PHONY: test_kreyvium_transciphering_fast # Same as above but only the non-FHE tests (plain + seek_plain)
test_kreyvium_transciphering_fast:
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::kreyvium::test::kreyvium_test_plain"
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::kreyvium::test::kreyvium_plain_encrypt_decrypt_round_trip"
	RUSTFLAGS="$(RUSTFLAGS)" cargo test --profile $(CARGO_PROFILE) \
		--features=shortint -p tfhe --lib \
		"transciphering::ciphers::kreyvium::test::kreyvium_seek_plain"

#
# Benchmarks
#

.PHONY: bench_aes_transciphering # Run criterion benches for the CPU bit-sliced AES-128 transciphering pipeline
bench_aes_transciphering:
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo bench \
		--bench transciphering-aes \
		--features=shortint,internal-keycache \
		-p tfhe-benchmark -- $(BENCH_FILTER)

# Convenience shortcuts: each sets BENCH_FILTER and recurses into the main rule.

.PHONY: bench_aes_keystream_1 # AES: single CTR block (128 bits) keystream
bench_aes_keystream_1:
	$(MAKE) bench_aes_transciphering BENCH_FILTER=keystream_1_block

.PHONY: bench_aes_keystream_16 # AES: 16 CTR blocks keystream
bench_aes_keystream_16:
	$(MAKE) bench_aes_transciphering BENCH_FILTER=keystream_16_blocks

.PHONY: bench_aes_key_expansion # AES: one-time key schedule cost
bench_aes_key_expansion:
	$(MAKE) bench_aes_transciphering BENCH_FILTER=key_expansion::

.PHONY: bench_aes_key_expansion_plus_1_block # AES: cold-start (key schedule + 1 CTR block)
bench_aes_key_expansion_plus_1_block:
	$(MAKE) bench_aes_transciphering BENCH_FILTER=key_expansion_plus_1_block

.PHONY: bench_aes_transcipher # AES: end-to-end transcipher over 16 blocks
bench_aes_transcipher:
	$(MAKE) bench_aes_transciphering BENCH_FILTER=transcipher_16_blocks

.PHONY: bench_kreyvium_transciphering # Run criterion benches for the CPU Kreyvium transciphering pipeline
bench_kreyvium_transciphering:
	RUSTFLAGS="$(RUSTFLAGS)" __TFHE_RS_BENCH_TYPE=$(BENCH_TYPE) \
	cargo bench \
		--bench transciphering-kreyvium \
		--features=shortint,internal-keycache \
		-p tfhe-benchmark -- $(BENCH_FILTER)

.PHONY: bench_kreyvium_warmup # Kreyvium: 1152-step register warmup
bench_kreyvium_warmup:
	$(MAKE) bench_kreyvium_transciphering BENCH_FILTER=warmup

.PHONY: bench_kreyvium_keystream # Kreyvium: 64-bit keystream from a warmed state
bench_kreyvium_keystream:
	$(MAKE) bench_kreyvium_transciphering BENCH_FILTER=keystream_64bits

.PHONY: bench_kreyvium_transcipher # Kreyvium: end-to-end transcipher over 64 bits
bench_kreyvium_transcipher:
	$(MAKE) bench_kreyvium_transciphering BENCH_FILTER=transcipher_64bits
