use tfhe::core_crypto::prelude::*;

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;

pub fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_span_events(FmtSpan::NEW)
        .without_time()
        // Build & register the subscriber
        .init();

    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweKeyswitchKey creation
    let input_lwe_dimension = LweDimension(742);
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
    let output_lwe_dimension = LweDimension(2048);
    let decomp_base_log = DecompositionBaseLog(3);
    let decomp_level_count = DecompositionLevelCount(5);
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let input_lwe_secret_key =
        allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
    let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
        output_lwe_dimension,
        &mut secret_generator,
    );

    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &input_lwe_secret_key,
        &output_lwe_secret_key,
        decomp_base_log,
        decomp_level_count,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Create the plaintext
    let msg = 3u64;
    let plaintext = Plaintext(msg << 60);

    // Create a new LweCiphertext
    let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    let mut output_lwe = LweCiphertext::new(
        0,
        output_lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);

    let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

    // Round and remove encoding
    // First create a decomposer working on the high 4 bits corresponding to our encoding.
    let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

    let rounded = decomposer.closest_representable(decrypted_plaintext.0);

    // Remove the encoding
    let cleartext = rounded >> 60;

    // Check we recovered the original message
    assert_eq!(cleartext, msg);
}
