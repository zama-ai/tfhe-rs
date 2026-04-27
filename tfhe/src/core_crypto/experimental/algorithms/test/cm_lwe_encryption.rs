use crate::core_crypto::experimental::prelude::{
    allocate_and_encrypt_new_cm_lwe_ciphertext, CmDimension,
};
use crate::core_crypto::prelude::*;
use itertools::Itertools;

#[test]
fn cm_encryption() {
    let lwe_dimension = LweDimension(742);
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.0000000007069849454709433), 0.);
    let ciphertext_modulus = CiphertextModulus::new_native();

    let cm_dimension = CmDimension(10);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    // Create the LweSecretKey
    let lwe_secret_keys = (0..cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator)
        })
        .collect_vec();

    // Create the plaintext

    let plaintext = (0..cm_dimension.0).map(|i| (i as u64) << 55).collect_vec();

    let plaintext_list = PlaintextList::from_container(plaintext.as_slice());

    // Create a new LweCiphertext
    let lwe = allocate_and_encrypt_new_cm_lwe_ciphertext(
        &lwe_secret_keys,
        &plaintext_list,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    for i in 0..cm_dimension.0 {
        let decrypted_plaintext =
            decrypt_lwe_ciphertext(&lwe_secret_keys[i], &lwe.extract_lwe_ciphertext(i));

        // Round and remove encoding
        // First create a decomposer working on the high 4 bits corresponding to our encoding.
        let decomposer = SignedDecomposer::new(DecompositionBaseLog(9), DecompositionLevelCount(1));

        let rounded = decomposer.closest_representable(decrypted_plaintext.0);

        // Remove the encoding
        let cleartext = rounded >> 55;

        // Check we recovered the original message
        assert_eq!(cleartext, plaintext[i] >> 55);
    }
}
