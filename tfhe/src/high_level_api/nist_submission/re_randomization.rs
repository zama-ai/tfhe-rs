use crate::high_level_api::nist_submission::CompactPublicKey;
use crate::high_level_api::re_randomization::ReRandContextAdd;
use crate::integer::ciphertext::{ReRandomizationSeed, ReRandomizationSeedHasher};
use crate::prelude::ReRandomize;
use crate::shortint::ciphertext::ReRandomizationHashAlgo;
use crate::ReRandomizationContext;

pub trait NistSubmissionReRandomize: ReRandContextAdd {
    /// Re-randomize the ciphertext using the provided public key and seed.
    ///
    /// The random elements of the ciphertexts will be changed but it will still encrypt the same
    /// value.
    fn nist_submission_re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()>;
}

impl<T: ReRandomize> NistSubmissionReRandomize for T {
    fn nist_submission_re_randomize(
        &mut self,
        compact_public_key: &CompactPublicKey,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        self.re_randomize(compact_public_key, seed)
    }
}

pub fn preproc_eval(
    inputs: &mut [&mut dyn NistSubmissionReRandomize],
    function_description: &[u8],
    compact_public_key: &CompactPublicKey,
) -> crate::Result<()> {
    let mut re_rand_context = ReRandomizationContext::new_with_hasher(
        [function_description],
        *b"TFHE_Enc",
        ReRandomizationSeedHasher::new(ReRandomizationHashAlgo::Shake256, *b"TFHE_Rrd"),
    );

    for input in inputs.iter_mut() {
        re_rand_context.add_ciphertext(&**input);
    }

    let mut seed_gen = re_rand_context.finalize();

    for input in inputs {
        let seed = seed_gen.next_seed()?;
        input.nist_submission_re_randomize(compact_public_key, seed)?;
    }

    Ok(())
}
