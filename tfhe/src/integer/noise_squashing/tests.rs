use crate::integer::ciphertext::{
    SquashedNoiseBooleanBlock, SquashedNoiseRadixCiphertext, SquashedNoiseSignedRadixCiphertext,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::{
    BooleanBlock, RadixCiphertext, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::ciphertext::{Degree, SquashedNoiseCiphertext};
use crate::shortint::parameters::test_params::TestParameters;
use crate::shortint::parameters::{
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use rand::prelude::*;
use std::sync::Arc;

/// The function executor that squashes the noise of its input with a CPU noise squashing key
struct CpuNoiseSquashingExecutor<'key> {
    noise_squashing_private_key: &'key NoiseSquashingPrivateKey,
    /// The keys are set later, when the test case calls setup
    keys: Option<(NoiseSquashingKey, Arc<ServerKey>)>,
}

impl<'key> CpuNoiseSquashingExecutor<'key> {
    fn new(noise_squashing_private_key: &'key NoiseSquashingPrivateKey) -> Self {
        Self {
            noise_squashing_private_key,
            keys: None,
        }
    }

    fn setup_from_keys(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        let noise_squashing_key =
            NoiseSquashingKey::new(cks.as_ref(), self.noise_squashing_private_key);
        self.keys = Some((noise_squashing_key, sks));
    }
}

impl<'a> FunctionExecutor<&'a RadixCiphertext, SquashedNoiseRadixCiphertext>
    for CpuNoiseSquashingExecutor<'_>
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> SquashedNoiseRadixCiphertext {
        let (noise_squashing_key, sks) = self.keys.as_ref().expect("setup was not properly called");
        noise_squashing_key
            .squash_radix_ciphertext_noise(sks, input)
            .unwrap()
    }
}

impl<'a> FunctionExecutor<&'a SignedRadixCiphertext, SquashedNoiseSignedRadixCiphertext>
    for CpuNoiseSquashingExecutor<'_>
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> SquashedNoiseSignedRadixCiphertext {
        let (noise_squashing_key, sks) = self.keys.as_ref().expect("setup was not properly called");
        noise_squashing_key
            .squash_signed_radix_ciphertext_noise(sks, input)
            .unwrap()
    }
}

impl<'a> FunctionExecutor<&'a BooleanBlock, SquashedNoiseBooleanBlock>
    for CpuNoiseSquashingExecutor<'_>
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, sks);
    }

    fn execute(&mut self, input: &'a BooleanBlock) -> SquashedNoiseBooleanBlock {
        let (noise_squashing_key, sks) = self.keys.as_ref().expect("setup was not properly called");
        noise_squashing_key
            .squash_boolean_block_noise(sks, input)
            .unwrap()
    }
}

#[test]
fn test_noise_squashing_degrees() {
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
    let executor = CpuNoiseSquashingExecutor::new(&noise_squashing_private_key);
    noise_squashing_degrees_test(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        &noise_squashing_private_key,
        executor,
    );
}

/// Checks the degree that noise squashing records on each output block, and the decrypted values.
///
/// Noise squashing packs the input blocks by pairs as `low + message_modulus * high`. Each output
/// block must have the degree of its packed input: `low_degree + message_modulus * high_degree`
/// for a pair, and the degree of the input block for a block without a pair.
///
/// The executor must squash the noise with a key generated from `noise_squashing_private_key`,
/// which decrypts the outputs.
pub(crate) fn noise_squashing_degrees_test<P, T>(
    param: P,
    noise_squashing_private_key: &NoiseSquashingPrivateKey,
    mut executor: T,
) where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, SquashedNoiseRadixCiphertext>
        + for<'a> FunctionExecutor<&'a SignedRadixCiphertext, SquashedNoiseSignedRadixCiphertext>
        + for<'a> FunctionExecutor<&'a BooleanBlock, SquashedNoiseBooleanBlock>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let sks = Arc::new(sks);
    // Each encryption gives its block count. The block count of this key is not used.
    let cks = RadixClientKey::from((cks, 1));

    // The three implementations of the executor have the same setup
    FunctionExecutor::<&RadixCiphertext, SquashedNoiseRadixCiphertext>::setup(
        &mut executor,
        &cks,
        sks.clone(),
    );

    let degrees = |blocks: &[SquashedNoiseCiphertext]| {
        blocks
            .iter()
            .map(|block| block.degree())
            .collect::<Vec<_>>()
    };

    let message_modulus = cks.parameters().message_modulus().0;
    let fresh_degree = Degree::new(message_modulus - 1);
    let packed_fresh_degree = Degree::new(message_modulus * message_modulus - 1);

    // Fresh blocks, with an even and an odd block count. The last packed block of an odd block
    // count holds a single input block
    for num_blocks in [1usize, 3, 4, 8] {
        let mut expected_degrees = vec![packed_fresh_degree; num_blocks / 2];
        if num_blocks % 2 == 1 {
            expected_degrees.push(fresh_degree);
        }

        let clear = 0x9C27u64 % message_modulus.pow(num_blocks as u32);
        let ct = cks.as_ref().encrypt_radix(clear, num_blocks);
        let squashed: SquashedNoiseRadixCiphertext = executor.execute(&ct);
        assert_eq!(
            degrees(squashed.packed_blocks()),
            expected_degrees,
            "Invalid degrees for an unsigned radix of {num_blocks} fresh blocks"
        );
        let decrypted: u64 = noise_squashing_private_key
            .decrypt_radix(&squashed)
            .unwrap();
        assert_eq!(decrypted, clear);

        let clear = -1i16;
        let ct = cks.as_ref().encrypt_signed_radix(clear, num_blocks);
        let squashed: SquashedNoiseSignedRadixCiphertext = executor.execute(&ct);
        assert_eq!(
            degrees(squashed.packed_blocks()),
            expected_degrees,
            "Invalid degrees for a signed radix of {num_blocks} fresh blocks"
        );
        let decrypted: i16 = noise_squashing_private_key
            .decrypt_signed_radix(&squashed)
            .unwrap();
        assert_eq!(decrypted, clear);
    }

    // Trivial blocks: the degree of a trivial block is its value. The blocks of this value are
    // 0, 1 and 1. The fourth block, when there is one, is 0 and does not change the degree of the
    // second packed block
    let clear = message_modulus * (1 + message_modulus);
    let expected_degrees = [Degree::new(message_modulus), Degree::new(1)];
    for num_blocks in [3, 4] {
        let ct: RadixCiphertext = sks.create_trivial_radix(clear, num_blocks);
        let squashed: SquashedNoiseRadixCiphertext = executor.execute(&ct);
        assert_eq!(
            degrees(squashed.packed_blocks()),
            expected_degrees,
            "Invalid degrees for an unsigned radix of {num_blocks} trivial blocks"
        );
        let decrypted: u64 = noise_squashing_private_key
            .decrypt_radix(&squashed)
            .unwrap();
        assert_eq!(decrypted, clear);
    }

    // Boolean blocks, encrypted (degree 1) and trivial (degree 0). A boolean block is not packed,
    // so the output block keeps the degree of the input block
    for (clear, expected_input_degree, boolean_block) in [
        (false, Degree::new(1), cks.as_ref().encrypt_bool(false)),
        (true, Degree::new(1), cks.as_ref().encrypt_bool(true)),
        (
            false,
            Degree::new(0),
            sks.create_trivial_boolean_block(false),
        ),
    ] {
        let input_degree = boolean_block.0.degree;
        assert_eq!(input_degree, expected_input_degree);

        let squashed: SquashedNoiseBooleanBlock = executor.execute(&boolean_block);
        assert_eq!(
            squashed.packed_blocks().degree(),
            input_degree,
            "Invalid degree for a boolean block of degree {input_degree:?}"
        );
        assert_eq!(
            noise_squashing_private_key.decrypt_bool(&squashed).unwrap(),
            clear
        );
    }
}

#[test]
fn test_integer_noise_squashing_decrypt_auto_cast_and_bool() {
    let param = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let noise_squashing_parameters = NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    // The goal is to test that encrypting a value stored in a type
    // for which the bit count does not match the target block count of the encrypted
    // radix properly applies upcasting/downcasting
    let (cks, sks) = KEY_CACHE.get_from_params(param);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_parameters);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);

    let mut rng = rand::thread_rng();

    let num_blocks = 32u32.div_ceil(param.message_modulus.0.ilog2()) as usize;

    // Positive signed value
    let value = rng.gen_range(0..=i32::MAX);
    let ct = cks.encrypt_signed_radix(value, num_blocks * 2);
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_signed_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: i64 = noise_squashing_private_key
        .decrypt_signed_radix(&ct)
        .unwrap();
    assert_eq!(i64::from(value), d);

    let ct = cks.encrypt_signed_radix(value, num_blocks.div_ceil(2));
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_signed_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: i16 = noise_squashing_private_key
        .decrypt_signed_radix(&ct)
        .unwrap();
    assert_eq!(value as i16, d);

    let odd_block_count = if num_blocks % 2 == 1 {
        num_blocks
    } else {
        num_blocks + 1
    };

    // Negative signed value
    for block_count in [odd_block_count, num_blocks * 2, num_blocks.div_ceil(2)] {
        let value = rng.gen_range(i8::MIN..0);
        let ct = cks.encrypt_signed_radix(value, block_count);
        let ct = sks.bitand_parallelized(&ct, &ct);
        let ct = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct)
            .unwrap();
        let d: i64 = noise_squashing_private_key
            .decrypt_signed_radix(&ct)
            .unwrap();
        assert_eq!(i64::from(value), d);

        let ct = cks.encrypt_signed_radix(value, block_count);
        let ct = sks.bitand_parallelized(&ct, &ct);
        let ct = noise_squashing_key
            .squash_signed_radix_ciphertext_noise(&sks, &ct)
            .unwrap();
        let d: i16 = noise_squashing_private_key
            .decrypt_signed_radix(&ct)
            .unwrap();
        assert_eq!(value as i16, d);
    }

    // Unsigned value
    let value = rng.gen::<u32>();
    let ct = cks.encrypt_radix(value, num_blocks * 2);
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: u64 = noise_squashing_private_key.decrypt_radix(&ct).unwrap();
    assert_eq!(u64::from(value), d);

    let ct = cks.encrypt_radix(value, num_blocks.div_ceil(2));
    let ct = sks.bitand_parallelized(&ct, &ct);
    let ct = noise_squashing_key
        .squash_radix_ciphertext_noise(&sks, &ct)
        .unwrap();
    let d: u16 = noise_squashing_private_key.decrypt_radix(&ct).unwrap();
    assert_eq!(value as u16, d);

    // Booleans
    for val in [true, false] {
        let ct = cks.encrypt_bool(val);
        let ct = sks.boolean_bitand(&ct, &ct);
        let ct = noise_squashing_key
            .squash_boolean_block_noise(&sks, &ct)
            .unwrap();
        let d = noise_squashing_private_key.decrypt_bool(&ct).unwrap();
        assert_eq!(val, d);
    }
}

#[test]
fn test_repro_noise_squashing_degree_handling() {
    use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::integer::{gen_keys_radix, ClientKey, IntegerCiphertext};
    use crate::shortint::parameters::{
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as NSP,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P22,
    };

    let (rck, sks) = gen_keys_radix(P22, 4);
    let cks: &ClientKey = rck.as_ref();
    // public handle on the underlying shortint key (integer ServerKey::key is private)
    let shortint_sks = sks.clone().into_raw_parts();
    let nspk = NoiseSquashingPrivateKey::new(NSP);
    let nsk = NoiseSquashingKey::new(cks, &nspk);

    // --- non-canonical but valid radix encoding of 17 -> blocks [1, 4, 0, 0] ---
    {
        let mut ct = cks.encrypt_signed_radix(1i8, 4);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[1], 4);
        let dec_signed: i8 = cks.decrypt_signed_radix(&ct);
        assert_eq!(dec_signed, 17);
        let should_fail_signed = nsk.squash_signed_radix_ciphertext_noise(&sks, &ct);
        assert!(should_fail_signed.is_err());
    }

    // unsigned mirror of the identical construction
    {
        let mut ctu = cks.encrypt_radix(1u8, 4);
        shortint_sks.unchecked_scalar_add_assign(&mut ctu.blocks_mut()[1], 4);
        let dec_unsigned: u8 = cks.decrypt_radix(&ctu);
        assert_eq!(dec_unsigned, 17);
        let should_fail_unsigned = nsk.squash_radix_ciphertext_noise(&sks, &ctu);
        assert!(should_fail_unsigned.is_err());
    }
}

#[test]
fn test_noise_squashing_rejects_unpackable_inputs() {
    use crate::integer::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
    use crate::integer::{gen_keys_radix, ClientKey, IntegerCiphertext};
    use crate::shortint::ciphertext::NoiseLevel;
    use crate::shortint::parameters::{
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as NSP,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P22,
    };

    let (rck, sks) = gen_keys_radix(P22, 3);
    let cks: &ClientKey = rck.as_ref();
    let shortint_sks = sks.clone().into_raw_parts();
    let max_noise_level = shortint_sks.max_noise_level;
    let nspk = NoiseSquashingPrivateKey::new(NSP);
    let nsk = NoiseSquashingKey::new(cks, &nspk);

    // Odd block count: the last block is not packed but its carry must still be empty
    {
        let mut ct = cks.encrypt_radix(16u8, 3);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[2], 4);
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }
    {
        let mut ct = cks.encrypt_signed_radix(17i8, 3);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[2], 16);
        let dec: i8 = cks.decrypt_signed_radix(&ct);
        assert_eq!(dec, 17);
        assert!(nsk.squash_signed_radix_ciphertext_noise(&sks, &ct).is_err());
    }
    // Single block radix
    {
        let mut ct = cks.encrypt_radix(1u8, 1);
        shortint_sks.unchecked_scalar_add_assign(&mut ct.blocks_mut()[0], 4);
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }

    // Clean carries but the noise of the packed block exceeds the max noise level
    for (low_noise, high_noise) in [
        (NoiseLevel(1), NoiseLevel(2)),
        (NoiseLevel(5), NoiseLevel(1)),
    ] {
        let mut ct = cks.encrypt_radix(5u8, 2);
        ct.blocks_mut()[0].set_noise_level(low_noise, max_noise_level);
        ct.blocks_mut()[1].set_noise_level(high_noise, max_noise_level);
        assert!(ct.blocks().iter().all(|b| b.carry_is_empty()));
        assert!(nsk.squash_radix_ciphertext_noise(&sks, &ct).is_err());
    }

    // BooleanBlock with a non empty carry
    {
        let mut b = cks.encrypt_bool(false);
        shortint_sks.unchecked_scalar_add_assign(&mut b.0, 4);
        assert!(!cks.decrypt_bool(&b));
        assert!(nsk.squash_boolean_block_noise(&sks, &b).is_err());
    }
    // BooleanBlock with degree 2 but an empty carry: accepted, both decryptions agree
    {
        let mut b = cks.encrypt_bool(true);
        shortint_sks.unchecked_scalar_add_assign(&mut b.0, 1);
        assert!(b.0.degree.get() > 1 && b.0.carry_is_empty());
        assert!(cks.decrypt_bool(&b));
        let squashed = nsk.squash_boolean_block_noise(&sks, &b).unwrap();
        assert!(nspk.decrypt_bool(&squashed).unwrap());
    }
    // BooleanBlock from a list expanded without key keeps the degree of the list blocks
    // (message_modulus - 1) while holding a value in {0, 1}, it must be accepted
    {
        use crate::integer::ciphertext::CompactCiphertextList;
        use crate::integer::{BooleanBlock, CompactPublicKey};

        let pk = CompactPublicKey::new(cks);
        let list = CompactCiphertextList::builder(&pk)
            .push(false)
            .push(true)
            .build();
        let expander = list.expand_without_key().unwrap();
        for (i, expected) in [false, true].into_iter().enumerate() {
            let b: BooleanBlock = expander.get(i).unwrap().unwrap();
            assert!(b.0.degree.get() > 1 && b.0.carry_is_empty());
            let squashed = nsk.squash_boolean_block_noise(&sks, &b).unwrap();
            assert_eq!(nspk.decrypt_bool(&squashed).unwrap(), expected);
        }
    }

    // Sanity check: clean inputs with odd block counts still work
    for num_blocks in [1, 3] {
        let ct = cks.encrypt_radix(2u8, num_blocks);
        let squashed = nsk.squash_radix_ciphertext_noise(&sks, &ct).unwrap();
        let d: u8 = nspk.decrypt_radix(&squashed).unwrap();
        assert_eq!(d, 2);

        let ct = cks.encrypt_signed_radix(-1i8, num_blocks);
        let squashed = nsk.squash_signed_radix_ciphertext_noise(&sks, &ct).unwrap();
        let d: i8 = nspk.decrypt_signed_radix(&squashed).unwrap();
        assert_eq!(d, -1);
    }
}
