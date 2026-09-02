//! One protocol transaction, as a coprocessor runs it.
//!
//! Same workflow as the `gpu_protocol_long_run` stress test, minus everything only a test needs:
//! client encryption, decryptions, the determinism re-run, serialization. What is left is billable
//! coprocessor work, split in the two halves the protocol schedules as separate jobs.

use rand::Rng;
use tfhe::prelude::*;
use tfhe::shortint::parameters::MetaParameters;
use tfhe::{
    ClientKey, CompactPublicKey, CompressedCiphertextList, CompressedCiphertextListBuilder,
    CompressedServerKey, CompressedSquashedNoiseCiphertextList,
    CompressedSquashedNoiseCiphertextListBuilder, Config, FheBool, FheUint64,
    ReRandomizationContext, ReRandomizationSeedGen,
};

/// Stand-ins for the protocol's own domain separators and input hash.
const RERAND_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Rrd";
const CPK_ENCRYPTION_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Enc";
const METADATA_LEN: usize = 256 / 8;

/// Stands in for the protocol's opcode numbering. Only distinctness matters here.
type NodeOpcode = u32;

const OPCODE_GE: NodeOpcode = 1;
const OPCODE_IF_THEN_ELSE: NodeOpcode = 2;
const OPCODE_ADD: NodeOpcode = 3;
const OPCODE_SUB: NodeOpcode = 4;

/// `Off` is not a protocol mode. It exists so a benchmark can price re-randomization by difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReRandomization {
    On,
    Off,
}

impl ReRandomization {
    fn is_on(self) -> bool {
        self == Self::On
    }
}

/// Node seeds depend only on the opcode and the operands, which is what lets two coprocessors
/// agree on the same ciphertexts.
fn node_context(opcode: NodeOpcode) -> ReRandomizationContext {
    ReRandomizationContext::new(
        RERAND_DOMAIN_SEPARATOR,
        [opcode.to_be_bytes().as_slice()],
        CPK_ENCRYPTION_DOMAIN_SEPARATOR,
    )
}

/// Passing the compact public key covers both modes. A server key holding a CPK derived from the
/// compute key ignores it in favor of the derived one.
fn re_randomize_operand<T: ReRandomize>(
    ct: &mut T,
    cpk: &CompactPublicKey,
    seed_gen: &mut ReRandomizationSeedGen,
) {
    ct.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
}

fn node_ge(
    from_amount: &FheUint64,
    amount: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> FheBool {
    let mut lhs = from_amount.clone();
    let mut rhs = amount.clone();

    if rerand.is_on() {
        let mut ctx = node_context(OPCODE_GE);
        ctx.add_ciphertext(&lhs);
        ctx.add_ciphertext(&rhs);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
        re_randomize_operand(&mut rhs, cpk, &mut seed_gen);
    }

    lhs.ge(&rhs)
}

/// The zero counts as an operand. The GPU `if_then_else` rejects clear inputs, so it is trivially
/// encrypted and re-randomized like the rest.
fn node_if_then_else(
    has_enough_funds: &FheBool,
    amount: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> FheUint64 {
    let mut condition = has_enough_funds.clone();
    let mut then_value = amount.clone();
    let mut else_value = FheUint64::encrypt_trivial(0u64);

    if rerand.is_on() {
        let mut ctx = node_context(OPCODE_IF_THEN_ELSE);
        ctx.add_ciphertext(&condition);
        ctx.add_ciphertext(&then_value);
        ctx.add_ciphertext(&else_value);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut condition, cpk, &mut seed_gen);
        re_randomize_operand(&mut then_value, cpk, &mut seed_gen);
        re_randomize_operand(&mut else_value, cpk, &mut seed_gen);
    }

    condition.select(&then_value, &else_value)
}

fn node_add(
    to_amount: &FheUint64,
    amount_to_transfer: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> FheUint64 {
    let mut lhs = to_amount.clone();
    let mut rhs = amount_to_transfer.clone();

    if rerand.is_on() {
        let mut ctx = node_context(OPCODE_ADD);
        ctx.add_ciphertext(&lhs);
        ctx.add_ciphertext(&rhs);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
        re_randomize_operand(&mut rhs, cpk, &mut seed_gen);
    }

    &lhs + &rhs
}

fn node_sub(
    from_amount: &FheUint64,
    amount_to_transfer: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> FheUint64 {
    let mut lhs = from_amount.clone();
    let mut rhs = amount_to_transfer.clone();

    if rerand.is_on() {
        let mut ctx = node_context(OPCODE_SUB);
        ctx.add_ciphertext(&lhs);
        ctx.add_ciphertext(&rhs);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
        re_randomize_operand(&mut rhs, cpk, &mut seed_gen);
    }

    &lhs - &rhs
}

/// The ERC-7984 whitepaper transfer, the flavor the protocol runs. Every node re-randomizes its own
/// operands before evaluating, so this graph carries nine of them. Other flavors carry a different
/// count.
///
/// Operands are cloned per node on purpose. A value feeding several nodes is re-randomized once in
/// each, like a handle read several times by a transaction.
///
/// Sequential, for throughput runs where the parallelism comes from the transactions in flight.
pub fn transfer(
    from_amount: &FheUint64,
    to_amount: &FheUint64,
    amount: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> (FheUint64, FheUint64) {
    let has_enough_funds = node_ge(from_amount, amount, cpk, rerand);
    let amount_to_transfer = node_if_then_else(&has_enough_funds, amount, cpk, rerand);

    let new_to_amount = node_add(to_amount, &amount_to_transfer, cpk, rerand);
    let new_from_amount = node_sub(from_amount, &amount_to_transfer, cpk, rerand);

    (new_from_amount, new_to_amount)
}

/// [`transfer`] with its two independent nodes in parallel, for latency runs. Nothing is shared
/// between them, so the results cannot change.
pub fn par_transfer(
    from_amount: &FheUint64,
    to_amount: &FheUint64,
    amount: &FheUint64,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> (FheUint64, FheUint64) {
    let has_enough_funds = node_ge(from_amount, amount, cpk, rerand);
    let amount_to_transfer = node_if_then_else(&has_enough_funds, amount, cpk, rerand);

    let (new_to_amount, new_from_amount) = rayon::join(
        || node_add(to_amount, &amount_to_transfer, cpk, rerand),
        || node_sub(from_amount, &amount_to_transfer, cpk, rerand),
    );

    (new_from_amount, new_to_amount)
}

/// F1, the compute half of a transaction.
pub fn f1_decomp_transfer_comp(
    compressed_inputs: &CompressedCiphertextList,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> CompressedCiphertextList {
    let from_amount: FheUint64 = compressed_inputs.get(0).unwrap().unwrap();
    let to_amount: FheUint64 = compressed_inputs.get(1).unwrap().unwrap();
    let amount: FheUint64 = compressed_inputs.get(2).unwrap().unwrap();

    let (new_from_amount, new_to_amount) = transfer(&from_amount, &to_amount, &amount, cpk, rerand);

    CompressedCiphertextListBuilder::new()
        .push(new_from_amount)
        .push(new_to_amount)
        .build()
        .unwrap()
}

/// F2, what the protocol runs before handing results to threshold decryption. The two noise
/// squashings are the reason a transaction costs much more than the transfer graph alone.
pub fn f2_decomp_sns_comp(
    compressed_outputs: &CompressedCiphertextList,
) -> CompressedSquashedNoiseCiphertextList {
    let new_from_amount: FheUint64 = compressed_outputs.get(0).unwrap().unwrap();
    let new_to_amount: FheUint64 = compressed_outputs.get(1).unwrap().unwrap();

    let ns_new_from = new_from_amount.squash_noise().unwrap();
    let ns_new_to = new_to_amount.squash_noise().unwrap();

    CompressedSquashedNoiseCiphertextListBuilder::new()
        .push(ns_new_from)
        .push(ns_new_to)
        .build()
        .unwrap()
}

pub fn full_transaction(
    compressed_inputs: &CompressedCiphertextList,
    cpk: &CompactPublicKey,
    rerand: ReRandomization,
) -> CompressedSquashedNoiseCiphertextList {
    let compressed_outputs = f1_decomp_transfer_comp(compressed_inputs, cpk, rerand);

    f2_decomp_sns_comp(&compressed_outputs)
}

pub struct ProtocolKeys {
    pub client_key: ClientKey,
    pub compressed_server_key: CompressedServerKey,
    pub compact_public_key: CompactPublicKey,
}

/// The meta parameters have to carry a compact public key, a compression key, a noise squashing key
/// and a noise squashing compression key. The workflow uses all of them.
pub fn generate_keys(meta_params: MetaParameters) -> ProtocolKeys {
    let config = Config::from(meta_params);
    let client_key = ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let compact_public_key = CompactPublicKey::new(&client_key);

    ProtocolKeys {
        client_key,
        compressed_server_key,
        compact_public_key,
    }
}

/// One transaction as its inputs reach a coprocessor. The metadata ties an input to its origin and
/// is absorbed into the re-randomization context along with the ciphertext.
pub fn encrypt_compressed_inputs<R: Rng>(
    client_key: &ClientKey,
    rng: &mut R,
) -> CompressedCiphertextList {
    let mut from_amount = FheUint64::encrypt(rng.gen::<u64>(), client_key);
    let mut to_amount = FheUint64::encrypt(rng.gen::<u64>(), client_key);
    let mut amount = FheUint64::encrypt(rng.gen::<u64>(), client_key);

    for ct in [&mut from_amount, &mut to_amount, &mut amount] {
        let metadata: [u8; METADATA_LEN] = rng.gen();
        ct.re_randomization_metadata_mut().set_data(&metadata);
    }

    CompressedCiphertextListBuilder::new()
        .push(from_amount)
        .push(to_amount)
        .push(amount)
        .build()
        .unwrap()
}

/// Transfer results, so F2 can be measured without running F1 first.
pub fn encrypt_compressed_outputs<R: Rng>(
    client_key: &ClientKey,
    rng: &mut R,
) -> CompressedCiphertextList {
    let new_from_amount = FheUint64::encrypt(rng.gen::<u64>(), client_key);
    let new_to_amount = FheUint64::encrypt(rng.gen::<u64>(), client_key);

    CompressedCiphertextListBuilder::new()
        .push(new_from_amount)
        .push(new_to_amount)
        .build()
        .unwrap()
}
