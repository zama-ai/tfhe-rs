//! CPU benchmarks for the one-time-pad transciphering flow, as it is run by the coprocessor.
//!
//! Available cases:
//!   * `pad_worker`: generation of a pad with the OPRF, compression of the pad (stored for
//!     unmasking), and noise squashing + compression of the squashed pad (sent to the KMS for
//!     decryption).
//!   * `unmask`: decompression of a stored pad and unmasking of a list of `FheUint64` encrypted
//!     with it, until all the elements of the list are expanded.
//!   * `unmask_cold`: unmasking when the pad is not stored yet. The pad is generated with the OPRF,
//!     compressed and decompressed, then used to unmask the list as in `unmask`.
//!
//! Run with:
//! ```sh
//! make bench_otp_transciphering
//! ```

use benchmark::find_optimal_batch::find_optimal_batch;
use benchmark::params_aliases::BENCH_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use benchmark::utilities::{bench_and_record, will_this_bench_run};
use benchmark_spec::tfhe::transciphering::one_time_pad::OneTimePadFlavor;
use benchmark_spec::{
    get_bench_type, BenchmarkSpec, BenchmarkType, PrecisionTag, TranscipheringBench,
};
use criterion::measurement::WallTime;
use criterion::{criterion_group, BenchmarkGroup, Criterion, Throughput};
use rand::Rng;
use rayon::prelude::*;
use std::env;
use std::hint::black_box;
use std::time::Duration;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::transciphering::{OneTimePadPlainSecretMask, OneTimePadPlainState};
use tfhe::{
    set_server_key, ClientKey, CompressedOneTimePadFheSecretMask, CompressedServerKey, Config,
    FheUint64, HlTranscipherer, OneTimePadFheSecretMask, Seed, StreamCiphertextList,
    TranscipherSession,
};

const BENCH_GROUP: &str = "transciphering::one_time_pad";

/// Number of bits of the pads, also used as the size of the unmasked lists, which are made of
/// `FheUint64`.
fn bench_bit_sizes() -> Vec<usize> {
    if let Ok(val) = env::var("__TFHE_RS_BENCH_OP_FLAVOR") {
        match val.to_lowercase().as_str() {
            "fast_default" | "fast" => return vec![64],
            _ => (),
        }
    }

    vec![64, 4 * 64, 2048]
}

fn random_seed() -> Seed {
    Seed(rand::thread_rng().gen())
}

/// Run `run_once` in a latency or throughput benchmark, depending on the benchmark type.
fn bench_latency_or_throughput<F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    spec: &BenchmarkSpec,
    display_name: &str,
    msg_bits: u32,
    n_bits: usize,
    run_once: F,
) where
    F: Fn() + Sync,
{
    let decomposition_basis = vec![msg_bits; n_bits / msg_bits as usize];

    match get_bench_type() {
        BenchmarkType::Latency => {
            bench_and_record(
                group,
                spec,
                display_name,
                n_bits as u64,
                decomposition_basis,
                |b| b.iter(&run_once),
            );
        }
        BenchmarkType::Throughput => {
            let num_ops = if will_this_bench_run(BENCH_GROUP, &spec.to_string()) {
                let setup = |_batch_size: usize| ();
                let run = |_: &mut (), batch_size: usize| {
                    (0..batch_size).into_par_iter().for_each(|_| run_once());
                };
                find_optimal_batch(run, setup)
            } else {
                0
            };

            group.throughput(Throughput::Elements(num_ops as u64));
            bench_and_record(
                group,
                spec,
                display_name,
                n_bits as u64,
                decomposition_basis,
                |b| {
                    b.iter(|| {
                        (0..num_ops).into_par_iter().for_each(|_| run_once());
                    })
                },
            );
        }
    }
}

fn bench_pad_worker(
    group: &mut BenchmarkGroup<'_, WallTime>,
    param_name: &str,
    msg_bits: u32,
    n_bits: usize,
) {
    let spec = BenchmarkSpec::new_transciphering(
        TranscipheringBench::OneTimePad(OneTimePadFlavor::PadWorker),
        param_name,
        Some(PrecisionTag::Bits(n_bits as u32).into()),
        get_bench_type(),
        None,
    );

    bench_latency_or_throughput(group, &spec, "otp_pad_worker", msg_bits, n_bits, || {
        let mask = OneTimePadFheSecretMask::new_random(random_seed(), n_bits as u64).unwrap();
        let (ct64, ct128) = rayon::join(
            || mask.compress().unwrap(),
            || mask.squash_noise().unwrap().compress().unwrap(),
        );
        black_box((ct64, ct128));
    });
}

fn bench_unmask(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    param_name: &str,
    msg_bits: u32,
    n_bits: usize,
) {
    let spec = BenchmarkSpec::new_transciphering(
        TranscipheringBench::OneTimePad(OneTimePadFlavor::Unmask),
        param_name,
        Some(PrecisionTag::Bits(n_bits as u32).into()),
        get_bench_type(),
        None,
    );

    // Pad worker: generate and store the pad
    let mask = OneTimePadFheSecretMask::new_random(random_seed(), n_bits as u64).unwrap();
    let compressed_mask: CompressedOneTimePadFheSecretMask = mask.compress().unwrap();

    // Client: encrypt the inputs with the decrypted pad
    let plain_mask: OneTimePadPlainSecretMask = mask.decrypt(client_key);
    let mut rng = rand::thread_rng();
    let num_inputs = n_bits / 64;
    let list = StreamCiphertextList::builder()
        .extend((0..num_inputs).map(|_| rng.gen::<u64>()))
        .build(&mut OneTimePadPlainState::new(plain_mask))
        .unwrap();

    bench_latency_or_throughput(group, &spec, "otp_unmask", msg_bits, n_bits, || {
        let mask = compressed_mask.decompress().unwrap();
        let mut session = TranscipherSession::one_time_pad(mask).unwrap();
        let expander = session.transcipher_list(&list).unwrap();
        for i in 0..num_inputs {
            let value: FheUint64 = expander.get(i).unwrap().unwrap();
            black_box(value);
        }
    });
}

fn bench_unmask_cold(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    param_name: &str,
    msg_bits: u32,
    n_bits: usize,
) {
    let spec = BenchmarkSpec::new_transciphering(
        TranscipheringBench::OneTimePad(OneTimePadFlavor::UnmaskCold),
        param_name,
        Some(PrecisionTag::Bits(n_bits as u32).into()),
        get_bench_type(),
        None,
    );

    // Pad decryption: the pad is generated from its seed and decrypted for the client, but not
    // stored
    let seed = random_seed();
    let mask = OneTimePadFheSecretMask::new_random(seed, n_bits as u64).unwrap();

    // Client: encrypt the inputs with the decrypted pad
    let plain_mask: OneTimePadPlainSecretMask = mask.decrypt(client_key);
    let mut rng = rand::thread_rng();
    let num_inputs = n_bits / 64;
    let list = StreamCiphertextList::builder()
        .extend((0..num_inputs).map(|_| rng.gen::<u64>()))
        .build(&mut OneTimePadPlainState::new(plain_mask))
        .unwrap();

    bench_latency_or_throughput(group, &spec, "otp_unmask_cold", msg_bits, n_bits, || {
        // The pad is regenerated from the same seed, so it matches the one used by the client
        let mask = OneTimePadFheSecretMask::new_random(seed, n_bits as u64).unwrap();
        let compressed_mask = mask.compress().unwrap();
        let mask = compressed_mask.decompress().unwrap();
        let mut session = TranscipherSession::one_time_pad(mask).unwrap();
        let expander = session.transcipher_list(&list).unwrap();
        for i in 0..num_inputs {
            let value: FheUint64 = expander.get(i).unwrap().unwrap();
            black_box(value);
        }
    });
}

fn cpu_otp_transciphering(c: &mut Criterion) {
    // Production CPU parameters: compression, noise squashing (with compression) and a dedicated
    // OPRF key for transciphering
    let meta_params = BENCH_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
    let param_name = meta_params.compute_parameters.name();
    let msg_bits = meta_params.compute_parameters.message_modulus().0.ilog2();

    let client_key = ClientKey::generate(Config::from(meta_params));
    let server_key = CompressedServerKey::new(&client_key).decompress();
    rayon::broadcast(|_| set_server_key(server_key.clone()));
    set_server_key(server_key);

    let mut group = c.benchmark_group(BENCH_GROUP);
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
        .warm_up_time(Duration::from_secs(5));

    for n_bits in bench_bit_sizes() {
        bench_pad_worker(&mut group, &param_name, msg_bits, n_bits);
        bench_unmask(&mut group, &client_key, &param_name, msg_bits, n_bits);
        bench_unmask_cold(&mut group, &client_key, &param_name, msg_bits, n_bits);
    }

    group.finish();
}

criterion_group!(cpu_otp, cpu_otp_transciphering);

fn main() {
    cpu_otp();
    Criterion::default().configure_from_args().final_summary();
}
