use criterion::Criterion;

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use benchmark::utilities::{write_to_json_unchecked, OperatorType};
    use criterion::{black_box, criterion_group, BenchmarkGroup, Criterion, Throughput};
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::{AtomicPatternParameters, Ciphertext};

    /// Per-element key width reported in the JSON metadata `bit_size` and `decomposition_basis`
    /// fields. One benchmark element is one keystream lane, whose key is 128 bits regardless of how
    /// many lanes run in parallel.
    const KREYVIUM_KEY_BITS: usize = 128;

    /// Default independent (key, iv) lanes per GPU in the throughput benchmarks, used when the env
    /// var `KREYVIUM_THROUGHPUT_ELEMS_PER_GPU` is unset or unparsable. The total lane count scales
    /// with the active GPU count (see `bench_kreyvium_throughput`) so each GPU stays saturated at
    /// any device count. Sized so one GPU's share fits in an 80 GB H100 (~46 GB at 64 lanes).
    const DEFAULT_ELEMENTS_PER_GPU: usize = 64;

    /// Reads the per-GPU lane count from `KREYVIUM_THROUGHPUT_ELEMS_PER_GPU`, falling back to
    /// `DEFAULT_ELEMENTS_PER_GPU`. Exposed as an env var so the saturation point can be swept (e.g.
    /// `KREYVIUM_THROUGHPUT_ELEMS_PER_GPU=16`) without recompiling.
    fn elements_per_gpu() -> usize {
        std::env::var("KREYVIUM_THROUGHPUT_ELEMS_PER_GPU")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_ELEMENTS_PER_GPU)
    }

    fn encrypt_bits(cks: &RadixClientKey, bits: &[u64]) -> RadixCiphertext {
        RadixCiphertext::from(
            bits.iter()
                .map(|&bit| cks.encrypt_one_block(bit))
                .collect::<Vec<Ciphertext>>(),
        )
    }

    /// Opens a criterion group with the sampling configuration shared by every Kreyvium benchmark
    /// (latency and throughput). Centralizing it keeps the two from silently drifting apart.
    fn new_kreyvium_bench_group<'a>(
        c: &'a mut Criterion,
        bench_name: &str,
    ) -> BenchmarkGroup<'a, criterion::measurement::WallTime> {
        let mut bench_group = c.benchmark_group(bench_name);
        bench_group
            .sample_size(15)
            .measurement_time(std::time::Duration::from_secs(60))
            .warm_up_time(std::time::Duration::from_secs(5));
        bench_group
    }

    /// Runs the init / next / generate benchmark cases for one Kreyvium variant on one parameter
    /// set. `init`, `next` and `generate` are the variant-specific entry points; `method_label`
    /// (e.g. "kreyvium" or "fast_kreyvium") only affects the JSON metadata key.
    fn bench_kreyvium_variant<State, Init, Next, Generate>(
        bench_group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
        bench_name: &str,
        method_label: &str,
        atomic_param: AtomicPatternParameters,
        param_name: String,
        init: Init,
        mut next: Next,
        generate: Generate,
    ) where
        Init: Fn(
            &CudaServerKey,
            &CudaUnsignedRadixCiphertext,
            &CudaUnsignedRadixCiphertext,
            &CudaStreams,
        ) -> State,
        Next: FnMut(&CudaServerKey, &mut State, usize, &CudaStreams) -> CudaUnsignedRadixCiphertext,
        Generate: Fn(
            &CudaServerKey,
            &CudaUnsignedRadixCiphertext,
            &CudaUnsignedRadixCiphertext,
            usize,
            &CudaStreams,
        ) -> CudaUnsignedRadixCiphertext,
    {
        let key_bits = vec![0u64; KREYVIUM_KEY_BITS];
        let iv_bits = vec![0u64; KREYVIUM_KEY_BITS];

        let streams = CudaStreams::new_multi_gpu();
        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);
        let cks = RadixClientKey::from((cpu_cks, 1));

        let ct_key = encrypt_bits(&cks, &key_bits);
        let ct_iv = encrypt_bits(&cks, &iv_bits);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

        // 1. Benchmark: init
        let init_bench_id = format!("{bench_name}::{param_name}::init");
        bench_group.bench_function(&init_bench_id, |b| {
            b.iter(|| {
                black_box(init(&sks, &d_key, &d_iv, &streams));
            })
        });

        write_to_json_unchecked::<u64, _>(
            &init_bench_id,
            atomic_param,
            param_name.clone(),
            &format!("{method_label}_init"),
            &OperatorType::Atomic,
            u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
            vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
        );

        let mut state = init(&sks, &d_key, &d_iv, &streams);

        for num_steps in [64, 512] {
            // 2. Benchmark: next
            let next_bench_id = format!("{bench_name}::{param_name}::next_{num_steps}_bits");

            bench_group.bench_function(&next_bench_id, |b| {
                b.iter(|| {
                    black_box(next(&sks, &mut state, num_steps, &streams));
                })
            });

            write_to_json_unchecked::<u64, _>(
                &next_bench_id,
                atomic_param,
                param_name.clone(),
                &format!("{method_label}_next_{num_steps}_bits"),
                &OperatorType::Atomic,
                u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );

            // 3. Benchmark: generate_keystream
            let gen_bench_id = format!("{bench_name}::{param_name}::generate_{num_steps}_bits");

            bench_group.bench_function(&gen_bench_id, |b| {
                b.iter(|| {
                    black_box(generate(&sks, &d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json_unchecked::<u64, _>(
                &gen_bench_id,
                atomic_param,
                param_name.clone(),
                &format!("{method_label}_generation_{num_steps}_bits"),
                &OperatorType::Atomic,
                u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );
        }
    }

    /// Runs the throughput benchmarks for one Kreyvium variant, batched over
    /// `elements_per_gpu() * num_gpus` independent lanes and reporting aggregate throughput in
    /// lanes/sec (`Throughput::Elements`). Keeping the lane count per GPU constant saturates every
    /// device at any GPU count (at 64 lanes/GPU: 1 GPU -> 64 lanes, 8 GPUs -> 512). `num_gpus` is
    /// the number of GPUs the multi-GPU streams actually use (honoring `CUDA_VISIBLE_DEVICES`),
    /// read from `CudaStreams::len`.
    ///
    /// Five cases are measured, mirroring the latency bench:
    /// - `throughput::{param_tag}::init`: times `init` (the warmup-heavy key/iv load) per call.
    /// - `throughput::{param_tag}::next_64` / `next_512`: times advancing an already-initialized
    ///   state. Each iteration continues from where the previous one left off.
    /// - `throughput::{param_tag}::generate_64` / `generate_512`: times `generate` (init + advance
    ///   N) as a single timed call.
    ///
    /// `param_tag` is a short discriminator (e.g. `mbg4`, `classical`) kept in the criterion id so
    /// it stays under criterion's 64-char directory cap; the full `param_name` is preserved in
    /// the JSON metadata. The key/iv inputs are bit-sliced across lanes, which for the all-zero
    /// benchmark inputs is simply `KREYVIUM_KEY_BITS * num_inputs` zero blocks each.
    fn bench_kreyvium_throughput<State, Init, Next, Generate>(
        bench_group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
        bench_name: &str,
        method_label: &str,
        param_tag: &str,
        atomic_param: AtomicPatternParameters,
        param_name: String,
        init: Init,
        mut next: Next,
        generate: Generate,
    ) where
        Init: Fn(
            &CudaServerKey,
            &CudaUnsignedRadixCiphertext,
            &CudaUnsignedRadixCiphertext,
            &CudaStreams,
        ) -> State,
        Next: FnMut(&CudaServerKey, &mut State, usize, &CudaStreams) -> CudaUnsignedRadixCiphertext,
        Generate: Fn(
            &CudaServerKey,
            &CudaUnsignedRadixCiphertext,
            &CudaUnsignedRadixCiphertext,
            usize,
            &CudaStreams,
        ) -> CudaUnsignedRadixCiphertext,
    {
        let streams = CudaStreams::new_multi_gpu();
        let num_inputs = elements_per_gpu() * streams.len();
        let key_bits = vec![0u64; KREYVIUM_KEY_BITS * num_inputs];
        let iv_bits = vec![0u64; KREYVIUM_KEY_BITS * num_inputs];

        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);
        let cks = RadixClientKey::from((cpu_cks, 1));

        let ct_key = encrypt_bits(&cks, &key_bits);
        let ct_iv = encrypt_bits(&cks, &iv_bits);

        let d_key = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_key, &streams);
        let d_iv = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_iv, &streams);

        bench_group.throughput(Throughput::Elements(num_inputs as u64));

        // 1. init throughput
        let init_bench_id = format!("{bench_name}::throughput::{param_tag}::init");
        bench_group.bench_function(&init_bench_id, |b| {
            b.iter(|| {
                black_box(init(&sks, &d_key, &d_iv, &streams));
            })
        });

        write_to_json_unchecked::<u64, _>(
            &init_bench_id,
            atomic_param,
            param_name.clone(),
            &format!("{method_label}_throughput_init"),
            &OperatorType::Atomic,
            u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
            vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
        );

        // 2 & 3. next_N and generate_N throughput for each step count.
        // next: continues the same keystream from where the previous iteration left off.
        // generate: a full init + advance in a single timed call.
        let mut state = init(&sks, &d_key, &d_iv, &streams);
        for num_steps in [64usize, 512] {
            let next_bench_id = format!("{bench_name}::throughput::{param_tag}::next_{num_steps}");
            bench_group.bench_function(&next_bench_id, |b| {
                b.iter(|| {
                    black_box(next(&sks, &mut state, num_steps, &streams));
                })
            });

            write_to_json_unchecked::<u64, _>(
                &next_bench_id,
                atomic_param,
                param_name.clone(),
                &format!("{method_label}_throughput_next_{num_steps}"),
                &OperatorType::Atomic,
                u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );

            let gen_bench_id =
                format!("{bench_name}::throughput::{param_tag}::generate_{num_steps}");
            bench_group.bench_function(&gen_bench_id, |b| {
                b.iter(|| {
                    black_box(generate(&sks, &d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json_unchecked::<u64, _>(
                &gen_bench_id,
                atomic_param,
                param_name.clone(),
                &format!("{method_label}_throughput_generate_{num_steps}"),
                &OperatorType::Atomic,
                u32::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );
        }
    }

    pub fn cuda_kreyvium(c: &mut Criterion) {
        let bench_name = "integer::cuda::kreyvium";
        let mut bench_group = new_kreyvium_bench_group(c, bench_name);

        let params = [
            (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_variant(
                &mut bench_group,
                bench_name,
                "kreyvium",
                atomic_param,
                param_name,
                |sks, key, iv, streams| sks.kreyvium_init(key, iv, streams).unwrap(),
                |sks, state, steps, streams| sks.kreyvium_next(state, steps, streams).unwrap(),
                |sks, key, iv, steps, streams| {
                    sks.kreyvium_generate_keystream(key, iv, steps, streams)
                        .unwrap()
                },
            );
        }

        bench_group.finish();
    }

    pub fn cuda_fast_kreyvium(c: &mut Criterion) {
        let bench_name = "integer::cuda::fast_kreyvium";
        let mut bench_group = new_kreyvium_bench_group(c, bench_name);

        let params = [
            (
                BENCH_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_variant(
                &mut bench_group,
                bench_name,
                "fast_kreyvium",
                atomic_param,
                param_name,
                |sks, key, iv, streams| sks.fast_kreyvium_init(key, iv, streams).unwrap(),
                |sks, state, steps, streams| sks.fast_kreyvium_next(state, steps, streams).unwrap(),
                |sks, key, iv, steps, streams| {
                    sks.fast_kreyvium_generate_keystream(key, iv, steps, streams)
                        .unwrap()
                },
            );
        }

        bench_group.finish();
    }

    pub fn cuda_kreyvium_throughput(c: &mut Criterion) {
        let bench_name = "integer::cuda::kreyvium";
        let mut bench_group = new_kreyvium_bench_group(c, bench_name);

        let params = [
            (
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
                "mbg4",
            ),
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
                "classical",
            ),
        ];

        for (atomic_param_val, param_name, param_tag) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_throughput(
                &mut bench_group,
                bench_name,
                "kreyvium",
                param_tag,
                atomic_param,
                param_name,
                |sks, key, iv, streams| sks.kreyvium_init(key, iv, streams).unwrap(),
                |sks, state, steps, streams| sks.kreyvium_next(state, steps, streams).unwrap(),
                |sks, key, iv, steps, streams| {
                    sks.kreyvium_generate_keystream(key, iv, steps, streams)
                        .unwrap()
                },
            );
        }

        bench_group.finish();
    }

    pub fn cuda_fast_kreyvium_throughput(c: &mut Criterion) {
        let bench_name = "integer::cuda::fast_kreyvium";
        let mut bench_group = new_kreyvium_bench_group(c, bench_name);

        let params = [
            (
                BENCH_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128.name(),
                "mbg4",
            ),
            (
                BENCH_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128.name(),
                "classical",
            ),
        ];

        for (atomic_param_val, param_name, param_tag) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_throughput(
                &mut bench_group,
                bench_name,
                "fast_kreyvium",
                param_tag,
                atomic_param,
                param_name,
                |sks, key, iv, streams| sks.fast_kreyvium_init(key, iv, streams).unwrap(),
                |sks, state, steps, streams| sks.fast_kreyvium_next(state, steps, streams).unwrap(),
                |sks, key, iv, steps, streams| {
                    sks.fast_kreyvium_generate_keystream(key, iv, steps, streams)
                        .unwrap()
                },
            );
        }

        bench_group.finish();
    }

    criterion_group!(
        gpu_kreyvium,
        cuda_kreyvium,
        cuda_fast_kreyvium,
        cuda_kreyvium_throughput,
        cuda_fast_kreyvium_throughput
    );
}

#[cfg(feature = "gpu")]
use cuda::gpu_kreyvium;

fn main() {
    #[cfg(feature = "gpu")]
    gpu_kreyvium();

    Criterion::default().configure_from_args().final_summary();
}
