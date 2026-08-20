use criterion::Criterion;

#[cfg(feature = "gpu")]
pub mod cuda {
    use benchmark::params_aliases::{
        BENCH_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128,
        BENCH_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    };
    use benchmark::utilities::{write_to_json, OperatorType};
    use benchmark_spec::tfhe::transciphering::kreyvium::KreyviumFlavor;
    use benchmark_spec::{BenchmarkMetric, BenchmarkSpec, PrecisionTag, TranscipheringBench};
    use criterion::{criterion_group, BenchmarkGroup, Criterion, Throughput};
    use std::hint::black_box;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;
    use tfhe::integer::keycache::KEY_CACHE;
    use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
    use tfhe::keycache::NamedParam;
    use tfhe::shortint::{AtomicPatternParameters, Ciphertext};

    /// Kreyvium key width, which is also what one benchmark element (one keystream lane) is worth
    /// in the JSON metadata, whatever the number of lanes running in parallel.
    const KREYVIUM_KEY_BITS: usize = 128;

    /// Independent (key, iv) lanes per GPU in the throughput benchmarks, overridable through
    /// `KREYVIUM_THROUGHPUT_ELEMS_PER_GPU` to sweep the saturation point. Sized so one GPU's share
    /// fits in an 80 GB H100 (~46 GB at 64 lanes).
    const DEFAULT_ELEMENTS_PER_GPU: usize = 64;

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

    /// Runs the init / next / generate latency cases for one Kreyvium variant. `bench` is the spec
    /// node the variant is filed under, which is what tells kreyvium and fast_kreyvium apart.
    fn bench_kreyvium_variant<State, Init, Next, Generate>(
        bench_group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
        bench: fn(KreyviumFlavor) -> TranscipheringBench,
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
        // Display on a spec node yields its own token alone, so the flavor is a placeholder.
        let method_label = bench(KreyviumFlavor::Init).to_string();

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
        let init_spec = BenchmarkSpec::new_transciphering(
            bench(KreyviumFlavor::Init),
            &param_name,
            None,
            BenchmarkMetric::Latency,
            None,
        );
        let init_bench_id = init_spec.to_string();
        bench_group.bench_function(&init_bench_id, |b| {
            b.iter(|| {
                black_box(init(&sks, &d_key, &d_iv, &streams));
            })
        });

        write_to_json(
            &init_spec,
            format!("{method_label}_init"),
            &OperatorType::Atomic,
            u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
            vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
        );

        let mut state = init(&sks, &d_key, &d_iv, &streams);

        for num_steps in [64, 512] {
            // The GPU API takes a `usize`, the grammar counts bits.
            let steps = PrecisionTag::Bits(num_steps as u32);

            // 2. Benchmark: next
            let next_spec = BenchmarkSpec::new_transciphering(
                bench(KreyviumFlavor::Next),
                &param_name,
                Some(steps.into()),
                BenchmarkMetric::Latency,
                None,
            );
            let next_bench_id = next_spec.to_string();

            bench_group.bench_function(&next_bench_id, |b| {
                b.iter(|| {
                    black_box(next(&sks, &mut state, num_steps, &streams));
                })
            });

            write_to_json(
                &next_spec,
                format!("{method_label}_next_{num_steps}_bits"),
                &OperatorType::Atomic,
                u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );

            // 3. Benchmark: generate_keystream
            let gen_spec = BenchmarkSpec::new_transciphering(
                bench(KreyviumFlavor::Generate),
                &param_name,
                Some(steps.into()),
                BenchmarkMetric::Latency,
                None,
            );
            let gen_bench_id = gen_spec.to_string();

            bench_group.bench_function(&gen_bench_id, |b| {
                b.iter(|| {
                    black_box(generate(&sks, &d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json(
                &gen_spec,
                format!("{method_label}_generate_{num_steps}_bits"),
                &OperatorType::Atomic,
                u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );
        }
    }

    /// Same cases as [`bench_kreyvium_variant`], batched over `elements_per_gpu() * num_gpus`
    /// independent lanes and reported in lanes/sec. Scaling the lane count with the GPU count read
    /// from `CudaStreams::len` keeps every device saturated at any device count. `next` continues
    /// the keystream across iterations, `generate` re-runs init on every call.
    fn bench_kreyvium_throughput<State, Init, Next, Generate>(
        bench_group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
        bench: fn(KreyviumFlavor) -> TranscipheringBench,
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
        // Display on a spec node yields its own token alone, so the flavor is a placeholder.
        let method_label = bench(KreyviumFlavor::Init).to_string();

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

        let lanes = u64::try_from(num_inputs).unwrap();

        // 1. init throughput
        let init_spec = BenchmarkSpec::new_transciphering(
            bench(KreyviumFlavor::Init),
            &param_name,
            None,
            BenchmarkMetric::Throughput,
            Some(lanes),
        );
        let init_bench_id = init_spec.to_string();
        bench_group.bench_function(&init_bench_id, |b| {
            b.iter(|| {
                black_box(init(&sks, &d_key, &d_iv, &streams));
            })
        });

        write_to_json(
            &init_spec,
            format!("{method_label}_init"),
            &OperatorType::Atomic,
            u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
            vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
        );

        // 2 & 3. next and generate throughput, per step count
        let mut state = init(&sks, &d_key, &d_iv, &streams);
        for num_steps in [64usize, 512] {
            let steps = PrecisionTag::Bits(num_steps as u32);

            let next_spec = BenchmarkSpec::new_transciphering(
                bench(KreyviumFlavor::Next),
                &param_name,
                Some(steps.into()),
                BenchmarkMetric::Throughput,
                Some(lanes),
            );
            let next_bench_id = next_spec.to_string();
            bench_group.bench_function(&next_bench_id, |b| {
                b.iter(|| {
                    black_box(next(&sks, &mut state, num_steps, &streams));
                })
            });

            write_to_json(
                &next_spec,
                format!("{method_label}_next_{num_steps}_bits"),
                &OperatorType::Atomic,
                u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
                vec![atomic_param.message_modulus().0.ilog2(); KREYVIUM_KEY_BITS],
            );

            let gen_spec = BenchmarkSpec::new_transciphering(
                bench(KreyviumFlavor::Generate),
                &param_name,
                Some(steps.into()),
                BenchmarkMetric::Throughput,
                Some(lanes),
            );
            let gen_bench_id = gen_spec.to_string();
            bench_group.bench_function(&gen_bench_id, |b| {
                b.iter(|| {
                    black_box(generate(&sks, &d_key, &d_iv, num_steps, &streams));
                })
            });

            write_to_json(
                &gen_spec,
                format!("{method_label}_generate_{num_steps}_bits"),
                &OperatorType::Atomic,
                u64::try_from(KREYVIUM_KEY_BITS).unwrap(),
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
                TranscipheringBench::Kreyvium,
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
                BENCH_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_variant(
                &mut bench_group,
                TranscipheringBench::FastKreyvium,
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
            ),
            (
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
                BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_throughput(
                &mut bench_group,
                TranscipheringBench::Kreyvium,
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
                BENCH_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_TUNIFORM_2M128.name(),
            ),
            (
                BENCH_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128.into(),
                BENCH_PARAM_GPU_KREYVIUM_MESSAGE_1_CARRY_0_TUNIFORM_2M128.name(),
            ),
        ];

        for (atomic_param_val, param_name) in params {
            let atomic_param: AtomicPatternParameters = atomic_param_val;

            bench_kreyvium_throughput(
                &mut bench_group,
                TranscipheringBench::FastKreyvium,
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
