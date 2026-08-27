// A/B bench of the prefix network used by ilog2 / leading_zeros on GPU.
// Run twice, once with TFHE_SKLANSKY=1, and compare.
use std::time::Instant;
use tfhe::core_crypto::gpu::vec::GpuIndex;
use tfhe::core_crypto::gpu::CudaStreams;
use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use tfhe::integer::gpu::server_key::CudaServerKey;
use tfhe::integer::RadixClientKey;
use tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

const WARMUP: usize = 5;
const ITERS: usize = 40;

fn stats(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = v[v.len() / 2];
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    (median, mean)
}

fn main() {
    let flag = std::env::var("TFHE_SKLANSKY").unwrap_or_default();
    let network = if flag == "1" { "sklansky" } else { "hillis-steele" };

    // One GPU by default: the scan is a few dozen blocks, splitting it across
    // devices would measure the scatter/gather, not the network.
    let multi = std::env::var("TFHE_MULTI_GPU").unwrap_or_default() == "1";
    let streams = if multi {
        CudaStreams::new_multi_gpu()
    } else {
        CudaStreams::new_single_gpu(GpuIndex::new(0))
    };
    let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    println!("network,gpus,bits,blocks,op,median_ms,mean_ms");

    for bits in [64usize, 128, 256] {
        let num_blocks = bits / 2;
        let cks = RadixClientKey::new(params, num_blocks);
        let sks = CudaServerKey::new(&cks, &streams);

        // Correctness at the widths actually benchmarked. u64::MAX is the
        // stressful one: 32 consecutive full blocks the scan must propagate
        // through, plus (bits - 64) empty ones above them.
        for v in [1u64, 12345, u64::MAX] {
            let c = cks.encrypt(v);
            let d = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&c, &streams);
            let lz: u64 = cks
                .as_ref()
                .decrypt_radix(&sks.leading_zeros(&d, &streams).to_radix_ciphertext(&streams));
            let tz: u64 = cks
                .as_ref()
                .decrypt_radix(&sks.trailing_zeros(&d, &streams).to_radix_ciphertext(&streams));
            let lg: u64 = cks
                .as_ref()
                .decrypt_radix(&sks.ilog2(&d, &streams).to_radix_ciphertext(&streams));
            let want_lz = bits as u64 - 1 - v.ilog2() as u64;
            assert_eq!(lz, want_lz, "{network} {bits}b leading_zeros({v})");
            assert_eq!(tz, v.trailing_zeros() as u64, "{network} {bits}b trailing_zeros({v})");
            assert_eq!(lg, v.ilog2() as u64, "{network} {bits}b ilog2({v})");
        }
        eprintln!("[{network}] {bits} bits: correctness ok");

        let ct = cks.encrypt(12345u64);
        let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &streams);

        for (name, run) in [
            ("leading_zeros", 0u8),
            ("trailing_zeros", 1),
            ("ilog2", 2),
        ] {
            let call = |d: &CudaUnsignedRadixCiphertext| match run {
                0 => {
                    let _ = sks.leading_zeros(d, &streams);
                }
                1 => {
                    let _ = sks.trailing_zeros(d, &streams);
                }
                _ => {
                    let _ = sks.ilog2(d, &streams);
                }
            };

            for _ in 0..WARMUP {
                call(&d_ct);
            }
            streams.synchronize();

            let mut samples = Vec::with_capacity(ITERS);
            for _ in 0..ITERS {
                let t = Instant::now();
                call(&d_ct);
                streams.synchronize();
                samples.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            let (median, mean) = stats(samples);
            let g = if multi { "multi" } else { "single" };
            println!("{network},{g},{bits},{num_blocks},{name},{median:.3},{mean:.3}");
        }

        // Radix carry propagation: the scan runs over num_groups - 1 only,
        // Thomas' grouping having already divided it by four.
        let a = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt(0xdead_beefu64),
            &streams,
        );
        let b = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt(0xcafe_babeu64),
            &streams,
        );
        for (name, kind) in [("add", 0u8), ("gt", 1)] {
            let call = || match kind {
                0 => {
                    let _ = sks.add(&a, &b, &streams);
                }
                _ => {
                    let _ = sks.gt(&a, &b, &streams);
                }
            };
            for _ in 0..WARMUP {
                call();
            }
            streams.synchronize();
            let mut samples = Vec::with_capacity(ITERS);
            for _ in 0..ITERS {
                let t = Instant::now();
                call();
                streams.synchronize();
                samples.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            let (median, mean) = stats(samples);
            let g = if multi { "multi" } else { "single" };
            println!("{network},{g},{bits},{num_blocks},{name},{median:.3},{mean:.3}");
        }
    }

    // first_index_of: the scan runs over the whole list, ungrouped.
    for n_inputs in [256usize, 1024] {
        let num_blocks = 8; // 16-bit elements
        let cks = RadixClientKey::new(params, num_blocks);
        let sks = CudaServerKey::new(&cks, &streams);

        let list: Vec<CudaUnsignedRadixCiphertext> = (0..n_inputs)
            .map(|i| {
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                    &cks.encrypt(i as u64),
                    &streams,
                )
            })
            .collect();
        // Needle in the last position, the worst case for the scan.
        let needle = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt((n_inputs - 1) as u64),
            &streams,
        );

        let (idx, found) = sks.first_index_of(&list, &needle, &streams);
        let got: u64 = cks
            .as_ref()
            .decrypt_radix(&idx.to_radix_ciphertext(&streams));
        let hit = cks.as_ref().decrypt_bool(&found.to_boolean_block(&streams));
        assert_eq!(got, (n_inputs - 1) as u64, "{network} first_index_of index");
        assert!(hit, "{network} first_index_of found flag");
        eprintln!("[{network}] first_index_of n={n_inputs}: correctness ok");

        for _ in 0..WARMUP {
            let _ = sks.first_index_of(&list, &needle, &streams);
        }
        streams.synchronize();
        let iters = 10;
        let mut samples = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let _ = sks.first_index_of(&list, &needle, &streams);
            streams.synchronize();
            samples.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        let (median, mean) = stats(samples);
        let g = if multi { "multi" } else { "single" };
        println!("{network},{g},16,{n_inputs},first_index_of,{median:.3},{mean:.3}");
    }
}
