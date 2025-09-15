use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::{write_to_json, OperatorType};
use criterion::Criterion;
use rand::prelude::*;
use tfhe::array::GpuFheUint64Array;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{ClientKey, CompressedServerKey};

#[cfg(feature = "gpu")]
fn main() {
    let cks = {
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key(compressed_sks.decompress_to_gpu());
        cks
    };

    let array_dim = 32;
    let num_elems = array_dim * array_dim;
    let mut rng = thread_rng();
    let clear_xs = (0..num_elems as u64)
        .map(|_| rng.gen::<u64>())
        .collect::<Vec<_>>();
    let clear_ys = (0..num_elems as u64)
        .map(|_| rng.gen::<u64>())
        .collect::<Vec<_>>();

    let xs =
        GpuFheUint64Array::try_encrypt((clear_xs.as_slice(), vec![array_dim, array_dim]), &cks)
            .unwrap();
    let ys =
        GpuFheUint64Array::try_encrypt((clear_ys.as_slice(), vec![array_dim, array_dim]), &cks)
            .unwrap();

    let mut c = Criterion::default().configure_from_args();
    let bench_id = format!("bench::hlapi::array::cuda::bitand::");
    c.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = &xs & &ys;
        })
    });

    let params = cks.computation_parameters();

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params.name(),
        "erc20-transfer",
        &OperatorType::Atomic,
        64,
        vec![],
    );

    c.final_summary();
}
