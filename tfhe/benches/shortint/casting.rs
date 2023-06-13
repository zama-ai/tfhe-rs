use crate::utilities::{write_to_json, OperatorType};

use tfhe::shortint::prelude::*;

use rayon::prelude::*;

use criterion::Criterion;

pub fn pack_cast_64(c: &mut Criterion) {
    let bench_name = "pack_cast_64";
    let mut bench_group = c.benchmark_group(bench_name);

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let ks_param = PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS;
    let ks_param_name = "PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS";

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let vec_ct = vec![client_key_1.encrypt(1); 64];

    let bench_id = format!("{bench_name}_{ks_param_name}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = (0..32)
                .into_par_iter()
                .map(|i| {
                    let byte_idx = 7 - i / 4;
                    let pair_idx = i % 4;

                    let b0 = &vec_ct[8 * byte_idx + 2 * pair_idx];
                    let b1 = &vec_ct[8 * byte_idx + 2 * pair_idx + 1];

                    ksk.cast(
                        &server_key_1.unchecked_add(b0, &server_key_1.unchecked_scalar_mul(b1, 2)),
                    )
                })
                .collect::<Vec<_>>();
        });
    });

    write_to_json::<u64, _>(
        &bench_id,
        ks_param,
        ks_param_name,
        "pack_cast_64",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}

pub fn pack_cast(c: &mut Criterion) {
    let bench_name = "pack_cast";
    let mut bench_group = c.benchmark_group(bench_name);

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let ks_param = PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS;
    let ks_param_name = "PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS";

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let ct_1 = client_key_1.encrypt(1);
    let ct_2 = client_key_1.encrypt(1);

    let bench_id = format!("{bench_name}_{ks_param_name}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = ksk.cast(
                &server_key_1.unchecked_add(&ct_1, &server_key_1.unchecked_scalar_mul(&ct_2, 2)),
            );
        });
    });

    write_to_json::<u64, _>(
        &bench_id,
        ks_param,
        ks_param_name,
        "pack_cast",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}

pub fn cast(c: &mut Criterion) {
    let bench_name = "cast";
    let mut bench_group = c.benchmark_group(bench_name);

    let (client_key_1, server_key_1): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) =
        gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let ks_param = PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS;
    let ks_param_name = "PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS";

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        ks_param,
    );

    let ct = client_key_1.encrypt(1);

    let bench_id = format!("{bench_name}_{ks_param_name}");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let _ = ksk.cast(&ct);
        });
    });

    write_to_json::<u64, _>(
        &bench_id,
        ks_param,
        ks_param_name,
        "cast",
        &OperatorType::Atomic,
        0,
        vec![],
    );
}
