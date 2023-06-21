use tfhe::shortint::prelude::*;

use rayon::prelude::*;

use criterion::Criterion;

pub fn pack_cast_64(c: &mut Criterion) {
    let (client_key_1, server_key_1): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        PARAM_KEYSWITCH_1_1_TO_2_2,
    );

    let vec_ct = vec![client_key_1.encrypt(1); 64];

    c.bench_function("pack_cast_64", |b| {
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
}

pub fn pack_cast(c: &mut Criterion) {
    let (client_key_1, server_key_1): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        PARAM_KEYSWITCH_1_1_TO_2_2,
    );

    let ct_1 = client_key_1.encrypt(1);
    let ct_2 = client_key_1.encrypt(1);

    c.bench_function("pack_cast", |b| {
        b.iter(|| {
            let _ = ksk.cast(
                &server_key_1.unchecked_add(&ct_1, &server_key_1.unchecked_scalar_mul(&ct_2, 2)),
            );
        });
    });
}

pub fn cast(c: &mut Criterion) {
    let (client_key_1, server_key_1): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1);
    let (client_key_2, server_key_2): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let ksk = KeySwitchingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
        PARAM_KEYSWITCH_1_1_TO_2_2,
    );

    let ct = client_key_1.encrypt(1);

    c.bench_function("cast", |b| {
        b.iter(|| {
            let _ = ksk.cast(&ct);
        });
    });
}
