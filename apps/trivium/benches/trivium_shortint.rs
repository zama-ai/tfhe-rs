use tfhe::prelude::*;
use tfhe::shortint::prelude::*;
use tfhe::shortint::KeySwitchingKey;
use tfhe::{generate_keys, ConfigBuilder, FheUint64};

use tfhe_trivium::{TransCiphering, TriviumStreamShortint};

use criterion::Criterion;

pub fn trivium_shortint_warmup(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (hl_client_key, hl_server_key) = generate_keys(config);
    let underlying_ck: tfhe::shortint::ClientKey = (*hl_client_key.as_ref()).clone().into();
    let underlying_sk: tfhe::shortint::ServerKey = (*hl_server_key.as_ref()).clone().into();

    let (client_key, server_key): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);

    let ksk = KeySwitchingKey::new(
        (&client_key, &server_key),
        (&underlying_ck, &underlying_sk),
        PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    );

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    c.bench_function("trivium 1_1 warmup", |b| {
        b.iter(|| {
            let cipher_key = key.map(|x| client_key.encrypt(x));
            let _trivium = TriviumStreamShortint::new(
                cipher_key,
                iv,
                server_key.clone(),
                ksk.clone(),
                hl_server_key.clone(),
            );
        })
    });
}

pub fn trivium_shortint_gen(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (hl_client_key, hl_server_key) = generate_keys(config);
    let underlying_ck: tfhe::shortint::ClientKey = (*hl_client_key.as_ref()).clone().into();
    let underlying_sk: tfhe::shortint::ServerKey = (*hl_server_key.as_ref()).clone().into();

    let (client_key, server_key): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);

    let ksk = KeySwitchingKey::new(
        (&client_key, &server_key),
        (&underlying_ck, &underlying_sk),
        PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    );

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let cipher_key = key.map(|x| client_key.encrypt(x));

    let mut trivium = TriviumStreamShortint::new(cipher_key, iv, server_key, ksk, hl_server_key);

    c.bench_function("trivium 1_1 generate 64 bits", |b| {
        b.iter(|| trivium.next_64())
    });
}

pub fn trivium_shortint_trans(c: &mut Criterion) {
    let config = ConfigBuilder::default().build();
    let (hl_client_key, hl_server_key) = generate_keys(config);
    let underlying_ck: tfhe::shortint::ClientKey = (*hl_client_key.as_ref()).clone().into();
    let underlying_sk: tfhe::shortint::ServerKey = (*hl_server_key.as_ref()).clone().into();

    let (client_key, server_key): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);

    let ksk = KeySwitchingKey::new(
        (&client_key, &server_key),
        (&underlying_ck, &underlying_sk),
        PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    );

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let cipher_key = key.map(|x| client_key.encrypt(x));

    let ciphered_message = FheUint64::try_encrypt(0u64, &hl_client_key).unwrap();
    let mut trivium = TriviumStreamShortint::new(cipher_key, iv, server_key, ksk, hl_server_key);

    c.bench_function("trivium 1_1 transencrypt 64 bits", |b| {
        b.iter(|| trivium.trans_encrypt_64(ciphered_message.clone()))
    });
}
