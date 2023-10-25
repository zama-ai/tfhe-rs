use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool, FheUint64, FheUint8};

use crate::{KreyviumStream, KreyviumStreamByte, KreyviumStreamShortint, TransCiphering};

// Values for these tests come from the github repo renaud1239/Kreyvium,
// commit fd6828f68711276c25f55e605935028f5e843f43

fn get_hexadecimal_string_from_lsb_first_stream(a: Vec<bool>) -> String {
    assert!(a.len() % 8 == 0);
    let mut hexadecimal: String = "".to_string();
    for test in a.chunks(8) {
        // Encoding is bytes in LSB order
        match test[4..8] {
            [false, false, false, false] => hexadecimal.push('0'),
            [true, false, false, false] => hexadecimal.push('1'),
            [false, true, false, false] => hexadecimal.push('2'),
            [true, true, false, false] => hexadecimal.push('3'),

            [false, false, true, false] => hexadecimal.push('4'),
            [true, false, true, false] => hexadecimal.push('5'),
            [false, true, true, false] => hexadecimal.push('6'),
            [true, true, true, false] => hexadecimal.push('7'),

            [false, false, false, true] => hexadecimal.push('8'),
            [true, false, false, true] => hexadecimal.push('9'),
            [false, true, false, true] => hexadecimal.push('A'),
            [true, true, false, true] => hexadecimal.push('B'),

            [false, false, true, true] => hexadecimal.push('C'),
            [true, false, true, true] => hexadecimal.push('D'),
            [false, true, true, true] => hexadecimal.push('E'),
            [true, true, true, true] => hexadecimal.push('F'),
            _ => (),
        };
        match test[0..4] {
            [false, false, false, false] => hexadecimal.push('0'),
            [true, false, false, false] => hexadecimal.push('1'),
            [false, true, false, false] => hexadecimal.push('2'),
            [true, true, false, false] => hexadecimal.push('3'),

            [false, false, true, false] => hexadecimal.push('4'),
            [true, false, true, false] => hexadecimal.push('5'),
            [false, true, true, false] => hexadecimal.push('6'),
            [true, true, true, false] => hexadecimal.push('7'),

            [false, false, false, true] => hexadecimal.push('8'),
            [true, false, false, true] => hexadecimal.push('9'),
            [false, true, false, true] => hexadecimal.push('A'),
            [true, true, false, true] => hexadecimal.push('B'),

            [false, false, true, true] => hexadecimal.push('C'),
            [true, false, true, true] => hexadecimal.push('D'),
            [false, true, true, true] => hexadecimal.push('E'),
            [true, true, true, true] => hexadecimal.push('F'),
            _ => (),
        };
    }
    hexadecimal
}

fn get_hexagonal_string_from_bytes(a: Vec<u8>) -> String {
    assert!(a.len() % 8 == 0);
    let mut hexadecimal: String = "".to_string();
    for test in a {
        hexadecimal.push_str(&format!("{:02X?}", test));
    }
    hexadecimal
}

fn get_hexagonal_string_from_u64(a: Vec<u64>) -> String {
    let mut hexadecimal: String = "".to_string();
    for test in a {
        hexadecimal.push_str(&format!("{:016X?}", test));
    }
    hexadecimal
}

#[test]
fn kreyvium_test_1() {
    let key = [false; 128];
    let iv = [false; 128];
    let output = "26DCF1F4BC0F1922";

    let mut kreyvium = KreyviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(64);
    while vec.len() < 64 {
        vec.push(kreyvium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_2() {
    let mut key = [false; 128];
    let iv = [false; 128];
    key[0] = true;

    let output = "4FD421D4DA3D2C8A";

    let mut kreyvium = KreyviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(64);
    while vec.len() < 64 {
        vec.push(kreyvium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_3() {
    let key = [false; 128];
    let mut iv = [false; 128];
    iv[0] = true;

    let output = "C9217BA0D762ACA1";

    let mut kreyvium = KreyviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(64);
    while vec.len() < 64 {
        vec.push(kreyvium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_4() {
    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [false; 128];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [false; 128];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let output = "D1F0303482061111";

    let mut kreyvium = KreyviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(64);
    while vec.len() < 64 {
        vec.push(kreyvium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(hexadecimal, output);
}

#[test]
fn kreyvium_test_fhe_long() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [false; 128];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [false; 128];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let output = "D1F0303482061111";

    let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));

    let mut kreyvium = KreyviumStream::<FheBool>::new(cipher_key, iv, &server_key);

    let mut vec = Vec::<bool>::with_capacity(64);
    while vec.len() < 64 {
        let cipher_outputs = kreyvium.next_64();
        for c in cipher_outputs {
            vec.push(c.decrypt(&client_key))
        }
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output, hexadecimal);
}

use tfhe::shortint::prelude::*;

#[test]
fn kreyvium_test_shortint_long() {
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

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [0; 128];

    for i in (0..key_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [0; 128];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val = u64::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2;
            val >>= 1;
        }
    }
    let output = "D1F0303482061111".to_string();

    let cipher_key = key.map(|x| client_key.encrypt(x));

    let ciphered_message = FheUint64::try_encrypt(0u64, &hl_client_key).unwrap();

    let mut kreyvium = KreyviumStreamShortint::new(cipher_key, iv, server_key, ksk, hl_server_key);

    let trans_ciphered_message = kreyvium.trans_encrypt_64(ciphered_message);
    let ciphered_message = trans_ciphered_message.decrypt(&hl_client_key);

    let hexadecimal = get_hexagonal_string_from_u64(vec![ciphered_message]);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_clear_byte() {
    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key_bytes = [0u8; 16];

    for i in (0..key_string.len()).step_by(2) {
        key_bytes[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv_bytes = [0u8; 16];

    for i in (0..iv_string.len()).step_by(2) {
        iv_bytes[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let output = "D1F0303482061111".to_string();

    let mut kreyvium = KreyviumStreamByte::<u8>::new(key_bytes, iv_bytes);

    let mut vec = Vec::<u8>::with_capacity(8);
    while vec.len() < 8 {
        let outputs = kreyvium.next_64();
        for c in outputs {
            vec.push(c)
        }
    }

    let hexadecimal = get_hexagonal_string_from_bytes(vec);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_byte_long() {
    let config = ConfigBuilder::default()
        .enable_function_evaluation()
        .build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key_bytes = [0u8; 16];

    for i in (0..key_string.len()).step_by(2) {
        key_bytes[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv_bytes = [0u8; 16];

    for i in (0..iv_string.len()).step_by(2) {
        iv_bytes[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let cipher_key = key_bytes.map(|x| FheUint8::encrypt(x, &client_key));

    let output = "D1F0303482061111".to_string();

    let mut kreyvium = KreyviumStreamByte::<FheUint8>::new(cipher_key, iv_bytes, &server_key);

    let mut vec = Vec::<u8>::with_capacity(8);
    while vec.len() < 8 {
        let cipher_outputs = kreyvium.next_64();
        for c in cipher_outputs {
            vec.push(c.decrypt(&client_key))
        }
    }

    let hexadecimal = get_hexagonal_string_from_bytes(vec);
    assert_eq!(output, hexadecimal);
}

#[test]
fn kreyvium_test_fhe_byte_transciphering_long() {
    let config = ConfigBuilder::default()
        .enable_function_evaluation()
        .build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [0u8; 16];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [0u8; 16];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let output = "D1F0303482061111".to_string();

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let ciphered_message = FheUint64::try_encrypt(0u64, &client_key).unwrap();

    let mut kreyvium = KreyviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    let trans_ciphered_message = kreyvium.trans_encrypt_64(ciphered_message);
    let ciphered_message = trans_ciphered_message.decrypt(&client_key);

    let hexadecimal = get_hexagonal_string_from_u64(vec![ciphered_message]);
    assert_eq!(output, hexadecimal);
}
