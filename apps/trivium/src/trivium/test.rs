use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool, FheUint64, FheUint8};

use crate::{TransCiphering, TriviumStream, TriviumStreamByte, TriviumStreamShortint};

// Values for these tests come from the github repo cantora/avr-crypto-lib, commit 2a5b018,
// file testvectors/trivium-80.80.test-vectors

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
fn trivium_test_1() {
    let key = [false; 80];
    let iv = [false; 80];
    let output_0_63    = "FBE0BF265859051B517A2E4E239FC97F563203161907CF2DE7A8790FA1B2E9CDF75292030268B7382B4C1A759AA2599A285549986E74805903801A4CB5A5D4F2".to_string();
    let output_192_255 = "0F1BE95091B8EA857B062AD52BADF47784AC6D9B2E3F85A9D79995043302F0FDF8B76E5BC8B7B4F0AA46CD20DDA04FDD197BC5E1635496828F2DBFB23F6BD5D0".to_string();
    let output_256_319 = "80F9075437BAC73F696D0ABE3972F5FCE2192E5FCC13C0CB77D0ABA09126838D31A2D38A2087C46304C8A63B54109F679B0B1BC71E72A58D6DD3E0A3FF890D4A".to_string();
    let output_448_511 = "68450EB0910A98EF1853E0FC1BED8AB6BB08DF5F167D34008C2A85284D4B886DD56883EE92BF18E69121670B4C81A5689C9B0538373D22EB923A28A2DB44C0EB".to_string();

    let mut trivium = TriviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(512 * 8);
    while vec.len() < 512 * 8 {
        vec.push(trivium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
    assert_eq!(output_192_255, hexadecimal[192 * 2..256 * 2]);
    assert_eq!(output_256_319, hexadecimal[256 * 2..320 * 2]);
    assert_eq!(output_448_511, hexadecimal[448 * 2..512 * 2]);
}

#[test]
fn trivium_test_2() {
    let mut key = [false; 80];
    let iv = [false; 80];
    key[7] = true;

    let output_0_63    = "38EB86FF730D7A9CAF8DF13A4420540DBB7B651464C87501552041C249F29A64D2FBF515610921EBE06C8F92CECF7F8098FF20CCCC6A62B97BE8EF7454FC80F9".to_string();
    let output_192_255 = "EAF2625D411F61E41F6BAEEDDD5FE202600BD472F6C9CD1E9134A745D900EF6C023E4486538F09930CFD37157C0EB57C3EF6C954C42E707D52B743AD83CFF297".to_string();
    let output_256_319 = "9A203CF7B2F3F09C43D188AA13A5A2021EE998C42F777E9B67C3FA221A0AA1B041AA9E86BC2F5C52AFF11F7D9EE480CB1187B20EB46D582743A52D7CD080A24A".to_string();
    let output_448_511 = "EBF14772061C210843C18CEA2D2A275AE02FCB18E5D7942455FF77524E8A4CA51E369A847D1AEEFB9002FCD02342983CEAFA9D487CC2032B10192CD416310FA4".to_string();

    let mut trivium = TriviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(512 * 8);
    while vec.len() < 512 * 8 {
        vec.push(trivium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
    assert_eq!(output_192_255, hexadecimal[192 * 2..256 * 2]);
    assert_eq!(output_256_319, hexadecimal[256 * 2..320 * 2]);
    assert_eq!(output_448_511, hexadecimal[448 * 2..512 * 2]);
}

#[test]
fn trivium_test_3() {
    let key = [false; 80];
    let mut iv = [false; 80];
    iv[7] = true;

    let output_0_63    = "F8901736640549E3BA7D42EA2D07B9F49233C18D773008BD755585B1A8CBAB86C1E9A9B91F1AD33483FD6EE3696D659C9374260456A36AAE11F033A519CBD5D7".to_string();
    let output_192_255 = "87423582AF64475C3A9C092E32A53C5FE07D35B4C9CA288A89A43DEF3913EA9237CA43342F3F8E83AD3A5C38D463516F94E3724455656A36279E3E924D442F06".to_string();
    let output_256_319 = "D94389A90E6F3BF2BB4C8B057339AAD8AA2FEA238C29FCAC0D1FF1CB2535A07058BA995DD44CFC54CCEC54A5405B944C532D74E50EA370CDF1BA1CBAE93FC0B5".to_string();
    let output_448_511 = "4844151714E56A3A2BBFBA426A1D60F9A4F265210A91EC29259AE2035234091C49FFB1893FA102D425C57C39EB4916F6D148DC83EBF7DE51EEB9ABFE045FB282".to_string();

    let mut trivium = TriviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(512 * 8);
    while vec.len() < 512 * 8 {
        vec.push(trivium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
    assert_eq!(output_192_255, hexadecimal[192 * 2..256 * 2]);
    assert_eq!(output_256_319, hexadecimal[256 * 2..320 * 2]);
    assert_eq!(output_448_511, hexadecimal[448 * 2..512 * 2]);
}

#[test]
fn trivium_test_4() {
    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [false; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [false; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();
    let output_65472_65535 = "C04C24A6938C8AF8A491D5E481271E0E601338F01067A86A795CA493AA4FF265619B8D448B706B7C88EE8395FC79E5B51AB40245BBF7773AE67DF86FCFB71F30".to_string();
    let output_65536_65599 = "011A0D7EC32FA102C66C164CFCB189AED9F6982E8C7370A6A37414781192CEB155C534C1C8C9E53FDEADF2D3D0577DAD3A8EB2F6E5265F1E831C86844670BC69".to_string();
    let output_131008_131071 = "48107374A9CE3AAF78221AE77789247CF6896A249ED75DCE0CF2D30EB9D889A0C61C9F480E5C07381DED9FAB2AD54333E82C89BA92E6E47FD828F1A66A8656E0".to_string();

    let mut trivium = TriviumStream::<bool>::new(key, iv);

    let mut vec = Vec::<bool>::with_capacity(131072 * 8);
    while vec.len() < 131072 * 8 {
        vec.push(trivium.next_bool());
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
    assert_eq!(output_65472_65535, hexadecimal[65472 * 2..65536 * 2]);
    assert_eq!(output_65536_65599, hexadecimal[65536 * 2..65600 * 2]);
    assert_eq!(output_131008_131071, hexadecimal[131008 * 2..131072 * 2]);
}

#[test]
fn trivium_test_clear_byte() {
    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();
    let output_65472_65535 = "C04C24A6938C8AF8A491D5E481271E0E601338F01067A86A795CA493AA4FF265619B8D448B706B7C88EE8395FC79E5B51AB40245BBF7773AE67DF86FCFB71F30".to_string();
    let output_65536_65599 = "011A0D7EC32FA102C66C164CFCB189AED9F6982E8C7370A6A37414781192CEB155C534C1C8C9E53FDEADF2D3D0577DAD3A8EB2F6E5265F1E831C86844670BC69".to_string();
    let output_131008_131071 = "48107374A9CE3AAF78221AE77789247CF6896A249ED75DCE0CF2D30EB9D889A0C61C9F480E5C07381DED9FAB2AD54333E82C89BA92E6E47FD828F1A66A8656E0".to_string();

    let mut trivium = TriviumStreamByte::<u8>::new(key, iv);

    let mut vec = Vec::<u8>::with_capacity(131072);
    while vec.len() < 131072 {
        let outputs = trivium.next_64();
        for c in outputs {
            vec.push(c)
        }
    }

    let hexadecimal = get_hexagonal_string_from_bytes(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
    assert_eq!(output_65472_65535, hexadecimal[65472 * 2..65536 * 2]);
    assert_eq!(output_65536_65599, hexadecimal[65536 * 2..65600 * 2]);
    assert_eq!(output_131008_131071, hexadecimal[131008 * 2..131072 * 2]);
}

#[test]
fn trivium_test_fhe_long() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [false; 80];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [false; 80];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

    let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));

    let mut trivium = TriviumStream::<FheBool>::new(cipher_key, iv, &server_key);

    let mut vec = Vec::<bool>::with_capacity(64 * 8);
    while vec.len() < 64 * 8 {
        let cipher_outputs = trivium.next_64();
        for c in cipher_outputs {
            vec.push(c.decrypt(&client_key))
        }
    }

    let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
}

#[test]
fn trivium_test_fhe_byte_long() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    let mut vec = Vec::<u8>::with_capacity(64);
    while vec.len() < 64 {
        let cipher_outputs = trivium.next_64();
        for c in cipher_outputs {
            vec.push(c.decrypt(&client_key))
        }
    }

    let hexadecimal = get_hexagonal_string_from_bytes(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
}

#[test]
fn trivium_test_fhe_byte_transciphering_long() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let mut ciphered_message = vec![FheUint64::try_encrypt(0u64, &client_key).unwrap(); 9];

    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    let mut vec = Vec::<u64>::with_capacity(8);
    while vec.len() < 8 {
        let trans_ciphered_message = trivium.trans_encrypt_64(ciphered_message.pop().unwrap());
        vec.push(trans_ciphered_message.decrypt(&client_key));
    }

    let hexadecimal = get_hexagonal_string_from_u64(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
}

use tfhe::shortint::prelude::*;

#[test]
fn trivium_test_shortint_long() {
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
    let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

    let cipher_key = key.map(|x| client_key.encrypt(x));

    let mut ciphered_message = vec![FheUint64::try_encrypt(0u64, &hl_client_key).unwrap(); 9];

    let mut trivium = TriviumStreamShortint::new(cipher_key, iv, server_key, ksk, hl_server_key);

    let mut vec = Vec::<u64>::with_capacity(8);
    while vec.len() < 8 {
        let trans_ciphered_message = trivium.trans_encrypt_64(ciphered_message.pop().unwrap());
        vec.push(trans_ciphered_message.decrypt(&hl_client_key));
    }

    let hexadecimal = get_hexagonal_string_from_u64(vec);
    assert_eq!(output_0_63, hexadecimal[0..64 * 2]);
}
