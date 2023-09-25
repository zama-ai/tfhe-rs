# FHE boolean Trivium implementation using TFHE-rs

The cleartext boolean Trivium is available to be built using the function `TriviumStream::<bool>::new`. 
This takes as input 2 arrays of 80 bool: the Trivium key and the IV. After initialization, it returns a TriviumStream on 
which the user can call `next`, getting the next bit of the cipher stream, or `next_64`, which will compute 64 values at once,
using multithreading to accelerate the computation.


Quite similarly, the function `TriviumStream::<FheBool>::new` will return a very similar object running in FHE space. Its arguments are
2 arrays of 80 FheBool representing the encrypted Trivium key, and the encrypted IV. It also requires a reference to the the server key of the 
current scheme. This means that any user of this feature must also have the `tfhe-rs` crate as a dependency.


Example of a Rust main below:
```rust
use tfhe::{ConfigBuilder, generate_keys, FheBool};
use tfhe::prelude::*;

use tfhe_trivium::TriviumStream;

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
			_ => ()
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
			_ => ()
		};
	}
	return hexadecimal;
}

fn main() {
	let config = ConfigBuilder::all_disabled().enable_default_bool().build();
	let (client_key, server_key) = generate_keys(config);

	let key_string = "0053A6F94C9FF24598EB".to_string();
	let mut key = [false; 80];

	for i in (0..key_string.len()).step_by(2) {
		let mut val: u8 = u8::from_str_radix(&key_string[i..i+2], 16).unwrap();
		for j in 0..8 {
			key[8*(i>>1) + j] = val % 2 == 1;
			val >>= 1;
		}
	}

	let iv_string = "0D74DB42A91077DE45AC".to_string();
	let mut iv = [false; 80];

	for i in (0..iv_string.len()).step_by(2) {
		let mut val: u8 = u8::from_str_radix(&iv_string[i..i+2], 16).unwrap();
		for j in 0..8 {
			iv[8*(i>>1) + j] = val % 2 == 1;
			val >>= 1;
		}
	}
	
	let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

	let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));
	let cipher_iv = iv.map(|x| FheBool::encrypt(x, &client_key));


	let mut trivium = TriviumStream::<FheBool>::new(cipher_key, cipher_iv, &server_key);

	let mut vec = Vec::<bool>::with_capacity(64*8);
	while vec.len() < 64*8 {
		let cipher_outputs = trivium.next_64();
		for c in cipher_outputs {
			vec.push(c.decrypt(&client_key))
		}
	}

	let hexadecimal = get_hexadecimal_string_from_lsb_first_stream(vec);
	assert_eq!(output_0_63, hexadecimal[0..64*2]);
}
```

# FHE byte Trivium implementation

The same objects have also been implemented to stream bytes instead of booleans. They can be constructed and used in the same way via the functions `TriviumStreamByte::<u8>::new` and 
`TriviumStreamByte::<FheUint8>::new` with the same arguments as before. The `FheUint8` version is significantly slower than the `FheBool` version, because not running 
with the same cryptographic parameters. Its interest lie in its trans-ciphering capabilities: `TriviumStreamByte<FheUint8>` implements the trait `TransCiphering`, 
meaning it implements the functions `trans_encrypt_64`. This function takes as input a `FheUint64` and outputs a `FheUint64`, the output being
encrypted via tfhe and trivium. For convenience we also provide `trans_decrypt_64`, but this is of course the exact same function.

Other sizes than 64 bit are expected to be available in the future.

# FHE shortint Trivium implementation

The same implementation is also available for generic Ciphertexts representing bits (meant to be used with parameters `PARAM_MESSAGE_1_CARRY_1_KS_PBS`). It uses a lower level API 
of tfhe-rs, so the syntax is a little bit different. It also implements the `TransCiphering` trait. For optimization purposes, it does not internally run on the same 
cryptographic parameters as the high level API of tfhe-rs. As such, it requires the usage of a casting key, to switch from one parameter space to another, which makes 
its setup a little more intricate.

Example code:
```rust
use tfhe::shortint::prelude::*;
use tfhe::shortint::CastingKey;

use tfhe::{ConfigBuilder, generate_keys, FheUint64};
use tfhe::prelude::*;

use tfhe_trivium::TriviumStreamShortint;

fn test_shortint() {
	let config = ConfigBuilder::all_disabled().enable_default_integers().build();
	let (hl_client_key, hl_server_key) = generate_keys(config);
	let (client_key, server_key): (ClientKey, ServerKey) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
	let ksk = CastingKey::new((&client_key, &server_key), (&hl_client_key, &hl_server_key));

	let key_string = "0053A6F94C9FF24598EB".to_string();
	let mut key = [0; 80];

	for i in (0..key_string.len()).step_by(2) {
		let mut val = u64::from_str_radix(&key_string[i..i+2], 16).unwrap();
		for j in 0..8 {
			key[8*(i>>1) + j] = val % 2;
			val >>= 1;
		}
	}

	let iv_string = "0D74DB42A91077DE45AC".to_string();
	let mut iv = [0; 80];

	for i in (0..iv_string.len()).step_by(2) {
		let mut val = u64::from_str_radix(&iv_string[i..i+2], 16).unwrap();
		for j in 0..8 {
			iv[8*(i>>1) + j] = val % 2;
			val >>= 1;
		}
	}
	let output_0_63    = "F4CD954A717F26A7D6930830C4E7CF0819F80E03F25F342C64ADC66ABA7F8A8E6EAA49F23632AE3CD41A7BD290A0132F81C6D4043B6E397D7388F3A03B5FE358".to_string();

	let cipher_key = key.map(|x| client_key.encrypt(x));
	let cipher_iv = iv.map(|x| client_key.encrypt(x));

	let mut ciphered_message = vec![FheUint64::try_encrypt(0u64, &hl_client_key).unwrap(); 9];

	let mut trivium = TriviumStreamShortint::new(cipher_key, cipher_iv, &server_key, &ksk);

	let mut vec = Vec::<u64>::with_capacity(8);
	while vec.len() < 8 {
		let trans_ciphered_message = trivium.trans_encrypt_64(ciphered_message.pop().unwrap(), &hl_server_key);
		vec.push(trans_ciphered_message.decrypt(&hl_client_key));
	}

	let hexadecimal = get_hexagonal_string_from_u64(vec);
	assert_eq!(output_0_63, hexadecimal[0..64*2]);
}
```

# FHE Kreyvium implementation using tfhe-rs crate

This will work in exactly the same way as the Trivium implementation, except that the key and iv need to be 128 bits now. Available for the same internal types as Trivium, with similar syntax.

`KreyviumStreamByte<FheUint8>` and `KreyviumStreamShortint` also implement the `TransCiphering` trait.

# Testing

If you wish to run tests on this app, please run `cargo test -r trivium -- --test-threads=1` as multithreading provokes interferences between several running 
Triviums at the same time.
