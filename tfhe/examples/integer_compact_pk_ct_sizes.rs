use rand::Rng;

use tfhe::core_crypto::commons::numeric::Numeric;
use tfhe::integer::block_decomposition::{DecomposableInto, RecomposableFrom};
use tfhe::integer::public_key::{CompactPublicKeyBig, CompactPublicKeySmall};
use tfhe::integer::{gen_keys, U256};
use tfhe::shortint::keycache::NamedParam;
use tfhe::shortint::parameters::parameters_compact_pk::*;

pub fn main() {
    fn size_func<Scalar: Numeric + DecomposableInto<u64> + RecomposableFrom<u64> + From<u32>>() {
        let mut rng = rand::thread_rng();
        let num_bits = Scalar::BITS;

        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK;
        {
            println!("Sizes for: {} and {num_bits} bits", params.name());
            let (cks, _) = gen_keys(params);
            let pk = CompactPublicKeyBig::new(&cks);

            println!("PK size: {} bytes", bincode::serialize(&pk).unwrap().len());

            let num_block =
                (num_bits as f64 / (params.message_modulus.0 as f64).log(2.0)).ceil() as usize;

            const MAX_CT: usize = 20;

            let mut clear_vec = Vec::with_capacity(MAX_CT);
            // 5 inputs to a smart contract
            let num_ct_for_this_iter = 5;
            clear_vec.truncate(0);
            for _ in 0..num_ct_for_this_iter {
                let clear = rng.gen::<u32>();
                clear_vec.push(Scalar::from(clear));
            }

            let compact_encrypted_list = pk.encrypt_slice_radix_compact(&clear_vec, num_block);

            println!(
                "Compact CT list for {num_ct_for_this_iter} CTs: {} bytes",
                bincode::serialize(&compact_encrypted_list).unwrap().len()
            );

            let ciphertext_vec = compact_encrypted_list.expand();

            for (ciphertext, clear) in ciphertext_vec.iter().zip(clear_vec.iter().copied()) {
                let decrypted: Scalar = cks.decrypt_radix(ciphertext);
                assert_eq!(decrypted, clear);
            }
        }

        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_SMALL;
        {
            println!("Sizes for: {} and {num_bits} bits", params.name());
            let (cks, _) = gen_keys(params);
            let pk = CompactPublicKeySmall::new(&cks);

            println!("PK size: {} bytes", bincode::serialize(&pk).unwrap().len());

            let num_block =
                (num_bits as f64 / (params.message_modulus.0 as f64).log(2.0)).ceil() as usize;

            const MAX_CT: usize = 20;

            let mut clear_vec = Vec::with_capacity(MAX_CT);
            // 5 inputs to a smart contract
            let num_ct_for_this_iter = 5;
            clear_vec.truncate(0);
            for _ in 0..num_ct_for_this_iter {
                let clear = rng.gen::<u32>();
                clear_vec.push(Scalar::from(clear));
            }

            let compact_encrypted_list = pk.encrypt_slice_radix_compact(&clear_vec, num_block);

            println!(
                "Compact CT list for {num_ct_for_this_iter} CTs: {} bytes",
                bincode::serialize(&compact_encrypted_list).unwrap().len()
            );

            let ciphertext_vec = compact_encrypted_list.expand();

            for (ciphertext, clear) in ciphertext_vec.iter().zip(clear_vec.iter().copied()) {
                let decrypted: Scalar = cks.decrypt_radix(ciphertext);
                assert_eq!(decrypted, clear);
            }
        }
    }

    size_func::<u32>();
    size_func::<U256>();
}
