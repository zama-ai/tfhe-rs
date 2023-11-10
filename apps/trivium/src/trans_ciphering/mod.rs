//! This module will contain extensions of some TriviumStream of KreyviumStream objects,
//! when trans ciphering is available to them.

use crate::{KreyviumStreamByte, KreyviumStreamShortint, TriviumStreamByte, TriviumStreamShortint};
use tfhe::shortint::Ciphertext;

use tfhe::prelude::*;
use tfhe::{set_server_key, unset_server_key, FheUint64, FheUint8, ServerKey};

use rayon::prelude::*;

/// Triat specifying the interface for trans ciphering a FheUint64 object. Since it is meant
/// to be used with stream ciphers, encryption and decryption are by default the same.
pub trait TransCiphering {
    fn trans_encrypt_64(&mut self, cipher: FheUint64) -> FheUint64;
    fn trans_decrypt_64(&mut self, cipher: FheUint64) -> FheUint64 {
        self.trans_encrypt_64(cipher)
    }
}

fn transcipher_from_fheu8_stream(
    stream: Vec<FheUint8>,
    cipher: FheUint64,
    fhe_server_key: &ServerKey,
) -> FheUint64 {
    assert_eq!(stream.len(), 8);

    set_server_key(fhe_server_key.clone());
    rayon::broadcast(|_| set_server_key(fhe_server_key.clone()));

    let ret: FheUint64 = stream
        .into_par_iter()
        .enumerate()
        .map(|(i, x)| &cipher ^ &(FheUint64::cast_from(x) << (8 * (7 - i) as u8)))
        .reduce_with(|a, b| a | b)
        .unwrap();

    unset_server_key();
    rayon::broadcast(|_| unset_server_key());

    ret
}

fn transcipher_from_1_1_stream(
    stream: Vec<Ciphertext>,
    cipher: FheUint64,
    hl_server_key: &ServerKey,
    internal_server_key: &tfhe::shortint::ServerKey,
    casting_key: &tfhe::shortint::KeySwitchingKey,
) -> FheUint64 {
    assert_eq!(stream.len(), 64);

    let pairs = (0..32)
        .into_par_iter()
        .map(|i| {
            let byte_idx = 7 - i / 4;
            let pair_idx = i % 4;

            let b0 = &stream[8 * byte_idx + 2 * pair_idx];
            let b1 = &stream[8 * byte_idx + 2 * pair_idx + 1];

            casting_key.cast(
                &internal_server_key
                    .unchecked_add(b0, &internal_server_key.unchecked_scalar_mul(b1, 2)),
            )
        })
        .collect::<Vec<_>>();

    set_server_key(hl_server_key.clone());
    let ret = &cipher ^ &FheUint64::try_from(pairs).unwrap();
    unset_server_key();
    ret
}

impl TransCiphering for TriviumStreamByte<FheUint8> {
    /// `TriviumStreamByte<FheUint8>`: since a full step outputs 8 bytes, these bytes
    /// are each shifted by a number in [0, 8), and XORed with the input cipher
    fn trans_encrypt_64(&mut self, cipher: FheUint64) -> FheUint64 {
        transcipher_from_fheu8_stream(self.next_64(), cipher, self.get_server_key())
    }
}

impl TransCiphering for KreyviumStreamByte<FheUint8> {
    /// `KreyviumStreamByte<FheUint8>`: since a full step outputs 8 bytes, these bytes
    /// are each shifted by a number in [0, 8), and XORed with the input cipher
    fn trans_encrypt_64(&mut self, cipher: FheUint64) -> FheUint64 {
        transcipher_from_fheu8_stream(self.next_64(), cipher, self.get_server_key())
    }
}

impl TransCiphering for TriviumStreamShortint {
    /// TriviumStreamShortint: since a full step outputs 64 shortints, these bits
    /// are paired 2 by 2 in the HL parameter space and packed in a full word,
    /// and XORed with the input cipher
    fn trans_encrypt_64(&mut self, cipher: FheUint64) -> FheUint64 {
        transcipher_from_1_1_stream(
            self.next_64(),
            cipher,
            self.get_hl_server_key(),
            self.get_internal_server_key(),
            self.get_casting_key(),
        )
    }
}

impl TransCiphering for KreyviumStreamShortint {
    /// KreyviumStreamShortint: since a full step outputs 64 shortints, these bits
    /// are paired 2 by 2 in the HL parameter space and packed in a full word,
    /// and XORed with the input cipher
    fn trans_encrypt_64(&mut self, cipher: FheUint64) -> FheUint64 {
        transcipher_from_1_1_stream(
            self.next_64(),
            cipher,
            self.get_hl_server_key(),
            self.get_internal_server_key(),
            self.get_casting_key(),
        )
    }
}
