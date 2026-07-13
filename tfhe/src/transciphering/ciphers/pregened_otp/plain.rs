use crate::shortint::client_key::ClientKey;
use crate::transciphering::ciphers::pregened_otp::fhe::PreGenedOtpFheSecretMask;
use crate::transciphering::ciphers::unpack_bits_lsb_first_with_early_stop;
use crate::transciphering::{StreamCipher, StreamCipherKind};

pub struct PreGenedOtpPlainSecretMask {
    /// Collection of random u8, from which one can pull secret bits to hide sensitive values by
    /// XOR-ing them together.
    secret_mask: Vec<u8>,
    /// How many bits in the secret mask are actually usable.
    bit_count: usize,
}

impl PreGenedOtpPlainSecretMask {
    pub fn try_new(secret_mask: Vec<u8>, bit_count: usize) -> Result<Self, &'static str> {
        let expected_byte_count = bit_count.div_ceil(8);

        if secret_mask.len() != expected_byte_count {
            return Err("Invalid bit_count for provided secret_mask");
        }

        Ok(Self {
            secret_mask,
            bit_count,
        })
    }

    /// # Panics
    ///
    /// Panics if `secret_mask` does not have the expected length: `bit_count.div_ceil(8)`
    pub fn new(secret_mask: Vec<u8>, bit_count: usize) -> Self {
        Self::try_new(secret_mask, bit_count).unwrap()
    }

    pub fn encrypt(&self, client_key: &ClientKey) -> PreGenedOtpFheSecretMask {
        let mut bits = vec![false; self.bit_count];
        unpack_bits_lsb_first_with_early_stop(&self.secret_mask, &mut bits);

        let secret_mask = bits
            .into_iter()
            .map(|b| client_key.encrypt_bool(b))
            .collect();

        PreGenedOtpFheSecretMask::new(secret_mask)
    }
}

pub struct PreGenedOtpPlainState {
    secret_mask: PreGenedOtpPlainSecretMask,
    current_counter: u64,
}

impl PreGenedOtpPlainState {
    pub fn new(secret_mask: PreGenedOtpPlainSecretMask) -> Self {
        Self {
            secret_mask,
            current_counter: 0,
        }
    }

    pub fn remaining_bits(&self) -> u64 {
        let bit_count_u64: u64 = self.secret_mask.bit_count.try_into().unwrap();
        bit_count_u64.saturating_sub(self.current_counter)
    }
}

impl StreamCipher for PreGenedOtpPlainState {
    fn kind(&self) -> StreamCipherKind {
        StreamCipherKind::PreGenedOtp
    }

    fn next_keystream_bits(&mut self, n_bits: usize) -> Vec<u8> {
        if n_bits == 0 {
            return vec![];
        }

        let n_bits_u64: u64 = n_bits.try_into().unwrap();

        let remaining_bits = self.remaining_bits();
        assert!(
            remaining_bits >= n_bits_u64,
            "Requested more bits ({n_bits_u64}) than remaining ({remaining_bits})."
        );

        let start_mask_idx: usize = (self.current_counter / 8).try_into().unwrap();
        let last_bit_idx = self.current_counter.checked_add(n_bits_u64 - 1).unwrap();
        // Exclusive, so range is start_mask_idx..stop_mask_idx
        let stop_mask_idx: usize = (last_bit_idx / 8 + 1).try_into().unwrap();

        // We may need to look at most at mask_bytes_to_return + 1, e.g. if n_bits == 10 and we have
        // 3 bytes
        // LSB first repr
        // [x,x,x,x,x,x,x,0][1,2,3,4,5,6,7,8][9,x,x,x,x,x,x,x]
        // We have to return, 2 bytes
        // [0,1,2,3,4,5,6,7][8,9,x,x,x,x,x,x]
        let mask_bytes_to_return_count = n_bits.div_ceil(8);

        let mut result = vec![0u8; mask_bytes_to_return_count];

        let mask_bytes = &self.secret_mask.secret_mask[start_mask_idx..stop_mask_idx];

        // Amount by which each byte will need to be shifted down/right
        let first_bit_position_in_byte = (self.current_counter % 8) as u32;

        if first_bit_position_in_byte == 0 {
            // Happy path no cross-byte shifts
            result.copy_from_slice(mask_bytes);
        } else {
            // Need some cross-byte shifts: result byte i takes the end of mask byte i,
            // completed with the start of mask byte i + 1. Continuing the example above:
            // result[0] == mask_bytes[0] >> 7 | mask_bytes[1] << 1
            // result[1] == mask_bytes[1] >> 7 | mask_bytes[2] << 1
            let shift_down = first_bit_position_in_byte;
            let shift_up = 8 - shift_down;
            for (result_byte, (mask, mask_next)) in result.iter_mut().zip(
                mask_bytes
                    .iter()
                    .copied()
                    .zip(mask_bytes[1..].iter().copied().chain(core::iter::once(0))),
            ) {
                *result_byte = (mask >> shift_down) | (mask_next << shift_up);
            }
        }

        // Mask the last byte to return only the bits we are supposed to. Result bits are
        // realigned to position 0 whatever the start position in the mask was, so the last
        // of the n_bits sits at this position in the last byte:
        let last_bit_position_in_byte = ((n_bits_u64 - 1) % 8) as u32;
        // if the last bit is at position 0, then we need to mask out the 7 high bits
        // u8 MSB repr
        // base_mask = 0b1111_1111
        // mask_to_apply = base_mask >> shift_to_apply
        // Case 0
        // mask_to_apply = 0b0000_0001 => shift == 7
        // Case 7
        // mask_to_apply = 0b1111_1111 => shift == 0
        let shift_to_apply = 7 - last_bit_position_in_byte;
        let last_byte_mask = u8::MAX >> shift_to_apply;
        result[mask_bytes_to_return_count - 1] &= last_byte_mask;

        self.current_counter = self.current_counter.checked_add(n_bits_u64).unwrap();

        result
    }

    fn seek(&mut self, target_counter: u64) {
        let bit_count_u64: u64 = self.secret_mask.bit_count.try_into().unwrap();
        assert!(
            target_counter <= bit_count_u64,
            "Requested seek ({target_counter}), beyond maximum bit count ({bit_count_u64})"
        );

        self.current_counter = target_counter;
    }

    fn current_counter(&self) -> u64 {
        self.current_counter
    }
}
