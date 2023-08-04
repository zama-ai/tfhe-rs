//! Module with the definition of the WopbsKey (WithOut padding PBS Key).
//!
//! This module implements the generation of another server public key, which allows to compute
//! an alternative version of the programmable bootstrapping. This does not require the use of a
//! bit of padding.
#[cfg(test)]
mod test;

use super::ciphertext::RadixCiphertext;
pub use crate::core_crypto::commons::parameters::{CiphertextCount, PlaintextCount};
use crate::core_crypto::prelude::*;
use crate::integer::client_key::utils::i_crt;
use crate::integer::{ClientKey, CrtCiphertext, IntegerCiphertext, ServerKey};
use crate::shortint::ciphertext::Degree;
use crate::shortint::wopbs::WopbsLUTBase;
use crate::shortint::WopbsParameters;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct WopbsKey {
    wopbs_key: crate::shortint::wopbs::WopbsKey,
}

#[must_use]
pub struct IntegerWopbsLUT {
    inner: WopbsLUTBase,
}

impl IntegerWopbsLUT {
    pub fn new(small_lut_size: PlaintextCount, output_ciphertext_count: CiphertextCount) -> Self {
        Self {
            inner: WopbsLUTBase::new(small_lut_size, output_ciphertext_count),
        }
    }
}

impl TryFrom<Vec<Vec<u64>>> for IntegerWopbsLUT {
    type Error = &'static str;

    fn try_from(value: Vec<Vec<u64>>) -> Result<Self, Self::Error> {
        let small_lut_size = value[0].len();
        if !value.iter().all(|x| x.len() == small_lut_size) {
            return Err("All small luts must have the same size");
        }

        let small_lut_count = value.len();

        Ok(Self {
            inner: WopbsLUTBase::from_vec(
                value.into_iter().flatten().collect(),
                CiphertextCount(small_lut_count),
            ),
        })
    }
}

impl AsRef<WopbsLUTBase> for IntegerWopbsLUT {
    fn as_ref(&self) -> &WopbsLUTBase {
        &self.inner
    }
}

impl AsMut<WopbsLUTBase> for IntegerWopbsLUT {
    fn as_mut(&mut self) -> &mut WopbsLUTBase {
        &mut self.inner
    }
}

/// ```rust
/// use tfhe::integer::wopbs::{decode_radix, encode_radix};
///
/// let val = 11;
/// let basis = 2;
/// let nb_block = 5;
/// let radix = encode_radix(val, basis, nb_block);
///
/// assert_eq!(val, decode_radix(radix, basis));
/// ```
pub fn encode_radix(val: u64, basis: u64, nb_block: u64) -> Vec<u64> {
    let mut output = vec![];
    //Bits of message put to 1éfé
    let mask = basis - 1;

    let mut power = 1_u64;
    //Put each decomposition into a new ciphertext
    for _ in 0..nb_block {
        let mut decomp = val & (mask * power);
        decomp /= power;

        // fill the vector with the message moduli
        output.push(decomp);

        //modulus to the power i
        power *= basis;
    }
    output
}

pub fn encode_crt(val: u64, basis: &[u64]) -> Vec<u64> {
    let mut output = vec![];
    //Put each decomposition into a new ciphertext
    for i in basis {
        output.push(val % i);
    }
    output
}

//Concatenate two ciphertexts in one
//Used to compute bivariate wopbs
fn ciphertext_concatenation<T>(ct1: &T, ct2: &T) -> T
where
    T: IntegerCiphertext,
{
    let mut new_blocks = ct1.blocks().to_vec();
    new_blocks.extend_from_slice(ct2.blocks());
    T::from_blocks(new_blocks)
}

pub fn encode_mix_radix(mut val: u64, basis: &[u64], modulus: u64) -> Vec<u64> {
    let mut output = vec![];
    for basis in basis.iter() {
        output.push(val % modulus);
        val -= val % modulus;
        let tmp = (val % (1 << basis)) >> (f64::log2(modulus as f64) as u64);
        val >>= basis;
        val += tmp;
    }
    output
}

// Example: val = 5 = 0b101 , basis = [1,2] -> output = [1, 1]
/// ```rust
/// use tfhe::integer::wopbs::split_value_according_to_bit_basis;
/// // Generate the client key and the server key:
/// let val = 5;
/// let basis = vec![1, 2];
/// assert_eq!(vec![1, 2], split_value_according_to_bit_basis(val, &basis));
/// ```
pub fn split_value_according_to_bit_basis(value: u64, basis: &[u64]) -> Vec<u64> {
    let mut output = vec![];
    let mut tmp = value;
    let mask = 1;

    for i in basis {
        let mut tmp_output = 0;
        for j in 0..*i {
            let val = tmp & mask;
            tmp_output += val << j;
            tmp >>= 1;
        }
        output.push(tmp_output);
    }
    output
}

/// ```rust
/// use tfhe::integer::wopbs::{decode_radix, encode_radix};
///
/// let val = 11;
/// let basis = 2;
/// let nb_block = 5;
/// assert_eq!(val, decode_radix(encode_radix(val, basis, nb_block), basis));
/// ```
pub fn decode_radix(val: Vec<u64>, basis: u64) -> u64 {
    let mut result = 0_u64;
    let mut shift = 1_u64;
    for v_i in val.iter() {
        //decrypt the component i of the integer and multiply it by the radix product
        let tmp = v_i.wrapping_mul(shift);

        // update the result
        result = result.wrapping_add(tmp);

        // update the shift for the next iteration
        shift = shift.wrapping_mul(basis);
    }
    result
}

impl From<crate::shortint::wopbs::WopbsKey> for WopbsKey {
    fn from(wopbs_key: crate::shortint::wopbs::WopbsKey) -> Self {
        Self { wopbs_key }
    }
}

impl WopbsKey {
    /// Generates the server key required to compute a WoPBS from the client and the server keys.
    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    /// ```
    pub fn new_wopbs_key(
        cks: &ClientKey,
        sks: &ServerKey,
        parameters: &WopbsParameters,
    ) -> WopbsKey {
        WopbsKey {
            wopbs_key: crate::shortint::wopbs::WopbsKey::new_wopbs_key(
                &cks.key, &sks.key, parameters,
            ),
        }
    }

    pub fn new_from_shortint(wopbskey: &crate::shortint::wopbs::WopbsKey) -> WopbsKey {
        let key = wopbskey.clone();
        WopbsKey { wopbs_key: key }
    }

    pub fn new_wopbs_key_only_for_wopbs(cks: &ClientKey, sks: &ServerKey) -> WopbsKey {
        WopbsKey {
            wopbs_key: crate::shortint::wopbs::WopbsKey::new_wopbs_key_only_for_wopbs(
                &cks.key, &sks.key,
            ),
        }
    }

    /// Computes the WoP-PBS given the luts.
    ///
    /// This works for both RadixCiphertext and CrtCiphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear = 42 % moduli;
    /// let ct = cks.encrypt_radix(clear as u64, nb_block);
    /// let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    /// let lut = wopbs_key.generate_lut_radix(&ct, |x| x);
    /// let ct_res = wopbs_key.wopbs(&ct, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert_eq!(res, clear);
    /// ```
    pub fn wopbs<T>(&self, ct_in: &T, lut: &IntegerWopbsLUT) -> T
    where
        T: IntegerCiphertext,
    {
        let total_bits_extracted = ct_in.blocks().iter().fold(0usize, |acc, block| {
            acc + f64::log2((block.degree.0 + 1) as f64).ceil() as usize
        });

        let extract_bits_output_lwe_size = self
            .wopbs_key
            .wopbs_server_key
            .key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size();

        let mut extracted_bits_blocks = LweCiphertextList::new(
            0u64,
            extract_bits_output_lwe_size,
            LweCiphertextCount(total_bits_extracted),
            self.wopbs_key.param.ciphertext_modulus,
        );

        let mut bits_extracted_so_far = 0;

        // Extraction of each bit for each block
        for block in ct_in.blocks().iter().rev() {
            let message_modulus = self.wopbs_key.param.message_modulus.0 as u64;
            let carry_modulus = self.wopbs_key.param.carry_modulus.0 as u64;
            let delta = (1u64 << 63) / (carry_modulus * message_modulus);
            // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
            let delta_log = DeltaLog(delta.ilog2() as usize);
            let nb_bit_to_extract = f64::log2((block.degree.0 + 1) as f64).ceil() as usize;

            let extract_from_bit = bits_extracted_so_far;
            let extract_to_bit = extract_from_bit + nb_bit_to_extract;
            bits_extracted_so_far += nb_bit_to_extract;

            let mut lwe_sub_list =
                extracted_bits_blocks.get_sub_mut(extract_from_bit..extract_to_bit);

            self.wopbs_key.extract_bits_assign(
                delta_log,
                block,
                nb_bit_to_extract,
                &mut lwe_sub_list,
            );
        }

        let vec_ct_out = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);

        let mut ct_vec_out = vec![];
        for (block, block_out) in ct_in.blocks().iter().zip(vec_ct_out.into_iter()) {
            ct_vec_out.push(crate::shortint::Ciphertext {
                ct: block_out,
                degree: Degree(block.message_modulus.0 - 1),
                message_modulus: block.message_modulus,
                carry_modulus: block.carry_modulus,
                pbs_order: block.pbs_order,
            });
        }
        T::from_blocks(ct_vec_out)
    }

    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::WopbsKey;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear = 15 % moduli;
    /// let ct = cks.encrypt_radix_without_padding(clear as u64, nb_block);
    /// let lut = wopbs_key.generate_lut_radix_without_padding(&ct, |x| 2 * x);
    /// let ct_res = wopbs_key.wopbs_without_padding(&ct, &lut);
    /// let res: u64 = cks.decrypt_radix_without_padding(&ct_res);
    ///
    /// assert_eq!(res, (clear * 2) % moduli)
    /// ```
    pub fn wopbs_without_padding<T>(&self, ct_in: &T, lut: &IntegerWopbsLUT) -> T
    where
        T: IntegerCiphertext,
    {
        let total_bits_extracted = ct_in.blocks().iter().fold(0usize, |acc, block| {
            acc + f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64) as usize
        });

        let extract_bits_output_lwe_size = self
            .wopbs_key
            .wopbs_server_key
            .key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size();

        let mut extracted_bits_blocks = LweCiphertextList::new(
            0u64,
            extract_bits_output_lwe_size,
            LweCiphertextCount(total_bits_extracted),
            self.wopbs_key.param.ciphertext_modulus,
        );

        let mut bits_extracted_so_far = 0;
        // Extraction of each bit for each block
        for block in ct_in.blocks().iter().rev() {
            let block_modulus = block.message_modulus.0 as u64 * block.carry_modulus.0 as u64;
            let delta = (1_u64 << 63) / (block_modulus / 2);
            // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
            let delta_log = DeltaLog(delta.ilog2() as usize);
            let nb_bit_to_extract =
                f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64) as usize;

            let extract_from_bit = bits_extracted_so_far;
            let extract_to_bit = extract_from_bit + nb_bit_to_extract;
            bits_extracted_so_far += nb_bit_to_extract;

            let mut lwe_sub_list =
                extracted_bits_blocks.get_sub_mut(extract_from_bit..extract_to_bit);

            self.wopbs_key.extract_bits_assign(
                delta_log,
                block,
                nb_bit_to_extract,
                &mut lwe_sub_list,
            );
        }

        let vec_ct_out = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);

        let mut ct_vec_out = vec![];
        for (block, block_out) in ct_in.blocks().iter().zip(vec_ct_out.into_iter()) {
            ct_vec_out.push(crate::shortint::Ciphertext {
                ct: block_out,
                degree: Degree(block.message_modulus.0 - 1),
                message_modulus: block.message_modulus,
                carry_modulus: block.carry_modulus,
                pbs_order: block.pbs_order,
            });
        }
        T::from_blocks(ct_vec_out)
    }

    /// WOPBS for native CRT
    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::parameters::PARAM_4_BITS_5_BLOCKS;
    /// use tfhe::integer::wopbs::WopbsKey;
    ///
    /// let basis: Vec<u64> = vec![9, 11];
    ///
    /// let param = PARAM_4_BITS_5_BLOCKS;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(param);
    /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear = 42 % msg_space; // Encrypt the integers
    /// let mut ct = cks.encrypt_native_crt(clear, basis.clone());
    /// let lut = wopbs_key.generate_lut_native_crt(&ct, |x| x);
    /// let ct_res = wopbs_key.wopbs_native_crt(&mut ct, &lut);
    /// let res = cks.decrypt_native_crt(&ct_res);
    /// assert_eq!(res, clear);
    /// ```
    pub fn wopbs_native_crt(&self, ct1: &CrtCiphertext, lut: &IntegerWopbsLUT) -> CrtCiphertext {
        self.circuit_bootstrap_vertical_packing_native_crt(&[ct1.clone()], lut)
    }

    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// //Generate wopbs_v0 key    ///
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear1 = 42 % moduli;
    /// let clear2 = 24 % moduli;
    /// let ct1 = cks.encrypt_radix(clear1 as u64, nb_block);
    /// let ct2 = cks.encrypt_radix(clear2 as u64, nb_block);
    ///
    /// let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
    /// let ct2 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct2);
    /// let lut = wopbs_key.generate_lut_bivariate_radix(&ct1, &ct2, |x, y| 2 * x * y);
    /// let ct_res = wopbs_key.bivariate_wopbs_with_degree(&ct1, &ct2, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert_eq!(res, (2 * clear1 * clear2) % moduli);
    /// ```
    pub fn bivariate_wopbs_with_degree<T>(&self, ct1: &T, ct2: &T, lut: &IntegerWopbsLUT) -> T
    where
        T: IntegerCiphertext,
    {
        let ct = ciphertext_concatenation(ct1, ct2);
        self.wopbs(&ct, lut)
    }

    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// //Generate wopbs_v0 key    ///
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear = 42 % moduli;
    /// let ct = cks.encrypt_radix(clear as u64, nb_block);
    /// let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    /// let lut = wopbs_key.generate_lut_radix(&ct, |x| 2 * x);
    /// let ct_res = wopbs_key.wopbs(&ct, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert_eq!(res, (2 * clear) % moduli);
    /// ```
    pub fn generate_lut_radix<F, T>(&self, ct: &T, f: F) -> IntegerWopbsLUT
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let mut total_bit = 0;
        let block_nb = ct.blocks().len();
        let mut modulus = 1;

        //This contains the basis of each block depending on the degree
        let mut vec_deg_basis = vec![];

        for (i, deg) in ct.moduli().iter().zip(ct.blocks().iter()) {
            modulus *= i;
            let b = f64::log2((deg.degree.0 + 1) as f64).ceil() as u64;
            vec_deg_basis.push(b);
            total_bit += b;
        }

        let mut lut_size = 1 << total_bit;
        if 1 << total_bit < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut =
            IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(ct.blocks().len()));

        let basis = ct.moduli()[0];
        let delta: u64 = (1 << 63)
            / (self.wopbs_key.param.message_modulus.0 * self.wopbs_key.param.carry_modulus.0)
                as u64;

        for lut_index_val in 0..(1 << total_bit) {
            let encoded_with_deg_val = encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
            let decoded_val = decode_radix(encoded_with_deg_val.clone(), basis);
            let f_val = f(decoded_val % modulus) % modulus;
            let encoded_f_val = encode_radix(f_val, basis, block_nb as u64);
            for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
                lut.as_mut().get_small_lut_mut(lut_number).as_mut()[lut_index_val as usize] =
                    radix_encoded_val * delta;
            }
        }
        lut
    }

    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::WopbsKey;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// //Generate wopbs_v0 key
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear = 15 % moduli;
    /// let ct = cks.encrypt_radix_without_padding(clear as u64, nb_block);
    /// let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    /// let lut = wopbs_key.generate_lut_radix_without_padding(&ct, |x| 2 * x);
    /// let ct_res = wopbs_key.wopbs_without_padding(&ct, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res: u64 = cks.decrypt_radix_without_padding(&ct_res);
    ///
    /// assert_eq!(res, (clear * 2) % moduli)
    /// ```
    pub fn generate_lut_radix_without_padding<F, T>(&self, ct: &T, f: F) -> IntegerWopbsLUT
    where
        F: Fn(u64) -> u64,
        T: IntegerCiphertext,
    {
        let log_message_modulus = f64::log2((self.wopbs_key.param.message_modulus.0) as f64) as u64;
        let log_carry_modulus = f64::log2((self.wopbs_key.param.carry_modulus.0) as f64) as u64;
        let log_basis = log_message_modulus + log_carry_modulus;
        let delta = 64 - log_basis;
        let nb_block = ct.blocks().len();
        let poly_size = self.wopbs_key.param.polynomial_size.0;
        let mut lut_size = 1 << (nb_block * log_basis as usize);
        if lut_size < poly_size {
            lut_size = poly_size;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(nb_block));

        for index in 0..lut_size {
            // find the value represented by the index
            let mut value = 0;
            let mut tmp_index = index;
            for i in 0..nb_block as u64 {
                let tmp = tmp_index % (1 << (log_basis * (i + 1)));
                tmp_index -= tmp;
                value += tmp >> (log_carry_modulus * i);
            }

            // fill the LUTs
            for block_index in 0..nb_block {
                let mut lut_block = lut.as_mut().get_small_lut_mut(block_index);
                lut_block.as_mut()[index] = ((f(value as u64)
                    >> (log_carry_modulus * block_index as u64))
                    % (1 << log_message_modulus))
                    << delta
            }
        }
        lut
    }

    /// generate lut for native CRT
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::parameters::PARAM_4_BITS_5_BLOCKS;
    /// use tfhe::integer::wopbs::WopbsKey;
    ///
    /// let basis: Vec<u64> = vec![9, 11];
    ///
    /// let param = PARAM_4_BITS_5_BLOCKS;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(param);
    /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear = 42 % msg_space; // Encrypt the integers
    /// let mut ct = cks.encrypt_native_crt(clear, basis.clone());
    /// let lut = wopbs_key.generate_lut_native_crt(&ct, |x| x);
    /// let ct_res = wopbs_key.wopbs_native_crt(&mut ct, &lut);
    /// let res = cks.decrypt_native_crt(&ct_res);
    /// assert_eq!(res, clear);
    /// ```
    pub fn generate_lut_native_crt<F>(&self, ct: &CrtCiphertext, f: F) -> IntegerWopbsLUT
    where
        F: Fn(u64) -> u64,
    {
        let mut bit = vec![];
        let mut total_bit = 0;
        let mut modulus = 1;
        let basis: Vec<_> = ct.moduli();

        for i in basis.iter() {
            modulus *= i;
            let b = f64::log2(*i as f64).ceil() as u64;
            total_bit += b;
            bit.push(b);
        }
        let mut lut_size = 1 << total_bit;
        if 1 << total_bit < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(basis.len()));

        for value in 0..modulus {
            let mut index_lut = 0;
            let mut tmp = 1;
            for (base, bit) in basis.iter().zip(bit.iter()) {
                index_lut += (((value % base) << bit) / base) * tmp;
                tmp <<= bit;
            }
            for (j, b) in basis.iter().enumerate() {
                lut.as_mut().get_small_lut_mut(j).as_mut()[index_lut as usize] =
                    (((f(value) % b) as u128 * (1 << 64)) / *b as u128) as u64
            }
        }
        lut
    }

    /// generate LUt for crt
    /// # Example
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// let basis: Vec<u64> = vec![5, 7];
    /// let nb_block = basis.len();
    ///
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_3_CARRY_3_KS_PBS);
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear = 42 % msg_space;
    /// let ct = cks.encrypt_crt(clear, basis.clone());
    /// let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    /// let lut = wopbs_key.generate_lut_crt(&ct, |x| x);
    /// let ct_res = wopbs_key.wopbs(&ct, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res = cks.decrypt_crt(&ct_res);
    /// assert_eq!(res, clear);
    /// ```
    pub fn generate_lut_crt<F>(&self, ct: &CrtCiphertext, f: F) -> IntegerWopbsLUT
    where
        F: Fn(u64) -> u64,
    {
        let mut bit = vec![];
        let mut total_bit = 0;
        let mut modulus = 1;
        let basis = ct.moduli();

        for (i, deg) in basis.iter().zip(ct.blocks.iter()) {
            modulus *= i;
            let b = f64::log2((deg.degree.0 + 1) as f64).ceil() as u64;
            total_bit += b;
            bit.push(b);
        }
        let mut lut_size = 1 << total_bit;
        if 1 << total_bit < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(basis.len()));

        for i in 0..(1 << total_bit) {
            let mut value = i;
            for (j, block) in ct.blocks.iter().enumerate() {
                let deg = f64::log2((block.degree.0 + 1) as f64).ceil() as u64;
                let delta: u64 = (1 << 63)
                    / (self.wopbs_key.param.message_modulus.0
                        * self.wopbs_key.param.carry_modulus.0) as u64;
                lut.as_mut().get_small_lut_mut(j).as_mut()[i as usize] =
                    ((f((value % (1 << deg)) % block.message_modulus.0 as u64))
                        % block.message_modulus.0 as u64)
                        * delta;
                value >>= deg;
            }
        }
        lut
    }

    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let nb_block = 3;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// //Generate wopbs_v0 key    ///
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let mut moduli = 1_u64;
    /// for _ in 0..nb_block {
    ///     moduli *= cks.parameters().message_modulus().0 as u64;
    /// }
    /// let clear1 = 42 % moduli;
    /// let clear2 = 24 % moduli;
    /// let ct1 = cks.encrypt_radix(clear1 as u64, nb_block);
    /// let ct2 = cks.encrypt_radix(clear2 as u64, nb_block);
    ///
    /// let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
    /// let ct2 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct2);
    /// let lut = wopbs_key.generate_lut_bivariate_radix(&ct1, &ct2, |x, y| 2 * x * y);
    /// let ct_res = wopbs_key.bivariate_wopbs_with_degree(&ct1, &ct2, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res: u64 = cks.decrypt_radix(&ct_res);
    ///
    /// assert_eq!(res, (2 * clear1 * clear2) % moduli);
    /// ```
    pub fn generate_lut_bivariate_radix<F>(
        &self,
        ct1: &RadixCiphertext,
        ct2: &RadixCiphertext,
        f: F,
    ) -> IntegerWopbsLUT
    where
        RadixCiphertext: IntegerCiphertext,
        F: Fn(u64, u64) -> u64,
    {
        let mut nb_bit_to_extract = vec![0; 2];
        let block_nb = ct1.blocks.len();
        //ct2 & ct1 should have the same basis
        let basis = ct1.moduli();

        //This contains the basis of each block depending on the degree
        let mut vec_deg_basis = vec![vec![]; 2];

        let mut modulus = 1;
        for (ct_num, ct) in [ct1, ct2].iter().enumerate() {
            modulus = 1;
            for deg in ct.blocks.iter() {
                modulus *= self.wopbs_key.param.message_modulus.0 as u64;
                let b = f64::log2((deg.degree.0 + 1) as f64).ceil() as u64;
                vec_deg_basis[ct_num].push(b);
                nb_bit_to_extract[ct_num] += b;
            }
        }

        let total_bit: u64 = nb_bit_to_extract.iter().sum();

        let mut lut_size = 1 << total_bit;
        if 1 << total_bit < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(basis.len()));
        let basis = ct1.moduli()[0];

        let delta: u64 = (1 << 63)
            / (self.wopbs_key.param.message_modulus.0 * self.wopbs_key.param.carry_modulus.0)
                as u64;

        for lut_index_val in 0..(1 << total_bit) {
            let split = vec![
                lut_index_val % (1 << nb_bit_to_extract[0]),
                lut_index_val >> nb_bit_to_extract[0],
            ];
            let mut decoded_val = vec![0; 2];
            for i in 0..2 {
                let encoded_with_deg_val = encode_mix_radix(split[i], &vec_deg_basis[i], basis);
                decoded_val[i] = decode_radix(encoded_with_deg_val.clone(), basis);
            }
            let f_val = f(decoded_val[0] % modulus, decoded_val[1] % modulus) % modulus;
            let encoded_f_val = encode_radix(f_val, basis, block_nb as u64);
            for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
                lut.as_mut().get_small_lut_mut(lut_number).as_mut()[lut_index_val as usize] =
                    radix_encoded_val * delta;
            }
        }
        lut
    }

    /// generate bivariate LUT for 'fake' CRT
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::wopbs::*;
    /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3_KS_PBS;
    ///
    /// let basis: Vec<u64> = vec![5, 7];
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_3_CARRY_3_KS_PBS);
    /// let wopbs_key = WopbsKey::new_wopbs_key(&cks, &sks, &WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear1 = 42 % msg_space; // Encrypt the integers
    /// let clear2 = 24 % msg_space; // Encrypt the integers
    /// let ct1 = cks.encrypt_crt(clear1, basis.clone());
    /// let ct2 = cks.encrypt_crt(clear2, basis.clone());
    ///
    /// let ct1 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct1);
    /// let ct2 = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct2);
    ///
    /// let lut = wopbs_key.generate_lut_bivariate_crt(&ct1, &ct2, |x, y| x * y * 2);
    /// let ct_res = wopbs_key.bivariate_wopbs_with_degree(&ct1, &ct2, &lut);
    /// let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    /// let res = cks.decrypt_crt(&ct_res);
    /// assert_eq!(res, (clear1 * clear2 * 2) % msg_space);
    /// ```
    pub fn generate_lut_bivariate_crt<F>(
        &self,
        ct1: &CrtCiphertext,
        ct2: &CrtCiphertext,
        f: F,
    ) -> IntegerWopbsLUT
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut bit = vec![];
        let mut nb_bit_to_extract = vec![0; 2];
        let mut modulus = 1;

        //ct2 & ct1 should have the same basis
        let basis = ct1.moduli();

        for (ct_num, ct) in [ct1, ct2].iter().enumerate() {
            for (i, deg) in basis.iter().zip(ct.blocks.iter()) {
                modulus *= i;
                let b = f64::log2((deg.degree.0 + 1) as f64).ceil() as u64;
                nb_bit_to_extract[ct_num] += b;
                bit.push(b);
            }
        }

        let total_bit: u64 = nb_bit_to_extract.iter().sum();

        let mut lut_size = 1 << total_bit;
        if 1 << total_bit < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(basis.len()));

        let delta: u64 = (1 << 63)
            / (self.wopbs_key.param.message_modulus.0 * self.wopbs_key.param.carry_modulus.0)
                as u64;

        for index in 0..(1 << total_bit) {
            let mut split = encode_radix(index, 1 << nb_bit_to_extract[0], 2);
            let mut crt_value = vec![vec![0; ct1.blocks.len()]; 2];
            for (j, base) in basis.iter().enumerate().take(ct1.blocks.len()) {
                let deg_1 = f64::log2((ct1.blocks[j].degree.0 + 1) as f64).ceil() as u64;
                let deg_2 = f64::log2((ct2.blocks[j].degree.0 + 1) as f64).ceil() as u64;
                crt_value[0][j] = (split[0] % (1 << deg_1)) % base;
                crt_value[1][j] = (split[1] % (1 << deg_2)) % base;
                split[0] >>= deg_1;
                split[1] >>= deg_2;
            }
            let value_1 = i_crt(&ct1.moduli(), &crt_value[0]);
            let value_2 = i_crt(&ct2.moduli(), &crt_value[1]);
            for (j, current_mod) in basis.iter().enumerate() {
                let value = f(value_1, value_2) % current_mod;
                lut.as_mut().get_small_lut_mut(j).as_mut()[index as usize] =
                    (value % current_mod) * delta;
            }
        }

        lut
    }

    /// generate bivariate LUT for 'true' CRT
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::parameters::PARAM_4_BITS_5_BLOCKS;
    /// use tfhe::integer::wopbs::WopbsKey;
    ///
    /// let basis: Vec<u64> = vec![9, 11];
    ///
    /// let param = PARAM_4_BITS_5_BLOCKS;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(param);
    /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear1 = 42 % msg_space;
    /// let clear2 = 24 % msg_space;
    /// let mut ct1 = cks.encrypt_native_crt(clear1, basis.clone());
    /// let mut ct2 = cks.encrypt_native_crt(clear2, basis.clone());
    /// let lut = wopbs_key.generate_lut_bivariate_native_crt(&ct1, |x, y| x * y * 2);
    /// let ct_res = wopbs_key.bivariate_wopbs_native_crt(&mut ct1, &mut ct2, &lut);
    /// let res = cks.decrypt_native_crt(&ct_res);
    /// assert_eq!(res, (clear1 * clear2 * 2) % msg_space);
    /// ```
    pub fn generate_lut_bivariate_native_crt<F>(
        &self,
        ct_1: &CrtCiphertext,
        f: F,
    ) -> IntegerWopbsLUT
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut bit = vec![];
        let mut total_bit = 0;
        let mut modulus = 1;
        let basis = ct_1.moduli();
        for i in basis.iter() {
            modulus *= i;
            let b = f64::log2(*i as f64).ceil() as u64;
            total_bit += b;
            bit.push(b);
        }
        let mut lut_size = 1 << (2 * total_bit);
        if 1 << (2 * total_bit) < self.wopbs_key.param.polynomial_size.0 as u64 {
            lut_size = self.wopbs_key.param.polynomial_size.0;
        }
        let mut lut = IntegerWopbsLUT::new(PlaintextCount(lut_size), CiphertextCount(basis.len()));

        for value in 0..1 << (2 * total_bit) {
            let value_1 = value % (1 << total_bit);
            let value_2 = value >> total_bit;
            let mut index_lut_1 = 0;
            let mut index_lut_2 = 0;
            let mut tmp = 1;
            for (base, bit) in basis.iter().zip(bit.iter()) {
                index_lut_1 += (((value_1 % base) << bit) / base) * tmp;
                index_lut_2 += (((value_2 % base) << bit) / base) * tmp;
                tmp <<= bit;
            }
            let index = (index_lut_2 << total_bit) + (index_lut_1);
            for (j, b) in basis.iter().enumerate() {
                lut.as_mut().get_small_lut_mut(j).as_mut()[index as usize] =
                    (((f(value_1, value_2) % b) as u128 * (1 << 64)) / *b as u128) as u64
            }
        }
        lut
    }

    /// bivariate WOPBS for native CRT
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::gen_keys;
    /// use tfhe::integer::parameters::PARAM_4_BITS_5_BLOCKS;
    /// use tfhe::integer::wopbs::WopbsKey;
    ///
    /// let basis: Vec<u64> = vec![9, 11];
    ///
    /// let param = PARAM_4_BITS_5_BLOCKS;
    /// //Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(param);
    /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(&cks, &sks);
    ///
    /// let mut msg_space = 1;
    /// for modulus in basis.iter() {
    ///     msg_space *= modulus;
    /// }
    /// let clear1 = 42 % msg_space;
    /// let clear2 = 24 % msg_space;
    /// let mut ct1 = cks.encrypt_native_crt(clear1, basis.clone());
    /// let mut ct2 = cks.encrypt_native_crt(clear2, basis.clone());
    /// let lut = wopbs_key.generate_lut_bivariate_native_crt(&ct1, |x, y| x * y * 2);
    /// let ct_res = wopbs_key.bivariate_wopbs_native_crt(&mut ct1, &mut ct2, &lut);
    /// let res = cks.decrypt_native_crt(&ct_res);
    /// assert_eq!(res, (clear1 * clear2 * 2) % msg_space);
    /// ```
    pub fn bivariate_wopbs_native_crt(
        &self,
        ct1: &CrtCiphertext,
        ct2: &CrtCiphertext,
        lut: &IntegerWopbsLUT,
    ) -> CrtCiphertext {
        self.circuit_bootstrap_vertical_packing_native_crt(&[ct1.clone(), ct2.clone()], lut)
    }

    fn circuit_bootstrap_vertical_packing_native_crt<T>(
        &self,
        vec_ct_in: &[T],
        lut: &IntegerWopbsLUT,
    ) -> T
    where
        T: IntegerCiphertext,
    {
        let total_bits_extracted = vec_ct_in.iter().fold(0usize, |acc, ct_in| {
            acc + ct_in.blocks().iter().fold(0usize, |inner_acc, block| {
                inner_acc
                    + f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64).ceil()
                        as usize
            })
        });

        let extract_bits_output_lwe_size = self
            .wopbs_key
            .wopbs_server_key
            .key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size();

        let mut extracted_bits_blocks = LweCiphertextList::new(
            0u64,
            extract_bits_output_lwe_size,
            LweCiphertextCount(total_bits_extracted),
            self.wopbs_key.param.ciphertext_modulus,
        );

        let mut bits_extracted_so_far = 0;
        for ct_in in vec_ct_in.iter().rev() {
            let mut ct_in = ct_in.clone();
            // Extraction of each bit for each block
            for block in ct_in.blocks_mut().iter_mut().rev() {
                let nb_bit_to_extract =
                    f64::log2((block.message_modulus.0 * block.carry_modulus.0) as f64).ceil()
                        as usize;
                let delta_log = DeltaLog(64 - nb_bit_to_extract);

                // trick ( ct - delta/2 + delta/2^4  )
                lwe_ciphertext_plaintext_sub_assign(
                    &mut block.ct,
                    Plaintext(
                        (1 << (64 - nb_bit_to_extract - 1)) - (1 << (64 - nb_bit_to_extract - 5)),
                    ),
                );

                let extract_from_bit = bits_extracted_so_far;
                let extract_to_bit = extract_from_bit + nb_bit_to_extract;
                bits_extracted_so_far += nb_bit_to_extract;

                let mut lwe_sub_list =
                    extracted_bits_blocks.get_sub_mut(extract_from_bit..extract_to_bit);

                self.wopbs_key.extract_bits_assign(
                    delta_log,
                    block,
                    nb_bit_to_extract,
                    &mut lwe_sub_list,
                );
            }
        }

        let vec_ct_out = self
            .wopbs_key
            .circuit_bootstrapping_vertical_packing(lut.as_ref(), &extracted_bits_blocks);

        let mut ct_vec_out = Vec::with_capacity(vec_ct_in.len());
        for (block, block_out) in vec_ct_in[0].blocks().iter().zip(vec_ct_out.into_iter()) {
            ct_vec_out.push(crate::shortint::Ciphertext {
                ct: block_out,
                degree: Degree(block.message_modulus.0 - 1),
                message_modulus: block.message_modulus,
                carry_modulus: block.carry_modulus,
                pbs_order: block.pbs_order,
            });
        }
        T::from_blocks(ct_vec_out)
    }

    pub fn keyswitch_to_wopbs_params<'a, T>(&self, sks: &ServerKey, ct_in: &'a T) -> T
    where
        T: IntegerCiphertext,
        &'a [crate::shortint::Ciphertext]:
            IntoParallelIterator<Item = &'a crate::shortint::Ciphertext>,
    {
        let blocks: Vec<_> = ct_in
            .blocks()
            .par_iter()
            .map(|block| self.wopbs_key.keyswitch_to_wopbs_params(&sks.key, block))
            .collect();
        T::from_blocks(blocks)
    }

    pub fn keyswitch_to_pbs_params<'a, T>(&self, ct_in: &'a T) -> T
    where
        T: IntegerCiphertext,
        &'a [crate::shortint::Ciphertext]:
            IntoParallelIterator<Item = &'a crate::shortint::Ciphertext>,
    {
        let blocks: Vec<_> = ct_in
            .blocks()
            .par_iter()
            .map(|block| self.wopbs_key.keyswitch_to_pbs_params(block))
            .collect();
        T::from_blocks(blocks)
    }
}
