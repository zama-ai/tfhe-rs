use crate::server_key::Ciphertext;
use crate::ServerKey;
use shortint::ciphertext::{Ciphertext as ShortintCiphertext, Degree};

use std::cmp::{max, min};
use tfhe::core_crypto::algorithms::{
    cmux_assign, extract_lwe_sample_from_glwe_ciphertext, keyswitch_lwe_ciphertext,
    par_keyswitch_lwe_ciphertext,
};

use aligned_vec::ABox;
use dyn_stack::{GlobalPodBuffer, PodStack, ReborrowMut, StackReq};
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::fft_impl::fft64::crypto::ggsw::fill_with_forward_fourier_scratch;
use tfhe::core_crypto::fft_impl::fft64::crypto::wop_pbs::{
    circuit_bootstrap_boolean, circuit_bootstrap_boolean_parallelized,
    circuit_bootstrap_boolean_scratch, extract_bits, extract_bits_parallelized,
    extract_bits_scratch,
};
use tfhe::core_crypto::fft_impl::fft64::math::fft::par_convert_polynomials_list_to_fourier;
use tfhe::core_crypto::prelude::{ContiguousEntityContainer, Fft};
use tfhe::shortint;
use tfhe::shortint::ciphertext::NoiseLevel;

use rayon::prelude::*;

impl ServerKey {
    pub fn ggsw_pbs_ks_cbs(
        &self,
        ct1: &ShortintCiphertext,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        let accumulator = self.key.generate_lookup_table(|x| min(1, x) as u64);
        let res = self.key.apply_lookup_table(&ct1, &accumulator);
        self.ggsw_ks_cbs(&res, message_space)
    }

    /// return ggsw(0) if ct1 = 0, return ggsw(1) otherwise
    pub fn ggsw_ks_cbs(
        &self,
        ct1: &ShortintCiphertext,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        let ciphertext_modulus = ct1.ct.ciphertext_modulus();

        let mut res_ks = LweCiphertext::new(
            0u64,
            LweSize(self.wopbs_key.param.lwe_dimension.to_lwe_size().0),
            ciphertext_modulus,
        );
        keyswitch_lwe_ciphertext(&self.key.key_switching_key, &ct1.ct, &mut res_ks);
        self.ggsw_cbs(&res_ks.as_view(), message_space)
    }

    /// return ggsw(0) if ct1 = 0, return ggsw(1) otherwise
    pub fn ggsw_cbs(
        &self,
        ct: &LweCiphertext<&[u64]>,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        let glwe_dimension = self.wopbs_key.param.glwe_dimension;
        let polynomial_size = self.wopbs_key.param.polynomial_size;
        let base_log_cbs = self.wopbs_key.param.cbs_base_log;
        let level_count_cbs = self.wopbs_key.param.cbs_level;
        let ciphertext_modulus = ct.ciphertext_modulus();

        let fourier_bsk = match &self.wopbs_key.wopbs_server_key.bootstrapping_key {
            shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk.as_view(),
            _ => unreachable!(),
        };
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let mut cbs_res = GgswCiphertext::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            base_log_cbs,
            level_count_cbs,
            ciphertext_modulus,
        );
        let mut ggsw = FourierGgswCiphertext::new(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            base_log_cbs,
            level_count_cbs,
        );

        let mut mem = GlobalPodBuffer::new(
            circuit_bootstrap_boolean_scratch::<u64>(
                ct.lwe_size(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        );
        let mut stack = PodStack::new(&mut mem);
        circuit_bootstrap_boolean(
            fourier_bsk,
            ct.as_view(),
            cbs_res.as_mut_view(),
            DeltaLog(63 - message_space),
            self.wopbs_key.cbs_pfpksk.as_view(),
            fft,
            stack.rb_mut(),
        );

        let mut mem = GlobalPodBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
        let mut stack = PodStack::new(&mut mem);
        ggsw.as_mut_view()
            .fill_with_forward_fourier(cbs_res.as_view(), fft, stack.rb_mut());
        ggsw
    }

    pub fn extract_bit_cbs(
        &self,
        ct1: &ShortintCiphertext,
    ) -> Vec<FourierGgswCiphertext<ABox<[c64]>>> {
        let glwe_dimension = self.wopbs_key.param.glwe_dimension;
        let polynomial_size = self.wopbs_key.param.polynomial_size;
        let lwe_dimension = self.wopbs_key.param.lwe_dimension;
        let message_modulus = self.wopbs_key.param.message_modulus;
        let log_message_modulus = f64::log2(message_modulus.0 as f64) as usize;
        let log_carry_modulus = f64::log2(self.wopbs_key.param.carry_modulus.0 as f64) as usize;
        let ciphertext_modulus = ct1.ct.ciphertext_modulus();

        let ksk = &self.key.key_switching_key;
        let delta_log = 63 - log_message_modulus * log_carry_modulus;
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let req = || {
            StackReq::try_any_of([
                fill_with_forward_fourier_scratch(fft)?,
                extract_bits_scratch::<u64>(
                    lwe_dimension,
                    LweDimension(polynomial_size.0 * glwe_dimension.0 + 1),
                    glwe_dimension.to_glwe_size(),
                    polynomial_size,
                    fft,
                )?,
            ])
        };
        let req = req().unwrap();
        let mut mem = GlobalPodBuffer::new(req);
        let stack = PodStack::new(&mut mem);
        let fourier_bsk = match &self.wopbs_key.wopbs_server_key.bootstrapping_key {
            shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk.as_view(),
            _ => unreachable!(),
        };
        let mut lwe_out_list = LweCiphertextList::new(
            0u64,
            ksk.output_lwe_size(),
            LweCiphertextCount(log_message_modulus),
            ciphertext_modulus,
        );
        extract_bits(
            lwe_out_list.as_mut_view(),
            ct1.ct.as_view(),
            ksk.as_view(),
            fourier_bsk,
            DeltaLog(delta_log),
            ExtractedBitsCount(log_message_modulus),
            fft,
            stack,
        );
        let mut out_vec_ggsw: Vec<FourierGgswCiphertext<ABox<[c64]>>> = Vec::new();
        for lwe in lwe_out_list.iter() {
            let ggsw = self.ggsw_cbs_parallelized(&lwe, 0);
            out_vec_ggsw.append(&mut vec![ggsw]);
        }
        out_vec_ggsw
    }

    //return ct0 if we have ggsw(0)
    //return ct1 if we have ggsw(1)
    //with cti a ShortintCiphertext
    pub fn cmux(
        &self,
        ct0: &ShortintCiphertext,
        ct1: &ShortintCiphertext,
        ggsw: &FourierGgswCiphertext<ABox<[c64]>>,
    ) -> ShortintCiphertext {
        let polynomial_size = self.wopbs_key.param.polynomial_size;
        let glwe_dim = self.wopbs_key.param.glwe_dimension;
        let mut vec_0 = vec![0u64; polynomial_size.0 * (glwe_dim.0 + 1)];
        let mut vec_1 = vec![0u64; polynomial_size.0 * (glwe_dim.0 + 1)];
        for (i, (ct_i_0, ct_i_1)) in ct0
            .ct
            .as_ref()
            .iter()
            .zip(ct1.ct.as_ref().iter())
            .enumerate()
        {
            if i % polynomial_size.0 == 0 {
                vec_0[i] = *ct_i_0;
                vec_1[i] = *ct_i_1;
            } else {
                let index =
                    (i / polynomial_size.0 + 1) * polynomial_size.0 - (i % polynomial_size.0);
                vec_0[index] = 0 - (*ct_i_0);
                vec_1[index] = 0 - (*ct_i_1);
            }
        }
        let mut rlwe_0 =
            GlweCiphertext::from_container(vec_0, polynomial_size, self.key.ciphertext_modulus);
        let mut rlwe_1 =
            GlweCiphertext::from_container(vec_1, polynomial_size, self.key.ciphertext_modulus);

        cmux_assign(&mut rlwe_0, &mut rlwe_1, ggsw);

        let mut output = LweCiphertext::new(
            0_u64,
            LweSize(polynomial_size.0 * glwe_dim.0 + 1),
            self.key.ciphertext_modulus,
        );
        extract_lwe_sample_from_glwe_ciphertext(&rlwe_0, &mut output, MonomialDegree(0));
        let ct_out = shortint::Ciphertext::new(
            output,
            Degree::new(max(ct0.degree.get(), ct1.degree.get())),
            NoiseLevel::NOMINAL, // TODO: check this is valid in the context of floats
            ct0.message_modulus,
            ct0.carry_modulus,
            PBSOrder::KeyswitchBootstrap,
        );
        ct_out
    }

    //return ct0 in ct0 if we have ggsw(0)
    //return ct1 in ct0 if we have ggsw(1)
    //with cti = [Ciphertext]
    pub fn cmuxes(
        &self,
        ct0: &[ShortintCiphertext],
        ct1: &[ShortintCiphertext],
        ggsw: &FourierGgswCiphertext<ABox<[c64]>>,
    ) -> Vec<shortint::Ciphertext> {
        let mut vec_output: Vec<ShortintCiphertext> = Vec::new();
        for (ct_0, ct_1) in ct0.iter().zip(ct1.iter()) {
            let output = self.cmux(ct_0, ct_1, ggsw);
            vec_output.push(output);
        }
        vec_output
    }

    //return ct0 in a nwe ct if we have ggsw(0)
    //return ct1 in a new ct if we have ggsw(1)
    //with cti a fp
    pub fn cmuxes_full(
        &self,
        ct0: &Ciphertext,
        ct1: &Ciphertext,
        ggsw: &FourierGgswCiphertext<ABox<[c64]>>,
    ) -> Ciphertext {
        let res_man = self.cmuxes(&ct0.ct_vec_mantissa, &ct1.ct_vec_mantissa, &ggsw);
        let res_exp = self.cmuxes(&ct0.ct_vec_exponent, &ct1.ct_vec_exponent, &ggsw);
        let res_sig = self.cmux(&ct0.ct_sign, &ct1.ct_sign, &ggsw);
        let mut new = self.create_trivial_zero_from_ct(ct0);
        new.ct_vec_mantissa = res_man;
        new.ct_vec_exponent = res_exp;
        new.ct_sign = res_sig;
        new
    }

    pub fn cmux_tree_mantissa(
        &self,
        vec_mantissa: &Vec<shortint::Ciphertext>,
        vec_ggsw: &[FourierGgswCiphertext<ABox<[c64]>>],
    ) -> Vec<shortint::Ciphertext> {
        let zero = self.key.create_trivial(0_u64);
        let mut cpy = vec_mantissa.clone();
        let mut vec_fp = Vec::new();
        for _ in 0..(vec_mantissa.len() + 1) {
            vec_fp.push(cpy.clone());
            cpy.push(zero.clone());
            let _ = cpy.remove(0);
        }
        let vec_zero = cpy;
        for ggsw in vec_ggsw.iter().rev() {
            if vec_fp.len() == 1 {
                vec_fp[0] = self.cmuxes(&mut vec_fp[0], &vec_zero, ggsw);
            } else {
                if vec_fp.len() % 2 == 0 {
                    for i in 0..vec_fp.len() / 2 {
                        let ct_0 = vec_fp.get_mut(2 * i).unwrap().clone();
                        let ct_1 = vec_fp.get_mut(2 * i + 1).unwrap().clone();
                        vec_fp[i] = self.cmuxes(&ct_0, &ct_1, ggsw);
                    }
                    vec_fp.truncate(vec_fp.len() / 2);
                } else {
                    for i in 0..vec_fp.len() / 2 {
                        let ct_0 = vec_fp.get_mut(2 * i).unwrap().clone();
                        let ct_1 = vec_fp.get_mut(2 * i + 1).unwrap().clone();
                        vec_fp[i] = self.cmuxes(&ct_0, &ct_1, ggsw);
                    }
                    let last = vec_fp.len();
                    let ct_0 = vec_fp.last().unwrap().clone();
                    let ct_1 = &vec_zero;
                    vec_fp[last / 2] = self.cmuxes(&ct_0, &ct_1, ggsw);
                    vec_fp.truncate((vec_fp.len() + 1) / 2);
                }
            }
        }
        vec_fp[0].clone()
    }

    pub fn is_block_non_zero_ggsw_pbs_ks_cbs_parallelized(
        &self,
        ct1: &ShortintCiphertext,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        let accumulator = self.key.generate_lookup_table(|x| u64::from(x != 0));
        let res = self.key.apply_lookup_table(&ct1, &accumulator);
        self.ggsw_ks_cbs_parallelized(&res, message_space)
    }

    /// return ggsw(0) if ct1 = 0, return ggsw(1) otherwise
    pub fn ggsw_ks_cbs_parallelized(
        &self,
        ct1: &ShortintCiphertext,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        let ciphertext_modulus = ct1.ct.ciphertext_modulus();

        let mut res_ks = LweCiphertext::new(
            0u64,
            LweSize(self.wopbs_key.param.lwe_dimension.to_lwe_size().0),
            ciphertext_modulus,
        );
        par_keyswitch_lwe_ciphertext(&self.key.key_switching_key, &ct1.ct, &mut res_ks);
        self.ggsw_cbs_parallelized(&res_ks.as_view(), message_space)
    }

    /// return ggsw(0) if ct1 = 0, return ggsw(1) otherwise
    pub fn ggsw_cbs_parallelized(
        &self,
        ct: &LweCiphertext<&[u64]>,
        message_space: usize,
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
        // todo!("ggsw_cbs_parallelized");
        let glwe_dimension = self.wopbs_key.param.glwe_dimension;
        let polynomial_size = self.wopbs_key.param.polynomial_size;
        let base_log_cbs = self.wopbs_key.param.cbs_base_log;
        let level_count_cbs = self.wopbs_key.param.cbs_level;
        let ciphertext_modulus = ct.ciphertext_modulus();

        let fourier_bsk = match &self.wopbs_key.wopbs_server_key.bootstrapping_key {
            shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk.as_view(),
            _ => unreachable!(),
        };
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let mut cbs_res = GgswCiphertext::new(
            0u64,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            base_log_cbs,
            level_count_cbs,
            ciphertext_modulus,
        );
        let mut ggsw = FourierGgswCiphertext::new(
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            base_log_cbs,
            level_count_cbs,
        );

        let mut mem = GlobalPodBuffer::new(
            circuit_bootstrap_boolean_scratch::<u64>(
                ct.lwe_size(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                fft,
            )
            .unwrap(),
        );
        let mut stack = PodStack::new(&mut mem);
        circuit_bootstrap_boolean_parallelized(
            fourier_bsk,
            ct.as_view(),
            cbs_res.as_mut_view(),
            DeltaLog(63 - message_space),
            self.wopbs_key.cbs_pfpksk.as_view(),
            fft,
            stack.rb_mut(),
        );

        let mut mem = GlobalPodBuffer::new(fill_with_forward_fourier_scratch(fft).unwrap());
        let mut _stack = PodStack::new(&mut mem);

        par_convert_polynomials_list_to_fourier(
            ggsw.as_mut_view().data(),
            cbs_res.as_ref(),
            polynomial_size,
            fft,
        );
        // ggsw.as_mut_view()
        //     .fill_with_forward_fourier(cbs_res.as_view(), fft, stack.rb_mut());
        ggsw
    }

    pub fn extract_bit_cbs_parallelized(
        &self,
        ct1: &ShortintCiphertext,
    ) -> Vec<FourierGgswCiphertext<ABox<[c64]>>> {
        // todo!("extract_bit_cbs_parallelized");
        let glwe_dimension = self.wopbs_key.param.glwe_dimension;
        let polynomial_size = self.wopbs_key.param.polynomial_size;
        let lwe_dimension = self.wopbs_key.param.lwe_dimension;
        let message_modulus = self.wopbs_key.param.message_modulus;
        let log_message_modulus = f64::log2(message_modulus.0 as f64) as usize;
        let log_carry_modulus = f64::log2(self.wopbs_key.param.carry_modulus.0 as f64) as usize;
        let ciphertext_modulus = ct1.ct.ciphertext_modulus();

        let ksk = &self.key.key_switching_key;
        let delta_log = 63 - log_message_modulus * log_carry_modulus;
        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();
        let req = || {
            StackReq::try_any_of([
                fill_with_forward_fourier_scratch(fft)?,
                extract_bits_scratch::<u64>(
                    lwe_dimension,
                    LweDimension(polynomial_size.0 * glwe_dimension.0 + 1),
                    glwe_dimension.to_glwe_size(),
                    polynomial_size,
                    fft,
                )?,
            ])
        };
        let req = req().unwrap();
        let mut mem = GlobalPodBuffer::new(req);
        let stack = PodStack::new(&mut mem);
        let fourier_bsk = match &self.wopbs_key.wopbs_server_key.bootstrapping_key {
            shortint::server_key::ShortintBootstrappingKey::Classic(fbsk) => fbsk.as_view(),
            _ => unreachable!(),
        };
        let mut lwe_out_list = LweCiphertextList::new(
            0u64,
            ksk.output_lwe_size(),
            LweCiphertextCount(log_message_modulus),
            ciphertext_modulus,
        );
        extract_bits_parallelized(
            lwe_out_list.as_mut_view(),
            ct1.ct.as_view(),
            ksk.as_view(),
            fourier_bsk,
            DeltaLog(delta_log),
            ExtractedBitsCount(log_message_modulus),
            fft,
            stack,
        );
        let mut out_vec_ggsw: Vec<FourierGgswCiphertext<ABox<[c64]>>> = Vec::new();
        for lwe in lwe_out_list.iter() {
            let ggsw = self.ggsw_cbs(&lwe, 0);
            out_vec_ggsw.append(&mut vec![ggsw]);
        }
        out_vec_ggsw
    }

    //return ct0 in ct0 if we have ggsw(0)
    //return ct1 in ct0 if we have ggsw(1)
    //with cti = [Ciphertext]
    pub fn cmuxes_parallelized(
        &self,
        ct0: &[ShortintCiphertext],
        ct1: &[ShortintCiphertext],
        ggsw: &FourierGgswCiphertext<ABox<[c64]>>,
    ) -> Vec<shortint::Ciphertext> {
        assert_eq!(ct0.len(), ct1.len());
        let len = ct0.len();
        let mut vec_output: Vec<ShortintCiphertext> = Vec::with_capacity(len);

        ct0.par_iter()
            .zip(ct1.par_iter())
            .map(|(ct_0_i, ct_1_i)| self.cmux(ct_0_i, ct_1_i, ggsw))
            .collect_into_vec(&mut vec_output);

        vec_output
    }

    //return ct0 in a nwe ct if we have ggsw(0)
    //return ct1 in a new ct if we have ggsw(1)
    //with cti a fp
    pub fn cmuxes_full_parallelized(
        &self,
        ct0: &Ciphertext,
        ct1: &Ciphertext,
        ggsw: &FourierGgswCiphertext<ABox<[c64]>>,
    ) -> Ciphertext {
        // todo!("cmuxes_full_parallelized");
        let (res_man, res_exp) = rayon::join(
            || self.cmuxes_parallelized(&ct0.ct_vec_mantissa, &ct1.ct_vec_mantissa, &ggsw),
            || self.cmuxes_parallelized(&ct0.ct_vec_exponent, &ct1.ct_vec_exponent, &ggsw),
        );
        let res_sig = self.cmux(&ct0.ct_sign, &ct1.ct_sign, &ggsw);
        let mut new = self.create_trivial_zero_from_ct(ct0);
        new.ct_vec_mantissa = res_man;
        new.ct_vec_exponent = res_exp;
        new.ct_sign = res_sig;
        new
    }

    pub fn cmux_tree_mantissa_parallelized(
        &self,
        vec_mantissa: &Vec<shortint::Ciphertext>,
        vec_ggsw: &[FourierGgswCiphertext<ABox<[c64]>>],
    ) -> Vec<shortint::Ciphertext> {
        // todo!("cmux_tree_mantissa_parallelized");
        let zero = self.key.create_trivial(0_u64);
        let mut cpy = vec_mantissa.clone();
        let mut vec_fp = Vec::new();
        for _ in 0..(vec_mantissa.len() + 1) {
            vec_fp.push(cpy.clone());
            cpy.push(zero.clone());
            let _ = cpy.remove(0);
        }
        let vec_zero = cpy;
        // TODO cmux tree in parallel
        for ggsw in vec_ggsw.iter().rev() {
            if vec_fp.len() == 1 {
                vec_fp[0] = self.cmuxes_parallelized(&mut vec_fp[0], &vec_zero, ggsw);
            } else {
                if vec_fp.len() % 2 == 0 {
                    for i in 0..vec_fp.len() / 2 {
                        let ct_0 = vec_fp.get_mut(2 * i).unwrap().clone();
                        let ct_1 = vec_fp.get_mut(2 * i + 1).unwrap().clone();
                        vec_fp[i] = self.cmuxes_parallelized(&ct_0, &ct_1, ggsw);
                    }
                    vec_fp.truncate(vec_fp.len() / 2);
                } else {
                    for i in 0..vec_fp.len() / 2 {
                        let ct_0 = vec_fp.get_mut(2 * i).unwrap().clone();
                        let ct_1 = vec_fp.get_mut(2 * i + 1).unwrap().clone();
                        vec_fp[i] = self.cmuxes_parallelized(&ct_0, &ct_1, ggsw);
                    }
                    let last = vec_fp.len();
                    let ct_0 = vec_fp.last().unwrap().clone();
                    let ct_1 = &vec_zero;
                    vec_fp[last / 2] = self.cmuxes_parallelized(&ct_0, &ct_1, ggsw);
                    vec_fp.truncate((vec_fp.len() + 1) / 2);
                }
            }
        }
        vec_fp[0].clone()
    }
}
