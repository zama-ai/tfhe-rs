//! # WARNING: this module is experimental.
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::math::fft::Fft;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::server_key::MaxDegree;
use crate::shortint::wopbs::WopbsKey;
use crate::shortint::{CiphertextBase, ClientKey, PBSOrderMarker, Parameters, ServerKey};

impl ShortintEngine {
    // Creates a key when ONLY a wopbs is used.
    pub(crate) fn new_wopbs_key_only_for_wopbs(
        &mut self,
        cks: &ClientKey,
        sks: &ServerKey,
    ) -> EngineResult<WopbsKey> {
        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &cks.large_lwe_secret_key,
            &cks.glwe_secret_key,
            cks.parameters.pfks_base_log,
            cks.parameters.pfks_level,
            cks.parameters.pfks_modular_std_dev,
            &mut self.encryption_generator,
        );

        let sks_cpy = sks.clone();

        let wopbs_key = WopbsKey {
            wopbs_server_key: sks_cpy.clone(),
            cbs_pfpksk,
            ksk_pbs_to_wopbs: sks.key_switching_key.clone(),
            param: cks.parameters,
            pbs_server_key: sks_cpy,
        };
        Ok(wopbs_key)
    }

    //Creates a new WoPBS key.
    pub(crate) fn new_wopbs_key(
        &mut self,
        cks: &ClientKey,
        sks: &ServerKey,
        parameters: &Parameters,
    ) -> EngineResult<WopbsKey> {
        //Independent client key generation dedicated to the WoPBS
        let small_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        let large_lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();

        //BSK dedicated to the WoPBS
        let bootstrap_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &small_lwe_secret_key,
                &glwe_secret_key,
                parameters.pbs_base_log,
                parameters.pbs_level,
                parameters.glwe_modular_std_dev,
                &mut self.encryption_generator,
            );

        // Creation of the bootstrapping key in the Fourier domain
        let mut small_bsk = FourierLweBootstrapKey::new(
            bootstrap_key.input_lwe_dimension(),
            bootstrap_key.glwe_size(),
            bootstrap_key.polynomial_size(),
            bootstrap_key.decomposition_base_log(),
            bootstrap_key.decomposition_level_count(),
        );

        let fft = Fft::new(bootstrap_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &bootstrap_key,
            &mut small_bsk,
            fft,
            stack,
        );

        //KSK encryption_key -> small WoPBS key (used in the 1st KS in the extract bit)
        let ksk_wopbs_large_to_wopbs_small = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_secret_key,
            &small_lwe_secret_key,
            parameters.ks_base_log,
            parameters.ks_level,
            parameters.lwe_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        // KSK to convert from input ciphertext key to the wopbs input one
        let ksk_pbs_large_to_wopbs_large = allocate_and_generate_new_lwe_keyswitch_key(
            &cks.large_lwe_secret_key,
            &large_lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            parameters.lwe_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        // KSK large_wopbs_key -> small PBS key (used after the WoPBS computation to compute a
        // classical PBS. This allows compatibility between PBS and WoPBS
        let ksk_wopbs_large_to_pbs_small = allocate_and_generate_new_lwe_keyswitch_key(
            &large_lwe_secret_key,
            &cks.small_lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            parameters.ciphertext_modulus,
            &mut self.encryption_generator,
        );

        let cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
            &large_lwe_secret_key,
            &glwe_secret_key,
            parameters.pfks_base_log,
            parameters.pfks_level,
            parameters.pfks_modular_std_dev,
            &mut self.encryption_generator,
        );

        let wopbs_server_key = ServerKey {
            key_switching_key: ksk_wopbs_large_to_wopbs_small,
            bootstrapping_key: small_bsk,
            message_modulus: parameters.message_modulus,
            carry_modulus: parameters.carry_modulus,
            max_degree: MaxDegree(parameters.message_modulus.0 * parameters.carry_modulus.0 - 1),
            ciphertext_modulus: parameters.ciphertext_modulus,
        };

        let pbs_server_key = ServerKey {
            key_switching_key: ksk_wopbs_large_to_pbs_small,
            bootstrapping_key: sks.bootstrapping_key.clone(),
            message_modulus: cks.parameters.message_modulus,
            carry_modulus: cks.parameters.carry_modulus,
            max_degree: MaxDegree(
                cks.parameters.message_modulus.0 * cks.parameters.carry_modulus.0 - 1,
            ),
            ciphertext_modulus: cks.parameters.ciphertext_modulus,
        };

        let wopbs_key = WopbsKey {
            wopbs_server_key,
            pbs_server_key,
            cbs_pfpksk,
            ksk_pbs_to_wopbs: ksk_pbs_large_to_wopbs_large,
            param: *parameters,
        };
        Ok(wopbs_key)
    }

    pub(crate) fn extract_bits(
        &mut self,
        delta_log: DeltaLog,
        lwe_in: &LweCiphertextOwned<u64>,
        wopbs_key: &WopbsKey,
        extracted_bit_count: ExtractedBitsCount,
    ) -> EngineResult<LweCiphertextListOwned<u64>> {
        let server_key = &wopbs_key.wopbs_server_key;

        let lwe_size = server_key
            .key_switching_key
            .output_key_lwe_dimension()
            .to_lwe_size();

        let mut output = LweCiphertextListOwned::new(
            0u64,
            lwe_size,
            LweCiphertextCount(extracted_bit_count.0),
            wopbs_key.param.ciphertext_modulus,
        );

        self.extract_bits_assign(
            delta_log,
            lwe_in,
            wopbs_key,
            extracted_bit_count,
            &mut output,
        );

        Ok(output)
    }

    pub(crate) fn extract_bits_assign<OutputCont>(
        &mut self,
        delta_log: DeltaLog,
        lwe_in: &LweCiphertextOwned<u64>,
        wopbs_key: &WopbsKey,
        extracted_bit_count: ExtractedBitsCount,
        output: &mut LweCiphertextList<OutputCont>,
    ) where
        OutputCont: ContainerMut<Element = u64>,
    {
        let server_key = &wopbs_key.wopbs_server_key;

        let bsk = &server_key.bootstrapping_key;
        let ksk = &server_key.key_switching_key;

        let fft = Fft::new(bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
                lwe_in.lwe_size().to_lwe_dimension(),
                ksk.output_key_lwe_dimension(),
                bsk.glwe_size(),
                bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let stack = self.computation_buffers.stack();

        extract_bits_from_lwe_ciphertext_mem_optimized(
            lwe_in,
            output,
            bsk,
            ksk,
            delta_log,
            extracted_bit_count,
            fft,
            stack,
        );
    }

    pub(crate) fn circuit_bootstrap_with_bits<InputCont>(
        &mut self,
        wopbs_key: &WopbsKey,
        extracted_bits: &LweCiphertextList<InputCont>,
        lut: &PlaintextListView<'_, u64>,
        count: LweCiphertextCount,
    ) -> EngineResult<LweCiphertextListOwned<u64>>
    where
        InputCont: Container<Element = u64>,
    {
        let sks = &wopbs_key.wopbs_server_key;
        let fourier_bsk = &sks.bootstrapping_key;

        let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

        let mut output_cbs_vp_ct = LweCiphertextListOwned::new(
            0u64,
            output_lwe_size,
            count,
            wopbs_key.param.ciphertext_modulus,
        );
        let lut = PolynomialListView::from_container(lut.as_ref(), fourier_bsk.polynomial_size());

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<u64>(
                extracted_bits.lwe_ciphertext_count(),
                output_cbs_vp_ct.lwe_ciphertext_count(),
                extracted_bits.lwe_size(),
                lut.polynomial_count(),
                fourier_bsk.output_lwe_dimension().to_lwe_size(),
                fourier_bsk.glwe_size(),
                wopbs_key.cbs_pfpksk.output_polynomial_size(),
                wopbs_key.param.cbs_level,
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );

        let stack = self.computation_buffers.stack();

        circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
            extracted_bits,
            &mut output_cbs_vp_ct,
            &lut,
            &sks.bootstrapping_key,
            &wopbs_key.cbs_pfpksk,
            wopbs_key.param.cbs_base_log,
            wopbs_key.param.cbs_level,
            fft,
            stack,
        );

        Ok(output_cbs_vp_ct)
    }

    pub(crate) fn extract_bits_circuit_bootstrapping<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        ct_in: &CiphertextBase<OpOrder>,
        lut: &[u64],
        delta_log: DeltaLog,
        nb_bit_to_extract: ExtractedBitsCount,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let extracted_bits =
            self.extract_bits(delta_log, &ct_in.ct, wopbs_key, nb_bit_to_extract)?;

        let plaintext_lut = PlaintextList::from_container(lut);

        let ciphertext_list = self.circuit_bootstrap_with_bits(
            wopbs_key,
            &extracted_bits.as_view(),
            &plaintext_lut,
            LweCiphertextCount(1),
        )?;

        // Here the output list contains a single ciphertext, we can consume the container to
        // convert it to a single ciphertext
        let ciphertext = LweCiphertextOwned::from_container(
            ciphertext_list.into_container(),
            wopbs_key.param.ciphertext_modulus,
        );

        let sks = &wopbs_key.wopbs_server_key;
        let ct_out = CiphertextBase {
            ct: ciphertext,
            degree: Degree(sks.message_modulus.0 - 1),
            message_modulus: sks.message_modulus,
            carry_modulus: sks.carry_modulus,
            _order_marker: Default::default(),
        };

        Ok(ct_out)
    }

    pub(crate) fn programmable_bootstrapping_without_padding<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        ct_in: &CiphertextBase<OpOrder>,
        lut: &[u64],
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let sks = &wopbs_key.wopbs_server_key;
        let delta = (1_usize << 63) / (sks.message_modulus.0 * sks.carry_modulus.0) * 2;
        let delta_log = DeltaLog(f64::log2(delta as f64) as usize);

        let nb_bit_to_extract =
            f64::log2((sks.message_modulus.0 * sks.carry_modulus.0) as f64) as usize;

        let ciphertext = self.extract_bits_circuit_bootstrapping(
            wopbs_key,
            ct_in,
            lut,
            delta_log,
            ExtractedBitsCount(nb_bit_to_extract),
        )?;

        Ok(ciphertext)
    }

    pub(crate) fn keyswitch_to_wopbs_params<OpOrder: PBSOrderMarker>(
        &mut self,
        sks: &ServerKey,
        wopbs_key: &WopbsKey,
        ct_in: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        // First PBS to remove the noise
        let acc = self.generate_accumulator(sks, |x| x)?;
        let ct_clean = self.apply_lookup_table(sks, ct_in, &acc)?;

        let mut buffer_lwe_after_ks = LweCiphertextOwned::new(
            0,
            wopbs_key
                .ksk_pbs_to_wopbs
                .output_key_lwe_dimension()
                .to_lwe_size(),
            wopbs_key.param.ciphertext_modulus,
        );

        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &wopbs_key.ksk_pbs_to_wopbs,
            &ct_clean.ct,
            &mut buffer_lwe_after_ks,
        );

        Ok(CiphertextBase {
            ct: buffer_lwe_after_ks,
            degree: ct_clean.degree,
            message_modulus: ct_clean.message_modulus,
            carry_modulus: ct_clean.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn keyswitch_to_pbs_params<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        ct_in: &CiphertextBase<OpOrder>,
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        // move to wopbs parameters to pbs parameters
        //Keyswitch-PBS:
        // 1. KS to go back to the original encryption key
        // 2. PBS to remove the noise added by the previous KS
        //
        let acc = self.generate_accumulator(&wopbs_key.pbs_server_key, |x| x)?;
        let (mut ciphertext_buffers, buffers) =
            self.get_carry_clearing_accumulator_and_buffers(&wopbs_key.pbs_server_key);
        // Compute a key switch
        keyswitch_lwe_ciphertext(
            &wopbs_key.pbs_server_key.key_switching_key,
            &ct_in.ct,
            &mut ciphertext_buffers.buffer_lwe_after_ks,
        );

        let fourier_bsk = &wopbs_key.pbs_server_key.bootstrapping_key;

        let out_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();
        let mut ct_out =
            LweCiphertextOwned::new(0, out_lwe_size, wopbs_key.param.ciphertext_modulus);

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();
        buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = buffers.stack();

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext_buffers.buffer_lwe_after_ks,
            &mut ct_out,
            &acc.acc,
            fourier_bsk,
            fft,
            stack,
        );

        Ok(CiphertextBase {
            ct: ct_out,
            degree: ct_in.degree,
            message_modulus: ct_in.message_modulus,
            carry_modulus: ct_in.carry_modulus,
            _order_marker: Default::default(),
        })
    }

    pub(crate) fn wopbs<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        ct_in: &CiphertextBase<OpOrder>,
        lut: &[u64],
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let tmp_sks = &wopbs_key.wopbs_server_key;
        let delta = (1_usize << 63) / (tmp_sks.message_modulus.0 * tmp_sks.carry_modulus.0);
        let delta_log = DeltaLog(f64::log2(delta as f64) as usize);
        let nb_bit_to_extract =
            f64::log2((tmp_sks.message_modulus.0 * tmp_sks.carry_modulus.0) as f64) as usize;

        let ct_out = self.extract_bits_circuit_bootstrapping(
            wopbs_key,
            ct_in,
            lut,
            delta_log,
            ExtractedBitsCount(nb_bit_to_extract),
        )?;

        Ok(ct_out)
    }

    pub(crate) fn programmable_bootstrapping<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        sks: &ServerKey,
        ct_in: &CiphertextBase<OpOrder>,
        lut: &[u64],
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let ct_wopbs = self.keyswitch_to_wopbs_params(sks, wopbs_key, ct_in)?;
        let result_ct = self.wopbs(wopbs_key, &ct_wopbs, lut)?;
        let ct_out = self.keyswitch_to_pbs_params(wopbs_key, &result_ct)?;

        Ok(ct_out)
    }

    pub(crate) fn programmable_bootstrapping_native_crt<OpOrder: PBSOrderMarker>(
        &mut self,
        wopbs_key: &WopbsKey,
        ct_in: &mut CiphertextBase<OpOrder>,
        lut: &[u64],
    ) -> EngineResult<CiphertextBase<OpOrder>> {
        let nb_bit_to_extract =
            f64::log2((ct_in.message_modulus.0 * ct_in.carry_modulus.0) as f64).ceil() as usize;
        let delta_log = DeltaLog(64 - nb_bit_to_extract);

        // trick ( ct - delta/2 + delta/2^4  )
        let lwe_size = ct_in.ct.lwe_size().0;
        let mut cont = vec![0u64; lwe_size];
        cont[lwe_size - 1] =
            (1 << (64 - nb_bit_to_extract - 1)) - (1 << (64 - nb_bit_to_extract - 5));
        let tmp = LweCiphertextOwned::from_container(cont, wopbs_key.param.ciphertext_modulus);

        lwe_ciphertext_sub_assign(&mut ct_in.ct, &tmp);

        let ciphertext = self.extract_bits_circuit_bootstrapping(
            wopbs_key,
            ct_in,
            lut,
            delta_log,
            ExtractedBitsCount(nb_bit_to_extract),
        )?;

        Ok(ciphertext)
    }

    /// Temporary wrapper.
    ///
    /// # Warning Experimental
    pub fn circuit_bootstrapping_vertical_packing<InputCont>(
        &mut self,
        wopbs_key: &WopbsKey,
        vec_lut: &[Vec<u64>],
        extracted_bits_blocks: &LweCiphertextList<InputCont>,
    ) -> Vec<LweCiphertextOwned<u64>>
    where
        InputCont: Container<Element = u64>,
    {
        let flattened_lut: Vec<u64> = vec_lut.iter().flatten().copied().collect();
        let plaintext_lut = PlaintextListView::from_container(&flattened_lut);
        let output_list = self
            .circuit_bootstrap_with_bits(
                wopbs_key,
                extracted_bits_blocks,
                &plaintext_lut,
                LweCiphertextCount(vec_lut.len()),
            )
            .unwrap();

        assert_eq!(output_list.lwe_ciphertext_count().0, vec_lut.len());

        let output_container = output_list.into_container();
        let ciphertext_modulus = wopbs_key.param.ciphertext_modulus;
        let lwes: Vec<_> = output_container
            .chunks_exact(output_container.len() / vec_lut.len())
            .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
            .collect();

        assert_eq!(lwes.len(), vec_lut.len());
        lwes
    }
}
