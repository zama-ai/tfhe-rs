use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{ByteRandomGenerator, ParallelByteRandomGenerator};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::crypto::wop_pbs::{
    circuit_bootstrap_boolean_vertical_packing, circuit_bootstrap_boolean_vertical_packing_scratch,
    extract_bits, extract_bits_scratch,
};
use crate::core_crypto::fft_impl::math::fft::FftView;
use crate::core_crypto::specification::dispersion::DispersionParameter;
use crate::core_crypto::specification::parameters::*;
use concrete_fft::c64;
use dyn_stack::{DynStack, SizeOverflow, StackReq};
use rayon::prelude::*;

pub fn allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
    );

    generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

pub fn generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar>,
    GlweKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    for ((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator) in output_cbs_pfpksk_list
        .iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .iter()
                .chain(last_polynomial_as_list.iter()),
        )
        .zip(gen_iter)
    {
        generate_lwe_private_functional_packing_keyswitch_key(
            input_lwe_secret_key,
            output_glwe_secret_key,
            &mut lwe_pfpksk,
            noise_parameters,
            &mut loop_generator,
            |x| Scalar::ZERO.wrapping_sub(x),
            &polynomial_to_encrypt,
        );
    }
}

pub fn par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut cbs_pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyListOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        FunctionalPackingKeyswitchKeyCount(
            output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        ),
    );

    par_generate_circuit_bootstrap_lwe_pfpksk_list(
        &mut cbs_pfpksk_list,
        input_lwe_secret_key,
        output_glwe_secret_key,
        noise_parameters,
        generator,
    );

    cbs_pfpksk_list
}

pub fn par_generate_circuit_bootstrap_lwe_pfpksk_list<
    Scalar,
    OutputCont,
    LweKeyCont,
    GlweKeyCont,
    Gen,
>(
    output_cbs_pfpksk_list: &mut LwePrivateFunctionalPackingKeyswitchKeyList<OutputCont>,
    input_lwe_secret_key: &LweSecretKey<LweKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    OutputCont: ContainerMut<Element = Scalar>,
    LweKeyCont: Container<Element = Scalar> + Sync,
    GlweKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output_cbs_pfpksk_list.lwe_pfpksk_count().0
            == output_glwe_secret_key.glwe_dimension().to_glwe_size().0,
        "Current list has {} pfpksk, need to have {} \
        (output_glwe_key.glwe_dimension().to_glwe_size())",
        output_cbs_pfpksk_list.lwe_pfpksk_count().0,
        output_glwe_secret_key.glwe_dimension().to_glwe_size().0
    );

    let decomp_level_count = output_cbs_pfpksk_list.decomposition_level_count();

    let gen_iter = generator
        .par_fork_cbs_pfpksk_to_pfpksk::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
            output_cbs_pfpksk_list.lwe_pfpksk_count(),
        )
        .unwrap();

    let mut last_polynomial_as_list = PolynomialListOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.polynomial_size(),
        PolynomialCount(1),
    );
    // We apply the x -> -x function so instead of putting one in the first coeff of the
    // polynomial, we put Scalar::MAX == - Sclar::One so that we can use a single function in
    // the loop avoiding branching
    last_polynomial_as_list.get_mut(0)[0] = Scalar::MAX;

    output_cbs_pfpksk_list
        .par_iter_mut()
        .zip(
            output_glwe_secret_key
                .as_polynomial_list()
                .par_iter()
                .chain(last_polynomial_as_list.par_iter()),
        )
        .zip(gen_iter)
        .for_each(
            |((mut lwe_pfpksk, polynomial_to_encrypt), mut loop_generator)| {
                par_generate_lwe_private_functional_packing_keyswitch_key(
                    input_lwe_secret_key,
                    output_glwe_secret_key,
                    &mut lwe_pfpksk,
                    noise_parameters,
                    &mut loop_generator,
                    |x| Scalar::ZERO.wrapping_sub(x),
                    &polynomial_to_encrypt,
                );
            },
        );
}

#[allow(clippy::too_many_arguments)]
pub fn extract_bits_from_lwe_ciphertext<Scalar, InputCont, OutputCont, BskCont, KSKCont>(
    lwe_in: &LweCiphertext<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    ksk: &LweKeyswitchKey<KSKCont>,
    delta_log: DeltaLog,
    number_of_bits_to_extract: ExtractedBitsCount,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    BskCont: Container<Element = c64>,
    KSKCont: Container<Element = Scalar>,
{
    extract_bits(
        lwe_list_out.as_mut_view(),
        lwe_in.as_view(),
        ksk.as_view(),
        fourier_bsk.as_view(),
        delta_log,
        number_of_bits_to_extract,
        fft,
        stack,
    )
}

pub fn extract_bits_from_lwe_ciphertext_scratch<Scalar>(
    lwe_dimension: LweDimension,
    ksk_output_key_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    extract_bits_scratch::<Scalar>(
        lwe_dimension,
        ksk_output_key_lwe_dimension,
        glwe_size,
        polynomial_size,
        fft,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list<
    Scalar,
    InputCont,
    OutputCont,
    LutCont,
    BskCont,
    PFPKSKCont,
>(
    lwe_list_in: &LweCiphertextList<InputCont>,
    lwe_list_out: &mut LweCiphertextList<OutputCont>,
    big_lut_as_polynomial_list: &PolynomialList<LutCont>,
    fourier_bsk: &FourierLweBootstrapKey<BskCont>,
    pfpksk_list: &LwePrivateFunctionalPackingKeyswitchKeyList<PFPKSKCont>,
    level_cbs: DecompositionLevelCount,
    base_log_cbs: DecompositionBaseLog,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    // CastInto required for PBS modulus switch which returns a usize
    Scalar: UnsignedTorus + CastInto<usize>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    LutCont: Container<Element = Scalar>,
    BskCont: Container<Element = c64>,
    PFPKSKCont: Container<Element = Scalar>,
{
    circuit_bootstrap_boolean_vertical_packing(
        big_lut_as_polynomial_list.as_view(),
        fourier_bsk.as_view(),
        lwe_list_out.as_mut_view(),
        lwe_list_in.as_view(),
        pfpksk_list.as_view(),
        level_cbs,
        base_log_cbs,
        fft,
        stack,
    )
}

// TODO big_lut_polynomial_count looks wrong
#[allow(clippy::too_many_arguments)]
pub fn circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_scracth<Scalar>(
    lwe_list_in_count: LweCiphertextCount,
    lwe_list_out_count: LweCiphertextCount,
    lwe_in_size: LweSize,
    big_lut_polynomial_count: PolynomialCount,
    bsk_output_lwe_size: LweSize,
    fpksk_output_polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    level_cbs: DecompositionLevelCount,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    circuit_bootstrap_boolean_vertical_packing_scratch::<Scalar>(
        lwe_list_in_count,
        lwe_list_out_count,
        lwe_in_size,
        big_lut_polynomial_count,
        bsk_output_lwe_size,
        fpksk_output_polynomial_size,
        glwe_size,
        level_cbs,
        fft,
    )
}
