use super::fourier_lwe_multi_bit_bootstrap_key_size;
use crate::core_crypto::backward_compatibility::entities::lwe_multi_bit_bootstrap_key::Fourier128MultiBitLweBootstrapKeyVersions;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweBskGroupingFactor, LweDimension,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, Split};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::fft_impl::fft128::crypto::ggsw::Fourier128GgswCiphertext;

use aligned_vec::{avec, ABox};
use tfhe_versionable::Versionize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(Fourier128MultiBitLweBootstrapKeyVersions)]
pub struct Fourier128LweMultiBitBootstrapKey<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,
    polynomial_size: PolynomialSize,
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
}

impl<C: Container<Element = f64>> Fourier128LweMultiBitBootstrapKey<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        let container_len = fourier_lwe_multi_bit_bootstrap_key_size(
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_level_count,
            grouping_factor,
        )
        .unwrap();
        assert_eq!(data_re0.container_len(), container_len);
        assert_eq!(data_re1.container_len(), container_len);
        assert_eq!(data_im0.container_len(), container_len);
        assert_eq!(data_im1.container_len(), container_len);
        Self {
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
            grouping_factor,
        }
    }

    /// Return an iterator over the GGSW ciphertexts composing the key.
    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = Fourier128GgswCiphertext<C>>
    where
        C: Split,
    {
        let multi_bit_lwe_dim = self.multi_bit_input_lwe_dimension();
        let ggsw_count =
            multi_bit_lwe_dim.0 * self.grouping_factor().ggsw_per_multi_bit_element().0;

        izip!(
            self.data_re0.split_into(ggsw_count),
            self.data_re1.split_into(ggsw_count),
            self.data_im0.split_into(ggsw_count),
            self.data_im1.split_into(ggsw_count),
        )
        .map(move |(data_re0, data_re1, data_im0, data_im1)| {
            Fourier128GgswCiphertext::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                self.polynomial_size,
                self.glwe_size,
                self.decomposition_base_log,
                self.decomposition_level_count,
            )
        })
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension((self.glwe_size.0 - 1) * self.polynomial_size().0)
    }

    pub fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    pub fn multi_bit_input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.input_lwe_dimension().0 / self.grouping_factor.0)
    }

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }

    pub fn as_view(&self) -> Fourier128LweMultiBitBootstrapKey<&[C::Element]> {
        Fourier128LweMultiBitBootstrapKey {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
            grouping_factor: self.grouping_factor,
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128LweMultiBitBootstrapKey<&mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        Fourier128LweMultiBitBootstrapKey {
            data_re0: self.data_re0.as_mut(),
            data_re1: self.data_re1.as_mut(),
            data_im0: self.data_im0.as_mut(),
            data_im1: self.data_im1.as_mut(),
            polynomial_size: self.polynomial_size,
            input_lwe_dimension: self.input_lwe_dimension,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
            grouping_factor: self.grouping_factor,
        }
    }
}

pub type Fourier128LweMultiBitBootstrapKeyOwned = Fourier128LweMultiBitBootstrapKey<ABox<[f64]>>;

impl Fourier128LweMultiBitBootstrapKey<ABox<[f64]>> {
    pub fn new(
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
    ) -> Self {
        let container_len = fourier_lwe_multi_bit_bootstrap_key_size(
            input_lwe_dimension,
            glwe_size,
            polynomial_size,
            decomposition_level_count,
            grouping_factor,
        )
        .unwrap();

        let boxed_re0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_re1 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im0 = avec![0.0f64; container_len].into_boxed_slice();
        let boxed_im1 = avec![0.0f64; container_len].into_boxed_slice();

        Fourier128LweMultiBitBootstrapKey::from_container(
            boxed_re0,
            boxed_re1,
            boxed_im0,
            boxed_im1,
            polynomial_size,
            input_lwe_dimension,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
            grouping_factor,
        )
    }
}
