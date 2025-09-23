//! CUDA implementations of the LWE programmable bootstrap for noise measurement traits.

use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::LweClassicFftBootstrap;
use crate::core_crypto::commons::numeric::CastFrom;
use crate::core_crypto::gpu::algorithms::lwe_programmable_bootstrapping::cuda_programmable_bootstrap_lwe_ciphertext;
use crate::core_crypto::gpu::entities::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::entities::lwe_bootstrap_key::CudaLweBootstrapKey;
use crate::core_crypto::gpu::entities::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaSideResources;
use crate::core_crypto::prelude::{CastInto, UnsignedTorus};

impl<Scalar>
    LweClassicFftBootstrap<
        CudaLweCiphertextList<Scalar>,
        CudaLweCiphertextList<Scalar>,
        CudaGlweCiphertextList<Scalar>,
    > for CudaLweBootstrapKey
where
    Scalar: UnsignedTorus + CastInto<usize> + CastFrom<usize>,
{
    type SideResources = CudaSideResources;

    fn lwe_classic_fft_pbs(
        &self,
        input: &CudaLweCiphertextList<Scalar>,
        output: &mut CudaLweCiphertextList<Scalar>,
        accumulator: &CudaGlweCiphertextList<Scalar>,
        side_resources: &mut Self::SideResources,
    ) {
        // Create simple index vectors for single operation
        let count = input.lwe_ciphertext_count().0;
        let indexes: Vec<Scalar> = (0..count).map(|i| Scalar::cast_from(i)).collect();

        let mut lut_indexes = unsafe { CudaVec::new_async(count, &side_resources.streams, 0) };
        let mut output_indexes = unsafe { CudaVec::new_async(count, &side_resources.streams, 0) };
        let mut input_indexes = unsafe { CudaVec::new_async(count, &side_resources.streams, 0) };

        unsafe {
            lut_indexes.copy_from_cpu_async(&indexes, &side_resources.streams, 0);
            output_indexes.copy_from_cpu_async(&indexes, &side_resources.streams, 0);
            input_indexes.copy_from_cpu_async(&indexes, &side_resources.streams, 0);
        }

        cuda_programmable_bootstrap_lwe_ciphertext(
            input,
            output,
            accumulator,
            &input_indexes,
            &lut_indexes,
            &output_indexes,
            self,
            &side_resources.streams,
        );
    }
}
