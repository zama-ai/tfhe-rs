use super::{BooleanServerKey, Bootstrapper, CpuBootstrapKey};
use crate::boolean::PLAINTEXT_TRUE;
use crate::core_crypto::prelude::*;
use crate::seeders::new_seeder;

use std::collections::BTreeMap;

use crate::boolean::ciphertext::Ciphertext;

pub(crate) struct CudaBootstrapKey {
    bootstrapping_key: CudaFourierLweBootstrapKey32,
    key_switching_key: CudaLweKeyswitchKey32,
}

impl BooleanServerKey for CudaBootstrapKey {
    fn lwe_size(&self) -> LweSize {
        self.bootstrapping_key.input_lwe_dimension().to_lwe_size()
    }
}

#[derive(PartialOrd, PartialEq, Ord, Eq)]
struct KeyId {
    // Both of these are for the accumulator
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    lwe_dimension_after_bootstrap: LweDimension,
}

#[derive(Default)]
struct CudaMemory {
    cuda_buffers: BTreeMap<KeyId, CudaBuffers>,
}

/// All the buffers needed to do a bootstrap or a keyswitch or bootstrap + keyswitch
struct CudaBuffers {
    accumulator: CudaGlweCiphertext32,
    // Its size is the one of a ciphertext after pbs
    lwe_after_bootstrap: CudaLweCiphertext32,
    // Its size is the one of a ciphertext after a keyswitch
    // ie the size of a ciphertext before the bootstrap
    lwe_after_keyswitch: CudaLweCiphertext32,
}

impl CudaMemory {
    /// Returns the buffers that matches the given key.
    fn as_buffers_for_key(
        &mut self,
        cpu_engine: &mut DefaultEngine,
        cuda_engine: &mut CudaEngine,
        server_key: &CudaBootstrapKey,
    ) -> &mut CudaBuffers {
        let key_id = KeyId {
            glwe_dimension: server_key.bootstrapping_key.glwe_dimension(),
            polynomial_size: server_key.bootstrapping_key.polynomial_size(),
            lwe_dimension_after_bootstrap: server_key.bootstrapping_key.output_lwe_dimension(),
        };

        self.cuda_buffers.entry(key_id).or_insert_with(|| {
            let output_lwe_size = server_key
                .bootstrapping_key
                .output_lwe_dimension()
                .to_lwe_size();
            let output_ciphertext = cpu_engine
                .create_lwe_ciphertext_from(vec![0u32; output_lwe_size.0])
                .unwrap();
            let cuda_lwe_after_bootstrap = cuda_engine
                .convert_lwe_ciphertext(&output_ciphertext)
                .unwrap();

            let num_elements = server_key
                .bootstrapping_key
                .glwe_dimension()
                .to_glwe_size()
                .0
                * server_key.bootstrapping_key.polynomial_size().0;
            let mut acc = vec![0u32; num_elements];
            acc[num_elements - server_key.bootstrapping_key.polynomial_size().0..]
                .fill(PLAINTEXT_TRUE);
            let accumulator = cpu_engine
                .create_glwe_ciphertext_from(acc, server_key.bootstrapping_key.polynomial_size())
                .unwrap();
            let cuda_accumulator = cuda_engine.convert_glwe_ciphertext(&accumulator).unwrap();

            let lwe_size_after_keyswitch = server_key
                .key_switching_key
                .output_lwe_dimension()
                .to_lwe_size();
            let output_ciphertext = cpu_engine
                .create_lwe_ciphertext_from(vec![0u32; lwe_size_after_keyswitch.0])
                .unwrap();
            let cuda_lwe_after_keyswitch = cuda_engine
                .convert_lwe_ciphertext(&output_ciphertext)
                .unwrap();

            CudaBuffers {
                accumulator: cuda_accumulator,
                lwe_after_bootstrap: cuda_lwe_after_bootstrap,
                lwe_after_keyswitch: cuda_lwe_after_keyswitch,
            }
        })
    }
}

pub(crate) struct CudaBootstrapper {
    cuda_engine: CudaEngine,
    cpu_engine: DefaultEngine,
    memory: CudaMemory,
}

impl Default for CudaBootstrapper {
    fn default() -> Self {
        Self {
            cuda_engine: CudaEngine::new(()).unwrap(),
            // Secret does not matter, we won't generate keys or ciphertext.
            cpu_engine: DefaultEngine::new(new_seeder()).unwrap(),
            memory: Default::default(),
        }
    }
}

impl CudaBootstrapper {
    pub(crate) fn new_serverk_key(
        &mut self,
        server_key: &CpuBootstrapKey,
    ) -> Result<CudaBootstrapKey, Box<dyn std::error::Error>> {
        let bootstrapping_key = self
            .cuda_engine
            .convert_lwe_bootstrap_key(&server_key.standard_bootstraping_key)?;

        let key_switching_key = self
            .cuda_engine
            .convert_lwe_keyswitch_key(&server_key.key_switching_key)?;

        Ok(CudaBootstrapKey {
            bootstrapping_key,
            key_switching_key,
        })
    }
}

impl Bootstrapper for CudaBootstrapper {
    type ServerKey = CudaBootstrapKey;

    fn bootstrap(
        &mut self,
        input: &LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<LweCiphertext32, Box<dyn std::error::Error>> {
        let cuda_buffers =
            self.memory
                .as_buffers_for_key(&mut self.cpu_engine, &mut self.cuda_engine, server_key);

        // The output size of keyswitch is the one of regular boolean ciphertext
        // so we can use lwe_after_keyswitch
        self.cuda_engine
            .discard_convert_lwe_ciphertext(&mut cuda_buffers.lwe_after_keyswitch, input)?;

        self.cuda_engine.discard_bootstrap_lwe_ciphertext(
            &mut cuda_buffers.lwe_after_bootstrap,
            &cuda_buffers.lwe_after_keyswitch,
            &cuda_buffers.accumulator,
            &server_key.bootstrapping_key,
        )?;

        let output_ciphertext = self
            .cuda_engine
            .convert_lwe_ciphertext(&cuda_buffers.lwe_after_bootstrap)?;
        Ok(output_ciphertext)
    }

    fn keyswitch(
        &mut self,
        input: &LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<LweCiphertext32, Box<dyn std::error::Error>> {
        let cuda_buffers =
            self.memory
                .as_buffers_for_key(&mut self.cpu_engine, &mut self.cuda_engine, server_key);

        // The input of the function we implement must be a ciphertext that result of a bootstrap
        // so we can discard convert in the lwe ciphertext after bootstrap
        self.cuda_engine
            .discard_convert_lwe_ciphertext(&mut cuda_buffers.lwe_after_bootstrap, input)?;

        self.cuda_engine.discard_keyswitch_lwe_ciphertext(
            &mut cuda_buffers.lwe_after_keyswitch,
            &cuda_buffers.lwe_after_bootstrap,
            &server_key.key_switching_key,
        )?;

        let output_ciphertext = self
            .cuda_engine
            .convert_lwe_ciphertext(&cuda_buffers.lwe_after_keyswitch)?;
        Ok(output_ciphertext)
    }

    fn bootstrap_keyswitch(
        &mut self,
        ciphertext: LweCiphertext32,
        server_key: &Self::ServerKey,
    ) -> Result<Ciphertext, Box<dyn std::error::Error>> {
        // We re-implement instead of calling our bootstrap and then keyswitch fn
        // to avoid one extra conversion / copy  cpu <-> gpu

        let cuda_buffers =
            self.memory
                .as_buffers_for_key(&mut self.cpu_engine, &mut self.cuda_engine, server_key);

        // The output size of keyswitch is the one of regular boolean ciphertext
        // so we can use it
        self.cuda_engine
            .discard_convert_lwe_ciphertext(&mut cuda_buffers.lwe_after_keyswitch, &ciphertext)?;

        self.cuda_engine.discard_bootstrap_lwe_ciphertext(
            &mut cuda_buffers.lwe_after_bootstrap,
            &cuda_buffers.lwe_after_keyswitch,
            &cuda_buffers.accumulator,
            &server_key.bootstrapping_key,
        )?;

        self.cuda_engine.discard_keyswitch_lwe_ciphertext(
            &mut cuda_buffers.lwe_after_keyswitch,
            &cuda_buffers.lwe_after_bootstrap,
            &server_key.key_switching_key,
        )?;

        // We write the result from gpu to cpu avoiding an extra allocation
        let mut data = self
            .cpu_engine
            .consume_retrieve_lwe_ciphertext(ciphertext)?;
        let mut view = self
            .cpu_engine
            .create_lwe_ciphertext_from(data.as_mut_slice())?;
        self.cuda_engine
            .discard_convert_lwe_ciphertext(&mut view, &cuda_buffers.lwe_after_keyswitch)?;
        let output_ciphertext = self.cpu_engine.create_lwe_ciphertext_from(data)?;

        Ok(Ciphertext::Encrypted(output_ciphertext))
    }
}
