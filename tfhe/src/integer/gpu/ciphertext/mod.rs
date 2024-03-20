pub mod boolean_value;
pub mod info;

use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::CudaVec;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{LweCiphertextList, LweCiphertextOwned};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::{RadixCiphertext, SignedRadixCiphertext};
use crate::shortint::Ciphertext;

pub trait CudaIntegerRadixCiphertext: Sized {
    const IS_SIGNED: bool;
    fn as_ref(&self) -> &CudaRadixCiphertext;
    fn as_mut(&mut self) -> &mut CudaRadixCiphertext;
    fn from(ct: CudaRadixCiphertext) -> Self;

    fn duplicate(&self, stream: &CudaStream) -> Self {
        Self::from(self.as_ref().duplicate(stream))
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    unsafe fn duplicate_async(&self, stream: &CudaStream) -> Self {
        Self::from(self.as_ref().duplicate_async(stream))
    }

    fn block_carries_are_empty(&self) -> bool {
        self.as_ref()
            .info
            .blocks
            .iter()
            .all(CudaBlockInfo::carry_is_empty)
    }

    fn is_equal(&self, other: &Self, stream: &CudaStream) -> bool {
        self.as_ref().is_equal(other.as_ref(), stream)
    }
}

pub struct CudaRadixCiphertext {
    pub d_blocks: CudaLweCiphertextList<u64>,
    pub info: CudaRadixCiphertextInfo,
}

pub struct CudaUnsignedRadixCiphertext {
    pub ciphertext: CudaRadixCiphertext,
}

pub struct CudaSignedRadixCiphertext {
    pub ciphertext: CudaRadixCiphertext,
}

impl CudaIntegerRadixCiphertext for CudaUnsignedRadixCiphertext {
    const IS_SIGNED: bool = false;

    fn as_ref(&self) -> &CudaRadixCiphertext {
        &self.ciphertext
    }

    fn as_mut(&mut self) -> &mut CudaRadixCiphertext {
        &mut self.ciphertext
    }

    fn from(ct: CudaRadixCiphertext) -> Self {
        Self { ciphertext: ct }
    }
}

impl CudaIntegerRadixCiphertext for CudaSignedRadixCiphertext {
    const IS_SIGNED: bool = true;

    fn as_ref(&self) -> &CudaRadixCiphertext {
        &self.ciphertext
    }

    fn as_mut(&mut self) -> &mut CudaRadixCiphertext {
        &mut self.ciphertext
    }

    fn from(ct: CudaRadixCiphertext) -> Self {
        Self { ciphertext: ct }
    }
}

impl CudaUnsignedRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }
    /// Copies a RadixCiphertext to the GPU memory
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// let size = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let clear: u64 = 255;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt(clear);
    ///
    /// let mut d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &mut stream);
    /// let mut h_ctxt = d_ctxt.to_radix_ciphertext(&mut stream);
    ///
    /// assert_eq!(h_ctxt, ctxt);
    /// ```
    pub fn from_radix_ciphertext(radix: &RadixCiphertext, stream: &CudaStream) -> Self {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        let lwe_size = radix.blocks.first().unwrap().ct.lwe_size();
        let ciphertext_modulus = radix.blocks.first().unwrap().ct.ciphertext_modulus();

        let h_ct = LweCiphertextList::from_container(
            h_radix_ciphertext.as_mut_slice(),
            lwe_size,
            ciphertext_modulus,
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, stream);

        let info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };

        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }

    pub fn copy_from_radix_ciphertext(&mut self, radix: &RadixCiphertext, stream: &CudaStream) {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        unsafe {
            self.ciphertext
                .d_blocks
                .0
                .d_vec
                .copy_from_cpu_async(h_radix_ciphertext.as_mut_slice(), stream);
        }
        stream.synchronize();

        self.ciphertext.info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 10u32;
    /// let ct1 = cks.encrypt(msg1);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let ct2 = d_ct1.to_radix_ciphertext(&mut stream);
    /// let msg2 = cks.decrypt(&ct2);
    ///
    /// assert_eq!(msg1, msg2);
    /// ```
    pub fn to_radix_ciphertext(&self, stream: &CudaStream) -> RadixCiphertext {
        let h_lwe_ciphertext_list = self.ciphertext.d_blocks.to_lwe_ciphertext_list(stream);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();
        let lwe_size = h_lwe_ciphertext_list.lwe_size().0;

        let h_blocks: Vec<Ciphertext> = h_lwe_ciphertext_list
            .into_container()
            .chunks(lwe_size)
            .zip(&self.ciphertext.info.blocks)
            .map(|(data, i)| Ciphertext {
                ct: LweCiphertextOwned::from_container(data.to_vec(), ciphertext_modulus),
                degree: i.degree,
                noise_level: i.noise_level,
                message_modulus: i.message_modulus,
                carry_modulus: i.carry_modulus,
                pbs_order: i.pbs_order,
            })
            .collect();

        RadixCiphertext::from(h_blocks)
    }
}

impl CudaSignedRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }
    /// Copies a RadixCiphertext to the GPU memory
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// let size = 4;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, size, &mut stream);
    ///
    /// let clear: i64 = 255;
    ///
    /// // Encrypt two messages
    /// let ctxt = cks.encrypt_signed(clear);
    ///
    /// let mut d_ctxt = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ctxt, &mut stream);
    /// let mut h_ctxt = d_ctxt.to_signed_radix_ciphertext(&mut stream);
    ///
    /// assert_eq!(h_ctxt, ctxt);
    /// ```
    pub fn from_signed_radix_ciphertext(
        radix: &SignedRadixCiphertext,
        stream: &CudaStream,
    ) -> Self {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        let lwe_size = radix.blocks.first().unwrap().ct.lwe_size();
        let ciphertext_modulus = radix.blocks.first().unwrap().ct.ciphertext_modulus();

        let h_ct = LweCiphertextList::from_container(
            h_radix_ciphertext.as_mut_slice(),
            lwe_size,
            ciphertext_modulus,
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, stream);

        let info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };

        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }

    pub fn copy_from_signed_radix_ciphertext(
        &mut self,
        radix: &SignedRadixCiphertext,
        stream: &CudaStream,
    ) {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        unsafe {
            self.ciphertext
                .d_blocks
                .0
                .d_vec
                .copy_from_cpu_async(h_radix_ciphertext.as_mut_slice(), stream);
        }
        stream.synchronize();

        self.ciphertext.info = CudaRadixCiphertextInfo {
            blocks: radix
                .blocks
                .iter()
                .map(|block| CudaBlockInfo {
                    degree: block.degree,
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: block.noise_level(),
                })
                .collect(),
        };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaSignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 10i32;
    /// let ct1 = cks.encrypt_signed(msg1);
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct1, &mut stream);
    /// let ct2 = d_ct1.to_signed_radix_ciphertext(&mut stream);
    /// let msg2 = cks.decrypt_signed(&ct2);
    ///
    /// assert_eq!(msg1, msg2);
    /// ```
    pub fn to_signed_radix_ciphertext(&self, stream: &CudaStream) -> SignedRadixCiphertext {
        let h_lwe_ciphertext_list = self.ciphertext.d_blocks.to_lwe_ciphertext_list(stream);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();
        let lwe_size = h_lwe_ciphertext_list.lwe_size().0;

        let h_blocks: Vec<Ciphertext> = h_lwe_ciphertext_list
            .into_container()
            .chunks(lwe_size)
            .zip(&self.ciphertext.info.blocks)
            .map(|(data, i)| Ciphertext {
                ct: LweCiphertextOwned::from_container(data.to_vec(), ciphertext_modulus),
                degree: i.degree,
                noise_level: i.noise_level,
                message_modulus: i.message_modulus,
                carry_modulus: i.carry_modulus,
                pbs_order: i.pbs_order,
            })
            .collect();

        SignedRadixCiphertext::from(h_blocks)
    }
}

impl CudaRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self { d_blocks, info }
    }
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaSignedRadixCiphertext};
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = 10i32;
    /// let ct = cks.encrypt_signed(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaSignedRadixCiphertext::from_signed_radix_ciphertext(&ct, &mut stream);
    /// let d_ct_copied = d_ct.duplicate(&mut stream);
    ///
    /// let ct_copied = d_ct_copied.to_signed_radix_ciphertext(&mut stream);
    /// let msg_copied = cks.decrypt_signed(&ct_copied);
    ///
    /// assert_eq!(msg, msg_copied);
    /// ```
    fn duplicate(&self, stream: &CudaStream) -> Self {
        let ct = unsafe { self.duplicate_async(stream) };
        stream.synchronize();
        ct
    }
    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub(crate) unsafe fn duplicate_async(&self, stream: &CudaStream) -> Self {
        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();
        let ciphertext_modulus = self.d_blocks.ciphertext_modulus();

        let mut d_ct = CudaVec::new_async(self.d_blocks.0.d_vec.len(), stream);
        d_ct.copy_from_gpu_async(&self.d_blocks.0.d_vec, stream);

        let d_blocks =
            CudaLweCiphertextList::from_cuda_vec(d_ct, lwe_ciphertext_count, ciphertext_modulus);

        Self {
            d_blocks,
            info: self.info.clone(),
        }
    }

    fn is_equal(&self, other: &Self, stream: &CudaStream) -> bool {
        let self_size = self.d_blocks.0.d_vec.len();
        let other_size = other.d_blocks.0.d_vec.len();
        let mut self_container: Vec<u64> = vec![0; self_size];
        let mut other_container: Vec<u64> = vec![0; other_size];

        unsafe {
            self.d_blocks
                .0
                .d_vec
                .copy_to_cpu_async(self_container.as_mut_slice(), stream);
            other
                .d_blocks
                .0
                .d_vec
                .copy_to_cpu_async(other_container.as_mut_slice(), stream);
        }
        stream.synchronize();

        self_container == other_container
    }
}
