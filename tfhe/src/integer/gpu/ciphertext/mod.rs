use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{LweCiphertextList, LweCiphertextOwned};
use crate::integer::block_decomposition::{BlockDecomposer, DecomposableInto};
use crate::integer::server_key::TwosComplementNegation;
use crate::integer::RadixCiphertext;
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::{CarryModulus, Ciphertext, MessageModulus, PBSOrder};
use itertools::Itertools;

#[derive(Clone, Copy)]
pub struct CudaBlockInfo {
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl CudaBlockInfo {
    pub fn carry_is_empty(&self) -> bool {
        self.degree.get() < self.message_modulus.0
    }
}

#[derive(Clone)]
pub struct CudaRadixCiphertextInfo {
    pub blocks: Vec<CudaBlockInfo>,
}

impl CudaRadixCiphertextInfo {
    // Creates an iterator that return decomposed blocks of the negated
    // value of `scalar`
    //
    // Returns
    // - `None` if scalar is zero
    // - `Some` if scalar is non-zero
    //
    fn create_negated_block_decomposer<T>(&self, scalar: T) -> Option<impl Iterator<Item = u8>>
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        if scalar == T::ZERO {
            return None;
        }
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        assert!(bits_in_message <= u8::BITS);

        // The whole idea behind this iterator we construct is:
        // - to support combos of parameters and num blocks for which the total number of bits is
        //   not a multiple of T::BITS
        //
        // - Support subtraction in the case the T::BITS is lower than the target ciphertext bits.
        //   In clear rust this would require an upcast, to support that we have to do a few things

        let neg_scalar = scalar.twos_complement_negation();

        // If we had upcasted the scalar, its msb would be zeros (0)
        // then they would become ones (1) after the bitwise_not (!).
        // The only case where these msb could become 0 after the addition
        // is if scalar == T::ZERO (=> !T::ZERO == T::MAX => T::MAX + 1 == overflow),
        // but this case has been handled earlier.
        let padding_bit = 1u32; // To handle when bits is not a multiple of T::BITS
                                // All bits of message set to one
        let pad_block = (1 << bits_in_message as u8) - 1;

        let decomposer = BlockDecomposer::with_padding_bit(
            neg_scalar,
            bits_in_message,
            T::cast_from(padding_bit),
        )
        .iter_as::<u8>()
        .chain(std::iter::repeat(pad_block));
        Some(decomposer)
    }

    pub(crate) fn after_add(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree + right.degree,
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level + right.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_neg(&self) -> Self {
        let mut z;
        let mut z_b: u8 = 0;

        let mut new_degrees: Vec<Degree> = vec![];
        new_degrees.resize(self.blocks.len(), Degree::new(0));
        for (i, block) in self.blocks.iter().enumerate() {
            let mut degree = block.degree.get();
            let msg_mod = block.message_modulus.0;
            if z_b != 0 {
                // scalar_add degree
                degree += z_b as usize;
            }
            // neg_assign_with_correcting_term degree
            z = ((degree + msg_mod - 1) / msg_mod) as u64;
            z *= msg_mod as u64;

            new_degrees[i] = Degree::new(z as usize - z_b as usize);
            z_b = (z / msg_mod as u64) as u8;
        }

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(new_degrees.iter())
                .map(|(left, d)| CudaBlockInfo {
                    degree: *d,
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_mul(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|left| CudaBlockInfo {
                    degree: Degree::new(left.message_modulus.0 - 1),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level + NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_add<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: Degree::new(left.degree.get() + scalar_block as usize),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_small_scalar_mul(&self, scalar: u8) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .map(|left| CudaBlockInfo {
                    degree: Degree::new(left.degree.get() * scalar as usize),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_sub<T>(&self, scalar: T) -> Self
    where
        T: TwosComplementNegation + DecomposableInto<u8>,
    {
        let Some(decomposer) = self.create_negated_block_decomposer(scalar) else {
            // subtraction by zero
            return self.clone();
        };

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(decomposer)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: Degree::new(left.degree.get() + scalar_block as usize),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitand(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitand(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitor(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitor(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_bitxor(&self, other: &Self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .zip(&other.blocks)
                .map(|(left, right)| CudaBlockInfo {
                    degree: left.degree.after_bitxor(right.degree),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_bitand<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitand(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_bitor<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitor(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    pub(crate) fn after_scalar_bitxor<T>(&self, scalar: T) -> Self
    where
        T: DecomposableInto<u8>,
    {
        let message_modulus = self.blocks.first().unwrap().message_modulus;
        let bits_in_message = message_modulus.0.ilog2();
        let decomposer =
            BlockDecomposer::with_early_stop_at_zero(scalar, bits_in_message).iter_as::<u8>();
        let mut scalar_composed = decomposer.collect_vec();
        scalar_composed.resize(self.blocks.len(), 0);

        Self {
            blocks: self
                .blocks
                .iter()
                .zip(scalar_composed)
                .map(|(left, scalar_block)| CudaBlockInfo {
                    degree: left.degree.after_bitxor(Degree::new(scalar_block as usize)),
                    message_modulus: left.message_modulus,
                    carry_modulus: left.carry_modulus,
                    pbs_order: left.pbs_order,
                    noise_level: left.noise_level,
                })
                .collect(),
        }
    }

    // eq/ne, and comparisons retuns a ciphertext that encrypts a 0 or 1, so the first block
    // (least significant) has a degree of 1, the other blocks should be trivial lwe encrypting 0,
    // so degree 0
    pub(crate) fn after_eq(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .enumerate()
                .map(|(i, block)| CudaBlockInfo {
                    degree: if i == 0 {
                        Degree::new(1)
                    } else {
                        Degree::new(0)
                    },
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_ne(&self) -> Self {
        Self {
            blocks: self
                .blocks
                .iter()
                .enumerate()
                .map(|(i, block)| CudaBlockInfo {
                    degree: if i == 0 {
                        Degree::new(1)
                    } else {
                        Degree::new(0)
                    },
                    message_modulus: block.message_modulus,
                    carry_modulus: block.carry_modulus,
                    pbs_order: block.pbs_order,
                    noise_level: NoiseLevel::NOMINAL,
                })
                .collect(),
        }
    }

    pub(crate) fn after_extend_radix_with_trivial_zero_blocks_lsb(
        &self,
        num_blocks: usize,
    ) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len() + num_blocks),
        };
        for _ in 0..num_blocks {
            new_block_info.blocks.push(CudaBlockInfo {
                degree: Degree::new(0),
                message_modulus: self.blocks.first().unwrap().message_modulus,
                carry_modulus: self.blocks.first().unwrap().carry_modulus,
                pbs_order: self.blocks.first().unwrap().pbs_order,
                noise_level: NoiseLevel::ZERO,
            });
        }
        for &b in self.blocks.iter() {
            new_block_info.blocks.push(b);
        }
        new_block_info
    }

    pub(crate) fn after_extend_radix_with_trivial_zero_blocks_msb(
        &self,
        num_blocks: usize,
    ) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len() + num_blocks),
        };
        for &b in self.blocks.iter() {
            new_block_info.blocks.push(b);
        }
        for _ in 0..num_blocks {
            new_block_info.blocks.push(CudaBlockInfo {
                degree: Degree::new(0),
                message_modulus: self.blocks.first().unwrap().message_modulus,
                carry_modulus: self.blocks.first().unwrap().carry_modulus,
                pbs_order: self.blocks.first().unwrap().pbs_order,
                noise_level: NoiseLevel::ZERO,
            });
        }
        new_block_info
    }

    pub(crate) fn after_trim_radix_blocks_lsb(&self, num_blocks: usize) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len().saturating_sub(num_blocks)),
        };
        new_block_info
            .blocks
            .extend(self.blocks[num_blocks..].iter().copied());
        new_block_info
    }

    pub(crate) fn after_trim_radix_blocks_msb(&self, num_blocks: usize) -> Self {
        let mut new_block_info = Self {
            blocks: Vec::with_capacity(self.blocks.len().saturating_sub(num_blocks)),
        };
        new_block_info
            .blocks
            .extend(self.blocks[..num_blocks].iter().copied());
        new_block_info
    }
}

// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
// #[must_use]
pub struct CudaRadixCiphertext {
    pub d_blocks: CudaLweCiphertextList<u64>,
    pub info: CudaRadixCiphertextInfo,
}

impl CudaRadixCiphertext {
    pub fn new(d_blocks: CudaLweCiphertextList<u64>, info: CudaRadixCiphertextInfo) -> Self {
        Self { d_blocks, info }
    }
    /// Copies a RadixCiphertext to the GPU memory
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
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
    /// let mut d_ctxt = CudaRadixCiphertext::from_radix_ciphertext(&ctxt, &mut stream);
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

        Self { d_blocks, info }
    }

    pub fn copy_from_radix_ciphertext(&mut self, radix: &RadixCiphertext, stream: &CudaStream) {
        let mut h_radix_ciphertext = radix
            .blocks
            .iter()
            .flat_map(|block| block.ct.clone().into_container())
            .collect::<Vec<_>>();

        unsafe {
            stream.copy_to_gpu_async(
                &mut self.d_blocks.0.d_vec,
                h_radix_ciphertext.as_mut_slice(),
            );
        }
        stream.synchronize();

        self.info = CudaRadixCiphertextInfo {
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
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
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
    /// let d_ct1 = CudaRadixCiphertext::from_radix_ciphertext(&ct1, &mut stream);
    /// let ct2 = d_ct1.to_radix_ciphertext(&mut stream);
    /// let msg2 = cks.decrypt(&ct2);
    ///
    /// assert_eq!(msg1, msg2);
    /// ```
    pub fn to_radix_ciphertext(&self, stream: &CudaStream) -> RadixCiphertext {
        let h_lwe_ciphertext_list = self.d_blocks.to_lwe_ciphertext_list(stream);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();
        let lwe_size = h_lwe_ciphertext_list.lwe_size().0;

        let h_blocks: Vec<Ciphertext> = h_lwe_ciphertext_list
            .into_container()
            .chunks(lwe_size)
            .zip(&self.info.blocks)
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

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn duplicate_async(&self, stream: &CudaStream) -> Self {
        let lwe_ciphertext_count = self.d_blocks.lwe_ciphertext_count();
        let ciphertext_modulus = self.d_blocks.ciphertext_modulus();

        let mut d_ct = stream.malloc_async(self.d_blocks.0.d_vec.len() as u32);
        stream.copy_gpu_to_gpu_async(&mut d_ct, &self.d_blocks.0.d_vec);

        let d_blocks =
            CudaLweCiphertextList::from_cuda_vec(d_ct, lwe_ciphertext_count, ciphertext_modulus);

        Self {
            d_blocks,
            info: self.info.clone(),
        }
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::CudaRadixCiphertext;
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
    /// let msg = 10u32;
    /// let ct = cks.encrypt(msg);
    ///
    /// // Copy to GPU
    /// let d_ct = CudaRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    /// let d_ct_copied = d_ct.duplicate(&mut stream);
    ///
    /// let ct_copied = d_ct_copied.to_radix_ciphertext(&mut stream);
    /// let msg_copied = cks.decrypt(&ct_copied);
    ///
    /// assert_eq!(msg, msg_copied);
    /// ```
    pub fn duplicate(&self, stream: &CudaStream) -> Self {
        let ct = unsafe { self.duplicate_async(stream) };
        stream.synchronize();
        ct
    }

    pub fn is_equal(&self, other: &Self, stream: &CudaStream) -> bool {
        let self_size = self.d_blocks.0.d_vec.len();
        let other_size = other.d_blocks.0.d_vec.len();
        let mut self_container: Vec<u64> = vec![0; self_size];
        let mut other_container: Vec<u64> = vec![0; other_size];

        unsafe {
            stream.copy_to_cpu_async(self_container.as_mut_slice(), &self.d_blocks.0.d_vec);
            stream.copy_to_cpu_async(other_container.as_mut_slice(), &other.d_blocks.0.d_vec);
        }
        stream.synchronize();

        self_container == other_container
    }

    pub(crate) fn block_carries_are_empty(&self) -> bool {
        self.info.blocks.iter().all(CudaBlockInfo::carry_is_empty)
    }
}
