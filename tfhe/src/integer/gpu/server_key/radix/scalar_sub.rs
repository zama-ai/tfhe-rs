use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::Numeric;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::gpu::ciphertext::CudaIntegerRadixCiphertext;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::server_key::TwosComplementNegation;
use crate::prelude::CastInto;

impl CudaServerKey {
    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
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
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.unchecked_scalar_sub(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn unchecked_scalar_sub<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.unchecked_scalar_sub_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn unchecked_scalar_sub_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let negated_scalar = scalar.twos_complement_negation();
        self.unchecked_scalar_add_assign_async(ct, negated_scalar, stream);
        ct.as_mut().info = ct.as_ref().info.after_scalar_sub(scalar);
    }

    pub fn unchecked_scalar_sub_assign<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.unchecked_scalar_sub_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }

    /// Computes homomorphically a subtraction between a ciphertext and a scalar.
    ///
    /// This function computes the operation without checking if it exceeds the capacity of the
    /// ciphertext.
    ///
    /// The result is returned as a new ciphertext.
    ///
    /// # Example
    ///
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
    /// // We have 4 * 2 = 8 bits of message
    /// let num_blocks = 4;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg = 40;
    /// let scalar = 3;
    ///
    /// let ct = cks.encrypt(msg);
    /// let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct, &mut stream);
    ///
    /// // Compute homomorphically an addition:
    /// let d_ct_res = sks.scalar_sub(&d_ct, scalar, &mut stream);
    /// let ct_res = d_ct_res.to_radix_ciphertext(&mut stream);
    ///
    /// // Decrypt:
    /// let dec: u64 = cks.decrypt(&ct_res);
    /// assert_eq!(msg - scalar, dec);
    /// ```
    pub fn scalar_sub<Scalar, T>(&self, ct: &T, scalar: Scalar, stream: &CudaStream) -> T
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        let mut result = unsafe { ct.duplicate_async(stream) };
        self.scalar_sub_assign(&mut result, scalar, stream);
        result
    }

    /// # Safety
    ///
    /// - `stream` __must__ be synchronized to guarantee computation has finished, and inputs must
    ///   not be dropped until stream is synchronised
    pub unsafe fn scalar_sub_assign_async<Scalar, T>(
        &self,
        ct: &mut T,
        scalar: Scalar,
        stream: &CudaStream,
    ) where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        if !ct.block_carries_are_empty() {
            self.full_propagate_assign_async(ct, stream);
        };

        self.unchecked_scalar_sub_assign_async(ct, scalar, stream);
        self.propagate_single_carry_assign_async(ct, stream);
    }

    pub fn scalar_sub_assign<Scalar, T>(&self, ct: &mut T, scalar: Scalar, stream: &CudaStream)
    where
        Scalar: DecomposableInto<u8> + Numeric + TwosComplementNegation + CastInto<u64>,
        T: CudaIntegerRadixCiphertext,
    {
        unsafe {
            self.scalar_sub_assign_async(ct, scalar, stream);
        }
        stream.synchronize();
    }
}
