use std::borrow::Borrow;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};

use crate::conformance::ParameterSetConformant;
use crate::high_level_api::booleans::compressed::CompressedFheBool;
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_stream;
use crate::high_level_api::integers::{FheInt, FheIntId, FheUint, FheUintId};
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::traits::{FheEq, IfThenElse};
use crate::integer::parameters::RadixCiphertextConformanceParams;
use crate::integer::BooleanBlock;
use crate::named::Named;
use crate::shortint::ciphertext::NotTrivialCiphertextError;
use crate::{CompactFheBool, Device};
use serde::{Deserialize, Serialize};

use super::inner::InnerBoolean;

/// The FHE boolean data type.
///
/// # Example
///
/// ```rust
/// use tfhe::prelude::*;
/// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
///
/// let config = ConfigBuilder::default().build();
///
/// let (client_key, server_key) = generate_keys(config);
///
/// let ttrue = FheBool::encrypt(true, &client_key);
/// let ffalse = FheBool::encrypt(false, &client_key);
///
/// // Do not forget to set the server key before doing any computation
/// set_server_key(server_key);
///
/// let fhe_result = ttrue & ffalse;
///
/// let clear_result = fhe_result.decrypt(&client_key);
/// assert_eq!(clear_result, false);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct FheBool {
    pub(in crate::high_level_api) ciphertext: InnerBoolean,
}

impl Named for FheBool {
    const NAME: &'static str = "high_level_api::FheBool";
}

impl ParameterSetConformant for FheBool {
    type ParameterSet = RadixCiphertextConformanceParams;

    fn is_conformant(&self, params: &RadixCiphertextConformanceParams) -> bool {
        self.ciphertext
            .on_cpu()
            .0
            .is_conformant(&params.shortint_params)
    }
}

impl From<CompressedFheBool> for FheBool {
    fn from(value: CompressedFheBool) -> Self {
        value.decompress()
    }
}

impl From<CompactFheBool> for FheBool {
    fn from(value: CompactFheBool) -> Self {
        value.expand()
    }
}

impl FheBool {
    pub(in crate::high_level_api) fn new<T: Into<InnerBoolean>>(ciphertext: T) -> Self {
        Self {
            ciphertext: ciphertext.into(),
        }
    }

    pub fn current_device(&self) -> Device {
        self.ciphertext.current_device()
    }

    /// Moves (in-place) the ciphertext to the desired device.
    ///
    /// Does nothing if the ciphertext is already in the desired device
    pub fn move_to_device(&mut self, device: Device) {
        self.ciphertext.move_to_device(device)
    }

    /// Tries to decrypt a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::try_decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// // This is not a trivial ciphertext as we use a client key to encrypt.
    /// let non_trivial = FheBool::encrypt(false, &client_key);
    /// // This is a trivial ciphertext
    /// let trivial = FheBool::encrypt_trivial(true);
    ///
    /// // We can trivial decrypt
    /// let result: Result<bool, _> = trivial.try_decrypt_trivial();
    /// assert_eq!(result, Ok(true));
    ///
    /// // We cannot trivial decrypt
    /// let result: Result<bool, _> = non_trivial.try_decrypt_trivial();
    /// matches!(result, Err(_));
    /// ```
    pub fn try_decrypt_trivial(&self) -> Result<bool, NotTrivialCiphertextError> {
        self.ciphertext.on_cpu().decrypt_trivial()
    }

    /// Returns true if the ciphertext is a trivial encryption
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let non_trivial = FheBool::encrypt(false, &client_key);
    /// assert!(!non_trivial.is_trivial());
    ///
    /// let trivial = FheBool::encrypt_trivial(true);
    /// assert!(trivial.is_trivial());
    /// ```
    pub fn is_trivial(&self) -> bool {
        self.ciphertext.on_cpu().is_trivial()
    }
}

impl<Id> IfThenElse<FheUint<Id>> for FheBool
where
    Id: FheUintId,
{
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// - if `self` is true, the output will have the value of `ct_then`
    /// - if `self` is false, the output will have the value of `ct_else`
    fn if_then_else(&self, ct_then: &FheUint<Id>, ct_else: &FheUint<Id>) -> FheUint<Id> {
        let ct_condition = self;
        global_state::with_internal_keys(|sks| match sks {
            InternalServerKey::Cpu(cpu_sks) => {
                let inner = cpu_sks.pbs_key().if_then_else_parallelized(
                    &ct_condition.ciphertext.on_cpu(),
                    &*ct_then.ciphertext.on_cpu(),
                    &*ct_else.ciphertext.on_cpu(),
                );
                FheUint::new(inner)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key.key.if_then_else(
                    &self.ciphertext.on_gpu(),
                    &ct_then.ciphertext.on_gpu(),
                    &ct_else.ciphertext.on_gpu(),
                    stream,
                );

                FheUint::new(inner)
            }),
        })
    }
}

impl<Id: FheIntId> IfThenElse<FheInt<Id>> for FheBool {
    /// Conditional selection.
    ///
    /// The output value returned depends on the value of `self`.
    ///
    /// - if `self` is true, the output will have the value of `ct_then`
    /// - if `self` is false, the output will have the value of `ct_else`
    fn if_then_else(&self, ct_then: &FheInt<Id>, ct_else: &FheInt<Id>) -> FheInt<Id> {
        let ct_condition = self;
        let new_ct = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => key.pbs_key().if_then_else_parallelized(
                &ct_condition.ciphertext.on_cpu(),
                &ct_then.ciphertext,
                &ct_else.ciphertext,
            ),
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                panic!("Cuda devices do not support signed integers")
            }
        });

        FheInt::new(new_ct)
    }
}

impl<B> FheEq<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Test for equality between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a.eq(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true == false);
    /// ```
    fn eq(&self, other: B) -> Self {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key.pbs_key().key.equal(
                    self.ciphertext.on_cpu().as_ref(),
                    other.borrow().ciphertext.on_cpu().as_ref(),
                );
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key.key.eq(
                    &self.ciphertext.on_gpu(),
                    &other.borrow().ciphertext.on_gpu(),
                    stream,
                );
                InnerBoolean::Cuda(inner)
            }),
        });
        Self::new(ciphertext)
    }

    /// Test for difference between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a.ne(&b);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true != false);
    /// ```
    fn ne(&self, other: B) -> Self {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key.pbs_key().key.not_equal(
                    self.ciphertext.on_cpu().as_ref(),
                    other.borrow().ciphertext.on_cpu().as_ref(),
                );
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key.key.ne(
                    &self.ciphertext.on_gpu(),
                    &other.borrow().ciphertext.on_gpu(),
                    stream,
                );
                InnerBoolean::Cuda(inner)
            }),
        });
        Self::new(ciphertext)
    }
}

impl FheEq<bool> for FheBool {
    /// Test for equality between a [FheBool] and a [bool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a.eq(false);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true == false);
    /// ```
    fn eq(&self, other: bool) -> FheBool {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key
                    .pbs_key()
                    .key
                    .scalar_equal(self.ciphertext.on_cpu().as_ref(), u8::from(other));
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner =
                    cuda_key
                        .key
                        .scalar_eq(&self.ciphertext.on_gpu(), u8::from(other), stream);
                InnerBoolean::Cuda(inner)
            }),
        });
        Self::new(ciphertext)
    }

    /// Test for equality between a [FheBool] and a [bool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    ///
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a.ne(false);
    ///
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true != false);
    /// ```
    fn ne(&self, other: bool) -> FheBool {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key
                    .pbs_key()
                    .key
                    .scalar_not_equal(self.ciphertext.on_cpu().as_ref(), u8::from(other));
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner =
                    cuda_key
                        .key
                        .scalar_ne(&self.ciphertext.on_gpu(), u8::from(other), stream);
                InnerBoolean::Cuda(inner)
            }),
        });
        Self::new(ciphertext)
    }
}

impl<B> BitAnd<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'and' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a & &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true & true);
    /// ```
    fn bitand(self, rhs: B) -> Self::Output {
        BitAnd::bitand(&self, rhs)
    }
}

impl<B> BitAnd<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;
    /// Performs a bitwise 'and' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a & &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true & true);
    /// ```
    fn bitand(self, rhs: B) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .boolean_bitand(&self.ciphertext.on_cpu(), &rhs.borrow().ciphertext.on_cpu());
                InnerBoolean::Cpu(inner_ct)
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct = cuda_key.key.bitand(
                    &self.ciphertext.on_gpu(),
                    &rhs.borrow().ciphertext.on_gpu(),
                    stream,
                );
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl<B> BitOr<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = a | &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor(self, rhs: B) -> Self::Output {
        BitOr::bitor(&self, rhs)
    }
}

impl<B> BitOr<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;

    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(false, &client_key);
    ///
    /// let result = &a | &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor(self, rhs: B) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key.pbs_key().key.bitor(
                    self.ciphertext.on_cpu().as_ref(),
                    rhs.borrow().ciphertext.on_cpu().as_ref(),
                );
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct = cuda_key.key.bitor(
                    &self.ciphertext.on_gpu(),
                    &rhs.borrow().ciphertext.on_gpu(),
                    stream,
                );
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl<B> BitXor<B> for FheBool
where
    B: Borrow<Self>,
{
    type Output = Self;

    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true ^ true);
    /// ```
    fn bitxor(self, rhs: B) -> Self::Output {
        BitXor::bitxor(&self, rhs)
    }
}

impl<B> BitXor<B> for &FheBool
where
    B: Borrow<FheBool>,
{
    type Output = FheBool;

    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a ^ &b;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, true ^ true);
    /// ```
    fn bitxor(self, rhs: B) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key.pbs_key().key.bitxor(
                    self.ciphertext.on_cpu().as_ref(),
                    rhs.borrow().ciphertext.on_cpu().as_ref(),
                );
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct = cuda_key.key.bitxor(
                    &self.ciphertext.on_gpu(),
                    &rhs.borrow().ciphertext.on_gpu(),
                    stream,
                );
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl BitAnd<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a & false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true & false);
    /// ```
    fn bitand(self, rhs: bool) -> Self::Output {
        <&Self as BitAnd<bool>>::bitand(&self, rhs)
    }
}

impl BitAnd<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = &a & false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true & false);
    /// ```
    fn bitand(self, rhs: bool) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitand(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct =
                    cuda_key
                        .key
                        .scalar_bitand(&self.ciphertext.on_gpu(), u8::from(rhs), stream);
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl BitOr<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a | false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true | false);
    /// ```
    fn bitor(self, rhs: bool) -> Self::Output {
        <&Self as BitOr<bool>>::bitor(&self, rhs)
    }
}

impl BitOr<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a | false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true | false);
    /// ```
    fn bitor(self, rhs: bool) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitor(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct =
                    cuda_key
                        .key
                        .scalar_bitor(&self.ciphertext.on_gpu(), u8::from(rhs), stream);
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl BitXor<bool> for FheBool {
    type Output = Self;

    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true ^ false);
    /// ```
    fn bitxor(self, rhs: bool) -> Self::Output {
        <&Self as BitXor<bool>>::bitxor(&self, rhs)
    }
}

impl BitXor<bool> for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = a ^ false;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, true ^ false);
    /// ```
    fn bitxor(self, rhs: bool) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner_ct = key
                    .pbs_key()
                    .key
                    .scalar_bitxor(self.ciphertext.on_cpu().as_ref(), u8::from(rhs));
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner_ct))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner_ct =
                    cuda_key
                        .key
                        .scalar_bitxor(&self.ciphertext.on_gpu(), u8::from(rhs), stream);
                InnerBoolean::Cuda(inner_ct)
            }),
        });
        FheBool::new(ciphertext)
    }
}

impl BitAnd<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false & a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false & true);
    /// ```
    fn bitand(self, rhs: FheBool) -> Self::Output {
        rhs & self
    }
}

impl BitAnd<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'and' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false & &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false & true);
    /// ```
    fn bitand(self, rhs: &FheBool) -> Self::Output {
        // and is commutative
        rhs & self
    }
}

impl BitOr<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false | a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false | true);
    /// ```
    fn bitor(self, rhs: FheBool) -> Self::Output {
        rhs | self
    }
}

impl BitOr<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'or' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false | &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false | true);
    /// ```
    fn bitor(self, rhs: &FheBool) -> Self::Output {
        // or is commutative
        rhs | self
    }
}

impl BitXor<FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false ^ a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false ^ true);
    /// ```
    fn bitxor(self, rhs: FheBool) -> Self::Output {
        // xor is commutative
        rhs ^ self
    }
}

impl BitXor<&FheBool> for bool {
    type Output = FheBool;

    /// Performs a bitwise 'xor' between a bool and a [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = false ^ &a;
    /// let decrypted = result.decrypt(&client_key);
    /// assert_eq!(decrypted, false ^ true);
    /// ```
    fn bitxor(self, rhs: &FheBool) -> Self::Output {
        // xor is commutative
        rhs ^ self
    }
}

impl<B> BitAndAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = true;
    ///
    /// a &= b;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true & true);
    /// ```
    fn bitand_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitand_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitand_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        });
    }
}

impl<B> BitOrAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'or' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// a |= &b;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true | true);
    /// ```
    fn bitor_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitor_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitor_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        });
    }
}

impl<B> BitXorAssign<B> for FheBool
where
    B: Borrow<Self>,
{
    /// Performs a bitwise 'xor' between two [FheBool]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    /// let b = FheBool::encrypt(true, &client_key);
    ///
    /// a ^= &b;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true ^ true);
    /// ```
    fn bitxor_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key().key.bitxor_assign(
                    &mut self.ciphertext.as_cpu_mut().0,
                    &rhs.ciphertext.on_cpu().0,
                );
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.bitxor_assign(
                    self.ciphertext.as_gpu_mut(),
                    &rhs.ciphertext.on_gpu(),
                    stream,
                );
            }),
        });
    }
}

impl BitAndAssign<bool> for FheBool {
    /// Performs a bitwise 'and' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a &= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true & false);
    /// ```
    fn bitand_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitand_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.scalar_bitand_assign(
                    self.ciphertext.as_gpu_mut(),
                    u8::from(rhs),
                    stream,
                );
            }),
        });
    }
}

impl BitOrAssign<bool> for FheBool {
    /// Performs a bitwise 'or' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a |= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true | false);
    /// ```
    fn bitor_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitor_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.scalar_bitor_assign(
                    self.ciphertext.as_gpu_mut(),
                    u8::from(rhs),
                    stream,
                );
            }),
        });
    }
}

impl BitXorAssign<bool> for FheBool {
    /// Performs a bitwise 'xor' between [FheBool] and a bool
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let mut a = FheBool::encrypt(true, &client_key);
    ///
    /// a ^= false;
    /// let result = a.decrypt(&client_key);
    /// assert_eq!(result, true ^ false);
    /// ```
    fn bitxor_assign(&mut self, rhs: bool) {
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.pbs_key()
                    .key
                    .scalar_bitxor_assign(&mut self.ciphertext.as_cpu_mut().0, u8::from(rhs));
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                cuda_key.key.scalar_bitxor_assign(
                    self.ciphertext.as_gpu_mut(),
                    u8::from(rhs),
                    stream,
                );
            }),
        });
    }
}

impl std::ops::Not for FheBool {
    type Output = Self;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = !a;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, false);
    /// ```
    fn not(self) -> Self::Output {
        (&self).not()
    }
}

impl std::ops::Not for &FheBool {
    type Output = FheBool;

    /// Performs a bitwise 'not'
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tfhe::prelude::*;
    /// # use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};
    /// #
    /// # let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    /// set_server_key(server_key);
    ///
    /// let a = FheBool::encrypt(true, &client_key);
    ///
    /// let result = !&a;
    /// let result = result.decrypt(&client_key);
    /// assert_eq!(result, false);
    /// ```
    fn not(self) -> Self::Output {
        let ciphertext = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let inner = key
                    .pbs_key()
                    .key
                    .scalar_bitxor(self.ciphertext.on_cpu().as_ref(), 1);
                InnerBoolean::Cpu(BooleanBlock::new_unchecked(inner))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_stream(|stream| {
                let inner = cuda_key
                    .key
                    .scalar_bitxor(&self.ciphertext.on_gpu(), 1, stream);
                InnerBoolean::Cuda(inner)
            }),
        });
        FheBool::new(ciphertext)
    }
}
