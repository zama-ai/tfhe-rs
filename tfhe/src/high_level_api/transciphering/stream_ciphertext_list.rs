use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::prelude::Numeric;
use crate::high_level_api::backward_compatibility::transciphering::StreamCiphertextListVersions;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::transciphering::{
    IntegerStreamCiphertextList, IntegerStreamCiphertextListBuilder,
    IntegerStreamCiphertextListConformanceParams, StreamPackable,
};
use crate::named::Named;
use crate::transciphering::StreamCipher;

/// A list of values encrypted with a single stream of a symmetric cipher, built with a
/// [`StreamCiphertextListBuilder`] and consumed by [`HlTranscipherer::transcipher_list`].
///
/// Like a [`StreamCiphertext`], it holds no FHE ciphertext.
///
/// [`HlTranscipherer::transcipher_list`]: super::HlTranscipherer::transcipher_list
/// [`StreamCiphertext`]: super::StreamCiphertext
/// [`Tag`]: crate::Tag
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(StreamCiphertextListVersions)]
pub struct StreamCiphertextList {
    inner: IntegerStreamCiphertextList,
}

impl StreamCiphertextList {
    pub fn builder() -> StreamCiphertextListBuilder {
        StreamCiphertextListBuilder::new()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Number of keystream bits used by the list
    pub fn n_bits(&self) -> usize {
        self.inner.inner().n_bits()
    }

    pub(super) fn integer(&self) -> &IntegerStreamCiphertextList {
        &self.inner
    }
}

impl ParameterSetConformant for StreamCiphertextList {
    type ParameterSet = IntegerStreamCiphertextListConformanceParams;

    fn is_conformant(&self, params: &Self::ParameterSet) -> bool {
        self.inner.is_conformant(params)
    }
}

impl Named for StreamCiphertextList {
    const NAME: &'static str = "high_level_api::StreamCiphertextList";
}

pub trait HlStreamPackable: StreamPackable {}

impl HlStreamPackable for bool {}

impl<T> HlStreamPackable for T where
    T: DecomposableInto<u8> + Numeric + std::ops::Shl<usize, Output = T>
{
}

#[derive(Default)]
pub struct StreamCiphertextListBuilder {
    inner: IntegerStreamCiphertextListBuilder,
}

impl StreamCiphertextListBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: HlStreamPackable,
    {
        self.inner.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: HlStreamPackable,
    {
        self.inner.extend(values);
        self
    }

    /// For integers, the server only accepts an `n_bits` that is a multiple of the number of
    /// message bits per block of its parameters (2 with the default parameters).
    ///
    /// # Panics
    /// Panics if `n_bits == 0`.
    pub fn push_with_num_bits<T>(&mut self, value: T, n_bits: usize) -> &mut Self
    where
        T: HlStreamPackable + Numeric,
    {
        self.inner.push_with_num_bits(value, n_bits);
        self
    }

    /// See [`Self::push_with_num_bits`]
    pub fn extend_with_num_bits<T>(
        &mut self,
        values: impl Iterator<Item = T>,
        n_bits: usize,
    ) -> &mut Self
    where
        T: HlStreamPackable + Numeric,
    {
        self.inner.extend_with_num_bits(values, n_bits);
        self
    }

    /// Number of keystream bits needed to build the list
    pub fn n_bits(&self) -> usize {
        self.inner.n_bits()
    }

    /// Encrypts the pushed values with the next [`Self::n_bits`] bits of keystream of `cipher`
    ///
    /// Errors if the cipher's keystream is exhausted.
    pub fn build<C>(&self, cipher: &mut C) -> crate::Result<StreamCiphertextList>
    where
        C: StreamCipher + ?Sized,
    {
        self.inner
            .build(cipher)
            .map(|inner| StreamCiphertextList { inner })
            .map_err(|e| crate::error!("{e}"))
    }
}
