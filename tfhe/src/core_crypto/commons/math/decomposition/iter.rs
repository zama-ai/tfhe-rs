use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, DecompositionTermNonNative, DecompositionTermSlice,
    DecompositionTermSliceNonNative, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
use dyn_stack::PodStack;

/// An iterator that yields the terms of the signed decomposition of an integer.
///
/// # Warning
///
/// This iterator yields the decomposition in reverse order. That means that the highest level
/// will be yielded first.
pub struct SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    // The base log of the decomposition
    base_log: usize,
    // The number of levels of the decomposition
    level_count: usize,
    // The internal state of the decomposition
    state: T,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: T,
    // A flag which store whether the iterator is a fresh one (for the recompose method)
    fresh: bool,
}

impl<T> SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    pub(crate) fn new(
        input: T,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
    ) -> Self {
        Self {
            base_log: base_log.0,
            level_count: level.0,
            state: input,
            current_level: level.0,
            mod_b_mask: (T::ONE << base_log.0) - T::ONE,
            fresh: true,
        }
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Return the logarithm in base two of the base of this decomposition.
    ///
    /// If the decomposition uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let val = 1_340_987_234_u32;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Return the number of levels of this decomposition.
    ///
    /// If the decomposition uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let val = 1_340_987_234_u32;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }
}

impl<T> Iterator for SignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    type Item = DecompositionTerm<T>;

    fn next(&mut self) -> Option<Self::Item> {
        // The iterator is not fresh anymore
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        // We decompose the current level
        let output = decompose_one_level(self.base_log, &mut self.state, self.mod_b_mask);
        self.current_level -= 1;
        // We return the output for this level
        Some(DecompositionTerm::new(
            DecompositionLevel(self.current_level + 1),
            DecompositionBaseLog(self.base_log),
            output,
        ))
    }
}

/// With
///
/// B = 2^base_log
/// res < B
///
/// returns 1 if the following condition is true otherwise 0
///
/// (res > B / 2) || ((res == B / 2) && ((state % B) >= B / 2));
#[inline(always)]
fn decomposition_bit_trick<Scalar: UnsignedInteger>(
    res: Scalar,
    state: Scalar,
    base_log: usize,
) -> Scalar {
    ((res.wrapping_sub(Scalar::ONE) | state) & res) >> (base_log - 1)
}

#[inline]
pub(crate) fn decompose_one_level<S: UnsignedInteger>(
    base_log: usize,
    state: &mut S,
    mod_b_mask: S,
) -> S {
    let res = *state & mod_b_mask;
    *state = (*state).arithmetic_shr(base_log);
    let carry = decomposition_bit_trick(res, *state, base_log);
    *state = (*state).wrapping_add(carry);
    res.wrapping_sub(carry << base_log)
}

/// An iterator-like object that yields the terms of the signed decomposition of a tensor of values.
///
/// # Note
///
/// On each call to [`SliceSignedDecompositionIter::next_term`], this structure yields a new
/// [`DecompositionTermSlice`], backed by a `Vec` owned by the structure. This vec is mutated at
/// each call of the `next_term` method, and as such the term must be dropped before `next_term` is
/// called again.
///
/// Such a pattern can not be implemented with iterators yet (without GATs), which is why this
/// iterator must be explicitly called.
///
/// # Warning
///
/// This iterator yields the decomposition in reverse order. That means that the highest level
/// will be yielded first.
pub struct SliceSignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    // The base log of the decomposition
    base_log: usize,
    // The number of levels of the decomposition
    level_count: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: T,
    // The internal states of each decomposition
    states: Vec<T>,
    // In order to avoid allocating a new Vec every time we yield a decomposition term, we store
    // a Vec inside the structure and yield slices pointing to it.
    outputs: Vec<T>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
}

impl<T> SliceSignedDecompositionIter<T>
where
    T: UnsignedInteger,
{
    // Creates a new tensor decomposition iterator.
    pub(crate) fn new(
        input: Vec<T>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
    ) -> Self {
        let len = input.len();
        Self {
            base_log: base_log.0,
            level_count: level.0,
            current_level: level.0,
            mod_b_mask: (T::ONE << base_log.0) - T::ONE,
            outputs: vec![T::ZERO; len],
            states: input,
            fresh: true,
        }
    }

    /// Returns the logarithm in base two of the base of this decomposition.
    ///
    /// If the decomposition uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let decomp = decomposer.decompose_slice(&decomposable);
    /// assert_eq!(decomp.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Returns the number of levels of this decomposition.
    ///
    /// If the decomposition uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let decomp = decomposer.decompose_slice(&decomposable);
    /// assert_eq!(decomp.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }

    /// Yield the next term of the decomposition, if any.
    ///
    /// # Note
    ///
    /// Because this function returns a borrowed tensor, owned by the iterator, the term must be
    /// dropped before `next_term` is called again.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
    /// use tfhe::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
    /// let decomposer =
    ///     SignedDecomposer::<u32>::new(DecompositionBaseLog(4), DecompositionLevelCount(3));
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let mut decomp = decomposer.decompose_slice(&decomposable);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(term.level(), DecompositionLevel(3));
    /// assert_eq!(term.as_slice()[0], 4294967295);
    /// ```
    pub fn next_term(&mut self) -> Option<DecompositionTermSlice<'_, T>> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        // We iterate over the elements of the outputs and decompose
        for (output_i, state_i) in self.outputs.iter_mut().zip(self.states.iter_mut()) {
            *output_i = decompose_one_level(self.base_log, state_i, self.mod_b_mask);
        }
        self.current_level -= 1;
        // We return the term tensor.
        Some(DecompositionTermSlice::new(
            DecompositionLevel(self.current_level + 1),
            DecompositionBaseLog(self.base_log),
            &self.outputs,
        ))
    }
}

/// An iterator that yields the terms of the signed decomposition of an integer.
///
/// # Warning
///
/// This iterator yields the decomposition in reverse order. That means that the highest level
/// will be yielded first.
#[derive(Clone, Debug)]
pub struct SignedDecompositionNonNativeIter<T>
where
    T: UnsignedInteger,
{
    // The base log of the decomposition
    base_log: usize,
    // The number of levels of the decomposition
    level_count: usize,
    // The internal state of the decomposition
    state: T,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: T,
    // Ciphertext modulus
    ciphertext_modulus: CiphertextModulus<T>,
    // A flag which store whether the iterator is a fresh one (for the recompose method)
    fresh: bool,
    // The sign of the input value, for the algorithm we use, returned values require an adaptation
    // depending of the sign of the input
    input_sign: ValueSign,
}

#[derive(Debug, Clone, Copy)]
pub enum ValueSign {
    Positive,
    Negative,
}

impl<T> SignedDecompositionNonNativeIter<T>
where
    T: UnsignedInteger,
{
    pub(crate) fn new(
        input: T,
        input_sign: ValueSign,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<T>,
    ) -> Self {
        Self {
            base_log: base_log.0,
            level_count: level.0,
            state: input
                >> (ciphertext_modulus.get_custom_modulus().ceil_ilog2() as usize
                    - base_log.0 * level.0),
            current_level: level.0,
            mod_b_mask: (T::ONE << base_log.0) - T::ONE,
            ciphertext_modulus,
            fresh: true,
            input_sign,
        }
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// Return the logarithm in base two of the base of this decomposition.
    ///
    /// If the decomposition uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let val = 9_223_372_036_854_775_808u64;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Return the number of levels of this decomposition.
    ///
    /// If the decomposition uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::commons::parameters::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap(),
    /// );
    /// let val = 9_223_372_036_854_775_808u64;
    /// let decomp = decomposer.decompose(val);
    /// assert_eq!(decomp.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }
}

impl<T> Iterator for SignedDecompositionNonNativeIter<T>
where
    T: UnsignedInteger,
{
    type Item = DecompositionTermNonNative<T>;

    fn next(&mut self) -> Option<Self::Item> {
        // The iterator is not fresh anymore
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        // We decompose the current level
        let output = decompose_one_level(self.base_log, &mut self.state, self.mod_b_mask);
        let output = match self.input_sign {
            ValueSign::Positive => output,
            ValueSign::Negative => output.wrapping_neg(),
        };
        self.current_level -= 1;
        // We return the output for this level
        Some(DecompositionTermNonNative::new(
            DecompositionLevel(self.current_level + 1),
            DecompositionBaseLog(self.base_log),
            output,
            self.ciphertext_modulus,
        ))
    }
}

/// An iterator-like object that yields the terms of the signed decomposition of a tensor of values.
///
/// # Note
///
/// On each call to [`SliceSignedDecompositionNonNativeIter::next_term`], this structure yields a
/// new
/// [`DecompositionTermSlice`], backed by a `Vec` owned by the structure. This vec is mutated at
/// each call of the `next_term` method, and as such the term must be dropped before `next_term` is
/// called again.
///
/// Such a pattern can not be implemented with iterators yet (without GATs), which is why this
/// iterator must be explicitly called.
///
/// # Warning
///
/// This iterator yields the decomposition in reverse order. That means that the highest level
/// will be yielded first.
pub struct SliceSignedDecompositionNonNativeIter<T>
where
    T: UnsignedInteger,
{
    // The base log of the decomposition
    base_log: usize,
    // The number of levels of the decomposition
    level_count: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: T,
    // Ciphertext modulus
    ciphertext_modulus: CiphertextModulus<T>,
    // The internal states of each decomposition
    states: Vec<T>,
    // In order to avoid allocating a new Vec every time we yield a decomposition term, we store
    // a Vec inside the structure and yield slices pointing to it.
    outputs: Vec<T>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
    // The signs of the input values, for the algorithm we use, returned values require adaption
    // depending on the sign of the input
    signs: Vec<ValueSign>,
}

impl<T> SliceSignedDecompositionNonNativeIter<T>
where
    T: UnsignedInteger,
{
    // Creates a new tensor decomposition iterator.
    pub(crate) fn new(
        mut input: Vec<T>,
        input_signs: Vec<ValueSign>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<T>,
    ) -> Self {
        let remove_zero_lsb_from_rounded = |i: T| {
            i >> (ciphertext_modulus.get_custom_modulus().ceil_ilog2() as usize
                - base_log.0 * level.0)
        };

        for i in &mut input {
            *i = remove_zero_lsb_from_rounded(*i);
        }

        Self {
            base_log: base_log.0,
            level_count: level.0,
            current_level: level.0,
            mod_b_mask: (T::ONE << base_log.0) - T::ONE,
            ciphertext_modulus,
            outputs: vec![T::ZERO; input.len()],
            states: input,
            fresh: true,
            signs: input_signs,
        }
    }

    /// Returns the logarithm in base two of the base of this decomposition.
    ///
    /// If the decomposition uses a base $B=2^b$, this returns $b$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u32>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 32) - (1 << 16) + 1).unwrap(),
    /// );
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let decomp = decomposer.decompose_slice(&decomposable);
    /// assert_eq!(decomp.base_log(), DecompositionBaseLog(4));
    /// ```
    pub fn base_log(&self) -> DecompositionBaseLog {
        DecompositionBaseLog(self.base_log)
    }

    /// Returns the number of levels of this decomposition.
    ///
    /// If the decomposition uses $l$ levels, this returns $l$.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u32>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 32) - (1 << 16) + 1).unwrap(),
    /// );
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let decomp = decomposer.decompose_slice(&decomposable);
    /// assert_eq!(decomp.level_count(), DecompositionLevelCount(3));
    /// ```
    pub fn level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.level_count)
    }

    /// Yield the next term of the decomposition, if any.
    ///
    /// # Note
    ///
    /// Because this function returns a borrowed tensor, owned by the iterator, the term must be
    /// dropped before `next_term` is called again.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::math::decomposition::{
    ///     DecompositionLevel, SignedDecomposerNonNative,
    /// };
    /// use tfhe::core_crypto::prelude::{
    ///     CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    /// };
    /// let decomposer = SignedDecomposerNonNative::<u32>::new(
    ///     DecompositionBaseLog(4),
    ///     DecompositionLevelCount(3),
    ///     CiphertextModulus::try_new((1 << 32) - (1 << 16) + 1).unwrap(),
    /// );
    /// let decomposable = vec![1_340_987_234_u32; 2];
    /// let mut decomp = decomposer.decompose_slice(&decomposable);
    /// let term = decomp.next_term().unwrap();
    /// assert_eq!(term.level(), DecompositionLevel(3));
    /// assert_eq!(term.as_slice()[0], u32::MAX);
    /// ```
    pub fn next_term(&mut self) -> Option<DecompositionTermSliceNonNative<'_, T>> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        // We iterate over the elements of the outputs and decompose
        for ((output_i, state_i), sign_i) in self
            .outputs
            .iter_mut()
            .zip(self.states.iter_mut())
            .zip(self.signs.iter())
        {
            *output_i = decompose_one_level(self.base_log, state_i, self.mod_b_mask);
            *output_i = match sign_i {
                ValueSign::Positive => *output_i,
                ValueSign::Negative => output_i.wrapping_neg(),
            };
        }
        self.current_level -= 1;
        // We return the term tensor.
        Some(DecompositionTermSliceNonNative::new(
            DecompositionLevel(self.current_level + 1),
            DecompositionBaseLog(self.base_log),
            &self.outputs,
            self.ciphertext_modulus,
        ))
    }
}

/// Specialized high performance implementation of a non native decomposer over a collection of
/// elements, used notably in the PBS.
pub struct TensorSignedDecompositionLendingIterNonNative<'buffers> {
    // The base log of the decomposition
    base_log: usize,
    // The current level
    current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: u64,
    // The internal states of each decomposition
    states: &'buffers mut [u64],
    // Corresponding input signs
    input_signs: &'buffers mut [u8],
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
    ciphertext_modulus: u64,
}

impl<'buffers> TensorSignedDecompositionLendingIterNonNative<'buffers> {
    #[inline]
    pub(crate) fn new(
        decomposer: &SignedDecomposerNonNative<u64>,
        input: &[u64],
        modulus: u64,
        stack: &'buffers mut PodStack,
    ) -> (Self, &'buffers mut PodStack) {
        let shift = modulus.ceil_ilog2() as usize - decomposer.base_log * decomposer.level_count;
        let input_size = input.len();
        let (states, stack) =
            stack.make_aligned_raw::<u64>(input_size, aligned_vec::CACHELINE_ALIGN);
        let (input_signs, stack) =
            stack.make_aligned_raw::<u8>(input_size, aligned_vec::CACHELINE_ALIGN);

        for ((i, state), sign) in input
            .iter()
            .copied()
            .zip(states.iter_mut())
            .zip(input_signs.iter_mut())
        {
            if i < modulus.div_ceil(2) {
                *state = decomposer.closest_representable(i) >> shift;
                *sign = 0;
            } else {
                *state = decomposer.closest_representable(modulus - i) >> shift;
                *sign = 1;
            }
        }

        let base_log = decomposer.base_log();
        let level_count = decomposer.level_count();
        (
            TensorSignedDecompositionLendingIterNonNative {
                base_log: base_log.0,
                current_level: level_count.0,
                mod_b_mask: (1u64 << base_log.0) - 1u64,
                states,
                input_signs,
                fresh: true,
                ciphertext_modulus: modulus,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term(
        &mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        impl Iterator<Item = u64> + '_,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        let current_level = self.current_level;
        let base_log = self.base_log;
        let mod_b_mask = self.mod_b_mask;
        let modulus = self.ciphertext_modulus;
        self.current_level -= 1;

        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(self.base_log),
            self.states
                .iter_mut()
                .zip(self.input_signs.iter().copied())
                .map(move |(state, input_sign)| {
                    let decomp_term = decompose_one_level(base_log, state, mod_b_mask);
                    let decomp_term = if input_sign == 0 {
                        decomp_term
                    } else {
                        decomp_term.wrapping_neg()
                    };

                    if decomp_term as i64 >= 0 {
                        decomp_term
                    } else {
                        // decomp_term being negative, we get a value smaller than modulus which is
                        // what we want
                        modulus.wrapping_add(decomp_term)
                    }
                }),
        ))
    }

    #[cfg_attr(feature = "__profiling", inline(never))]
    pub fn collect_next_term<'a>(
        &mut self,
        substack1: &'a mut PodStack,
        align: usize,
    ) -> (DecompositionLevel, &'a mut [u64], &'a mut PodStack) {
        let (glwe_level, _, glwe_decomp_term) = self.next_term().unwrap();
        let (glwe_decomp_term, substack2) = substack1.collect_aligned(align, glwe_decomp_term);
        (glwe_level, glwe_decomp_term, substack2)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decomp_bit_trick() {
        for rep_bit_count in 1..13 {
            println!("{rep_bit_count}");
            let b = 1u64 << rep_bit_count;
            let b_over_2 = b / 2;

            for val in 0..b {
                // Have a chance to sample all values in 0..b at least once, here we expect on
                // average about 10 occurrence for each value in the range
                for _ in 0..10 * b {
                    let state: u64 = rand::random();
                    let test_val =
                        (val > b_over_2) || ((val == b_over_2) && ((state % b) >= b_over_2));
                    let bit_trick = decomposition_bit_trick(val, state, rep_bit_count);
                    let bit_trick_as_bool = if bit_trick == 1 {
                        true
                    } else if bit_trick == 0 {
                        false
                    } else {
                        panic!("Bit trick result was not a bit.");
                    };

                    assert_eq!(
                        test_val, bit_trick_as_bool,
                        "\nval    ={val}\n\
                           val_b  ={val:064b}\n\
                           state  ={state}\n\
                           state_b={state:064b}\n\
                           expected: {test_val}\n\
                           got     : {bit_trick_as_bool}"
                    );
                }
            }
        }
    }
}
