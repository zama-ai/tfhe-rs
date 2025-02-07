use crate::integer::{BooleanBlock, ServerKey as IntegerServerKey};
use crate::strings::ciphertext::{FheString, GenericPatternRef, UIntArg};
use crate::strings::server_key::pattern::split::{
    SplitInternal, SplitNInternal, SplitNoLeading, SplitNoTrailing, SplitType,
};
use crate::strings::server_key::{FheStringIterator, ServerKey};
use std::borrow::Borrow;

pub struct RSplit {
    internal: SplitInternal,
}

pub struct Split {
    internal: SplitInternal,
}

pub struct SplitInclusive {
    internal: SplitNoTrailing,
}

pub struct RSplitN {
    internal: SplitNInternal,
}

pub struct SplitN {
    internal: SplitNInternal,
}

pub struct SplitTerminator {
    internal: SplitNoTrailing,
}

pub struct RSplitTerminator {
    internal: SplitNoLeading,
}

impl<T: Borrow<IntegerServerKey> + Sync> ServerKey<T> {
    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear).
    ///
    /// The iterator, of type `Split`, can be used to sequentially retrieve the substrings. Each
    /// call to `next` on the iterator returns a tuple with the next split substring as an encrypted
    /// string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello ", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// let mut split_iter = sk.split(&enc_s, enc_pat.as_ref());
    /// let (first_item, first_is_some) = split_iter.next(&sk);
    /// let (second_item, second_is_some) = split_iter.next(&sk);
    /// let (_, no_more_items) = split_iter.next(&sk); // Attempting to get a third item
    ///
    /// let first_decrypted = ck.decrypt_ascii(&first_item);
    /// let first_is_some = ck.inner().decrypt_bool(&first_is_some);
    /// let second_decrypted = ck.decrypt_ascii(&second_item);
    /// let second_is_some = ck.inner().decrypt_bool(&second_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(first_decrypted, "hello");
    /// assert!(first_is_some); // There is a first item
    /// assert_eq!(second_decrypted, "");
    /// assert!(second_is_some); // There is a second item
    /// assert!(!no_more_items); // No more items in the iterator
    /// ```
    pub fn split(&self, str: &FheString, pat: GenericPatternRef<'_>) -> Split {
        let internal = self.split_internal(str, pat, SplitType::Split);

        Split { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from
    /// the end based on a specified pattern (either encrypted or clear).
    ///
    /// The iterator, of type `RSplit`, can be used to sequentially retrieve the substrings in
    /// reverse order. Each call to `next` on the iterator returns a tuple with the next split
    /// substring as an encrypted string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello ", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// let mut rsplit_iter = sk.rsplit(&enc_s, enc_pat.as_ref());
    /// let (last_item, last_is_some) = rsplit_iter.next(&sk);
    /// let (second_last_item, second_last_is_some) = rsplit_iter.next(&sk);
    /// let (_, no_more_items) = rsplit_iter.next(&sk); // Attempting to get a third item
    ///
    /// let last_decrypted = ck.decrypt_ascii(&last_item);
    /// let last_is_some = ck.inner().decrypt_bool(&last_is_some);
    /// let second_last_decrypted = ck.decrypt_ascii(&second_last_item);
    /// let second_last_is_some = ck.inner().decrypt_bool(&second_last_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(last_decrypted, "");
    /// assert!(last_is_some); // The last item is empty
    /// assert_eq!(second_last_decrypted, "hello");
    /// assert!(second_last_is_some); // The second last item is "hello"
    /// assert!(!no_more_items); // No more items in the reverse iterator
    /// ```
    pub fn rsplit(&self, str: &FheString, pat: GenericPatternRef<'_>) -> RSplit {
        let internal = self.split_internal(str, pat, SplitType::RSplit);

        RSplit { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), limited to at most `n` results.
    ///
    /// The `n` is specified by a `UIntArg`, which can be either `Clear` or `Enc`. The iterator, of
    /// type `SplitN`, can be used to sequentially retrieve the substrings. Each call to `next` on
    /// the iterator returns a tuple with the next split substring as an encrypted string and a
    /// boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern, UIntArg};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello world", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// // Using Clear count
    /// let clear_count = UIntArg::Clear(1);
    /// let mut splitn_iter = sk.splitn(&enc_s, enc_pat.as_ref(), clear_count);
    /// let (first_item, first_is_some) = splitn_iter.next(&sk);
    /// let (_, no_more_items) = splitn_iter.next(&sk); // Attempting to get a second item
    ///
    /// let first_decrypted = ck.decrypt_ascii(&first_item);
    /// let first_is_some = ck.inner().decrypt_bool(&first_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// // We get the whole str as n is 1
    /// assert_eq!(first_decrypted, "hello world");
    /// assert!(first_is_some);
    /// assert!(!no_more_items);
    ///
    /// // Using Encrypted count
    /// let max = 2; // Restricts the range of enc_n to 0..=max
    /// let enc_n = ck.encrypt_u16(1, Some(max));
    /// let enc_count = UIntArg::Enc(enc_n);
    /// let _splitn_iter_enc = sk.splitn(&enc_s, enc_pat.as_ref(), enc_count);
    /// // Similar usage as with Clear count
    /// ```
    pub fn splitn(&self, str: &FheString, pat: GenericPatternRef<'_>, n: UIntArg) -> SplitN {
        let internal = self.splitn_internal(str, pat, n, SplitType::Split);

        SplitN { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from
    /// the end based on a specified pattern (either encrypted or clear), limited to at most `n`
    /// results.
    ///
    /// The `n` is specified by a `UIntArg`, which can be either `Clear` or `Enc`. The iterator, of
    /// type `RSplitN`, can be used to sequentially retrieve the substrings in reverse order. Each
    /// call to `next` on the iterator returns a tuple with the next split substring as an encrypted
    /// string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern, UIntArg};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello world", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// // Using Clear count
    /// let clear_count = UIntArg::Clear(1);
    /// let mut rsplitn_iter = sk.rsplitn(&enc_s, enc_pat.as_ref(), clear_count);
    /// let (last_item, last_is_some) = rsplitn_iter.next(&sk);
    /// let (_, no_more_items) = rsplitn_iter.next(&sk); // Attempting to get a second item
    ///
    /// let last_decrypted = ck.decrypt_ascii(&last_item);
    /// let last_is_some = ck.inner().decrypt_bool(&last_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// // We get the whole str as n is 1
    /// assert_eq!(last_decrypted, "hello world");
    /// assert!(last_is_some);
    /// assert!(!no_more_items);
    ///
    /// // Using Encrypted count
    /// let max = 2; // Restricts the range of enc_n to 0..=max
    /// let enc_n = ck.encrypt_u16(1, Some(max));
    /// let enc_count = UIntArg::Enc(enc_n);
    /// let _rsplitn_iter_enc = sk.rsplitn(&enc_s, enc_pat.as_ref(), enc_count);
    /// // Similar usage as with Clear count
    /// ```
    pub fn rsplitn(&self, str: &FheString, pat: GenericPatternRef<'_>, n: UIntArg) -> RSplitN {
        let internal = self.splitn_internal(str, pat, n, SplitType::RSplit);

        RSplitN { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), excluding trailing empty substrings.
    ///
    /// The iterator, of type `SplitTerminator`, can be used to sequentially retrieve the
    /// substrings. Each call to `next` on the iterator returns a tuple with the next split
    /// substring as an encrypted string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello world ", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// let mut split_terminator_iter = sk.split_terminator(&enc_s, enc_pat.as_ref());
    /// let (first_item, first_is_some) = split_terminator_iter.next(&sk);
    /// let (second_item, second_is_some) = split_terminator_iter.next(&sk);
    /// let (_, no_more_items) = split_terminator_iter.next(&sk); // Attempting to get a third item
    ///
    /// let first_decrypted = ck.decrypt_ascii(&first_item);
    /// let first_is_some = ck.inner().decrypt_bool(&first_is_some);
    /// let second_decrypted = ck.decrypt_ascii(&second_item);
    /// let second_is_some = ck.inner().decrypt_bool(&second_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(first_decrypted, "hello");
    /// assert!(first_is_some); // There is a first item
    /// assert_eq!(second_decrypted, "world");
    /// assert!(second_is_some); // There is a second item
    /// assert!(!no_more_items); // No more items in the iterator
    /// ```
    pub fn split_terminator(&self, str: &FheString, pat: GenericPatternRef<'_>) -> SplitTerminator {
        let internal = self.split_no_trailing(str, pat, SplitType::Split);

        SplitTerminator { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string from
    /// the end based on a specified pattern (either encrypted or clear), excluding leading empty
    /// substrings in the reverse order.
    ///
    /// The iterator, of type `RSplitTerminator`, can be used to sequentially retrieve the
    /// substrings in reverse order, ignoring any leading empty substring that would result from
    /// splitting at the end of the string. Each call to `next` on the iterator returns a tuple with
    /// the next split substring as an encrypted string and a boolean indicating `Some` (true) or
    /// `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello world ", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// let mut rsplit_terminator_iter = sk.rsplit_terminator(&enc_s, enc_pat.as_ref());
    /// let (last_item, last_is_some) = rsplit_terminator_iter.next(&sk);
    /// let (second_last_item, second_last_is_some) = rsplit_terminator_iter.next(&sk);
    /// let (_, no_more_items) = rsplit_terminator_iter.next(&sk); // Attempting to get a third item
    ///
    /// let last_decrypted = ck.decrypt_ascii(&last_item);
    /// let last_is_some = ck.inner().decrypt_bool(&last_is_some);
    /// let second_last_decrypted = ck.decrypt_ascii(&second_last_item);
    /// let second_last_is_some = ck.inner().decrypt_bool(&second_last_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(last_decrypted, "world");
    /// assert!(last_is_some); // The last item is "world" instead of ""
    /// assert_eq!(second_last_decrypted, "hello");
    /// assert!(second_last_is_some); // The second last item is "hello"
    /// assert!(!no_more_items); // No more items in the reverse iterator
    /// ```
    pub fn rsplit_terminator(
        &self,
        str: &FheString,
        pat: GenericPatternRef<'_>,
    ) -> RSplitTerminator {
        let internal = self.split_no_leading(str, pat);

        RSplitTerminator { internal }
    }

    /// Creates an iterator of encrypted substrings by splitting the original encrypted string based
    /// on a specified pattern (either encrypted or clear), where each substring includes the
    /// delimiter. If the string ends with the delimiter, it does not create a trailing empty
    /// substring.
    ///
    /// The iterator, of type `SplitInclusive`, can be used to sequentially retrieve the substrings.
    /// Each call to `next` on the iterator returns a tuple with the next split substring as an
    /// encrypted string and a boolean indicating `Some` (true) or `None` (false).
    ///
    /// The pattern to search for can be specified as either `GenericPatternRef::Clear` for a clear
    /// string or `GenericPatternRef::Enc` for an encrypted string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tfhe::integer::{ClientKey, ServerKey};
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// use tfhe::strings::ciphertext::{FheString, GenericPattern};
    /// use tfhe::strings::server_key::FheStringIterator;
    ///
    /// let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    /// let sk = ServerKey::new_radix_server_key(&ck);
    /// let ck = tfhe::strings::ClientKey::new(ck);
    /// let sk = tfhe::strings::ServerKey::new(sk);
    /// let (s, pat) = ("hello world ", " ");
    ///
    /// let enc_s = FheString::new(&ck, s, None);
    /// let enc_pat = GenericPattern::Enc(FheString::new(&ck, pat, None));
    ///
    /// let mut split_inclusive_iter = sk.split_inclusive(&enc_s, enc_pat.as_ref());
    /// let (first_item, first_is_some) = split_inclusive_iter.next(&sk);
    /// let (second_item, second_is_some) = split_inclusive_iter.next(&sk);
    /// let (_, no_more_items) = split_inclusive_iter.next(&sk); // Attempting to get a third item
    ///
    /// let first_decrypted = ck.decrypt_ascii(&first_item);
    /// let first_is_some = ck.inner().decrypt_bool(&first_is_some);
    /// let second_decrypted = ck.decrypt_ascii(&second_item);
    /// let second_is_some = ck.inner().decrypt_bool(&second_is_some);
    /// let no_more_items = ck.inner().decrypt_bool(&no_more_items);
    ///
    /// assert_eq!(first_decrypted, "hello ");
    /// assert!(first_is_some); // The first item includes the delimiter
    /// assert_eq!(second_decrypted, "world ");
    /// assert!(second_is_some); // The second item includes the delimiter
    /// assert!(!no_more_items); // No more items in the iterator, no trailing empty string
    /// ```
    pub fn split_inclusive(&self, str: &FheString, pat: GenericPatternRef<'_>) -> SplitInclusive {
        let internal = self.split_no_trailing(str, pat, SplitType::SplitInclusive);

        SplitInclusive { internal }
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for Split {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for RSplit {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for SplitN {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for RSplitN {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for SplitTerminator {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for RSplitTerminator {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}

impl<T: Borrow<IntegerServerKey> + Sync> FheStringIterator<T> for SplitInclusive {
    fn next(&mut self, sk: &ServerKey<T>) -> (FheString, BooleanBlock) {
        self.internal.next(sk)
    }
}
