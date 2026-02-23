use crate::high_level_api::backward_compatibility::tag::TagVersions;
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

const STACK_ARRAY_SIZE: usize = std::mem::size_of::<Vec<u8>>() - 1;

/// Simple short optimized vec, where if the data is small enough
/// (<= std::mem::size_of::<Vec<u8>>() - 1) the data will be stored on the stack
///
/// Once a true heap allocated Vec was needed, it won't be deallocated in favor
/// of stack data.
#[derive(Clone, Debug)]
pub(in crate::high_level_api) enum SmallVec {
    Stack {
        bytes: [u8; STACK_ARRAY_SIZE],
        // The array has a fixed size, but the user may not use all of it
        // so we keep track of the actual len
        len: u8,
    },
    Heap(Vec<u8>),
}

impl Default for SmallVec {
    fn default() -> Self {
        Self::Stack {
            bytes: Default::default(),
            len: 0,
        }
    }
}
impl PartialEq for SmallVec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Stack {
                    bytes: l_bytes,
                    len: l_len,
                },
                Self::Stack {
                    bytes: r_bytes,
                    len: r_len,
                },
            ) => l_len == r_len && l_bytes[..usize::from(*l_len)] == r_bytes[..usize::from(*l_len)],
            (Self::Heap(l_vec), Self::Heap(r_vec)) => l_vec == r_vec,
            (
                Self::Heap(l_vec),
                Self::Stack {
                    bytes: r_bytes,
                    len: r_len,
                },
            ) => l_vec.len() == usize::from(*r_len) && l_vec == &r_bytes[..usize::from(*r_len)],
            (
                Self::Stack {
                    bytes: l_bytes,
                    len: l_len,
                },
                Self::Heap(r_vec),
            ) => usize::from(*l_len) == r_vec.len() && &l_bytes[..usize::from(*l_len)] == r_vec,
        }
    }
}

impl Eq for SmallVec {}

impl SmallVec {
    /// Returns a slice to the bytes stored
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Stack { bytes, len } => &bytes[..usize::from(*len)],
            Self::Heap(vec) => vec.as_slice(),
        }
    }

    /// Returns a slice to the bytes stored (same a [Self::data])
    pub fn as_slice(&self) -> &[u8] {
        self.data()
    }

    /// Returns a mutable slice to the bytes stored
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Stack { bytes, len } => &mut bytes[..usize::from(*len)],
            Self::Heap(vec) => vec.as_mut_slice(),
        }
    }

    /// Returns the len, i.e. the number of bytes stored
    pub fn len(&self) -> usize {
        match self {
            Self::Stack { len, .. } => usize::from(*len),
            Self::Heap(vec) => vec.len(),
        }
    }

    /// Returns whether self is empty
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Stack { len, .. } => *len == 0,
            Self::Heap(vec) => vec.is_empty(),
        }
    }

    /// Return the u64 value when interpreting the bytes as a `u64`
    ///
    /// * Bytes are interpreted in little endian
    /// * Bytes above the 8th are ignored
    pub fn as_u64(&self) -> u64 {
        let mut le_bytes = [0u8; u64::BITS as usize / 8];
        let data = self.data();
        let smallest = le_bytes.len().min(data.len());
        le_bytes[..smallest].copy_from_slice(&data[..smallest]);

        u64::from_le_bytes(le_bytes)
    }

    /// Return the u128 value when interpreting the bytes as a `u128`
    ///
    /// * Bytes are interpreted in little endian
    /// * Bytes above the 16th are ignored
    pub fn as_u128(&self) -> u128 {
        let mut le_bytes = [0u8; u128::BITS as usize / 8];
        let data = self.data();
        let smallest = le_bytes.len().min(data.len());
        le_bytes[..smallest].copy_from_slice(&data[..smallest]);

        u128::from_le_bytes(le_bytes)
    }

    /// Sets the data stored in the tag
    ///
    /// This overwrites existing data stored
    pub fn set_data(&mut self, data: &[u8]) {
        match self {
            Self::Stack { bytes, len } => {
                if data.len() > bytes.len() {
                    // There is not enough space, so we have to allocate
                    // a Vec
                    *self = Self::Heap(data.to_vec());
                } else {
                    bytes[..data.len()].copy_from_slice(data);
                    *len = data.len() as u8;
                }
            }
            Self::Heap(vec) => {
                // Even if the data could fit in the Stack array,
                // Since, we already have a vec allocated we use it instead.
                //
                // And in that case, there won't be any allocations since,
                // to have a vec in the first place, the allocated size is >
                // size_of::<Vec<T>>
                //
                // But of course, if the new data is larger than the vec, a new
                // allocation will be made
                vec.clear();
                vec.extend_from_slice(data);
            }
        }
    }

    /// Sets the tag with the given u64 value
    ///
    /// * Bytes are stored in little endian
    /// * This overwrites existing data stored
    pub fn set_u64(&mut self, value: u64) {
        let le_bytes = value.to_le_bytes();
        self.set_data(le_bytes.as_slice());
    }

    /// Sets the tag with the given u128 value
    ///
    /// * Bytes are stored in little endian
    /// * This overwrites existing data stored
    pub fn set_u128(&mut self, value: u128) {
        let le_bytes = value.to_le_bytes();
        self.set_data(le_bytes.as_slice());
    }

    /// Clears the vector, removing all values.
    ///
    /// Note that this method has no effect on the allocated capacity of the vector.
    pub fn clear(&mut self) {
        match self {
            Self::Stack { bytes: _, len } => *len = 0,
            Self::Heap(items) => items.clear(),
        }
    }

    // Creates a SmallVec from the vec, but, only re-uses the vec
    // if its len would not fit on the stack part.
    //
    // Meant for versioning and deserializing
    fn from_vec_conservative(vec: Vec<u8>) -> Self {
        // We only re-use the versioned vec, if the SmallVec would actually
        // have had its data on the heap, otherwise we prefer to keep data on stack
        // as its cheaper in memory and copies
        if vec.len() > STACK_ARRAY_SIZE {
            Self::Heap(vec)
        } else {
            let mut data = Self::default();
            data.set_data(vec.as_slice());
            data
        }
    }
}

impl serde::Serialize for SmallVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.data())
    }
}

struct SmallVecVisitor;

impl serde::de::Visitor<'_> for SmallVecVisitor {
    type Value = SmallVec;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a slice of bytes (&[u8]) or Vec<u8>")
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let mut vec = SmallVec::default();
        vec.set_data(bytes);
        Ok(vec)
    }

    fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SmallVec::from_vec_conservative(bytes))
    }
}

impl Versionize for SmallVec {
    type Versioned<'vers>
        = &'vers [u8]
    where
        Self: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.data()
    }
}

impl VersionizeOwned for SmallVec {
    type VersionedOwned = Vec<u8>;

    fn versionize_owned(self) -> Self::VersionedOwned {
        match self {
            Self::Stack { bytes, len } => bytes[..usize::from(len)].to_vec(),
            Self::Heap(vec) => vec,
        }
    }
}

impl Unversionize for SmallVec {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(Self::from_vec_conservative(versioned))
    }
}

impl<'de> serde::Deserialize<'de> for SmallVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SmallVecVisitor)
    }
}

/// Tag
///
/// The `Tag` allows to store bytes alongside entities (keys, and ciphertexts)
/// the main purpose of this system is to `tag` / identify ciphertext with their keys.
///
/// TFHE-rs generally does not interpret or check this data, it only stores it and passes it around.
///
/// The [crate::upgrade::UpgradeKeyChain] uses the tag to differentiate keys
///
/// The rules for how the Tag is passed around are:
/// * When encrypted, a ciphertext gets the tag of the key used to encrypt it.
/// * Ciphertexts resulting from operations (add, sub, etc.) get the tag from the ServerKey used
/// * PublicKey gets its tag from the ClientKey that was used to create it
/// * ServerKey gets its tag from the ClientKey that was used to create it
///
/// User can change the tag of any entities at any point.
///
/// # Example
///
/// ```
/// use rand::random;
/// use tfhe::prelude::*;
/// use tfhe::{ClientKey, ConfigBuilder, FheUint32, ServerKey};
///
/// // Generate the client key then set its tag
/// let mut cks = ClientKey::generate(ConfigBuilder::default());
/// let tag_value = random();
/// cks.tag_mut().set_u64(tag_value);
/// assert_eq!(cks.tag().as_u64(), tag_value);
///
/// // The server key inherits the client key tag
/// let sks = ServerKey::new(&cks);
/// assert_eq!(sks.tag(), cks.tag());
///
/// // Encrypted data inherits the tag of the encryption key
/// let a = FheUint32::encrypt(32832u32, &cks);
/// assert_eq!(a.tag(), cks.tag());
/// ```
#[derive(
    Default, Clone, Debug, serde::Serialize, serde::Deserialize, Versionize, PartialEq, Eq,
)]
#[versionize(TagVersions)]
pub struct Tag {
    // We don't want the enum to be public
    inner: SmallVec,
}

impl Tag {
    /// Returns a slice to the bytes stored
    pub fn data(&self) -> &[u8] {
        self.inner.data()
    }

    /// Returns a slice to the bytes stored (same a [Self::data])
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Returns a mutable slice to the bytes stored
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    /// Returns the len, i.e. the number of bytes stored in the tag
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the tag is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return the u64 value when interpreting the bytes as a `u64`
    ///
    /// * Bytes are interpreted in little endian
    /// * Bytes above the 8th are ignored
    pub fn as_u64(&self) -> u64 {
        self.inner.as_u64()
    }

    /// Return the u128 value when interpreting the bytes as a `u128`
    ///
    /// * Bytes are interpreted in little endian
    /// * Bytes above the 16th are ignored
    pub fn as_u128(&self) -> u128 {
        self.inner.as_u128()
    }

    /// Sets the data stored in the tag
    ///
    /// This overwrites existing data stored
    pub fn set_data(&mut self, data: &[u8]) {
        self.inner.set_data(data);
    }

    /// Sets the tag with the given u64 value
    ///
    /// * Bytes are stored in little endian
    /// * This overwrites existing data stored
    pub fn set_u64(&mut self, value: u64) {
        self.inner.set_u64(value);
    }

    /// Sets the tag with the given u128 value
    ///
    /// * Bytes are stored in little endian
    /// * This overwrites existing data stored
    pub fn set_u128(&mut self, value: u128) {
        self.inner.set_u128(value);
    }
}

impl From<u64> for Tag {
    fn from(value: u64) -> Self {
        let mut s = Self::default();
        s.set_u64(value);
        s
    }
}

impl From<&str> for Tag {
    fn from(value: &str) -> Self {
        let mut tag = Self::default();
        tag.set_data(value.as_bytes());
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_small_vec() {
        let mut vec_1 = SmallVec::default();
        vec_1.set_data(&[1, 2, 3, 4, 5]);

        let mut vec_2 = SmallVec::default();
        vec_2.set_data(vec_1.data());

        assert!(matches!(vec_1, SmallVec::Stack { .. }));
        assert!(matches!(vec_2, SmallVec::Stack { .. }));
        assert_eq!(vec_2.len(), vec_1.len());
        assert_eq!(vec_1.len(), 5);
        assert_eq!(vec_1, vec_2); // Test both ways
        assert_eq!(vec_2, vec_1);

        // Put something big in vec_1, we expect the data to be on the heap now
        let big_data = (0..500u64).map(|x| (x % 256) as u8).collect::<Vec<_>>();
        vec_1.set_data(&big_data);
        assert!(matches!(vec_1, SmallVec::Heap(_)));
        assert!(matches!(vec_2, SmallVec::Stack { .. }));
        assert_ne!(vec_2.len(), vec_1.len());
        assert_eq!(vec_1.len(), big_data.len());
        assert_ne!(vec_1, vec_2);
        assert_ne!(vec_2, vec_1);

        // Put something the same big data in vec_2,
        // we also expect the data to be on the heap now
        vec_2.set_data(&big_data);
        assert!(matches!(vec_1, SmallVec::Heap(_)));
        assert!(matches!(vec_2, SmallVec::Heap(_)));
        assert_eq!(vec_2.len(), vec_1.len());
        assert_eq!(vec_1.len(), big_data.len());
        assert_eq!(vec_1, vec_2); // Test both ways
        assert_eq!(vec_2, vec_1);

        // Now put back something small in vec 1
        // We expect the data to still be on the heap, since
        // the heap was allocated to store the previous big data
        vec_1.set_data(&[1, 2, 3, 4, 5]);
        assert!(matches!(vec_1, SmallVec::Heap(_)));
        assert_eq!(vec_1.len(), 5);
        assert_eq!(vec_1.data(), &[1, 2, 3, 4, 5]);
        assert_ne!(vec_1, vec_2);
        assert_ne!(vec_2, vec_1);
    }

    #[test]
    fn test_small_vec_u64_u128() {
        let mut rng = rand::rng();

        let mut vec = SmallVec::default();
        {
            let value = rng.gen();
            vec.set_u64(value);
            assert_eq!(vec.as_u64(), value);

            assert_eq!(vec.as_u128(), u128::from(value));
        }

        {
            let value = rng.gen();
            vec.set_u128(value);
            assert_eq!(vec.as_u128(), value);

            assert_eq!(vec.as_u64(), value as u64);
        }
    }
}
