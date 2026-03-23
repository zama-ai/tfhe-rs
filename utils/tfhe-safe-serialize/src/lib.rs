//! Serialization utilities with some safety checks

// Types in this file should never be versioned because they are a wrapper around the versioning
// process
#![cfg_attr(
    dylint_lib = "tfhe_lints",
    allow(unknown_lints, serialize_without_versionize)
)]

use std::borrow::Cow;
use std::fmt::Display;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, Versionize};

mod traits;
pub use crate::traits::{EnumSet, Named, ParameterSetConformant};

/// This is the global version of the serialization scheme that is used. This should be updated when
/// the SerializationHeader is updated.
const SERIALIZATION_VERSION: &str = "0.5";

/// This is the version of the versioning scheme used to add backward compatibibility on tfhe-rs
/// types. Similar to SERIALIZATION_VERSION, this number should be increased when the versioning
/// scheme is upgraded.
const VERSIONING_VERSION: &str = "0.1";

/// This is the current version of this crate. This is used to be able to reject unversioned data
/// if they come from a previous version.
const CRATE_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

/// Tells if this serialized object is versioned or not
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
enum SerializationVersioningMode {
    /// Serialize with type versioning for backward compatibility
    Versioned {
        /// Version of the versioning scheme in use
        versioning_version: Cow<'static, str>,
    },
    /// Serialize the type without versioning information
    Unversioned {
        /// Version of tfhe-rs where this data was generated
        crate_version: Cow<'static, str>,
    },
}

impl Display for SerializationVersioningMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Versioned { .. } => write!(f, "versioned"),
            Self::Unversioned { .. } => write!(f, "unversioned"),
        }
    }
}

impl SerializationVersioningMode {
    fn versioned() -> Self {
        Self::Versioned {
            versioning_version: Cow::Borrowed(VERSIONING_VERSION),
        }
    }

    fn unversioned() -> Self {
        Self::Unversioned {
            crate_version: Cow::Borrowed(CRATE_VERSION),
        }
    }
}

/// Header with global metadata about the serialized object. This help checking that we are not
/// deserializing data that we can't handle.
#[derive(Serialize, Deserialize)]
struct SerializationHeader {
    header_version: Cow<'static, str>,
    versioning_mode: SerializationVersioningMode,
    name: Cow<'static, str>,
}

impl SerializationHeader {
    /// Creates a new header for a versioned message
    fn new_versioned<T: Named>() -> Self {
        Self {
            header_version: Cow::Borrowed(SERIALIZATION_VERSION),
            versioning_mode: SerializationVersioningMode::versioned(),
            name: Cow::Borrowed(T::NAME),
        }
    }

    /// Creates a new header for an unversioned message
    fn new_unversioned<T: Named>() -> Self {
        Self {
            header_version: Cow::Borrowed(SERIALIZATION_VERSION),
            versioning_mode: SerializationVersioningMode::unversioned(),
            name: Cow::Borrowed(T::NAME),
        }
    }

    /// Checks the validity of the header
    fn validate<T: Named>(&self) -> Result<(), String> {
        if self.header_version != SERIALIZATION_VERSION {
            return Err(format!(
                "On deserialization, expected serialization header version {SERIALIZATION_VERSION}, \
got version {}",
                self.header_version
            ));
        }

        match &self.versioning_mode {
            SerializationVersioningMode::Versioned { versioning_version } => {
                // For the moment there is only one versioning scheme, so another value is
                // a hard error. But maybe if we upgrade it we will be able to automatically convert
                // it.
                if versioning_version != VERSIONING_VERSION {
                    return Err(format!(
                        "On deserialization, expected versioning scheme version {VERSIONING_VERSION}, \
got version {versioning_version}"
                    ));
                }
            }
            SerializationVersioningMode::Unversioned { crate_version } => {
                if crate_version != CRATE_VERSION {
                    return Err(format!(
                        "This {} has been saved from TFHE-rs v{crate_version}, without versioning information. \
Please use the versioned serialization mode for backward compatibility.",
                        self.name
                    ));
                }
            }
        }

        if self.name != T::NAME
            && T::BACKWARD_COMPATIBILITY_ALIASES
                .iter()
                .all(|alias| self.name != *alias)
        {
            return Err(format!(
                "On deserialization, expected type {}, got type {}",
                T::NAME,
                self.name
            ));
        }

        Ok(())
    }
}

/// A configuration used to Serialize *TFHE-rs* objects. This configuration decides
/// if the object will be versioned and holds the max byte size of the written data.
#[derive(Clone)]
pub struct SerializationConfig {
    versioned: SerializationVersioningMode,
    serialized_size_limit: Option<u64>,
}

impl SerializationConfig {
    /// Creates a new serialization config. The default configuration will serialize the object
    /// with versioning information for backward compatibility.
    /// `serialized_size_limit` is the size limit (in number of bytes) of the serialized object
    /// (including the header).
    pub fn new(serialized_size_limit: u64) -> Self {
        Self {
            versioned: SerializationVersioningMode::versioned(),
            serialized_size_limit: Some(serialized_size_limit),
        }
    }

    /// Creates a new serialization config without any size check.
    pub fn new_with_unlimited_size() -> Self {
        Self {
            versioned: SerializationVersioningMode::versioned(),
            serialized_size_limit: None,
        }
    }

    /// Disables the size limit for serialized objects
    pub fn disable_size_limit(self) -> Self {
        Self {
            serialized_size_limit: None,
            ..self
        }
    }

    /// Disable the versioning of serialized objects
    pub fn disable_versioning(self) -> Self {
        Self {
            versioned: SerializationVersioningMode::unversioned(),
            ..self
        }
    }

    /// Sets the size limit for this serialization config
    pub fn with_size_limit(self, size: u64) -> Self {
        Self {
            serialized_size_limit: Some(size),
            ..self
        }
    }

    /// Create a serialization header based on the current config
    fn create_header<T: Named>(&self) -> SerializationHeader {
        match self.versioned {
            SerializationVersioningMode::Versioned { .. } => {
                SerializationHeader::new_versioned::<T>()
            }
            SerializationVersioningMode::Unversioned { .. } => {
                SerializationHeader::new_unversioned::<T>()
            }
        }
    }

    /// Returns the size the object would take if serialized using the current config
    ///
    /// The size is returned as a u64 to handle the serialization of large buffers under 32b
    /// architectures.
    pub fn serialized_size<T: Serialize + Versionize + Named>(
        &self,
        object: &T,
    ) -> bincode::Result<u64> {
        let options = bincode::DefaultOptions::new().with_fixint_encoding();

        let header = self.create_header::<T>();

        let header_size = options.serialized_size(&header)?;

        let data_size = match self.versioned {
            SerializationVersioningMode::Versioned { .. } => {
                options.serialized_size(&object.versionize())?
            }
            SerializationVersioningMode::Unversioned { .. } => options.serialized_size(&object)?,
        };

        Ok(header_size + data_size)
    }

    /// Serializes an object into a [writer](std::io::Write), based on the current config.
    /// The written bytes can be deserialized using [`DeserializationConfig::deserialize_from`].
    pub fn serialize_into<T: Serialize + Versionize + Named>(
        self,
        object: &T,
        mut writer: impl std::io::Write,
    ) -> bincode::Result<()> {
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(0); // Force to explicitly set the limit for each serialization

        let header = self.create_header::<T>();
        let header_size = options.with_no_limit().serialized_size(&header)?;

        if let Some(size_limit) = self.serialized_size_limit {
            options
                .with_limit(size_limit)
                .serialize_into(&mut writer, &header)?;

            let options = options.with_limit(size_limit - header_size);

            match self.versioned {
                SerializationVersioningMode::Versioned { .. } => {
                    options.serialize_into(&mut writer, &object.versionize())?
                }
                SerializationVersioningMode::Unversioned { .. } => {
                    options.serialize_into(&mut writer, &object)?
                }
            }
        } else {
            let options = options.with_no_limit();

            options.serialize_into(&mut writer, &header)?;

            match self.versioned {
                SerializationVersioningMode::Versioned { .. } => {
                    options.serialize_into(&mut writer, &object.versionize())?
                }
                SerializationVersioningMode::Unversioned { .. } => {
                    options.serialize_into(&mut writer, &object)?
                }
            }
        }

        Ok(())
    }
}

/// A configuration used to Serialize *TFHE-rs* objects. This configuration decides
/// the various sanity checks that will be performed during deserialization.
#[derive(Copy, Clone)]
pub struct DeserializationConfig {
    serialized_size_limit: Option<u64>,
    validate_header: bool,
}

/// A configuration used to Serialize *TFHE-rs* objects. This is similar to
/// [`DeserializationConfig`] but it will not require conformance parameters.
///
/// This type should be created with [`DeserializationConfig::disable_conformance`]
#[derive(Copy, Clone)]
pub struct NonConformantDeserializationConfig {
    serialized_size_limit: Option<u64>,
    validate_header: bool,
}

impl NonConformantDeserializationConfig {
    /// Deserialize a header using the current config
    fn deserialize_header(
        &self,
        reader: &mut impl std::io::Read,
    ) -> Result<SerializationHeader, String> {
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(0);

        if let Some(size_limit) = self.serialized_size_limit {
            options
                .with_limit(size_limit)
                .deserialize_from(reader)
                .map_err(|err| err.to_string())
        } else {
            options
                .with_no_limit()
                .deserialize_from(reader)
                .map_err(|err| err.to_string())
        }
    }

    /// Deserializes an object serialized by [`SerializationConfig::serialize_into`] from a
    /// [reader](std::io::Read). Performs various sanity checks based on the deserialization config,
    /// but skips conformance checks.
    pub fn deserialize_from<T: DeserializeOwned + Unversionize + Named>(
        self,
        mut reader: impl std::io::Read,
    ) -> Result<T, String> {
        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(0); // Force to explicitly set the limit for each deserialization

        let deserialized_header: SerializationHeader = self.deserialize_header(&mut reader)?;

        let header_size = options
            .with_no_limit()
            .serialized_size(&deserialized_header)
            .map_err(|err| err.to_string())?;

        if self.validate_header {
            deserialized_header.validate::<T>()?;
        }

        if let Some(size_limit) = self.serialized_size_limit {
            let options = options.with_limit(size_limit - header_size);
            match deserialized_header.versioning_mode {
                SerializationVersioningMode::Versioned { .. } => {
                    let deser_versioned = options
                        .deserialize_from(&mut reader)
                        .map_err(|err| err.to_string())?;

                    T::unversionize(deser_versioned).map_err(|e| e.to_string())
                }
                SerializationVersioningMode::Unversioned { .. } => options
                    .deserialize_from(&mut reader)
                    .map_err(|err| err.to_string()),
            }
        } else {
            let options = options.with_no_limit();
            match deserialized_header.versioning_mode {
                SerializationVersioningMode::Versioned { .. } => {
                    let deser_versioned = options
                        .deserialize_from(&mut reader)
                        .map_err(|err| err.to_string())?;

                    T::unversionize(deser_versioned).map_err(|e| e.to_string())
                }
                SerializationVersioningMode::Unversioned { .. } => options
                    .deserialize_from(&mut reader)
                    .map_err(|err| err.to_string()),
            }
        }
    }

    /// Enables the conformance check on an existing config.
    pub fn enable_conformance(self) -> DeserializationConfig {
        DeserializationConfig {
            serialized_size_limit: self.serialized_size_limit,
            validate_header: self.validate_header,
        }
    }
}

impl DeserializationConfig {
    /// Creates a new deserialization config.
    ///
    /// By default, it will check that the serialization version and the name of the
    /// deserialized type are correct.
    /// `deserialized_size_limit` is the size limit (in number of bytes) of the deserialized object.
    /// It should be set according to the expected size of the object and the maximum allocatable
    /// size on your system.
    ///
    /// It will also check that the object is conformant with the parameter set given in
    /// `conformance_params`. Finally, it will check the compatibility of the loaded data with
    /// the current *TFHE-rs* version.
    pub fn new(deserialized_size_limit: u64) -> Self {
        Self {
            serialized_size_limit: Some(deserialized_size_limit),
            validate_header: true,
        }
    }

    /// Creates a new config without any size limit for the deserialized objects.
    pub fn new_with_unlimited_size() -> Self {
        Self {
            serialized_size_limit: None,
            validate_header: true,
        }
    }

    /// Disables the size limit for the serialized objects.
    pub fn disable_size_limit(self) -> Self {
        Self {
            serialized_size_limit: None,
            ..self
        }
    }

    /// Sets the size limit for this deserialization config
    pub fn with_size_limit(self, size: u64) -> Self {
        Self {
            serialized_size_limit: Some(size),
            ..self
        }
    }

    /// Disables the header validation on the object. This header validations
    /// checks that the serialized object is the one that is supposed to be loaded
    /// and is compatible with this version of *TFHE-rs*.
    pub fn disable_header_validation(self) -> Self {
        Self {
            validate_header: false,
            ..self
        }
    }

    /// Disables the conformance check on an existing config.
    pub fn disable_conformance(self) -> NonConformantDeserializationConfig {
        NonConformantDeserializationConfig {
            serialized_size_limit: self.serialized_size_limit,
            validate_header: self.validate_header,
        }
    }

    /// Deserializes an object serialized by [`SerializationConfig::serialize_into`] from a
    /// [reader](std::io::Read). Performs various sanity checks based on the deserialization config.
    ///
    /// # Panics
    /// This function may panic if `serialized_size_limit` is larger than what can be allocated by
    /// the system. This may happen even if the size of the serialized data is short. An
    /// attacker could manipulate the data to create a short serialized message with a huge
    /// deserialized size.
    pub fn deserialize_from<T: DeserializeOwned + Unversionize + Named + ParameterSetConformant>(
        self,
        reader: impl std::io::Read,
        parameter_set: &T::ParameterSet,
    ) -> Result<T, String> {
        let deser: T = self.disable_conformance().deserialize_from(reader)?;
        if !deser.is_conformant(parameter_set) {
            return Err(format!(
                "Deserialized object of type {} not conformant with given parameter set",
                T::NAME
            ));
        }

        Ok(deser)
    }
}

/// Serialize an object with the default configuration (with size limit and versioning).
/// This is an alias for `SerializationConfig::new(serialized_size_limit).serialize_into`
pub fn safe_serialize<T: Serialize + Versionize + Named>(
    object: &T,
    writer: impl std::io::Write,
    serialized_size_limit: u64,
) -> bincode::Result<()> {
    SerializationConfig::new(serialized_size_limit).serialize_into(object, writer)
}

/// Return the size the object would take if serialized using [`safe_serialize`]
pub fn safe_serialized_size<T: Serialize + Versionize + Named>(object: &T) -> bincode::Result<u64> {
    SerializationConfig::new_with_unlimited_size().serialized_size(object)
}

/// Serialize an object with the default configuration (with size limit, header check and
/// versioning).
///
/// `deserialized_size_limit` is the size limit (in number of bytes) of the deserialized object.
/// It should be set according to the expected size of the object and the maximum allocatable size
/// on your system.
///
/// This is an alias for
/// `DeserializationConfig::new(serialized_size_limit).disable_conformance().deserialize_from`
///
/// # Panics
/// This function may panic if `serialized_size_limit` is larger than what can be allocated by the
/// system. This may happen even if the size of the serialized data is short. An attacker could
/// manipulate the data to create a short serialized message with a huge deserialized size.
pub fn safe_deserialize<T: DeserializeOwned + Unversionize + Named>(
    reader: impl std::io::Read,
    deserialized_size_limit: u64,
) -> Result<T, String> {
    DeserializationConfig::new(deserialized_size_limit)
        .disable_conformance()
        .deserialize_from(reader)
}

/// Serialize an object with the default configuration and conformance checks (with size limit,
/// header check and versioning).
///
/// `deserialized_size_limit` is the size limit (in number of bytes) of the deserialized object.
/// It should be set according to the expected size of the object and the maximum allocatable size
/// on your system.
///
/// This is an alias for
/// `DeserializationConfig::new(serialized_size_limit).deserialize_from`
///
/// # Panics
/// This function may panic if `serialized_size_limit` is larger than what can be allocated by the
/// system. This may happen even if the size of the serialized data is short. An attacker could
/// manipulate the data to create a short serialized message with a huge deserialized size.
pub fn safe_deserialize_conformant<
    T: DeserializeOwned + Unversionize + Named + ParameterSetConformant,
>(
    reader: impl std::io::Read,
    deserialized_size_limit: u64,
    parameter_set: &T::ParameterSet,
) -> Result<T, String> {
    DeserializationConfig::new(deserialized_size_limit).deserialize_from(reader, parameter_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Named;
    use std::ops::RangeInclusive;

    #[derive(Serialize, Deserialize, Versionize, Debug, PartialEq)]
    #[repr(transparent)]
    struct Foo(u64);

    impl Named for Foo {
        const NAME: &'static str = "Foo";
    }

    #[derive(Serialize, Deserialize, Versionize, Debug, PartialEq)]
    #[repr(transparent)]
    struct Bar(u64);

    impl Named for Bar {
        const NAME: &'static str = "Bar";
        const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] = &["Foo"];
    }

    #[derive(Serialize, Deserialize, Versionize, Debug, PartialEq)]
    #[repr(transparent)]
    struct Baz(u64);

    impl Named for Baz {
        const NAME: &'static str = "Baz";
    }

    #[derive(Serialize, Deserialize, Versionize, Debug, PartialEq)]
    #[repr(transparent)]
    struct Conformant(u64);

    impl Named for Conformant {
        const NAME: &'static str = "Conformant";
    }

    impl ParameterSetConformant for Conformant {
        type ParameterSet = RangeInclusive<u64>;

        fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
            parameter_set.contains(&self.0)
        }
    }

    fn serialize_versioned(obj: &Foo) -> Vec<u8> {
        let mut buf = Vec::new();
        SerializationConfig::new(1 << 20)
            .serialize_into(obj, &mut buf)
            .unwrap();
        buf
    }

    #[test]
    fn backward_compatibility_aliases() {
        let foo = Foo(3);
        let mut buf = Vec::new();
        safe_serialize(&foo, &mut buf, 0x1000).unwrap();

        let foo_deser: Foo = safe_deserialize(buf.as_slice(), 0x1000).unwrap();
        // Bar is backward compatible with Foo, this works
        let bar_deser: Bar = safe_deserialize(buf.as_slice(), 0x1000).unwrap();

        assert_eq!(foo_deser.0, bar_deser.0);
        // Baz is not backward compatible with Foo, this fails
        assert!(safe_deserialize::<Baz>(buf.as_slice(), 0x1000).is_err());
    }

    #[test]
    fn serialized_size_matches_actual_versioned() {
        let foo = Foo(123);
        let config = SerializationConfig::new(1 << 20);
        let size = config.serialized_size(&foo).unwrap();
        let buf = serialize_versioned(&foo);
        assert_eq!(size as usize, buf.len());
    }

    #[test]
    fn serialize_size_limit_works() {
        let foo = Foo(1);
        let exact_size = SerializationConfig::new(1 << 20)
            .serialized_size(&foo)
            .unwrap();

        let mut buf = Vec::new();
        let result = SerializationConfig::new(exact_size - 1).serialize_into(&foo, &mut buf);
        assert!(result.is_err());

        buf.clear();
        SerializationConfig::new(exact_size)
            .serialize_into(&foo, &mut buf)
            .unwrap();
        assert_eq!(buf.len(), exact_size as usize);
    }

    #[test]
    fn deserialize_size_limit_works() {
        let obj = Conformant(1);
        let mut buf = Vec::new();
        SerializationConfig::new(1 << 20)
            .serialize_into(&obj, &mut buf)
            .unwrap();
        let exact_size = buf.len() as u64;

        let result: Result<Conformant, _> =
            DeserializationConfig::new(exact_size - 1).deserialize_from(buf.as_slice(), &(0..=100));
        assert!(result.is_err());

        let result: Result<Conformant, _> =
            DeserializationConfig::new(exact_size).deserialize_from(buf.as_slice(), &(0..=100));
        assert!(result.is_ok());
    }

    #[test]
    fn header_validation_disabled() {
        let buf = serialize_versioned(&Foo(7));

        let result: Result<Baz, _> = DeserializationConfig::new(1 << 20)
            .disable_conformance()
            .deserialize_from(buf.as_slice());
        assert!(result.is_err());

        let deser: Baz = DeserializationConfig::new(1 << 20)
            .disable_header_validation()
            .disable_conformance()
            .deserialize_from(buf.as_slice())
            .unwrap();
        assert_eq!(deser.0, 7);
    }

    #[test]
    fn conformance_check() {
        let obj = Conformant(50);
        let mut buf = Vec::new();
        SerializationConfig::new(1 << 20)
            .serialize_into(&obj, &mut buf)
            .unwrap();

        let result: Result<Conformant, _> =
            DeserializationConfig::new(1 << 20).deserialize_from(buf.as_slice(), &(0..=100));
        assert!(result.is_ok());

        let result: Result<Conformant, _> =
            DeserializationConfig::new(1 << 20).deserialize_from(buf.as_slice(), &(0..=10));
        assert!(result.is_err());

        let deser: Conformant = DeserializationConfig::new(1 << 20)
            .disable_conformance()
            .deserialize_from(buf.as_slice())
            .unwrap();
        assert_eq!(deser, obj);
    }

    #[test]
    fn unlimited_size_configs() {
        let foo = Conformant(999);

        let mut buf = Vec::new();
        SerializationConfig::new_with_unlimited_size()
            .serialize_into(&foo, &mut buf)
            .unwrap();

        let deser: Conformant = DeserializationConfig::new_with_unlimited_size()
            .disable_conformance()
            .deserialize_from(buf.as_slice())
            .unwrap();
        assert_eq!(deser, foo);

        let deser: Result<Conformant, _> =
            DeserializationConfig::new(1).deserialize_from(buf.as_slice(), &(0..=1234));
        assert!(deser.is_err());
    }
}
