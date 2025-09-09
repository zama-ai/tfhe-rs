//! Serialization utilities with some safety checks

// Types in this file should never be versioned because they are a wrapper around the versioning
// process
#![cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]

use std::borrow::Cow;
use std::fmt::Display;

use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, Versionize};

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
got version {}", self.header_version
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

#[cfg(all(test, feature = "shortint"))]
mod test_shortint {
    use tfhe_versionable::Versionize;

    use crate::named::Named;
    use crate::shortint::parameters::test_params::{
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    };
    use crate::shortint::{gen_keys, Ciphertext};

    use super::*;

    #[test]
    fn safe_deserialization_ct_unversioned() {
        let (ck, _sk) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        let config = SerializationConfig::new(1 << 20).disable_versioning();

        let size = config.serialized_size(&ct).unwrap();
        config.serialize_into(&ct, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        assert!(DeserializationConfig::new(1 << 20)
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128.to_shortint_conformance_param()
            )
            .is_err());

        let ct2 = DeserializationConfig::new(1 << 20)
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.to_shortint_conformance_param(),
            )
            .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_ct_versioned() {
        let (ck, _sk) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        let config = SerializationConfig::new(1 << 20);

        let size = config.serialized_size(&ct).unwrap();
        config.serialize_into(&ct, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        assert!(DeserializationConfig::new(1 << 20,)
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128.to_shortint_conformance_param()
            )
            .is_err());

        let ct2 = DeserializationConfig::new(1 << 20)
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.to_shortint_conformance_param(),
            )
            .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_ct_unlimited_size() {
        let (ck, _sk) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        let config = SerializationConfig::new_with_unlimited_size();

        let size = config.serialized_size(&ct).unwrap();
        config.serialize_into(&ct, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        let ct2 = DeserializationConfig::new_with_unlimited_size()
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.to_shortint_conformance_param(),
            )
            .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_size_limit() {
        let (ck, _sk) = gen_keys(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        let config = SerializationConfig::new_with_unlimited_size().disable_versioning();

        let size = config.serialized_size(&ct).unwrap();
        config.serialize_into(&ct, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        let ct2 = DeserializationConfig::new(size)
            .deserialize_from::<Ciphertext>(
                buffer.as_slice(),
                &TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.to_shortint_conformance_param(),
            )
            .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_named() {
        #[derive(Serialize, Deserialize, Versionize)]
        #[repr(transparent)]
        struct Foo(u64);

        impl Named for Foo {
            const NAME: &'static str = "Foo";
        }

        #[derive(Deserialize, Versionize)]
        #[repr(transparent)]
        struct Bar(u64);

        impl Named for Bar {
            const NAME: &'static str = "Bar";

            const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] = &["Foo"];
        }

        #[derive(Deserialize, Versionize)]
        #[repr(transparent)]
        struct Baz(u64);

        impl Named for Baz {
            const NAME: &'static str = "Baz";
        }

        let foo = Foo(3);
        let mut foo_ser = Vec::new();
        safe_serialize(&foo, &mut foo_ser, 0x1000).unwrap();

        let foo_deser: Foo = safe_deserialize(foo_ser.as_slice(), 0x1000).unwrap();
        let bar_deser: Bar = safe_deserialize(foo_ser.as_slice(), 0x1000).unwrap();

        assert_eq!(foo_deser.0, bar_deser.0);

        assert!(safe_deserialize::<Baz>(foo_ser.as_slice(), 0x1000).is_err());
    }
}

#[cfg(all(test, feature = "integer"))]
mod test_integer {
    use crate::conformance::ListSizeConstraint;
    use crate::high_level_api::{generate_keys, ConfigBuilder};
    use crate::prelude::*;
    use crate::safe_serialization::{DeserializationConfig, SerializationConfig};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    };
    use crate::{
        set_server_key, CompactCiphertextList, CompactCiphertextListConformanceParams,
        CompactPublicKey, FheUint8,
    };

    #[test]
    fn safe_deserialization_ct_list() {
        let (client_key, sks) = generate_keys(ConfigBuilder::default().build());
        set_server_key(sks);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = [27u8, 10, 3];

        let ct_list = CompactCiphertextList::builder(&public_key)
            .push(27u8)
            .push(10u8)
            .push(3u8)
            .build();

        let mut buffer = vec![];

        let config = SerializationConfig::new(1 << 20).disable_versioning();

        let size = config.serialized_size(&ct_list).unwrap();
        config.serialize_into(&ct_list, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128
                    .to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(DeserializationConfig::new(1 << 20)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &param_set)
                .is_err());
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    .to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };

            DeserializationConfig::new(1 << 20)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &params)
                .unwrap();
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = DeserializationConfig::new(1 << 20)
            .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &params)
            .unwrap();

        let mut cts = Vec::with_capacity(3);
        let expander = ct2.expand().unwrap();
        for i in 0..3 {
            cts.push(expander.get::<FheUint8>(i).unwrap().unwrap());
        }

        let dec: Vec<u8> = cts.iter().map(|a| a.decrypt(&client_key)).collect();

        assert_eq!(&msg[..], &dec);
    }

    #[test]
    fn safe_deserialization_ct_list_versioned() {
        let (client_key, sks) = generate_keys(ConfigBuilder::default().build());
        set_server_key(sks);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = [27u8, 10, 3];

        let ct_list = CompactCiphertextList::builder(&public_key)
            .push(27u8)
            .push(10u8)
            .push(3u8)
            .build();

        let mut buffer = vec![];

        let config = SerializationConfig::new(1 << 20);

        let size = config.serialized_size(&ct_list).unwrap();
        config.serialize_into(&ct_list, &mut buffer).unwrap();

        assert_eq!(size as usize, buffer.len());

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128
                    .to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(DeserializationConfig::new(1 << 20)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &param_set)
                .is_err());
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    .to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };

            DeserializationConfig::new(1 << 20)
                .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &params)
                .unwrap();
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                .to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = DeserializationConfig::new(1 << 20)
            .deserialize_from::<CompactCiphertextList>(buffer.as_slice(), &params)
            .unwrap();

        let mut cts = Vec::with_capacity(3);
        let expander = ct2.expand().unwrap();
        for i in 0..3 {
            cts.push(expander.get::<FheUint8>(i).unwrap().unwrap());
        }

        let dec: Vec<u8> = cts.iter().map(|a| a.decrypt(&client_key)).collect();

        assert_eq!(&msg[..], &dec);
    }
}
