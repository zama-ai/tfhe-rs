use std::borrow::Cow;

use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Unversionize, Versionize};

// The `SERIALIZATION_VERSION` is serialized along objects serialized with `safe_serialize`.
// This `SERIALIZATION_VERSION` should be changed on each release where any object serialization
// details changes (this can happen when adding a field or reorderging fields of a struct).
// When a object is deserialized using `safe_deserialize`, the deserialized version is checked
// to be equal to SERIALIZATION_VERSION.
// This helps prevent users from inadvertently deserializaing an object serialized in another
// release.
// When this happens, it also gives a clear version mismatch error rather than a generic
// deserialization error or worse, a garbage object.
const SERIALIZATION_VERSION: &str = "0.4";

/// Tells if this serialized object is versioned or not
#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum SerializationMode {
    /// Serialize with type versioning for backward compatibility
    Versioned,
    /// Directly serialize the type as it is provided
    Direct,
}

/// Header with global metadata about the serialized object.
#[derive(Serialize, Deserialize)]
struct SerializationHeader {
    mode: SerializationMode,
    version: Cow<'static, str>,
    name: Cow<'static, str>,
}

impl SerializationHeader {
    /// Creates a new header for a versioned message
    fn new_versioned<T: Named>() -> Self {
        Self {
            mode: SerializationMode::Versioned,
            version: Cow::Borrowed(VERSIONING_VERSION),
            name: Cow::Borrowed(T::NAME),
        }
    }

    /// Checks the validity of a versioned message
    fn check_versioned<T: Named>(&self) -> Result<(), String> {
        if self.mode != SerializationMode::Versioned {
            return Err(
                "On deserialization, expected versioned type but got unversioned one".to_string(),
            );
        }

        // Since there is only one "VERSIONING_VERSION", a message with a different value than the
        // expected one is clearly invalid, so we return an error. In the future, we want to
        // be able to upgrade it to the new versioning scheme.
        if self.version != VERSIONING_VERSION {
            return Err(format!(
                "On deserialization, expected versioning scheme version {VERSIONING_VERSION}, \
                got version {}",
                self.version
            ));
        }

        if self.name != T::NAME {
            return Err(format!(
                "On deserialization, expected type {}, got type {}",
                T::NAME,
                self.name
            ));
        }

        Ok(())
    }
}

// This is the version of the versioning scheme used to add backward compatibibility on tfhe-rs
// types. Similar to SERIALIZATION_VERSION, this number should be increased when the versioning
// scheme is upgraded.
const VERSIONING_VERSION: &str = "0.1";

// `VERSION_LENGTH_LIMIT` is the maximum `SERIALIZATION_VERSION` size which `safe_deserialization`
// is going to try to read (it returns an error if it's too big).
// It helps prevent an attacker passing a very long `SERIALIZATION_VERSION` to exhaust memory.
const VERSION_LENGTH_LIMIT: u64 = 100;

const TYPE_NAME_LENGTH_LIMIT: u64 = 1000;

const HEADER_LENGTH_LIMIT: u64 = 1000;

/// Serializes an object into a [writer](std::io::Write).
/// The result contains a version of the serialization and the name of the
/// serialized type to provide checks on deserialization with [safe_deserialize].
/// `serialized_size_limit` is the size limit (in number of byte) of the serialized object
/// (excluding version and name serialization).
pub fn safe_serialize<T: Serialize + Named>(
    object: &T,
    mut writer: impl std::io::Write,
    serialized_size_limit: u64,
) -> bincode::Result<()> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(0);

    options
        .with_limit(VERSION_LENGTH_LIMIT)
        .serialize_into::<_, String>(&mut writer, &SERIALIZATION_VERSION.to_owned())?;

    options
        .with_limit(TYPE_NAME_LENGTH_LIMIT)
        .serialize_into::<_, String>(&mut writer, &T::NAME.to_owned())?;

    options
        .with_limit(serialized_size_limit)
        .serialize_into(&mut writer, object)?;

    Ok(())
}

/// Serializes an object into a [writer](std::io::Write) like [`safe_serialize`] does,
/// but adds versioning information before.
pub fn safe_serialize_versioned<T: Versionize + Named>(
    object: &T,
    mut writer: impl std::io::Write,
    serialized_size_limit: u64,
) -> bincode::Result<()> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(0);

    let header = SerializationHeader::new_versioned::<T>();
    options
        .with_limit(HEADER_LENGTH_LIMIT)
        .serialize_into(&mut writer, &header)?;

    options
        .with_limit(serialized_size_limit)
        .serialize_into(&mut writer, &object.versionize())?;

    Ok(())
}

/// Deserializes an object serialized by `safe_serialize` from a [reader](std::io::Read).
/// Checks that the serialization version and the name of the
/// deserialized type are correct.
/// `serialized_size_limit` is the size limit (in number of byte) of the serialized object
/// (excluding version and name serialization).
pub fn safe_deserialize<T: DeserializeOwned + Named>(
    mut reader: impl std::io::Read,
    serialized_size_limit: u64,
) -> Result<T, String> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(0);

    let deserialized_version: String = options
        .with_limit(VERSION_LENGTH_LIMIT)
        .deserialize_from::<_, String>(&mut reader)
        .map_err(|err| err.to_string())?;

    if deserialized_version != SERIALIZATION_VERSION {
        return Err(format!(
            "On deserialization, expected serialization version {SERIALIZATION_VERSION}, got version {deserialized_version}"
        ));
    }

    let deserialized_type: String = options
        .with_limit(TYPE_NAME_LENGTH_LIMIT)
        .deserialize_from::<_, String>(&mut reader)
        .map_err(|err| err.to_string())?;

    if deserialized_type != T::NAME {
        return Err(format!(
            "On deserialization, expected type {}, got type {}",
            T::NAME,
            deserialized_type
        ));
    }

    options
        .with_limit(serialized_size_limit)
        .deserialize_from(&mut reader)
        .map_err(|err| err.to_string())
}

/// Deserializes an object with [safe_deserialize] and checks than it is conformant with the given
/// parameter set
pub fn safe_deserialize_conformant<T: DeserializeOwned + Named + ParameterSetConformant>(
    reader: impl std::io::Read,
    serialized_size_limit: u64,
    parameter_set: &T::ParameterSet,
) -> Result<T, String> {
    let deser: T = safe_deserialize(reader, serialized_size_limit)?;

    if !deser.is_conformant(parameter_set) {
        return Err(format!(
            "Deserialized object of type {} not conformant with given parameter set",
            T::NAME
        ));
    }

    Ok(deser)
}

/// Deserializes an object serialized by `safe_serialize_versioned` from a [reader](std::io::Read).
/// Checks that the serialization version and the name of the
/// deserialized type are correct.
/// `serialized_size_limit` is the size limit (in number of byte) of the serialized object
/// (excluding version and name serialization).
pub fn safe_deserialize_versioned<T: Unversionize + Named>(
    mut reader: impl std::io::Read,
    serialized_size_limit: u64,
) -> Result<T, String> {
    let options = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(0);

    let deserialized_header: SerializationHeader = options
        .with_limit(HEADER_LENGTH_LIMIT)
        .deserialize_from(&mut reader)
        .map_err(|err| err.to_string())?;

    deserialized_header.check_versioned::<T>()?;

    options
        .with_limit(serialized_size_limit)
        .deserialize_from(&mut reader)
        .map_err(|err| err.to_string())
        .and_then(|val| T::unversionize(val).map_err(|err| err.to_string()))
}

/// Deserializes an object with [safe_deserialize] and checks than it is conformant with the given
/// parameter set
pub fn safe_deserialize_conformant_versioned<T: Unversionize + Named + ParameterSetConformant>(
    reader: impl std::io::Read,
    serialized_size_limit: u64,
    parameter_set: &T::ParameterSet,
) -> Result<T, String> {
    let deser: T = safe_deserialize_versioned(reader, serialized_size_limit)?;

    if !deser.is_conformant(parameter_set) {
        return Err(format!(
            "Deserialized object of type {} not conformant with given parameter set",
            T::NAME
        ));
    }

    Ok(deser)
}

#[cfg(all(test, feature = "shortint"))]
mod test_shortint {
    use crate::safe_deserialization::{
        safe_deserialize_conformant, safe_deserialize_conformant_versioned, safe_serialize,
        safe_serialize_versioned,
    };
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    };
    use crate::shortint::{gen_keys, Ciphertext};

    #[test]
    fn safe_deserialization_ct() {
        let (ck, _sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        safe_serialize(&ct, &mut buffer, 1 << 40).unwrap();

        assert!(safe_deserialize_conformant::<Ciphertext>(
            buffer.as_slice(),
            1 << 20,
            &PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
        )
        .is_err());

        let ct2 = safe_deserialize_conformant(
            buffer.as_slice(),
            1 << 20,
            &PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
        )
        .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_deserialization_ct_versioned() {
        let (ck, _sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

        let msg = 2_u64;

        let ct = ck.encrypt(msg);

        let mut buffer = vec![];

        safe_serialize_versioned(&ct, &mut buffer, 1 << 40).unwrap();

        assert!(safe_deserialize_conformant_versioned::<Ciphertext>(
            buffer.as_slice(),
            1 << 20,
            &PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
        )
        .is_err());

        let ct2 = safe_deserialize_conformant_versioned(
            buffer.as_slice(),
            1 << 20,
            &PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
        )
        .unwrap();

        let dec = ck.decrypt(&ct2);
        assert_eq!(msg, dec);
    }
}

#[cfg(all(test, feature = "integer"))]
mod test_integer {
    use crate::conformance::ListSizeConstraint;
    use crate::high_level_api::{generate_keys, ConfigBuilder};
    use crate::prelude::*;
    use crate::safe_deserialization::{
        safe_deserialize_conformant, safe_deserialize_conformant_versioned, safe_serialize,
        safe_serialize_versioned,
    };
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
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

        safe_serialize(&ct_list, &mut buffer, 1 << 40).unwrap();

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(safe_deserialize_conformant::<CompactCiphertextList>(
                buffer.as_slice(),
                1 << 20,
                &param_set
            )
            .is_err());
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };
            assert!(safe_deserialize_conformant::<CompactCiphertextList>(
                buffer.as_slice(),
                1 << 20,
                &params,
            )
            .is_ok());
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = safe_deserialize_conformant::<CompactCiphertextList>(
            buffer.as_slice(),
            1 << 20,
            &params,
        )
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

        safe_serialize_versioned(&ct_list, &mut buffer, 1 << 40).unwrap();

        let to_param_set = |list_size_constraint| CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: list_size_constraint,
        };

        for param_set in [
            CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_3_CARRY_3_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: ListSizeConstraint::exact_size(3),
            },
            to_param_set(ListSizeConstraint::exact_size(2)),
            to_param_set(ListSizeConstraint::exact_size(4)),
            to_param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            to_param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ] {
            assert!(
                safe_deserialize_conformant_versioned::<CompactCiphertextList>(
                    buffer.as_slice(),
                    1 << 20,
                    &param_set
                )
                .is_err()
            );
        }

        for len_constraint in [
            ListSizeConstraint::exact_size(3),
            ListSizeConstraint::try_size_in_range(2, 3).unwrap(),
            ListSizeConstraint::try_size_in_range(3, 4).unwrap(),
            ListSizeConstraint::try_size_in_range(2, 4).unwrap(),
        ] {
            let params = CompactCiphertextListConformanceParams {
                shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
                num_elements_constraint: len_constraint,
            };
            assert!(
                safe_deserialize_conformant_versioned::<CompactCiphertextList>(
                    buffer.as_slice(),
                    1 << 20,
                    &params,
                )
                .is_ok()
            );
        }

        let params = CompactCiphertextListConformanceParams {
            shortint_params: PARAM_MESSAGE_2_CARRY_2_KS_PBS.to_shortint_conformance_param(),
            num_elements_constraint: ListSizeConstraint::exact_size(3),
        };
        let ct2 = safe_deserialize_conformant_versioned::<CompactCiphertextList>(
            buffer.as_slice(),
            1 << 20,
            &params,
        )
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
