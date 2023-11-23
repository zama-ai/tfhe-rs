use crate::conformance::ParameterSetConformant;
use crate::named::Named;
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::Serialize;

// The `SERIALIZATION_VERSION` is serialized along objects serialized with `safe_serialize`.
// This `SERIALIZATION_VERSION` should be changed on each release where any object serialization
// details changes (this can happen when adding a field or reorderging fields of a struct).
// When a object is deserialized using `safe_deserialize`, the deserialized version is checked
// to be equal to SERIALIZATION_VERSION.
// This helps prevent users from inadvertently deserializaing an object serialized in another
// release.
// When this happens, it also gives a clear version mismatch error rather than a generic
// deserialization error or worse, a garbage object.
const SERIALIZATION_VERSION: &str = "0.1";

// `VERSION_LENGTH_LIMIT` is the maximum `SERIALIZATION_VERSION` size which `safe_deserialization`
// is going to try to read (it returns an error if it's too big).
// It helps prevent an attacker passing a very long `SERIALIZATION_VERSION` to exhaust memory.
const VERSION_LENGTH_LIMIT: u64 = 100;

const TYPE_NAME_LENGTH_LIMIT: u64 = 1000;

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

#[cfg(all(test, feature = "shortint"))]
mod test_shortint {
    use crate::safe_deserialization::{safe_deserialize_conformant, safe_serialize};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    };
    use crate::shortint::{gen_keys, Ciphertext};

    #[test]
    fn safe_desererialization_ct() {
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
}

#[cfg(all(test, feature = "integer"))]
mod test_integer {
    use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
    use crate::high_level_api::{generate_keys, ConfigBuilder};
    use crate::integer::parameters::RadixCiphertextConformanceParams;
    use crate::prelude::{FheDecrypt, FheTryEncrypt};
    use crate::safe_deserialization::{safe_deserialize_conformant, safe_serialize};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    };
    use crate::{CompactFheUint8, CompactFheUint8List, CompactPublicKey};

    #[test]
    fn safe_desererialization_ct() {
        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = 27u8;

        let num_blocks_per_integer = 4;

        let ct = CompactFheUint8::try_encrypt(msg, &public_key).unwrap();

        assert!(
            ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                num_blocks_per_integer
            ))
        );

        let mut buffer = vec![];

        safe_serialize(&ct, &mut buffer, 1 << 40).unwrap();

        assert!(safe_deserialize_conformant::<CompactFheUint8>(
            buffer.as_slice(),
            1 << 20,
            &RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                num_blocks_per_integer
            ),
        )
        .is_err());

        let ct2 = safe_deserialize_conformant::<CompactFheUint8>(
            buffer.as_slice(),
            1 << 20,
            &RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                num_blocks_per_integer,
            ),
        )
        .unwrap();

        let dec: u8 = ct2.expand().decrypt(&client_key);
        assert_eq!(msg, dec);
    }

    #[test]
    fn safe_desererialization_ct_list() {
        let config = ConfigBuilder::default().build();

        let (client_key, _server_key) = generate_keys(config);

        let public_key = CompactPublicKey::new(&client_key);

        let msg = [27u8, 10, 3];

        let num_blocks_per_integer = 4;

        let ct_list = CompactFheUint8List::try_encrypt(&msg, &public_key).unwrap();

        let mut buffer = vec![];

        safe_serialize(&ct_list, &mut buffer, 1 << 40).unwrap();

        let param_set = |list_size_constraint| {
            RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS,
                num_blocks_per_integer,
            )
            .to_ct_list_conformance_parameters(list_size_constraint)
        };

        for parameter_set in [
            RadixCiphertextConformanceParams::from_pbs_parameters(
                PARAM_MESSAGE_3_CARRY_3_KS_PBS,
                num_blocks_per_integer,
            )
            .to_ct_list_conformance_parameters(ListSizeConstraint::exact_size(3)),
            param_set(ListSizeConstraint::exact_size(2)),
            param_set(ListSizeConstraint::exact_size(4)),
            param_set(ListSizeConstraint::try_size_in_range(1, 2).unwrap()),
            param_set(ListSizeConstraint::try_size_in_range(4, 5).unwrap()),
        ]
        .iter()
        {
            assert!(safe_deserialize_conformant::<CompactFheUint8List>(
                buffer.as_slice(),
                1 << 20,
                parameter_set,
            )
            .is_err());
        }

        for parameter_set in [
            param_set(ListSizeConstraint::exact_size(3)),
            param_set(ListSizeConstraint::try_size_in_range(2, 3).unwrap()),
            param_set(ListSizeConstraint::try_size_in_range(3, 4).unwrap()),
            param_set(ListSizeConstraint::try_size_in_range(2, 4).unwrap()),
        ]
        .iter()
        {
            assert!(ct_list.is_conformant(parameter_set));
        }

        let ct2 = safe_deserialize_conformant::<CompactFheUint8List>(
            buffer.as_slice(),
            1 << 20,
            &param_set(ListSizeConstraint::exact_size(3)),
        )
        .unwrap();

        let dec: Vec<u8> = ct2
            .expand()
            .iter()
            .map(|a| a.decrypt(&client_key))
            .collect();

        assert_eq!(&msg[..], &dec);
    }
}
