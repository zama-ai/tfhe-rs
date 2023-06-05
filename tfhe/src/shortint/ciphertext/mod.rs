//! Module with the definition of the Ciphertext.
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;
use std::marker::PhantomData;

/// This tracks the number of operations that has been done.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct Degree(pub usize);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PBSOrder {
    /// Ciphertext is encrypted using the big LWE secret key corresponding to the GLWE secret key.
    ///
    /// A keyswitch is first performed to bring it to the small LWE secret key realm, then the PBS
    /// is computed bringing it back to the large LWE secret key.
    KeyswitchBootstrap = 0,
    /// Ciphertext is encrypted using the small LWE secret key.
    ///
    /// The PBS is computed first and a keyswitch is applied to get back to the small LWE secret
    /// key realm.
    BootstrapKeyswitch = 1,
}

mod seal {
    pub trait Sealed {}
    impl Sealed for super::BootstrapKeyswitch {}
    impl Sealed for super::KeyswitchBootstrap {}
}

/// Trait to mark Ciphertext with the order for the PBS operations
pub trait PBSOrderMarker: seal::Sealed + Debug + Clone + Copy + Send + Sync {
    fn pbs_order() -> PBSOrder;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyswitchBootstrap;

impl PBSOrderMarker for KeyswitchBootstrap {
    fn pbs_order() -> PBSOrder {
        PBSOrder::KeyswitchBootstrap
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BootstrapKeyswitch;

impl PBSOrderMarker for BootstrapKeyswitch {
    fn pbs_order() -> PBSOrder {
        PBSOrder::BootstrapKeyswitch
    }
}

impl Degree {
    pub(crate) fn after_bitxor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        //Try every possibility to find the worst case
        for i in 0..min + 1 {
            if max ^ i > result {
                result = max ^ i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        for i in 0..min + 1 {
            if max | i > result {
                result = max | i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitand(&self, other: Degree) -> Degree {
        Degree(cmp::min(self.0, other.0))
    }

    pub(crate) fn after_left_shift(&self, shift: u8, modulus: usize) -> Degree {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = (i << shift) % modulus;
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }

    #[allow(dead_code)]
    pub(crate) fn after_pbs<F>(&self, f: F) -> Degree
    where
        F: Fn(usize) -> usize,
    {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = f(i);
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct CiphertextBase<OpOrder: PBSOrderMarker> {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub _order_marker: PhantomData<OpOrder>,
}

pub type CiphertextBig = CiphertextBase<KeyswitchBootstrap>;
pub type CiphertextSmall = CiphertextBase<BootstrapKeyswitch>;

pub struct CiphertextTypeError<InputOpOrder, OutputOpOrder>
where
    InputOpOrder: PBSOrderMarker,
    OutputOpOrder: PBSOrderMarker,
{
    input_type: PhantomData<InputOpOrder>,
    output_type: PhantomData<OutputOpOrder>,
}

impl<InputOpOrder, OutputOpOrder> std::fmt::Debug
    for CiphertextTypeError<InputOpOrder, OutputOpOrder>
where
    InputOpOrder: PBSOrderMarker,
    OutputOpOrder: PBSOrderMarker,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Expected PBSOrder: {:?}, got {:?}, \
            did you mix CiphertextBig or CompressedCiphertextBig ({:?}) with CiphertextSmall or CompressedCiphertextSmall ({:?})?",
            InputOpOrder::pbs_order(),
            OutputOpOrder::pbs_order(),
            PBSOrder::KeyswitchBootstrap,
            PBSOrder::BootstrapKeyswitch
        )
    }
}

impl<OpOrder: PBSOrderMarker> CiphertextBase<OpOrder> {
    pub fn carry_is_empty(&self) -> bool {
        self.degree.0 < self.message_modulus.0
    }

    pub fn copy_from(&mut self, other: &Self) {
        self.ct.as_mut().copy_from_slice(other.ct.as_ref());
        self.message_modulus = other.message_modulus;
        self.carry_modulus = other.carry_modulus;
        self._order_marker = other._order_marker;
    }

    pub fn to_concrete_type<OtherOpOrder: PBSOrderMarker>(&self) -> &CiphertextBase<OtherOpOrder> {
        self.try_to_concrete_type().unwrap()
    }

    pub fn to_concrete_type_mut<OtherOpOrder: PBSOrderMarker>(
        &mut self,
    ) -> &mut CiphertextBase<OtherOpOrder> {
        self.try_to_concrete_type_mut().unwrap()
    }

    pub fn try_to_concrete_type<OtherOpOrder: PBSOrderMarker>(
        &self,
    ) -> Result<&CiphertextBase<OtherOpOrder>, CiphertextTypeError<OpOrder, OtherOpOrder>> {
        match (OpOrder::pbs_order(), OtherOpOrder::pbs_order()) {
            (op_order, other_op_order) if op_order == other_op_order => {
                Ok(unsafe { std::mem::transmute(self) })
            }
            _ => Err(CiphertextTypeError {
                input_type: PhantomData,
                output_type: PhantomData,
            }),
        }
    }

    pub fn try_to_concrete_type_mut<OtherOpOrder: PBSOrderMarker>(
        &mut self,
    ) -> Result<&mut CiphertextBase<OtherOpOrder>, CiphertextTypeError<OpOrder, OtherOpOrder>> {
        match (OpOrder::pbs_order(), OtherOpOrder::pbs_order()) {
            (op_order, other_op_order) if op_order == other_op_order => {
                Ok(unsafe { std::mem::transmute(self) })
            }
            _ => Err(CiphertextTypeError {
                input_type: PhantomData,
                output_type: PhantomData,
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerialiazableCiphertextBase {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub op_order: PBSOrder,
}

// Manual impl to be able to carry the OpOrder information
impl<OpOrder: PBSOrderMarker> Serialize for CiphertextBase<OpOrder> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerialiazableCiphertextBase {
            ct: self.ct.clone(),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            op_order: OpOrder::pbs_order(),
        }
        .serialize(serializer)
    }
}

// Manual impl to be able to check the OpOrder information
impl<'de, OpOrder: PBSOrderMarker> Deserialize<'de> for CiphertextBase<OpOrder> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let intermediate = SerialiazableCiphertextBase::deserialize(deserializer)?;
        if intermediate.op_order != OpOrder::pbs_order() {
            return Err(serde::de::Error::custom(format!(
                "Expected PBSOrder: {:?}, got {:?}, \
                did you mix CiphertextBig ({:?}) and CiphertextSmall ({:?})?",
                OpOrder::pbs_order(),
                intermediate.op_order,
                PBSOrder::KeyswitchBootstrap,
                PBSOrder::BootstrapKeyswitch
            )));
        }

        Ok(CiphertextBase {
            ct: intermediate.ct,
            degree: intermediate.degree,
            message_modulus: intermediate.message_modulus,
            carry_modulus: intermediate.carry_modulus,
            _order_marker: Default::default(),
        })
    }
}

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone)]
pub struct CompressedCiphertextBase<OpOrder: PBSOrderMarker> {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub _order_marker: PhantomData<OpOrder>,
}

pub type CompressedCiphertextBig = CompressedCiphertextBase<KeyswitchBootstrap>;
pub type CompressedCiphertextSmall = CompressedCiphertextBase<BootstrapKeyswitch>;

#[derive(Serialize, Deserialize)]
struct SerialiazableCompressedCiphertextBase {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub op_order: PBSOrder,
}

// Manual impl to be able to carry the OpOrder information
impl<OpOrder: PBSOrderMarker> Serialize for CompressedCiphertextBase<OpOrder> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerialiazableCompressedCiphertextBase {
            ct: self.ct.clone(),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            op_order: OpOrder::pbs_order(),
        }
        .serialize(serializer)
    }
}

// Manual impl to be able to check the OpOrder information
impl<'de, OpOrder: PBSOrderMarker> Deserialize<'de> for CompressedCiphertextBase<OpOrder> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let intermediate = SerialiazableCompressedCiphertextBase::deserialize(deserializer)?;
        if intermediate.op_order != OpOrder::pbs_order() {
            return Err(serde::de::Error::custom(format!(
                "Expected PBSOrder: {:?}, got {:?}, \
                    did you mix CompressedCiphertextBig ({:?}) and CompressedCiphertextSmall ({:?})?",
                OpOrder::pbs_order(),
                intermediate.op_order,
                PBSOrder::KeyswitchBootstrap,
                PBSOrder::BootstrapKeyswitch
            )));
        }

        Ok(CompressedCiphertextBase {
            ct: intermediate.ct,
            degree: intermediate.degree,
            message_modulus: intermediate.message_modulus,
            carry_modulus: intermediate.carry_modulus,
            _order_marker: Default::default(),
        })
    }
}

impl<OpOrder: PBSOrderMarker> CompressedCiphertextBase<OpOrder> {
    pub fn decompress(self) -> CiphertextBase<OpOrder> {
        let CompressedCiphertextBase {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            _order_marker,
        } = self;

        CiphertextBase {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
            _order_marker,
        }
    }
}

impl<OpOrder: PBSOrderMarker> From<CompressedCiphertextBase<OpOrder>> for CiphertextBase<OpOrder> {
    fn from(value: CompressedCiphertextBase<OpOrder>) -> Self {
        value.decompress()
    }
}

#[cfg(test)]
mod tests {
    use super::{BootstrapKeyswitch, KeyswitchBootstrap};
    use crate::shortint::gen_keys;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

    #[test]
    fn test_copy_from() {
        let (client_key, _server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

        let msg1 = 3;
        let msg2 = 2;

        // Encrypt two messages using the (private) client key:
        let mut ct_1 = client_key.encrypt(msg1);
        let ct_2 = client_key.encrypt(msg2);

        assert_ne!(ct_1, ct_2);

        ct_1.copy_from(&ct_2);
        assert_eq!(ct_1, ct_2);
    }

    #[test]
    fn test_concrete_type_conversion() {
        let (client_key, _server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

        let msg = 3;

        // Encrypt two messages using the (private) client key:
        let mut ct = client_key.encrypt(msg);

        let _test = ct.try_to_concrete_type_mut::<KeyswitchBootstrap>().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_concrete_type_conversion_fail() {
        let (client_key, _server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

        let msg = 3;

        // Encrypt two messages using the (private) client key:
        let mut ct = client_key.encrypt(msg);

        let _test = ct.try_to_concrete_type_mut::<BootstrapKeyswitch>().unwrap();
    }
}
