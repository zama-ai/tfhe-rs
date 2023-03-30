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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Clone)]
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
