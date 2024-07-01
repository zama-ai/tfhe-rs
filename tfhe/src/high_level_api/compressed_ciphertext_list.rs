use super::keys::InternalServerKey;
use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::high_level_api::integers::{FheIntId, FheUintId};
use crate::integer::ciphertext::{Compressible, DataKind, Expandable};
use crate::named::Named;
use crate::shortint::Ciphertext;
use crate::{FheBool, FheInt, FheUint};

impl<Id: FheUintId> Compressible for FheUint<Id> {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        self.ciphertext.into_cpu().compress_into(messages)
    }
}

impl<Id: FheIntId> Compressible for FheInt<Id> {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        self.ciphertext.into_cpu().compress_into(messages)
    }
}

impl Compressible for FheBool {
    fn compress_into(self, messages: &mut Vec<Ciphertext>) -> DataKind {
        self.ciphertext.into_cpu().compress_into(messages)
    }
}

pub struct CompressedCiphertextListBuilder {
    inner: crate::integer::ciphertext::CompressedCiphertextListBuilder,
}

impl CompressedCiphertextListBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: crate::integer::ciphertext::CompressedCiphertextListBuilder::new(),
        }
    }

    pub fn push<T>(&mut self, value: T) -> &mut Self
    where
        T: Compressible,
    {
        self.inner.push(value);
        self
    }

    pub fn extend<T>(&mut self, values: impl Iterator<Item = T>) -> &mut Self
    where
        T: Compressible,
    {
        self.inner.extend(values);
        self
    }

    pub fn build(&self) -> crate::Result<CompressedCiphertextList> {
        crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => cpu_key
                .compression_key
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::new("Compression key not set in server key".to_owned())
                })
                .map(|compression_key| CompressedCiphertextList(self.inner.build(compression_key))),
            _ => Err(crate::Error::new(
                "A Cpu server key is needed to be set to use compression".to_owned(),
            )),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedCiphertextList(crate::integer::ciphertext::CompressedCiphertextList);

impl Named for CompressedCiphertextList {
    const NAME: &'static str = "high_level_api::CompactCiphertextList";
}

impl CompressedCiphertextList {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_kind_of(&self, index: usize) -> Option<crate::FheTypes> {
        Some(match self.0.get_kind_of(index)? {
            DataKind::Unsigned(n) => {
                let num_bits_per_block = self.0.packed_list.message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => crate::FheTypes::Uint2,
                    4 => crate::FheTypes::Uint4,
                    6 => crate::FheTypes::Uint6,
                    8 => crate::FheTypes::Uint8,
                    10 => crate::FheTypes::Uint10,
                    12 => crate::FheTypes::Uint12,
                    14 => crate::FheTypes::Uint14,
                    16 => crate::FheTypes::Uint16,
                    32 => crate::FheTypes::Uint32,
                    64 => crate::FheTypes::Uint64,
                    128 => crate::FheTypes::Uint128,
                    160 => crate::FheTypes::Uint160,
                    256 => crate::FheTypes::Uint256,
                    _ => return None,
                }
            }
            DataKind::Signed(n) => {
                let num_bits_per_block = self.0.packed_list.message_modulus.0.ilog2() as usize;
                let num_bits = n * num_bits_per_block;
                match num_bits {
                    2 => crate::FheTypes::Int2,
                    4 => crate::FheTypes::Int4,
                    6 => crate::FheTypes::Int6,
                    8 => crate::FheTypes::Int8,
                    10 => crate::FheTypes::Int10,
                    12 => crate::FheTypes::Int12,
                    14 => crate::FheTypes::Int14,
                    16 => crate::FheTypes::Int16,
                    32 => crate::FheTypes::Int32,
                    64 => crate::FheTypes::Int64,
                    128 => crate::FheTypes::Int128,
                    160 => crate::FheTypes::Int160,
                    256 => crate::FheTypes::Int256,
                    _ => return None,
                }
            }
            DataKind::Boolean => crate::FheTypes::Bool,
        })
    }

    pub fn get<T>(&self, index: usize) -> crate::Result<Option<T>>
    where
        T: Expandable,
    {
        crate::high_level_api::global_state::try_with_internal_keys(|keys| match keys {
            Some(InternalServerKey::Cpu(cpu_key)) => cpu_key
                .decompression_key
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::new("Compression key not set in server key".to_owned())
                })
                .and_then(|decompression_key| self.0.get(index, decompression_key)),
            _ => Err(crate::Error::new(
                "A Cpu server key is needed to be set".to_string(),
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    use crate::{
        set_server_key, CompressedCiphertextList, CompressedCiphertextListBuilder, FheBool,
        FheInt64, FheUint16, FheUint2, FheUint32,
    };

    #[test]
    fn test_compressed_ct_list() {
        let config = crate::ConfigBuilder::with_custom_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        )
        .enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
        .build();

        let ck = crate::ClientKey::generate(config);
        let sk = crate::ServerKey::new(&ck);

        set_server_key(sk);

        let ct1 = FheUint32::encrypt(17_u32, &ck);

        let ct2 = FheInt64::encrypt(-1i64, &ck);

        let ct3 = FheBool::encrypt(false, &ck);

        let ct4 = FheUint2::encrypt(3u8, &ck);

        let compressed_list = CompressedCiphertextListBuilder::new()
            .push(ct1)
            .push(ct2)
            .push(ct3)
            .push(ct4)
            .build()
            .unwrap();

        let serialized = bincode::serialize(&compressed_list).unwrap();

        let compressed_list: CompressedCiphertextList = bincode::deserialize(&serialized).unwrap();

        {
            let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
            let b: FheInt64 = compressed_list.get(1).unwrap().unwrap();
            let c: FheBool = compressed_list.get(2).unwrap().unwrap();
            let d: FheUint2 = compressed_list.get(3).unwrap().unwrap();

            let a: u32 = a.decrypt(&ck);
            assert_eq!(a, 17);
            let b: i64 = b.decrypt(&ck);
            assert_eq!(b, -1);
            let c = c.decrypt(&ck);
            assert!(!c);
            let d: u8 = d.decrypt(&ck);
            assert_eq!(d, 3);

            assert!(compressed_list.get::<FheBool>(4).unwrap().is_none());
        }

        {
            // Incorrect type
            assert!(compressed_list.get::<FheInt64>(0).is_err());

            // Correct type but wrong number of bits
            assert!(compressed_list.get::<FheUint16>(0).is_err());
        }
    }
}
