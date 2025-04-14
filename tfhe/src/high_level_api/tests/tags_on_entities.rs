use crate::prelude::*;
use crate::shortint::parameters::{
    ClassicPBSParameters, CompactPublicKeyEncryptionParameters, CompressionParameters,
    ShortintKeySwitchingParameters, COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

use crate::{
    set_server_key, ClientKey, CompactCiphertextList, CompactCiphertextListExpander,
    CompactPublicKey, CompressedCiphertextList, CompressedCiphertextListBuilder, CompressedFheBool,
    CompressedFheInt32, CompressedFheUint32, CompressedServerKey, ConfigBuilder, Device, FheBool,
    FheInt32, FheInt64, FheUint32, KeySwitchingKey, ServerKey,
};
use rand::random;

#[test]
fn test_tag_propagation_cpu() {
    test_tag_propagation(
        Device::Cpu,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        Some((
            PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
        Some(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        Some((
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
    )
}

#[test]
#[cfg(feature = "zk-pok")]
fn test_tag_propagation_zk_pok() {
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::ProvenCompactCiphertextList;

    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
    let crs = crate::zk::CompactPkeCrs::from_config(config, (2 * 32) + (2 * 64) + 2).unwrap();

    let metadata = [b'h', b'l', b'a', b'p', b'i'];

    let mut cks = ClientKey::generate(config);
    let tag_value = random();
    cks.tag_mut().set_u64(tag_value);
    let cks = serialize_then_deserialize(&cks);
    assert_eq!(cks.tag().as_u64(), tag_value);

    let sks = ServerKey::new(&cks);
    set_server_key(sks);

    let cpk = CompactPublicKey::new(&cks);
    assert_eq!(cpk.tag(), cks.tag());

    let mut builder = CompactCiphertextList::builder(&cpk);

    let list_packed = builder
        .push(32u32)
        .push(1u32)
        .push(-1i64)
        .push(i64::MIN)
        .push(false)
        .push(true)
        .build_with_proof_packed(&crs, &metadata, crate::zk::ZkComputeLoad::Proof)
        .unwrap();

    let list_packed: ProvenCompactCiphertextList = serialize_then_deserialize(&list_packed);
    assert_eq!(list_packed.tag(), cks.tag());

    let expander = list_packed
        .verify_and_expand(&crs, &cpk, &metadata)
        .unwrap();

    {
        let au32: FheUint32 = expander.get(0).unwrap().unwrap();
        let bu32: FheUint32 = expander.get(1).unwrap().unwrap();
        assert_eq!(au32.tag(), cks.tag());
        assert_eq!(bu32.tag(), cks.tag());

        let cu32 = au32 + bu32;
        assert_eq!(cu32.tag(), cks.tag());
    }

    {
        let ai64: FheInt64 = expander.get(2).unwrap().unwrap();
        let bi64: FheInt64 = expander.get(3).unwrap().unwrap();
        assert_eq!(ai64.tag(), cks.tag());
        assert_eq!(bi64.tag(), cks.tag());

        let ci64 = ai64 + bi64;
        assert_eq!(ci64.tag(), cks.tag());
    }

    {
        let abool: FheBool = expander.get(4).unwrap().unwrap();
        let bbool: FheBool = expander.get(5).unwrap().unwrap();
        assert_eq!(abool.tag(), cks.tag());
        assert_eq!(bbool.tag(), cks.tag());

        let cbool = abool & bbool;
        assert_eq!(cbool.tag(), cks.tag());
    }

    let unverified_expander = list_packed.expand_without_verification().unwrap();

    {
        let au32: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
        let bu32: FheUint32 = unverified_expander.get(1).unwrap().unwrap();
        assert_eq!(au32.tag(), cks.tag());
        assert_eq!(bu32.tag(), cks.tag());

        let cu32 = au32 + bu32;
        assert_eq!(cu32.tag(), cks.tag());
    }

    {
        let ai64: FheInt64 = unverified_expander.get(2).unwrap().unwrap();
        let bi64: FheInt64 = unverified_expander.get(3).unwrap().unwrap();
        assert_eq!(ai64.tag(), cks.tag());
        assert_eq!(bi64.tag(), cks.tag());

        let ci64 = ai64 + bi64;
        assert_eq!(ci64.tag(), cks.tag());
    }

    {
        let abool: FheBool = unverified_expander.get(4).unwrap().unwrap();
        let bbool: FheBool = unverified_expander.get(5).unwrap().unwrap();
        assert_eq!(abool.tag(), cks.tag());
        assert_eq!(bbool.tag(), cks.tag());

        let cbool = abool & bbool;
        assert_eq!(cbool.tag(), cks.tag());
    }
}

#[test]
#[cfg(feature = "zk-pok")]
#[cfg(feature = "gpu")]
fn test_tag_propagation_zk_pok_gpu() {
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
    let crs = crate::zk::CompactPkeCrs::from_config(config, (2 * 32) + (2 * 64) + 2).unwrap();

    let metadata = [b'h', b'l', b'a', b'p', b'i'];

    let mut cks = ClientKey::generate(config);
    let tag_value = random();
    cks.tag_mut().set_u64(tag_value);
    let cks = serialize_then_deserialize(&cks);
    assert_eq!(cks.tag().as_u64(), tag_value);

    let compressed_server_key = CompressedServerKey::new(&cks);
    let gpu_sks = compressed_server_key.decompress_to_gpu();
    assert_eq!(gpu_sks.tag(), cks.tag());
    set_server_key(gpu_sks);

    let cpk = CompactPublicKey::new(&cks);
    assert_eq!(cpk.tag(), cks.tag());

    let mut builder = CompactCiphertextList::builder(&cpk);

    let list_packed = builder
        .push(32u32)
        .push(1u32)
        .push(-1i64)
        .push(i64::MIN)
        .push(false)
        .push(true)
        .build_with_proof_packed(&crs, &metadata, crate::zk::ZkComputeLoad::Proof)
        .unwrap();

    let expander = list_packed
        .verify_and_expand(&crs, &cpk, &metadata)
        .unwrap();

    {
        let au32: FheUint32 = expander.get(0).unwrap().unwrap();
        let bu32: FheUint32 = expander.get(1).unwrap().unwrap();
        assert_eq!(au32.tag(), cks.tag());
        assert_eq!(bu32.tag(), cks.tag());

        let cu32 = au32 + bu32;
        assert_eq!(cu32.tag(), cks.tag());
    }

    {
        let ai64: FheInt64 = expander.get(2).unwrap().unwrap();
        let bi64: FheInt64 = expander.get(3).unwrap().unwrap();
        assert_eq!(ai64.tag(), cks.tag());
        assert_eq!(bi64.tag(), cks.tag());

        let ci64 = ai64 + bi64;
        assert_eq!(ci64.tag(), cks.tag());
    }

    {
        let abool: FheBool = expander.get(4).unwrap().unwrap();
        let bbool: FheBool = expander.get(5).unwrap().unwrap();
        assert_eq!(abool.tag(), cks.tag());
        assert_eq!(bbool.tag(), cks.tag());

        let cbool = abool & bbool;
        assert_eq!(cbool.tag(), cks.tag());
    }

    let unverified_expander = list_packed.expand_without_verification().unwrap();

    {
        let au32: FheUint32 = unverified_expander.get(0).unwrap().unwrap();
        let bu32: FheUint32 = unverified_expander.get(1).unwrap().unwrap();
        assert_eq!(au32.tag(), cks.tag());
        assert_eq!(bu32.tag(), cks.tag());

        let cu32 = au32 + bu32;
        assert_eq!(cu32.tag(), cks.tag());
    }

    {
        let ai64: FheInt64 = unverified_expander.get(2).unwrap().unwrap();
        let bi64: FheInt64 = unverified_expander.get(3).unwrap().unwrap();
        assert_eq!(ai64.tag(), cks.tag());
        assert_eq!(bi64.tag(), cks.tag());

        let ci64 = ai64 + bi64;
        assert_eq!(ci64.tag(), cks.tag());
    }

    {
        let abool: FheBool = unverified_expander.get(4).unwrap().unwrap();
        let bbool: FheBool = unverified_expander.get(5).unwrap().unwrap();
        assert_eq!(abool.tag(), cks.tag());
        assert_eq!(bbool.tag(), cks.tag());

        let cbool = abool & bbool;
        assert_eq!(cbool.tag(), cks.tag());
    }
}

#[test]
#[cfg(feature = "gpu")]
fn test_tag_propagation_gpu() {
    test_tag_propagation(
        Device::CudaGpu,
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        None,
        Some(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        Some((
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
            PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )),
    )
}

fn serialize_then_deserialize<T>(value: &T) -> T
where
    T: serde::Serialize + for<'a> serde::de::Deserialize<'a>,
{
    let serialized = bincode::serialize(value).unwrap();
    bincode::deserialize(&serialized).unwrap()
}

fn test_tag_propagation(
    device: Device,
    pbs_parameters: ClassicPBSParameters,
    dedicated_compact_public_key_parameters: Option<(
        CompactPublicKeyEncryptionParameters,
        ShortintKeySwitchingParameters,
    )>,
    comp_parameters: Option<CompressionParameters>,
    ks_to_params: Option<(ClassicPBSParameters, ShortintKeySwitchingParameters)>,
) {
    let mut builder = ConfigBuilder::with_custom_parameters(pbs_parameters);
    if let Some(parameters) = dedicated_compact_public_key_parameters {
        builder = builder.use_dedicated_compact_public_key_parameters(parameters);
    }
    if let Some(parameters) = comp_parameters {
        builder = builder.enable_compression(parameters);
    }
    let config = builder.build();

    let mut cks = ClientKey::generate(config);
    let tag_value = random();
    cks.tag_mut().set_u64(tag_value);
    let cks = serialize_then_deserialize(&cks);
    assert_eq!(cks.tag().as_u64(), tag_value);

    let compressed_sks = CompressedServerKey::new(&cks);
    let compressed_sks = serialize_then_deserialize(&compressed_sks);
    assert_eq!(compressed_sks.tag(), cks.tag());
    let sks = ServerKey::new(&cks);

    match device {
        Device::Cpu => {
            let sks = serialize_then_deserialize(&sks);
            assert_eq!(sks.tag(), cks.tag());

            // Now test when the sks comes from a compressed one
            let sks = compressed_sks.decompress();
            let sks = serialize_then_deserialize(&sks);
            assert_eq!(sks.tag(), cks.tag());

            set_server_key(sks);
        }
        #[cfg(feature = "gpu")]
        Device::CudaGpu => {
            let sks = compressed_sks.decompress_to_gpu();
            assert_eq!(sks.tag(), cks.tag());

            set_server_key(sks);
        }
        #[cfg(feature = "hpu")]
        Device::Hpu => {
            todo!()
        }
    }

    // Check encrypting regular ct with client key
    {
        let mut compression_builder = CompressedCiphertextListBuilder::new();

        // Check FheUint have a tag
        {
            let ct_a = FheUint32::encrypt(8182u32, &cks);
            let ct_a = serialize_then_deserialize(&ct_a);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_b = FheUint32::encrypt(8182u32, &cks);
            assert_eq!(ct_b.tag(), cks.tag());

            let ct_c = ct_a + ct_b;
            assert_eq!(ct_c.tag(), cks.tag());

            compression_builder.push(ct_c);
        }

        // Check FheInt have a tag
        {
            let ct_a = FheInt32::encrypt(-1i32, &cks);
            let ct_a = serialize_then_deserialize(&ct_a);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_b = FheInt32::encrypt(i32::MIN, &cks);
            assert_eq!(ct_b.tag(), cks.tag());

            let ct_c = ct_a + ct_b;
            assert_eq!(ct_c.tag(), cks.tag());

            compression_builder.push(ct_c);
        }

        // Check FheBool have a tag
        {
            let ct_a = FheBool::encrypt(false, &cks);
            let ct_a = serialize_then_deserialize(&ct_a);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_b = FheBool::encrypt(true, &cks);
            assert_eq!(ct_b.tag(), cks.tag());

            let ct_c = ct_a | ct_b;
            assert_eq!(ct_c.tag(), cks.tag());

            compression_builder.push(ct_c);
        }

        {
            let compressed_list = compression_builder.build().unwrap();
            assert_eq!(compressed_list.tag(), cks.tag());

            let serialized = bincode::serialize(&compressed_list).unwrap();
            let compressed_list: CompressedCiphertextList =
                bincode::deserialize(&serialized).unwrap();
            assert_eq!(compressed_list.tag(), cks.tag());

            let a: FheUint32 = compressed_list.get(0).unwrap().unwrap();
            assert_eq!(a.tag(), cks.tag());
            let b: FheInt32 = compressed_list.get(1).unwrap().unwrap();
            assert_eq!(b.tag(), cks.tag());
            let c: FheBool = compressed_list.get(2).unwrap().unwrap();
            assert_eq!(c.tag(), cks.tag());

            if let Some((dest_params, ks_params)) = ks_to_params {
                let dest_config = ConfigBuilder::with_custom_parameters(dest_params);
                let mut dest_cks = ClientKey::generate(dest_config);
                dest_cks.tag_mut().set_u64(random());
                let compressed_dest_sks = CompressedServerKey::new(&dest_cks);
                let dest_sks = compressed_dest_sks.decompress();

                let ksk = KeySwitchingKey::with_parameters(
                    (&cks, &sks),
                    (&dest_cks, &dest_sks),
                    ks_params,
                );

                let ks_a = ksk.keyswitch(&a);
                assert_eq!(ks_a.tag(), dest_cks.tag());
                let ks_b = ksk.keyswitch(&b);
                assert_eq!(ks_b.tag(), dest_cks.tag());
                let ks_c = ksk.keyswitch(&c);
                assert_eq!(ks_c.tag(), dest_cks.tag());
            }
        }
    }

    // Check compressed encryption
    {
        {
            let ct_a = CompressedFheUint32::encrypt(8182u32, &cks);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_a = ct_a.decompress();
            assert_eq!(ct_a.tag(), cks.tag());
        }

        {
            let ct_a = CompressedFheInt32::encrypt(-1i32, &cks);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_a = ct_a.decompress();
            assert_eq!(ct_a.tag(), cks.tag());
        }

        {
            let ct_a = CompressedFheBool::encrypt(false, &cks);
            assert_eq!(ct_a.tag(), cks.tag());

            let ct_a = ct_a.decompress();
            assert_eq!(ct_a.tag(), cks.tag());
        }
    }

    // Test compact public key stuff
    if device == Device::Cpu {
        let cpk = CompactPublicKey::new(&cks);
        let cpk = serialize_then_deserialize(&cpk);
        assert_eq!(cpk.tag(), cks.tag());

        let mut builder = CompactCiphertextList::builder(&cpk);
        builder
            .push(32u32)
            .push(1u32)
            .push(-1i64)
            .push(i64::MIN)
            .push(false)
            .push(true);

        let expand_and_check_tags = |expander: CompactCiphertextListExpander, cks: &ClientKey| {
            {
                let au32: FheUint32 = expander.get(0).unwrap().unwrap();
                let bu32: FheUint32 = expander.get(1).unwrap().unwrap();
                assert_eq!(au32.tag(), cks.tag());
                assert_eq!(bu32.tag(), cks.tag());

                let cu32 = au32 + bu32;
                assert_eq!(cu32.tag(), cks.tag());
            }

            {
                let ai64: FheInt64 = expander.get(2).unwrap().unwrap();
                let bi64: FheInt64 = expander.get(3).unwrap().unwrap();
                assert_eq!(ai64.tag(), cks.tag());
                assert_eq!(bi64.tag(), cks.tag());

                let ci64 = ai64 + bi64;
                assert_eq!(ci64.tag(), cks.tag());
            }

            {
                let abool: FheBool = expander.get(4).unwrap().unwrap();
                let bbool: FheBool = expander.get(5).unwrap().unwrap();
                assert_eq!(abool.tag(), cks.tag());
                assert_eq!(bbool.tag(), cks.tag());

                let cbool = abool & bbool;
                assert_eq!(cbool.tag(), cks.tag());
            }
        };

        {
            let list = builder.build();
            let list: CompactCiphertextList = serialize_then_deserialize(&list);
            assert_eq!(list.tag(), cks.tag());
            expand_and_check_tags(list.expand().unwrap(), &cks);
        }

        {
            let list_packed = builder.build_packed();
            let list_packed: CompactCiphertextList = serialize_then_deserialize(&list_packed);
            assert_eq!(list_packed.tag(), cks.tag());
            expand_and_check_tags(list_packed.expand().unwrap(), &cks);
        }
    }
}
