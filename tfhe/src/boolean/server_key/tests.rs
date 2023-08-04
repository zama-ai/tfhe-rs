use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::client_key::ClientKey;
use crate::boolean::parameters::BooleanParameters;
use crate::boolean::server_key::{BinaryBooleanGates, BinaryBooleanGatesAssign, ServerKey};
use crate::boolean::{random_boolean, random_integer};

/// Number of assert in randomized tests
const NB_TEST: usize = 128;

/// Number of ciphertext in the deep circuit test
const NB_CT: usize = 8;

/// Number of gates computed in the deep circuit test
const NB_GATE: usize = 1 << 11;

mod default_parameters_tests {
    use super::*;
    use crate::boolean::parameters::DEFAULT_PARAMETERS;

    #[test]
    fn test_encrypt_decrypt_lwe_secret_key_default_parameters() {
        test_encrypt_decrypt_lwe_secret_key(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_and_gate_default_parameters() {
        test_and_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_nand_gate_default_parameters() {
        test_nand_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_or_gate_default_parameters() {
        test_or_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_nor_gate_default_parameters() {
        test_nor_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_xor_gate_default_parameters() {
        test_xor_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_xnor_gate_default_parameters() {
        test_xnor_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_not_gate_default_parameters() {
        test_not_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_mux_gate_default_parameters() {
        test_mux_gate(DEFAULT_PARAMETERS);
    }
    #[test]
    fn test_deep_circuit_default_parameters() {
        test_deep_circuit(DEFAULT_PARAMETERS);
    }
}

mod low_prob_parameters_tests {
    use super::*;
    use crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165;

    #[test]
    fn test_encrypt_decrypt_lwe_secret_key_low_prob() {
        test_encrypt_decrypt_lwe_secret_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_and_gate_low_prob() {
        test_and_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_nand_gate_low_prob() {
        test_nand_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_or_gate_low_prob() {
        test_or_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_nor_gate_low_prob() {
        test_nor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_xor_gate_low_prob() {
        test_xor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_xnor_gate_low_prob() {
        test_xnor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_not_gate_low_prob() {
        test_not_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_mux_gate_low_prob() {
        test_mux_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
    #[test]
    fn test_deep_circuit_low_prob() {
        test_deep_circuit(PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    }
}

mod default_parameters_ks_pbs_tests {
    use super::*;
    use crate::boolean::parameters::DEFAULT_PARAMETERS_KS_PBS;

    #[test]
    fn test_encrypt_decrypt_lwe_secret_key_default_parameters_ks_pbs() {
        test_encrypt_decrypt_lwe_secret_key(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_and_gate_default_parameters_ks_pbs() {
        test_and_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_nand_gate_default_parameters_ks_pbs() {
        test_nand_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_or_gate_default_parameters_ks_pbs() {
        test_or_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_nor_gate_default_parameters_ks_pbs() {
        test_nor_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_xor_gate_default_parameters_ks_pbs() {
        test_xor_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_xnor_gate_default_parameters_ks_pbs() {
        test_xnor_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_not_gate_default_parameters_ks_pbs() {
        test_not_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_mux_gate_default_parameters_ks_pbs() {
        test_mux_gate(DEFAULT_PARAMETERS_KS_PBS);
    }
    #[test]
    fn test_deep_circuit_default_parameters_ks_pbs() {
        test_deep_circuit(DEFAULT_PARAMETERS_KS_PBS);
    }
}

mod low_prob_parameters_ks_pbs_tests {
    use super::*;
    use crate::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS;

    #[test]
    fn test_encrypt_decrypt_lwe_secret_key_low_probability_ks_pbs() {
        test_encrypt_decrypt_lwe_secret_key(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_and_gate_low_probability_ks_pbs() {
        test_and_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_nand_gate_low_probability_ks_pbs() {
        test_nand_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_or_gate_low_probability_ks_pbs() {
        test_or_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_nor_gate_low_probability_ks_pbs() {
        test_nor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_xor_gate_low_probability_ks_pbs() {
        test_xor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_xnor_gate_low_probability_ks_pbs() {
        test_xnor_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_not_gate_low_probability_ks_pbs() {
        test_not_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_mux_gate_low_probability_ks_pbs() {
        test_mux_gate(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
    #[test]
    fn test_deep_circuit_low_probability_ks_pbs() {
        test_deep_circuit(PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS);
    }
}

mod tfhe_lib_parameters_tests {
    use super::*;
    use crate::boolean::parameters::TFHE_LIB_PARAMETERS;

    #[test]
    fn test_encrypt_decrypt_lwe_secret_key_tfhe_lib_parameters() {
        test_encrypt_decrypt_lwe_secret_key(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_and_gate_tfhe_lib_parameters() {
        test_and_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_nand_gate_tfhe_lib_parameters() {
        test_nand_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_or_gate_tfhe_lib_parameters() {
        test_or_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_nor_gate_tfhe_lib_parameters() {
        test_nor_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_xor_gate_tfhe_lib_parameters() {
        test_xor_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_xnor_gate_tfhe_lib_parameters() {
        test_xnor_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_not_gate_tfhe_lib_parameters() {
        test_not_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_mux_gate_tfhe_lib_parameters() {
        test_mux_gate(TFHE_LIB_PARAMETERS);
    }
    #[test]
    fn test_deep_circuit_tfhe_lib_parameters() {
        test_deep_circuit(TFHE_LIB_PARAMETERS);
    }
}

/// test encryption and decryption with the LWE secret key
fn test_encrypt_decrypt_lwe_secret_key(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // encryption of false
        let ct_false = cks.encrypt(false);

        // encryption of true
        let ct_true = cks.encrypt(true);

        // decryption of false
        let dec_false = cks.decrypt(&ct_false);

        // decryption of true
        let dec_true = cks.decrypt(&ct_true);

        // assert
        assert!(!dec_false);
        assert!(dec_true);

        // encryption of false
        let ct_false = sks.trivial_encrypt(false);

        // encryption of true
        let ct_true = sks.trivial_encrypt(true);

        // decryption of false
        let dec_false = cks.decrypt(&ct_false);

        // decryption of true
        let dec_true = cks.decrypt(&ct_true);

        // assert
        assert!(!dec_false);
        assert!(dec_true);
    }
}

/// This function randomly either computes a regular encryption of the message or a trivial
/// encryption of the message
fn random_enum_encryption(cks: &ClientKey, sks: &ServerKey, message: bool) -> Ciphertext {
    if random_boolean() {
        cks.encrypt(message)
    } else {
        sks.trivial_encrypt(message)
    }
}

fn test_and_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = b1 && b2;

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // AND gate -> "left: {:?}, right: {:?}",ct1, ct2
        let ct_res = sks.and(&ct1, &ct2);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {ct1:?}, right: {ct2:?}");

        // AND gate -> left: Ciphertext, right: bool
        let ct_res = sks.and(&ct1, b2);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {ct1:?}, right: {b2:?}");

        // AND gate -> left: bool, right: Ciphertext
        let ct_res = sks.and(b1, &ct2);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {b1:?}, right: {ct2:?}");

        // AND gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.and_assign(&mut ct_res, &ct2);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {ct1:?}, right: {ct2:?}");

        // AND gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.and_assign(&mut ct_res, b2);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {ct1:?}, right: {b2:?}");

        // AND gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.and_assign(b1, &mut ct_res);

        // decryption
        let dec_and = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_and, "left: {b1:?}, right: {ct2:?}");
    }
}

fn test_mux_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of three random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let b3 = random_boolean();
        let expected_result = if b1 { b2 } else { b3 };

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // encryption of b3
        let ct3 = random_enum_encryption(&cks, &sks, b3);

        // MUX gate
        let ct_res = sks.mux(&ct1, &ct2, &ct3);

        // decryption
        let dec_mux = cks.decrypt(&ct_res);

        // assert
        assert_eq!(
            expected_result, dec_mux,
            "cond: {ct1:?}, then: {ct2:?}, else: {ct3:?}"
        );
    }
}

fn test_nand_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = !(b1 && b2);

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // NAND gate -> left: Ciphertext, right: Ciphertext
        let ct_res = sks.nand(&ct1, &ct2);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {ct1:?}, right: {ct2:?}");

        // NAND gate -> left: Ciphertext, right: bool
        let ct_res = sks.nand(&ct1, b2);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {ct1:?}, right: {b2:?}");

        // NAND gate -> left: bool, right: Ciphertext
        let ct_res = sks.nand(b1, &ct2);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {b1:?}, right: {ct2:?}");

        // NAND gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.nand_assign(&mut ct_res, &ct2);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {ct1:?}, right: {ct2:?}");

        // NAND gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.nand_assign(&mut ct_res, b2);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {ct1:?}, right: {b2:?}");

        // NAND gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.nand_assign(b1, &mut ct_res);

        // decryption
        let dec_nand = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nand, "left: {b1:?}, right: {ct2:?}");
    }
}

fn test_nor_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = !(b1 || b2);

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // NOR gate -> left: Ciphertext, right: Ciphertext
        let ct_res = sks.nor(&ct1, &ct2);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {ct1:?}, right: {ct2:?}");

        // NOR gate -> left: Ciphertext, right: bool
        let ct_res = sks.nor(&ct1, b2);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {ct1:?}, right: {b2:?}");

        // NOR gate -> left: bool, right: Ciphertext
        let ct_res = sks.nor(b1, &ct2);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {b1:?}, right: {ct2:?}");

        // NOR gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.nor_assign(&mut ct_res, &ct2);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {ct1:?}, right: {ct2:?}");

        // NOR gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.nor_assign(&mut ct_res, b2);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {ct1:?}, right: {b2:?}");

        // NOR gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.nor_assign(b1, &mut ct_res);

        // decryption
        let dec_nor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_nor, "left: {b1:?}, right: {ct2:?}");
    }
}

fn test_not_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of one random booleans
        let b1 = random_boolean();
        let expected_result = !b1;

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // NOT gate
        let ct_res = sks.not(&ct1);

        // decryption
        let dec_not = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_not);

        // NOT gate
        let mut ct_res = ct1.clone();
        sks.not_assign(&mut ct_res);

        // decryption
        let dec_not = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_not);
    }
}

fn test_or_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = b1 || b2;

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // OR gate -> left: Ciphertext, right: Ciphertext
        let ct_res = sks.or(&ct1, &ct2);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {ct1:?}, right: {ct2:?}");

        // OR gate -> left: Ciphertext, right: bool
        let ct_res = sks.or(&ct1, b2);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {ct1:?}, right: {b2:?}");

        // OR gate -> left: bool, right: Ciphertext
        let ct_res = sks.or(b1, &ct2);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {b1:?}, right: {ct2:?}");

        // OR gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.or_assign(&mut ct_res, &ct2);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {ct1:?}, right: {ct2:?}");

        // OR gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.or_assign(&mut ct_res, b2);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {ct1:?}, right: {b2:?}");

        // OR gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.or_assign(b1, &mut ct_res);

        // decryption
        let dec_or = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_or, "left: {b1:?}, right: {ct2:?}");
    }
}

fn test_xnor_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = b1 == b2;

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // XNOR gate -> left: Ciphertext, right: Ciphertext
        let ct_res = sks.xnor(&ct1, &ct2);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {ct1:?}, right: {ct2:?}");

        // XNOR gate -> left: Ciphertext, right: bool
        let ct_res = sks.xnor(&ct1, b2);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {ct1:?}, right: {b2:?}");

        // XNOR gate -> left: bool, right: Ciphertext
        let ct_res = sks.xnor(b1, &ct2);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {b1:?}, right: {ct2:?}");

        // XNOR gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.xnor_assign(&mut ct_res, &ct2);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {ct1:?}, right: {ct2:?}");

        // XNOR gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.xnor_assign(&mut ct_res, b2);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {ct1:?}, right: {b2:?}");

        // XNOR gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.xnor_assign(b1, &mut ct_res);

        // decryption
        let dec_xnor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xnor, "left: {b1:?}, right: {ct2:?}");
    }
}

fn test_xor_gate(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    for _ in 0..NB_TEST {
        // generation of two random booleans
        let b1 = random_boolean();
        let b2 = random_boolean();
        let expected_result = b1 ^ b2;

        // encryption of b1
        let ct1 = random_enum_encryption(&cks, &sks, b1);

        // encryption of b2
        let ct2 = random_enum_encryption(&cks, &sks, b2);

        // XOR gate -> left: Ciphertext, right: Ciphertext
        let ct_res = sks.xor(&ct1, &ct2);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {ct1:?}, right: {ct2:?}");

        // XOR gate -> left: Ciphertext, right: bool
        let ct_res = sks.xor(&ct1, b2);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {ct1:?}, right: {b2:?}");

        // XOR gate -> left: bool, right: Ciphertext
        let ct_res = sks.xor(b1, &ct2);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {b1:?}, right: {ct2:?}");

        // XOR gate -> "left: {:?}, right: {:?}",ct1, ct2
        let mut ct_res = ct1.clone();
        sks.xor_assign(&mut ct_res, &ct2);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {ct1:?}, right: {ct2:?}");

        // XOR gate -> left: Ciphertext, right: bool
        let mut ct_res = ct1.clone();
        sks.xor_assign(&mut ct_res, b2);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {ct1:?}, right: {b2:?}");

        // XOR gate -> left: bool, right: Ciphertext
        let mut ct_res = ct2.clone();
        sks.xor_assign(b1, &mut ct_res);

        // decryption
        let dec_xor = cks.decrypt(&ct_res);

        // assert
        assert_eq!(expected_result, dec_xor, "left: {b1:?}, right: {ct2:?}");
    }
}

/// generate a random index for the table in the long run tests
fn random_index() -> usize {
    (random_integer() % (NB_CT as u32)) as usize
}

/// randomly select a gate, randomly select inputs and the output,
/// compute the selected gate with the selected inputs
/// and write in the selected output
fn random_gate_all(ct_tab: &mut [Ciphertext], bool_tab: &mut [bool], sks: &ServerKey) {
    // select a random gate in the array [NOT,CMUX,AND,NAND,NOR,OR,XOR,XNOR]
    let gate_id = random_integer() % 8;

    let index_1: usize = random_index();
    let index_2: usize = random_index();

    if gate_id == 0 {
        // NOT gate
        bool_tab[index_2] = !bool_tab[index_1];
        ct_tab[index_2] = sks.not(&ct_tab[index_1]);
    } else if gate_id == 1 {
        // MUX gate
        let index_3: usize = random_index();
        let index_4: usize = random_index();
        bool_tab[index_4] = if bool_tab[index_1] {
            bool_tab[index_2]
        } else {
            bool_tab[index_3]
        };
        ct_tab[index_4] = sks.mux(&ct_tab[index_1], &ct_tab[index_2], &ct_tab[index_3]);
    } else {
        // 2-input gate
        let index_3: usize = random_index();

        if gate_id == 2 {
            // AND gate
            bool_tab[index_3] = bool_tab[index_1] && bool_tab[index_2];
            ct_tab[index_3] = sks.and(&ct_tab[index_1], &ct_tab[index_2]);
        } else if gate_id == 3 {
            // NAND gate
            bool_tab[index_3] = !(bool_tab[index_1] && bool_tab[index_2]);
            ct_tab[index_3] = sks.nand(&ct_tab[index_1], &ct_tab[index_2]);
        } else if gate_id == 4 {
            // NOR gate
            bool_tab[index_3] = !(bool_tab[index_1] || bool_tab[index_2]);
            ct_tab[index_3] = sks.nor(&ct_tab[index_1], &ct_tab[index_2]);
        } else if gate_id == 5 {
            // OR gate
            bool_tab[index_3] = bool_tab[index_1] || bool_tab[index_2];
            ct_tab[index_3] = sks.or(&ct_tab[index_1], &ct_tab[index_2]);
        } else if gate_id == 6 {
            // XOR gate
            bool_tab[index_3] = bool_tab[index_1] ^ bool_tab[index_2];
            ct_tab[index_3] = sks.xor(&ct_tab[index_1], &ct_tab[index_2]);
        } else {
            // XNOR gate
            bool_tab[index_3] = !(bool_tab[index_1] ^ bool_tab[index_2]);
            ct_tab[index_3] = sks.xnor(&ct_tab[index_1], &ct_tab[index_2]);
        }
    }
}

fn test_deep_circuit(parameters: BooleanParameters) {
    // generate the client key set
    let cks = ClientKey::new(&parameters);

    // generate the server key set
    let sks = ServerKey::new(&cks);

    // create an array of ciphertexts
    let mut ct_tab: Vec<Ciphertext> = vec![cks.encrypt(true); NB_CT];

    // create an array of booleans
    let mut bool_tab: Vec<bool> = vec![true; NB_CT];

    // randomly fill both arrays
    for (ct, boolean) in ct_tab.iter_mut().zip(bool_tab.iter_mut()) {
        *boolean = random_boolean();
        *ct = cks.encrypt(*boolean);
    }

    // compute NB_GATE gates
    for _ in 0..NB_GATE {
        random_gate_all(&mut ct_tab, &mut bool_tab, &sks);
    }

    // decrypt and assert equality
    for (ct, boolean) in ct_tab.iter().zip(bool_tab.iter()) {
        let dec = cks.decrypt(ct);
        assert_eq!(*boolean, dec);
    }
}
