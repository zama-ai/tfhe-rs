use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::parameters::BooleanParameters;
use crate::boolean::{ClientKey, PublicKey, PLAINTEXT_FALSE, PLAINTEXT_TRUE};
use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use std::cell::RefCell;
pub mod bootstrapping;
use crate::boolean::engine::bootstrapping::{Bootstrapper, ServerKey};
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::commons::parameters::*;
use crate::seeders::new_seeder;

pub(crate) trait BinaryGatesEngine<L, R, K> {
    fn and(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn nand(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn nor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn or(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn xor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
    fn xnor(&mut self, ct_left: L, ct_right: R, server_key: &K) -> Ciphertext;
}

pub(crate) trait BinaryGatesAssignEngine<L, R, K> {
    fn and_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn nand_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn nor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn or_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn xor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
    fn xnor_assign(&mut self, ct_left: L, ct_right: R, server_key: &K);
}

/// Trait to be able to acces thread_local
/// engines in a generic way
pub(crate) trait WithThreadLocalEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R;
}

// All our thread local engines
// that our exposed types will use internally to implement their methods
thread_local! {
    static BOOLEAN_ENGINE: RefCell<BooleanEngine> = RefCell::new(BooleanEngine::new());
}

pub struct BooleanEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    bootstrapper: Bootstrapper,
}

impl WithThreadLocalEngine for BooleanEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        BOOLEAN_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}

// We have q = 2^32 so log2q = 32
const LOG2_Q_32: usize = 32;

impl BooleanEngine {
    pub fn create_client_key(&mut self, parameters: BooleanParameters) -> ClientKey {
        // generate the lwe secret key
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        // generate the glwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }

    pub fn create_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let server_key = self.bootstrapper.new_server_key(cks).unwrap();

        server_key
    }

    pub fn create_public_key(&mut self, client_key: &ClientKey) -> PublicKey {
        let client_parameters = client_key.parameters;

        // Formula is (n + 1) * log2(q) + 128
        let zero_encryption_count = LwePublicKeyZeroEncryptionCount(
            client_parameters.lwe_dimension.to_lwe_size().0 * LOG2_Q_32 + 128,
        );

        let lwe_public_key: LwePublicKeyOwned<u32> = par_allocate_and_generate_new_lwe_public_key(
            &client_key.lwe_secret_key,
            zero_encryption_count,
            client_key.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        PublicKey {
            lwe_public_key,
            parameters: client_key.parameters.to_owned(),
        }
    }

    pub fn trivial_encrypt(&mut self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn encrypt(&mut self, message: bool, cks: &ClientKey) -> Ciphertext {
        // encode the boolean message
        let plain: Plaintext<u32> = if message {
            Plaintext(PLAINTEXT_TRUE)
        } else {
            Plaintext(PLAINTEXT_FALSE)
        };

        // encryption
        let ct = allocate_and_encrypt_new_lwe_ciphertext(
            &cks.lwe_secret_key,
            plain,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        Ciphertext::Encrypted(ct)
    }

    pub fn encrypt_with_public_key(&mut self, message: bool, pks: &PublicKey) -> Ciphertext {
        // encode the boolean message
        let plain: Plaintext<u32> = if message {
            Plaintext(PLAINTEXT_TRUE)
        } else {
            Plaintext(PLAINTEXT_FALSE)
        };

        let mut output = LweCiphertext::new(0u32, pks.parameters.lwe_dimension.to_lwe_size());

        // encryption
        encrypt_lwe_ciphertext_with_public_key(
            &pks.lwe_public_key,
            &mut output,
            plain,
            &mut self.secret_generator,
        );

        Ciphertext::Encrypted(output)
    }

    pub fn decrypt(&mut self, ct: &Ciphertext, cks: &ClientKey) -> bool {
        match ct {
            Ciphertext::Trivial(b) => *b,
            Ciphertext::Encrypted(ciphertext) => {
                // decryption
                let decrypted = decrypt_lwe_ciphertext(&cks.lwe_secret_key, ciphertext);

                // cast as a u32
                let decrypted_u32 = decrypted.0;

                // return
                decrypted_u32 < (1 << 31)
            }
        }
    }

    pub fn not(&mut self, ct: &Ciphertext) -> Ciphertext {
        match ct {
            Ciphertext::Trivial(message) => Ciphertext::Trivial(!*message),
            Ciphertext::Encrypted(ct_ct) => {
                // Compute the linear combination for NOT: -ct
                let mut ct_res = ct_ct.clone();
                lwe_ciphertext_opposite_assign(&mut ct_res);

                // Output the result:
                Ciphertext::Encrypted(ct_res)
            }
        }
    }

    pub fn not_assign(&mut self, ct: &mut Ciphertext) {
        match ct {
            Ciphertext::Trivial(message) => *message = !*message,
            Ciphertext::Encrypted(ct_ct) => {
                lwe_ciphertext_opposite_assign(ct_ct); // compute the negation
            }
        }
    }
}

impl Default for BooleanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BooleanEngine {
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::<_>::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::<_>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            bootstrapper: Bootstrapper::new(&mut deterministic_seeder),
        }
    }

    /// convert into an actual LWE ciphertext even when trivial
    fn convert_into_lwe_ciphertext_32(
        &mut self,
        ct: &Ciphertext,
        server_key: &ServerKey,
    ) -> LweCiphertextOwned<u32> {
        match ct {
            Ciphertext::Encrypted(ct_ct) => ct_ct.clone(),
            Ciphertext::Trivial(message) => {
                // encode the boolean message
                let plain: Plaintext<u32> = if *message {
                    Plaintext(PLAINTEXT_TRUE)
                } else {
                    Plaintext(PLAINTEXT_FALSE)
                };
                allocate_and_trivially_encrypt_new_lwe_ciphertext(
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                    plain,
                )
            }
        }
    }

    pub fn mux(
        &mut self,
        ct_condition: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        // In theory MUX gate = (ct_condition AND ct_then) + (!ct_condition AND ct_else)

        match ct_condition {
            // in the case of the condition is trivially encrypted
            Ciphertext::Trivial(message_condition) => {
                if *message_condition {
                    ct_then.clone()
                } else {
                    ct_else.clone()
                }
            }
            Ciphertext::Encrypted(ct_condition_ct) => {
                // condition is actually encrypted

                // take a shortcut if ct_then is trivially encrypted
                if let Ciphertext::Trivial(message_then) = ct_then {
                    return if *message_then {
                        self.or(ct_condition, ct_else, server_key)
                    } else {
                        let ct_not_condition = self.not(ct_condition);
                        self.and(&ct_not_condition, ct_else, server_key)
                    };
                }

                // take a shortcut if ct_else is trivially encrypted
                if let Ciphertext::Trivial(message_else) = ct_else {
                    return if *message_else {
                        let ct_not_condition = self.not(ct_condition);
                        self.or(ct_then, &ct_not_condition, server_key)
                    } else {
                        self.and(ct_condition, ct_then, server_key)
                    };
                }

                // convert inputs into LweCiphertext32
                let ct_then_ct = self.convert_into_lwe_ciphertext_32(ct_then, server_key);
                let ct_else_ct = self.convert_into_lwe_ciphertext_32(ct_else, server_key);

                let mut buffer_lwe_before_pbs_o = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );

                let buffer_lwe_before_pbs = &mut buffer_lwe_before_pbs_o;
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for first AND: ct_condition + ct_then +
                // (0,...,0,-1/8)
                lwe_ciphertext_addition(buffer_lwe_before_pbs, ct_condition_ct, &ct_then_ct);
                let cst = Plaintext(PLAINTEXT_FALSE);
                lwe_ciphertext_plaintext_addition_assign(buffer_lwe_before_pbs, cst); // - 1/8

                // Compute the linear combination for second AND: - ct_condition + ct_else +
                // (0,...,0,-1/8)
                let mut ct_temp_2 = ct_condition_ct.clone(); // ct_condition
                lwe_ciphertext_opposite_assign(&mut ct_temp_2); // compute the negation
                lwe_ciphertext_addition_assign(&mut ct_temp_2, &ct_else_ct); // + ct_else
                let cst = Plaintext(PLAINTEXT_FALSE);
                lwe_ciphertext_plaintext_addition_assign(&mut ct_temp_2, cst); // - 1/8

                // Compute the first programmable bootstrapping with fixed test polynomial:
                let mut ct_pbs_1 = bootstrapper
                    .bootstrap(buffer_lwe_before_pbs, server_key)
                    .unwrap();

                let ct_pbs_2 = bootstrapper.bootstrap(&ct_temp_2, server_key).unwrap();

                // Compute the linear combination to add the two results:
                // buffer_lwe_pbs + ct_pbs_2 + (0,...,0, +1/8)
                lwe_ciphertext_addition_assign(&mut ct_pbs_1, &ct_pbs_2); // + buffer_lwe_pbs
                let cst = Plaintext(PLAINTEXT_TRUE);
                lwe_ciphertext_plaintext_addition_assign(&mut ct_pbs_1, cst); // + 1/8

                let ct_ks = bootstrapper.keyswitch(&ct_pbs_1, server_key).unwrap();

                // Output the result:
                Ciphertext::Encrypted(ct_ks)
            }
        }
    }
}

impl BinaryGatesEngine<&Ciphertext, &Ciphertext, ServerKey> for BooleanEngine {
    fn and(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(*message_left && *message_right)
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.and(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.and(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );

                let bootstrapper = &mut self.bootstrapper;

                // compute the linear combination for AND: ct_left + ct_right + (0,...,0,-1/8)
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                let cst = Plaintext(PLAINTEXT_FALSE);
                // - 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }

    fn nand(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(!(*message_left && *message_right))
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.nand(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.nand(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for NAND: - ct_left - ct_right + (0,...,0,1/8)
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                lwe_ciphertext_opposite_assign(&mut buffer_lwe_before_pbs);
                let cst = Plaintext(PLAINTEXT_TRUE);
                // + 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }

    fn nor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(!(*message_left || *message_right))
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.nor(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.nor(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for NOR: - ct_left - ct_right + (0,...,0,-1/8)
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                // compute the negation
                lwe_ciphertext_opposite_assign(&mut buffer_lwe_before_pbs);
                let cst = Plaintext(PLAINTEXT_FALSE);
                // - 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }

    fn or(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(*message_left || *message_right)
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.or(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.or(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for OR: ct_left + ct_right + (0,...,0,+1/8)
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                let cst = Plaintext(PLAINTEXT_TRUE);
                // + 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }

    fn xor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(*message_left ^ *message_right)
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.xor(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.xor(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for XOR: 2*(ct_left + ct_right) + (0,...,0,1/4)
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                let cst_add = Plaintext(PLAINTEXT_TRUE);
                // + 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst_add);
                let cst_mul = Cleartext(2u32);
                //* 2
                lwe_ciphertext_cleartext_multiplication_assign(&mut buffer_lwe_before_pbs, cst_mul);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }

    fn xnor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match (ct_left, ct_right) {
            (Ciphertext::Trivial(message_left), Ciphertext::Trivial(message_right)) => {
                Ciphertext::Trivial(!(*message_left ^ *message_right))
            }
            (Ciphertext::Encrypted(_), Ciphertext::Trivial(message_right)) => {
                self.xnor(ct_left, *message_right, server_key)
            }
            (Ciphertext::Trivial(message_left), Ciphertext::Encrypted(_)) => {
                self.xnor(*message_left, ct_right, server_key)
            }
            (Ciphertext::Encrypted(ct_left_ct), Ciphertext::Encrypted(ct_right_ct)) => {
                let mut buffer_lwe_before_pbs = LweCiphertext::new(
                    0u32,
                    server_key
                        .bootstrapping_key
                        .input_lwe_dimension()
                        .to_lwe_size(),
                );
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for XNOR: 2*(-ct_left - ct_right + (0,...,0,-1/8))
                // ct_left + ct_right
                lwe_ciphertext_addition(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct);
                let cst_add = Plaintext(PLAINTEXT_TRUE);
                // + 1/8
                lwe_ciphertext_plaintext_addition_assign(&mut buffer_lwe_before_pbs, cst_add);
                // compute the negation
                lwe_ciphertext_opposite_assign(&mut buffer_lwe_before_pbs);
                let cst_mul = Cleartext(2u32);
                //* 2
                lwe_ciphertext_cleartext_multiplication_assign(&mut buffer_lwe_before_pbs, cst_mul);

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }
}

impl BinaryGatesAssignEngine<&mut Ciphertext, &Ciphertext, ServerKey> for BooleanEngine {
    fn and_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.and(&ct_left_clone, ct_right, server_key);
    }

    fn nand_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nand(&ct_left_clone, ct_right, server_key);
    }

    fn nor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nor(&ct_left_clone, ct_right, server_key);
    }

    fn or_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.or(&ct_left_clone, ct_right, server_key);
    }

    fn xor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xor(&ct_left_clone, ct_right, server_key);
    }

    fn xnor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xnor(&ct_left_clone, ct_right, server_key);
    }
}

impl BinaryGatesAssignEngine<&mut Ciphertext, bool, ServerKey> for BooleanEngine {
    fn and_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.and(&ct_left_clone, ct_right, server_key);
    }

    fn nand_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nand(&ct_left_clone, ct_right, server_key);
    }

    fn nor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nor(&ct_left_clone, ct_right, server_key);
    }

    fn or_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.or(&ct_left_clone, ct_right, server_key);
    }

    fn xor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xor(&ct_left_clone, ct_right, server_key);
    }

    fn xnor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xnor(&ct_left_clone, ct_right, server_key);
    }
}

impl BinaryGatesAssignEngine<bool, &mut Ciphertext, ServerKey> for BooleanEngine {
    fn and_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.and(ct_left, &ct_right_clone, server_key);
    }

    fn nand_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.nand(ct_left, &ct_right_clone, server_key);
    }

    fn nor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.nor(ct_left, &ct_right_clone, server_key);
    }

    fn or_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.or(ct_left, &ct_right_clone, server_key);
    }

    fn xor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.xor(ct_left, &ct_right_clone, server_key);
    }

    fn xnor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.xnor(ct_left, &ct_right_clone, server_key);
    }
}

impl BinaryGatesEngine<&Ciphertext, bool, ServerKey> for BooleanEngine {
    fn and(&mut self, ct_left: &Ciphertext, ct_right: bool, _server_key: &ServerKey) -> Ciphertext {
        if ct_right {
            // ct AND true = ct
            ct_left.clone()
        } else {
            // ct AND false = false
            self.trivial_encrypt(false)
        }
    }

    fn nand(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &ServerKey,
    ) -> Ciphertext {
        if ct_right {
            // NOT (ct AND true) = NOT(ct)
            self.not(ct_left)
        } else {
            // NOT (ct AND false) = NOT(false) = true
            self.trivial_encrypt(true)
        }
    }

    fn nor(&mut self, ct_left: &Ciphertext, ct_right: bool, _server_key: &ServerKey) -> Ciphertext {
        if ct_right {
            // NOT (ct OR true) = NOT(true) = false
            self.trivial_encrypt(false)
        } else {
            // NOT (ct OR false) = NOT(ct)
            self.not(ct_left)
        }
    }

    fn or(&mut self, ct_left: &Ciphertext, ct_right: bool, _server_key: &ServerKey) -> Ciphertext {
        if ct_right {
            // ct OR true = true
            self.trivial_encrypt(true)
        } else {
            // ct OR false = ct
            ct_left.clone()
        }
    }

    fn xor(&mut self, ct_left: &Ciphertext, ct_right: bool, _server_key: &ServerKey) -> Ciphertext {
        if ct_right {
            // ct XOR true = NOT(ct)
            self.not(ct_left)
        } else {
            // ct XOR false = ct
            ct_left.clone()
        }
    }

    fn xnor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &ServerKey,
    ) -> Ciphertext {
        if ct_right {
            // NOT(ct XOR true) = NOT(NOT(ct)) = ct
            ct_left.clone()
        } else {
            // NOT(ct XOR false) = NOT(ct)
            self.not(ct_left)
        }
    }
}

impl BinaryGatesEngine<bool, &Ciphertext, ServerKey> for BooleanEngine {
    fn and(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.and(ct_right, ct_left, server_key)
    }

    fn nand(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.nand(ct_right, ct_left, server_key)
    }

    fn nor(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.nor(ct_right, ct_left, server_key)
    }

    fn or(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.or(ct_right, ct_left, server_key)
    }

    fn xor(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.xor(ct_right, ct_left, server_key)
    }

    fn xnor(&mut self, ct_left: bool, ct_right: &Ciphertext, server_key: &ServerKey) -> Ciphertext {
        self.xnor(ct_right, ct_left, server_key)
    }
}
