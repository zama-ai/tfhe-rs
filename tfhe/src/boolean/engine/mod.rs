use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::parameters::BooleanParameters;
use crate::boolean::{ClientKey, PublicKey, PLAINTEXT_FALSE, PLAINTEXT_TRUE};
use crate::core_crypto::prelude::*;
use bootstrapping::{BooleanServerKey, Bootstrapper, CpuBootstrapper};
use std::cell::RefCell;
pub mod bootstrapping;
use crate::boolean::engine::bootstrapping::CpuBootstrapKey;
use crate::core_crypto::backends::default::engines::ActivatedRandomGenerator;
use crate::core_crypto::commons::crypto::secret::generators::DeterministicSeeder;
use crate::seeders::new_seeder;

#[cfg(feature = "cuda")]
use bootstrapping::{CudaBootstrapKey, CudaBootstrapper};

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

pub(crate) type CpuBooleanEngine = BooleanEngine<CpuBootstrapper>;
#[cfg(feature = "cuda")]
pub(crate) type CudaBooleanEngine = BooleanEngine<CudaBootstrapper>;

// All our thread local engines
// that our exposed types will use internally to implement their methods
thread_local! {
    static CPU_ENGINE: RefCell<BooleanEngine<CpuBootstrapper>> = RefCell::new(BooleanEngine::<_>::new());
    #[cfg(feature = "cuda")]
    static CUDA_ENGINE: RefCell<BooleanEngine<CudaBootstrapper>> = RefCell::new(BooleanEngine::<_>::new());
}

impl WithThreadLocalEngine for CpuBooleanEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        CPU_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}

#[cfg(feature = "cuda")]
impl WithThreadLocalEngine for CudaBooleanEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        CUDA_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}

pub(crate) struct BooleanEngine<B> {
    pub(crate) engine: DefaultEngine,
    bootstrapper: B,
}

impl BooleanEngine<CpuBootstrapper> {
    pub fn create_server_key(&mut self, cks: &ClientKey) -> CpuBootstrapKey {
        let server_key = self.bootstrapper.new_server_key(cks).unwrap();

        server_key
    }
}

#[cfg(feature = "cuda")]
impl BooleanEngine<CudaBootstrapper> {
    pub fn create_server_key(&mut self, cpu_key: &CpuBootstrapKey) -> CudaBootstrapKey {
        let server_key = self.bootstrapper.new_serverk_key(cpu_key).unwrap();

        server_key
    }
}

// We have q = 32 so log2q = 5
const LOG2_Q_32: usize = 5;

impl<B> BooleanEngine<B> {
    pub fn create_client_key(&mut self, parameters: BooleanParameters) -> ClientKey {
        // generate the lwe secret key
        let lwe_secret_key: LweSecretKey32 = self
            .engine
            .generate_new_lwe_secret_key(parameters.lwe_dimension)
            .unwrap();

        // generate the rlwe secret key
        let glwe_secret_key: GlweSecretKey32 = self
            .engine
            .generate_new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size)
            .unwrap();

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }

    pub fn create_public_key(&mut self, client_key: &ClientKey) -> PublicKey {
        let client_parameters = client_key.parameters;

        // Formula is (n + 1) * log2(q) + 128
        let zero_encryption_count = LwePublicKeyZeroEncryptionCount(
            client_parameters.lwe_dimension.to_lwe_size().0 * LOG2_Q_32 + 128,
        );

        PublicKey {
            lwe_public_key: self
                .engine
                .generate_new_lwe_public_key(
                    &client_key.lwe_secret_key,
                    Variance(client_key.parameters.lwe_modular_std_dev.get_variance()),
                    zero_encryption_count,
                )
                .unwrap(),
            parameters: client_key.parameters.to_owned(),
        }
    }

    pub fn trivial_encrypt(&mut self, message: bool) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    pub fn encrypt(&mut self, message: bool, cks: &ClientKey) -> Ciphertext {
        // encode the boolean message
        let plain: Plaintext32 = if message {
            self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap()
        } else {
            self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap()
        };

        // convert into a variance
        let var = Variance(cks.parameters.lwe_modular_std_dev.get_variance());

        // encryption
        let ct = self
            .engine
            .encrypt_lwe_ciphertext(&cks.lwe_secret_key, &plain, var)
            .unwrap();

        Ciphertext::Encrypted(ct)
    }

    pub fn encrypt_with_public_key(&mut self, message: bool, pks: &PublicKey) -> Ciphertext {
        // encode the boolean message
        let plain: Plaintext32 = if message {
            self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap()
        } else {
            self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap()
        };

        let mut underlying_ciphertext = self
            .engine
            .create_lwe_ciphertext_from(vec![0u32; pks.parameters.lwe_dimension.to_lwe_size().0])
            .unwrap();

        // encryption
        self.engine
            .discard_encrypt_lwe_ciphertext_with_public_key(
                &pks.lwe_public_key,
                &mut underlying_ciphertext,
                &plain,
            )
            .unwrap();

        Ciphertext::Encrypted(underlying_ciphertext)
    }

    pub fn decrypt(&mut self, ct: &Ciphertext, cks: &ClientKey) -> bool {
        match ct {
            Ciphertext::Trivial(b) => *b,
            Ciphertext::Encrypted(ciphertext) => {
                // decryption
                let decrypted = self
                    .engine
                    .decrypt_lwe_ciphertext(&cks.lwe_secret_key, ciphertext)
                    .unwrap();

                // cast as a u32
                let mut decrypted_u32: u32 = 0;
                self.engine
                    .discard_retrieve_plaintext(&mut decrypted_u32, &decrypted)
                    .unwrap();

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
                self.engine.fuse_opp_lwe_ciphertext(&mut ct_res).unwrap(); // compute the negation

                // Output the result:
                Ciphertext::Encrypted(ct_res)
            }
        }
    }

    pub fn not_assign(&mut self, ct: &mut Ciphertext) {
        match ct {
            Ciphertext::Trivial(message) => *message = !*message,
            Ciphertext::Encrypted(ct_ct) => {
                self.engine.fuse_opp_lwe_ciphertext(ct_ct).unwrap(); // compute the negation
            }
        }
    }
}

impl<B> BooleanEngine<B>
where
    B: Bootstrapper,
{
    pub fn new() -> Self {
        let root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder)
    }

    pub fn new_from_seeder(mut root_seeder: Box<dyn Seeder>) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        let default_engine_seeder = Box::new(DeterministicSeeder::<ActivatedRandomGenerator>::new(
            deterministic_seeder.seed(),
        ));

        let engine =
            DefaultEngine::new(default_engine_seeder).expect("Failed to create a DefaultEngine");
        Self {
            engine,
            bootstrapper: Default::default(),
        }
    }

    /// convert into an actual LWE ciphertext even when trivial
    fn convert_into_lwe_ciphertext_32(
        &mut self,
        ct: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> LweCiphertext32 {
        match ct {
            Ciphertext::Encrypted(ct_ct) => ct_ct.clone(),
            Ciphertext::Trivial(message) => {
                // encode the boolean message
                let plain: Plaintext32 = if *message {
                    self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap()
                } else {
                    self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap()
                };
                self.engine
                    .trivially_encrypt_lwe_ciphertext(server_key.lwe_size(), &plain)
                    .unwrap()
            }
        }
    }

    pub fn mux(
        &mut self,
        ct_condition: &Ciphertext,
        ct_then: &Ciphertext,
        ct_else: &Ciphertext,
        server_key: &B::ServerKey,
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

                let mut buffer_lwe_before_pbs_o = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let buffer_lwe_before_pbs = &mut buffer_lwe_before_pbs_o;
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for first AND: ct_condition + ct_then +
                // (0,...,0,-1/8)
                self.engine
                    .discard_add_lwe_ciphertext(buffer_lwe_before_pbs, ct_condition_ct, &ct_then_ct)
                    .unwrap(); // ct_condition + ct_then
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(buffer_lwe_before_pbs, &cst)
                    .unwrap(); //
                               // - 1/8

                // Compute the linear combination for second AND: - ct_condition + ct_else +
                // (0,...,0,-1/8)
                let mut ct_temp_2 = ct_condition_ct.clone(); // ct_condition
                self.engine.fuse_opp_lwe_ciphertext(&mut ct_temp_2).unwrap(); // compute the negation
                self.engine
                    .fuse_add_lwe_ciphertext(&mut ct_temp_2, &ct_else_ct)
                    .unwrap(); // + ct_else
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut ct_temp_2, &cst)
                    .unwrap(); //
                               // - 1/8

                // Compute the first programmable bootstrapping with fixed test polynomial:
                let mut ct_pbs_1 = bootstrapper
                    .bootstrap(buffer_lwe_before_pbs, server_key)
                    .unwrap();

                let ct_pbs_2 = bootstrapper.bootstrap(&ct_temp_2, server_key).unwrap();

                // Compute the linear combination to add the two results:
                // buffer_lwe_pbs + ct_pbs_2 + (0,...,0, +1/8)
                self.engine
                    .fuse_add_lwe_ciphertext(&mut ct_pbs_1, &ct_pbs_2)
                    .unwrap(); // + buffer_lwe_pbs
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut ct_pbs_1, &cst)
                    .unwrap(); // + 1/8

                let ct_ks = bootstrapper.keyswitch(&ct_pbs_1, server_key).unwrap();

                // Output the result:
                Ciphertext::Encrypted(ct_ks)
            }
        }
    }
}

impl<B> BinaryGatesEngine<&Ciphertext, &Ciphertext, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // compute the linear combination for AND: ct_left + ct_right + (0,...,0,-1/8)
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst)
                    .unwrap(); //
                               // - 1/8

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
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for NAND: - ct_left - ct_right + (0,...,0,1/8)
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                self.engine
                    .fuse_opp_lwe_ciphertext(&mut buffer_lwe_before_pbs)
                    .unwrap(); // compute the negation
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst)
                    .unwrap(); // + 1/8

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
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for NOR: - ct_left - ct_right + (0,...,0,-1/8)
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                self.engine
                    .fuse_opp_lwe_ciphertext(&mut buffer_lwe_before_pbs)
                    .unwrap(); // compute the negation
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst)
                    .unwrap(); //
                               // - 1/8

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
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for OR: ct_left + ct_right + (0,...,0,+1/8)
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                let cst = self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst)
                    .unwrap(); // + 1/8

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
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for XOR: 2*(ct_left + ct_right) + (0,...,0,1/4)
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                let cst_add = self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst_add)
                    .unwrap(); // + 1/8
                let cst_mul = self.engine.create_cleartext_from(&2u32).unwrap();
                self.engine
                    .fuse_mul_lwe_ciphertext_cleartext(&mut buffer_lwe_before_pbs, &cst_mul)
                    .unwrap(); //* 2

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
        server_key: &B::ServerKey,
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
                let mut buffer_lwe_before_pbs = self
                    .engine
                    .create_lwe_ciphertext_from(vec![0u32; server_key.lwe_size().0])
                    .unwrap();
                let bootstrapper = &mut self.bootstrapper;

                // Compute the linear combination for XNOR: 2*(-ct_left - ct_right + (0,...,0,-1/8))
                self.engine
                    .discard_add_lwe_ciphertext(&mut buffer_lwe_before_pbs, ct_left_ct, ct_right_ct)
                    .unwrap(); // ct_left + ct_right
                let cst_add = self.engine.create_plaintext_from(&PLAINTEXT_TRUE).unwrap();
                self.engine
                    .fuse_add_lwe_ciphertext_plaintext(&mut buffer_lwe_before_pbs, &cst_add)
                    .unwrap(); // + 1/8
                self.engine
                    .fuse_opp_lwe_ciphertext(&mut buffer_lwe_before_pbs)
                    .unwrap(); // compute the negation
                let cst_mul = self.engine.create_cleartext_from(&2u32).unwrap();
                self.engine
                    .fuse_mul_lwe_ciphertext_cleartext(&mut buffer_lwe_before_pbs, &cst_mul)
                    .unwrap(); //* 2

                // compute the bootstrap and the key switch
                bootstrapper
                    .bootstrap_keyswitch(buffer_lwe_before_pbs, server_key)
                    .unwrap()
            }
        }
    }
}

impl<B> BinaryGatesAssignEngine<&mut Ciphertext, &Ciphertext, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.and(&ct_left_clone, ct_right, server_key);
    }

    fn nand_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nand(&ct_left_clone, ct_right, server_key);
    }

    fn nor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nor(&ct_left_clone, ct_right, server_key);
    }

    fn or_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.or(&ct_left_clone, ct_right, server_key);
    }

    fn xor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xor(&ct_left_clone, ct_right, server_key);
    }

    fn xnor_assign(
        &mut self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xnor(&ct_left_clone, ct_right, server_key);
    }
}

impl<B> BinaryGatesAssignEngine<&mut Ciphertext, bool, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.and(&ct_left_clone, ct_right, server_key);
    }

    fn nand_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nand(&ct_left_clone, ct_right, server_key);
    }

    fn nor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.nor(&ct_left_clone, ct_right, server_key);
    }

    fn or_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.or(&ct_left_clone, ct_right, server_key);
    }

    fn xor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xor(&ct_left_clone, ct_right, server_key);
    }

    fn xnor_assign(&mut self, ct_left: &mut Ciphertext, ct_right: bool, server_key: &B::ServerKey) {
        let ct_left_clone = ct_left.clone();
        *ct_left = self.xnor(&ct_left_clone, ct_right, server_key);
    }
}

impl<B> BinaryGatesAssignEngine<bool, &mut Ciphertext, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.and(ct_left, &ct_right_clone, server_key);
    }

    fn nand_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.nand(ct_left, &ct_right_clone, server_key);
    }

    fn nor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.nor(ct_left, &ct_right_clone, server_key);
    }

    fn or_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.or(ct_left, &ct_right_clone, server_key);
    }

    fn xor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.xor(ct_left, &ct_right_clone, server_key);
    }

    fn xnor_assign(&mut self, ct_left: bool, ct_right: &mut Ciphertext, server_key: &B::ServerKey) {
        let ct_right_clone = ct_right.clone();
        *ct_right = self.xnor(ct_left, &ct_right_clone, server_key);
    }
}

impl<B> BinaryGatesEngine<&Ciphertext, bool, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &B::ServerKey,
    ) -> Ciphertext {
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
        _server_key: &B::ServerKey,
    ) -> Ciphertext {
        if ct_right {
            // NOT (ct AND true) = NOT(ct)
            self.not(ct_left)
        } else {
            // NOT (ct AND false) = NOT(false) = true
            self.trivial_encrypt(true)
        }
    }

    fn nor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &B::ServerKey,
    ) -> Ciphertext {
        if ct_right {
            // NOT (ct OR true) = NOT(true) = false
            self.trivial_encrypt(false)
        } else {
            // NOT (ct OR false) = NOT(ct)
            self.not(ct_left)
        }
    }

    fn or(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &B::ServerKey,
    ) -> Ciphertext {
        if ct_right {
            // ct OR true = true
            self.trivial_encrypt(true)
        } else {
            // ct OR false = ct
            ct_left.clone()
        }
    }

    fn xor(
        &mut self,
        ct_left: &Ciphertext,
        ct_right: bool,
        _server_key: &B::ServerKey,
    ) -> Ciphertext {
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
        _server_key: &B::ServerKey,
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

impl<B> BinaryGatesEngine<bool, &Ciphertext, B::ServerKey> for BooleanEngine<B>
where
    B: Bootstrapper,
{
    fn and(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.and(ct_right, ct_left, server_key)
    }

    fn nand(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.nand(ct_right, ct_left, server_key)
    }

    fn nor(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.nor(ct_right, ct_left, server_key)
    }

    fn or(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.or(ct_right, ct_left, server_key)
    }

    fn xor(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.xor(ct_right, ct_left, server_key)
    }

    fn xnor(
        &mut self,
        ct_left: bool,
        ct_right: &Ciphertext,
        server_key: &B::ServerKey,
    ) -> Ciphertext {
        self.xnor(ct_right, ct_left, server_key)
    }
}
