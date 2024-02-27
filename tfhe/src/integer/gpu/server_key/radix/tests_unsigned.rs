use crate::core_crypto::gpu::{CudaDevice, CudaStream};
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests::GpuFunctionExecutor;
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::{RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use rand::Rng;
use std::cmp::{max, min};
use std::sync::Arc;

// Macro to generate tests for all parameter sets
macro_rules! create_gpu_parametrized_test{
    ($name:ident { $($param:ident),* $(,)? }) => {
        ::paste::paste! {
            $(
            #[test]
            fn [<test_gpu_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_gpu_parametrized_test!($name
        {
            // PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            // PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            // PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS
        });
    };
}

// Unchecked operations
create_gpu_parametrized_test!(integer_unchecked_mul);
create_gpu_parametrized_test!(integer_unchecked_add);
create_gpu_parametrized_test!(integer_unchecked_add_assign);
create_gpu_parametrized_test!(integer_unchecked_sub);
create_gpu_parametrized_test!(integer_unchecked_neg);
create_gpu_parametrized_test!(integer_unchecked_scalar_add);
create_gpu_parametrized_test!(integer_unchecked_scalar_sub);
create_gpu_parametrized_test!(integer_unchecked_small_scalar_mul);
create_gpu_parametrized_test!(integer_unchecked_bitnot);
create_gpu_parametrized_test!(integer_unchecked_bitand);
create_gpu_parametrized_test!(integer_unchecked_bitor);
create_gpu_parametrized_test!(integer_unchecked_bitxor);
create_gpu_parametrized_test!(integer_unchecked_scalar_bitand);
create_gpu_parametrized_test!(integer_unchecked_scalar_bitor);
create_gpu_parametrized_test!(integer_unchecked_scalar_bitxor);
create_gpu_parametrized_test!(integer_unchecked_eq);
create_gpu_parametrized_test!(integer_unchecked_ne);
create_gpu_parametrized_test!(integer_unchecked_gt);
create_gpu_parametrized_test!(integer_unchecked_ge);
create_gpu_parametrized_test!(integer_unchecked_lt);
create_gpu_parametrized_test!(integer_unchecked_le);
create_gpu_parametrized_test!(integer_unchecked_scalar_eq);
create_gpu_parametrized_test!(integer_unchecked_scalar_ne);
create_gpu_parametrized_test!(integer_unchecked_scalar_gt);
create_gpu_parametrized_test!(integer_unchecked_scalar_ge);
create_gpu_parametrized_test!(integer_unchecked_scalar_lt);
create_gpu_parametrized_test!(integer_unchecked_scalar_le);
create_gpu_parametrized_test!(integer_unchecked_scalar_left_shift);
create_gpu_parametrized_test!(integer_unchecked_scalar_right_shift);
create_gpu_parametrized_test!(integer_unchecked_if_then_else);
create_gpu_parametrized_test!(integer_unchecked_max);
create_gpu_parametrized_test!(integer_unchecked_min);
create_gpu_parametrized_test!(integer_unchecked_scalar_max);
create_gpu_parametrized_test!(integer_unchecked_scalar_min);
create_gpu_parametrized_test!(integer_unchecked_scalar_rotate_left);
create_gpu_parametrized_test!(integer_unchecked_scalar_rotate_right);

// Default operations
create_gpu_parametrized_test!(integer_mul);
create_gpu_parametrized_test!(integer_add);
create_gpu_parametrized_test!(integer_sub);
create_gpu_parametrized_test!(integer_neg);
create_gpu_parametrized_test!(integer_scalar_add);
create_gpu_parametrized_test!(integer_scalar_sub);
create_gpu_parametrized_test!(integer_small_scalar_mul);
create_gpu_parametrized_test!(integer_scalar_right_shift);
create_gpu_parametrized_test!(integer_scalar_left_shift);
create_gpu_parametrized_test!(integer_bitnot);
create_gpu_parametrized_test!(integer_bitand);
create_gpu_parametrized_test!(integer_bitor);
create_gpu_parametrized_test!(integer_bitxor);
create_gpu_parametrized_test!(integer_scalar_bitand);
create_gpu_parametrized_test!(integer_scalar_bitor);
create_gpu_parametrized_test!(integer_scalar_bitxor);
create_gpu_parametrized_test!(integer_eq);
create_gpu_parametrized_test!(integer_ne);
create_gpu_parametrized_test!(integer_gt);
create_gpu_parametrized_test!(integer_ge);
create_gpu_parametrized_test!(integer_lt);
create_gpu_parametrized_test!(integer_le);
create_gpu_parametrized_test!(integer_scalar_eq);
create_gpu_parametrized_test!(integer_scalar_ne);
create_gpu_parametrized_test!(integer_scalar_gt);
create_gpu_parametrized_test!(integer_scalar_ge);
create_gpu_parametrized_test!(integer_scalar_lt);
create_gpu_parametrized_test!(integer_scalar_le);
create_gpu_parametrized_test!(integer_if_then_else);
create_gpu_parametrized_test!(integer_max);
create_gpu_parametrized_test!(integer_min);
create_gpu_parametrized_test!(integer_scalar_max);
create_gpu_parametrized_test!(integer_scalar_min);

/// Number of loop iteration within randomized tests
const NB_TEST: usize = 1000;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
// const NB_TEST_SMALLER: usize = 10;
const NB_CTXT: usize = 4;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::*;

/// For default/unchecked binary functions
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, &'a RadixCiphertext)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &d_ctxt_2, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default assign binary functions
impl<'a, F> FunctionExecutor<(&'a mut RadixCiphertext, &'a RadixCiphertext), ()>
    for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &mut CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStream,
    ),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a mut RadixCiphertext, &'a RadixCiphertext)) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.1, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &d_ctxt_2, &context.stream);

        *input.0 = d_ctxt_1.to_radix_ciphertext(&context.stream);
    }
}

/// For unchecked/default binary functions with one scalar input
impl<'a, F> FunctionExecutor<(&'a RadixCiphertext, u64), RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStream,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (&'a RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

/// For unchecked/default binary functions with one scalar input
impl<F> FunctionExecutor<(RadixCiphertext, u64), RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        u64,
        &CudaStream,
    ) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: (RadixCiphertext, u64)) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&input.0, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, input.1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary Function
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &CudaUnsignedRadixCiphertext, &CudaStream) -> CudaUnsignedRadixCiphertext,
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        let gpu_result = (self.func)(&context.sks, &d_ctxt_1, &context.stream);

        gpu_result.to_radix_ciphertext(&context.stream)
    }
}

// Unary assign Function
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for GpuFunctionExecutor<F>
where
    F: Fn(&CudaServerKey, &mut CudaUnsignedRadixCiphertext, &CudaStream),
{
    fn setup(&mut self, cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.setup_from_keys(cks, &sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) {
        let context = self
            .context
            .as_ref()
            .expect("setup was not properly called");

        let mut d_ctxt_1 =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(input, &context.stream);

        (self.func)(&context.sks, &mut d_ctxt_1, &context.stream);

        *input = d_ctxt_1.to_radix_ciphertext(&context.stream)
    }
}

fn integer_unchecked_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_mul);
    unchecked_mul_test(param, executor);
}

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add_assign);
    unchecked_add_assign_test(param, executor);
}

fn integer_unchecked_scalar_add<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_add);
    unchecked_scalar_add_test(param, executor);
}

fn integer_unchecked_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_small_scalar_mul);
    unchecked_small_scalar_mul_test(param, executor);
}

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_sub);
    unchecked_sub_test(param, executor);
}

fn integer_unchecked_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_sub);
    unchecked_scalar_sub_test(param, executor);
}

fn integer_unchecked_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_neg);
    unchecked_neg_test(param, executor);
}

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear = rng.gen::<u64>() % modulus;
        println!("clear {clear}");
        // encryption of integers
        let ctxt = cks.encrypt_radix(clear, NB_CTXT);

        // Copy to the GPU
        let d_ctxt = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_bitnot(&d_ctxt, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        let clear_result = (!clear) % modulus;
        println!("not {clear} = {clear_result}");
        assert_eq!(clear_result, dec_res);
    }
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_bitand(&d_ctxt_0, &d_ctxt_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_bitor(&d_ctxt_0, &d_ctxt_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;

        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_radix(clear_1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_bitxor(&d_ctxt_0, &d_ctxt_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn integer_unchecked_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_scalar_bitand(&d_ctxt_0, clear_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 & clear_1, dec_res);
    }
}

fn integer_unchecked_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;
        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_scalar_bitor(&d_ctxt_0, clear_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 | clear_1, dec_res);
    }
}

fn integer_unchecked_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    // let (cks, sks) = KEY_CACHE.get_from_params(param);
    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        // encryption of integers
        let ctxt_0 = cks.encrypt_radix(clear_0, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_0, &stream);

        // add the two ciphertexts
        let d_ct_res = sks.unchecked_scalar_bitxor(&d_ctxt_0, clear_1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);

        // decryption of ct_res
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // assert
        assert_eq!(clear_0 ^ clear_1, dec_res);
    }
}

fn integer_unchecked_eq<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        // let h_ct_res = h_sks.unchecked_eq(&ctxt_1, &ctxt_2);
        let d_ct_res = sks.unchecked_eq(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 == clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ctxt_2 = d_ctxt_1.duplicate(&stream);
        let d_ct_res = sks.unchecked_eq(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(1, dec_res);
    }
}

fn integer_unchecked_ne<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_ne(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 != clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ctxt_2 = d_ctxt_1.duplicate(&stream);
        let d_ct_res = sks.unchecked_ne(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(0, dec_res);
    }
}

fn integer_unchecked_gt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_gt(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 > clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_ge<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_ge(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 >= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_lt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        // let _ = h_sks.unchecked_lt(&ctxt_1, &ctxt_2);
        let d_ct_res = sks.unchecked_lt(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 < clear2) as u64;
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_le<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_le(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 <= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_eq<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_eq(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        let expected: u64 = (clear1 == clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ct_res = sks.unchecked_scalar_eq(&d_ctxt_1, clear1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(1, dec_res);
    }
}

fn integer_unchecked_scalar_ne<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_ne(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        let expected: u64 = (clear1 != clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ct_res = sks.unchecked_scalar_ne(&d_ctxt_1, clear1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(0, dec_res);
    }
}

fn integer_unchecked_scalar_gt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    // Assert we are testing for 0
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_gt(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);
    let expected: u64 = (clear1 > clear2) as u64;

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_gt(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        let expected: u64 = (clear1 > clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_ge<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    // Assert we are testing for 0
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_ge(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);
    let expected: u64 = (clear1 >= clear2) as u64;

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_ge(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 >= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_lt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    // Assert we are testing for 0
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_lt(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);
    let expected: u64 = (clear1 < clear2) as u64;

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_lt(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 < clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_le<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    // Assert we are testing for 0
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_le(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);
    let expected: u64 = (clear1 <= clear2) as u64;

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_le(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 <= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_max<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_max(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = max(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_min<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.unchecked_min(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = min(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_max<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    // Assert we are testing for 0
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_max(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);

    let expected: u64 = max(clear1, clear2);

    // Check the correctness
    assert_eq!(expected, dec_res);

    // Define the cleartexts
    let clear1 = 0;
    let clear2 = rng.gen::<u64>() % modulus;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_max(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);

    let expected: u64 = max(clear1, clear2);

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_max(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = max(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_min<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;
    // Define the cleartexts
    let clear1 = rng.gen::<u64>() % modulus;
    let clear2 = 0;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_min(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);

    let expected: u64 = min(clear1, clear2);

    // Check the correctness
    assert_eq!(expected, dec_res);

    // Define the cleartexts
    let clear1 = 0;
    let clear2 = rng.gen::<u64>() % modulus;

    // Encrypt the integers;;
    let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

    // Copy to the GPU
    let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

    let d_ct_res = sks.unchecked_scalar_min(&d_ctxt_1, clear2, &stream);

    let ct_res = d_ct_res.to_radix_ciphertext(&stream);
    let dec_res: u64 = cks.decrypt_radix(&ct_res);

    let expected: u64 = min(clear1, clear2);

    // Check the correctness
    assert_eq!(expected, dec_res);

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.unchecked_scalar_min(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = min(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_if_then_else<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..1);

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);
        let ctxt_condition = cks.encrypt_radix(clear_condition, 1);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);
        let d_ctxt_condition =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_condition, &stream);

        let d_ct_res = sks.unchecked_if_then_else(&d_ctxt_condition, &d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(dec_res, if clear_condition == 1 { clear1 } else { clear2 });
    }
}

fn integer_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::mul);
    default_mul_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    default_add_test(param, executor);
}

fn integer_scalar_add<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_add);
    default_scalar_add_test(param, executor);
}

fn integer_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::small_scalar_mul);
    default_small_scalar_mul_test(param, executor);
}

fn integer_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::sub);
    default_sub_test(param, executor);
}

fn integer_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_sub);
    default_scalar_sub_test(param, executor);
}

fn integer_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::neg);
    default_neg_test(param, executor);
}

fn integer_bitnot<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitnot);
    default_bitnot_test(param, executor);
}

fn integer_bitand<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitand);
    default_bitand_test(param, executor);
}

fn integer_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitor);
    default_bitor_test(param, executor);
}

fn integer_bitxor<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitxor);
    default_bitxor_test(param, executor);
}

fn integer_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    default_scalar_bitand_test(param, executor);
}

fn integer_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    default_scalar_bitor_test(param, executor);
}

fn integer_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    default_scalar_bitxor_test(param, executor);
}

fn integer_eq<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        // let h_ct_res = h_sks.eq(&ctxt_1, &ctxt_2);
        let d_ct_res = sks.eq(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 == clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ctxt_2 = d_ctxt_1.duplicate(&stream);
        let d_ct_res = sks.eq(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(1, dec_res);
    }
}

fn integer_ne<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        // let h_ct_res = h_sks.eq(&ctxt_1, &ctxt_2);
        let d_ct_res = sks.ne(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 != clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ctxt_2 = d_ctxt_1.duplicate(&stream);
        let d_ct_res = sks.ne(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(0, dec_res);
    }
}

fn integer_gt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.gt(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 > clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_ge<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.ge(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 >= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_lt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        // let _ = h_sks.lt(&ctxt_1, &ctxt_2);
        let d_ct_res = sks.lt(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 < clear2) as u64;
        assert_eq!(expected, dec_res);
    }
}

fn integer_le<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.le(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 <= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_eq<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_eq(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        let expected: u64 = (clear1 == clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ct_res = sks.scalar_eq(&d_ctxt_1, clear1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(1, dec_res);
    }
}

fn integer_scalar_ne<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_ne(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);
        let expected: u64 = (clear1 != clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);

        let d_ct_res = sks.scalar_ne(&d_ctxt_1, clear1, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(0, dec_res);
    }
}

fn integer_scalar_gt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_gt(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 > clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_ge<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_ge(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 >= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_lt<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_lt(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 < clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_le<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_le(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = (clear1 <= clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_left_shift);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_right_shift);
    unchecked_scalar_right_shift_test(param, executor);
}

fn integer_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_right_shift);
    default_scalar_right_shift_test(param, executor);
}

fn integer_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    default_scalar_left_shift_test(param, executor);
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_left_rotate);
    unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_right_rotate);
    unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_if_then_else<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;
        let clear_condition = rng.gen_range(0u64..1);

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);
        let ctxt_condition = cks.encrypt_radix(clear_condition, 1);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);
        let d_ctxt_condition =
            CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_condition, &stream);

        let d_ct_res = sks.if_then_else(&d_ctxt_condition, &d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        // Check the correctness
        assert_eq!(dec_res, if clear_condition == 1 { clear1 } else { clear2 });
    }
}

fn integer_max<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.max(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = max(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_min<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);
        let ctxt_2 = cks.encrypt_radix(clear2, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);
        let d_ctxt_2 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_2, &stream);

        let d_ct_res = sks.min(&d_ctxt_1, &d_ctxt_2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = min(clear1, clear2);

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_max<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_max(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = max(clear1, clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}

fn integer_scalar_min<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let gpu_index = 0;
    let device = CudaDevice::new(gpu_index);
    let stream = CudaStream::new_unchecked(device);

    let (cks, sks) = gen_keys_gpu(param, &stream);

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for _ in 0..NB_TEST {
        // Define the cleartexts
        let clear1 = rng.gen::<u64>() % modulus;
        let clear2 = rng.gen::<u64>() % modulus;

        // Encrypt the integers;;
        let ctxt_1 = cks.encrypt_radix(clear1, NB_CTXT);

        // Copy to the GPU
        let d_ctxt_1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ctxt_1, &stream);

        let d_ct_res = sks.scalar_min(&d_ctxt_1, clear2, &stream);

        let ct_res = d_ct_res.to_radix_ciphertext(&stream);
        let dec_res: u64 = cks.decrypt_radix(&ct_res);

        let expected: u64 = min(clear1, clear2) as u64;

        // Check the correctness
        assert_eq!(expected, dec_res);
    }
}
