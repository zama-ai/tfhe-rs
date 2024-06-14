use rayon as __rayon_reexport;
use rayon::prelude::*;
use std::io::{stdin, Read};
use std::mem::MaybeUninit;
use std::{array, iter};
use tfhe::prelude::*;
use tfhe::shortint::parameters::*;
use tfhe::{set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, Device, FheUint32};

// might improve error message on type error
#[doc(hidden)]
pub fn __requires_sendable_closure<R, F: FnOnce() -> R + Send>(x: F) -> F {
    x
}
#[doc(hidden)]
macro_rules! __join_implementation {
    ($len:expr; $($f:ident $r:ident $a:expr),*; $b:expr, $($c:expr,)*) => {
        $crate::__join_implementation!{$len + 1; $($f $r $a,)* f r $b; $($c,)* }
    };
    ($len:expr; $($f:ident $r:ident $a:expr),* ;) => {
        match ($(Some($crate::__requires_sendable_closure($a)),)*) {
            ($(mut $f,)*) => {
                $(let mut $r = None;)*
                let array: [&mut (dyn FnMut() + Send); $len] = [
                    $(&mut || $r = Some((&mut $f).take().unwrap()())),*
                ];
                $crate::__rayon_reexport::iter::ParallelIterator::for_each(
                    $crate::__rayon_reexport::iter::IntoParallelIterator::into_par_iter(array),
                    |f| f(),
                );
                ($($r.unwrap(),)*)
            }
        }
    };
}

pub(crate) use __join_implementation;

macro_rules! join {
    ($($($a:expr),+$(,)?)?) => {
        $crate::__join_implementation!{0;;$($($a,)+)?}
    };
}

// In-House implementation of array_chunk
// as the one in stdlib is not stable.
pub struct ArrayChunks<T, const N: usize>
where
    T: Iterator,
{
    source: T,
}

impl<T, const N: usize> ArrayChunks<T, N>
where
    T: Iterator,
{
    fn new(iterator: T) -> Self {
        Self { source: iterator }
    }
}

impl<T, const N: usize> Iterator for ArrayChunks<T, N>
where
    T: Iterator,
    <T as Iterator>::Item: Sized,
    [T::Item; N]: Sized,
{
    type Item = [T::Item; N];

    fn next(&mut self) -> Option<Self::Item> {
        // The `assume_init` is
        // safe because the type we are claiming to have initialized here is a
        // bunch of `MaybeUninit`s, which do not require initialization.
        let mut data: [MaybeUninit<T::Item>; N] = unsafe { MaybeUninit::uninit().assume_init() };

        // We don't use a loop that has an early return
        // because we want to avoid potential memory leaks
        let mut i = 0;
        for elem in self.source.by_ref() {
            data[i].write(elem);
            i += 1;
            if i == N {
                break;
            }
        }

        if i == N {
            // This is not allowed
            // Some(unsafe { std::mem::transmute(data) })
            // https://github.com/rust-lang/rust/issues/61956
            assert_eq!(
                std::mem::size_of::<MaybeUninit<T::Item>>(),
                std::mem::size_of::<T::Item>()
            );
            assert_eq!(
                std::mem::size_of::<[MaybeUninit<T::Item>; N]>(),
                std::mem::size_of::<[T::Item; N]>()
            );

            let ptr = &mut data as *mut _ as *mut [T::Item; N];
            let res = unsafe { ptr.read() };
            #[allow(clippy::forget_non_drop)]
            core::mem::forget(data);
            Some(res)
        } else {
            // For each item in the array, drop if we allocated it.
            for elem in &mut data[0..i] {
                unsafe {
                    elem.assume_init_drop();
                }
            }
            None
        }
    }
}

#[derive(Debug)]
struct Args {
    device: Device,
    parallel: bool,
    trivial: bool,
    multibit: Option<usize>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            device: Device::Cpu,
            parallel: false,
            trivial: false,
            multibit: None,
        }
    }
}

impl Args {
    fn from_arg_list(mut progam_args: std::env::Args) -> Self {
        let mut args = Args::default();
        let mut had_invalid = false;

        progam_args.next().unwrap(); // This is argv[0], the program name/path
        while let Some(arg) = progam_args.next() {
            if arg == "--parallel" {
                args.parallel = true;
            } else if arg == "--trivial" {
                args.trivial = true;
            } else if arg == "--device" {
                let Some(value) = progam_args.next() else {
                    panic!("Expected value after --device");
                };

                match value.to_lowercase().as_str() {
                    "cpu" => args.device = Device::Cpu,
                    #[cfg(feature = "gpu")]
                    "gpu" | "cuda" => args.device = Device::CudaGpu,
                    #[cfg(not(feature = "gpu"))]
                    "gpu" | "cuda" => {
                        panic!("Needs to be compiled with gpu feature to support gpu")
                    }
                    _ => panic!("Unsupported device {value}"),
                }
            } else if arg == "--multibit" {
                let Some(value) = progam_args.next() else {
                    panic!("Expected value after --multibit");
                };

                args.multibit = Some(value.parse().unwrap());
            } else {
                println!("Unknown argument '{arg}'");
                had_invalid = true;
            }
        }

        if had_invalid {
            panic!("Invalid argument found, aborting");
        }
        args
    }
}

fn main() -> Result<(), std::io::Error> {
    let args = Args::from_arg_list(std::env::args());
    println!("Args: {args:?}");

    println!("key gen start");
    let config = match args.multibit {
        None => ConfigBuilder::default(),
        Some(2) => ConfigBuilder::with_custom_parameters(
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            None,
            None,
        ),
        Some(3) => ConfigBuilder::with_custom_parameters(
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
            None,
        ),
        Some(v) => {
            panic!("Invalid multibit setting {v}");
        }
    }
    .build();

    let client_key = ClientKey::generate(config);
    let csks = CompressedServerKey::new(&client_key);

    match (args.device, args.parallel) {
        (Device::Cpu, false) => {
            let server_key = csks.decompress();
            set_server_key(server_key);
        }
        (Device::Cpu, true) => {
            let server_key = csks.decompress();
            rayon::broadcast(|_| {
                set_server_key(server_key.clone());
            });
            set_server_key(server_key);
        }
        #[cfg(feature = "gpu")]
        (Device::CudaGpu, false) => {
            let server_key = csks.decompress_to_gpu();
            set_server_key(server_key);
        }
        #[cfg(feature = "gpu")]
        (Device::CudaGpu, true) => {
            let server_key = csks.decompress_to_gpu();
            rayon::broadcast(|_| {
                set_server_key(server_key.clone());
            });
            set_server_key(server_key);
        }
    }
    println!("key gen end");

    let mut buf = vec![];
    stdin().read_to_end(&mut buf)?;

    let client_key = if args.trivial { None } else { Some(client_key) };

    let encrypted_input = encrypt_data(buf, client_key.as_ref());

    let encrypted_hash = if args.parallel {
        sha256_fhe_parallel(encrypted_input)
    } else {
        sha256_fhe(encrypted_input)
    };
    let decrypted_hash = decrypt_hash(encrypted_hash, client_key.as_ref());
    println!("{}", hex::encode(decrypted_hash));
    Ok(())
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn par_rotr<const N: usize>(input: &FheUint32, amounts: [u32; N]) -> [FheUint32; N] {
    let mut result = array::from_fn(|_| input.clone());

    // TODO use input.rotate_right(amounts) when tfhe-rs adds it
    result
        .par_iter_mut()
        .zip(amounts.into_par_iter())
        .for_each(|(elem, amount)| elem.rotate_right_assign(amount));

    result
}

fn rotr<const N: usize>(input: &FheUint32, amounts: [u32; N]) -> [FheUint32; N] {
    let mut result = array::from_fn(|_| input.clone());

    // TODO use input.rotate_right(amounts) when tfhe-rs adds it
    result
        .iter_mut()
        .zip(amounts)
        .for_each(|(elem, amount)| elem.rotate_right_assign(amount));

    result
}

fn encrypt_data<T: AsRef<[u8]>>(input: T, client_key: Option<&ClientKey>) -> Vec<FheUint32> {
    let len = input.as_ref().len();
    let remainder = (len + 9) % 64;

    let bytes_iter = input
        .as_ref()
        .iter()
        .copied()
        .chain(iter::once(0x80))
        .chain(iter::repeat(0x00).take(if remainder == 0 { 0 } else { 64 - remainder }))
        .chain(((len * 8) as u64).to_be_bytes());

    ArrayChunks::<_, 4>::new(bytes_iter)
        .map(|bytes| {
            if let Some(cks) = client_key {
                FheUint32::encrypt(u32::from_be_bytes(bytes), cks)
            } else {
                FheUint32::encrypt_trivial(u32::from_be_bytes(bytes))
            }
        })
        .collect()
}

fn decrypt_hash(encrypted_hash: [FheUint32; 8], client_key: Option<&ClientKey>) -> [u8; 32] {
    let mut decrypted_hash = [0u8; 32];
    encrypted_hash
        .iter()
        .zip(decrypted_hash.chunks_exact_mut(4))
        .for_each(|(ciphertext, out_clear)| {
            let clear: u32 = if let Some(cks) = client_key {
                ciphertext.decrypt(cks)
            } else {
                ciphertext.try_decrypt_trivial().unwrap()
            };
            out_clear.copy_from_slice(&clear.to_be_bytes());
        });

    decrypted_hash
}

fn sha256_fhe(input: Vec<FheUint32>) -> [FheUint32; 8] {
    println!("len: {}", input.len());
    let k = K.map(|x: u32| FheUint32::encrypt_trivial(x));
    let mut hash = INIT.map(|x: u32| FheUint32::encrypt_trivial(x));
    let all_ones = FheUint32::encrypt_trivial(0xffffffff_u32);
    let mut w: [_; 64] = array::from_fn(|_| FheUint32::encrypt_trivial(0_u32));

    let len = input.len();
    let total_timer = std::time::Instant::now();
    println!("Starting main loop");
    for (chunk_index, mut chunk) in ArrayChunks::<_, 16>::new(input.into_iter()).enumerate() {
        let bfr = std::time::Instant::now();
        println!("Start chunk: {} / {}", chunk_index + 1, len / 16);
        w[0..16].swap_with_slice(&mut chunk);

        for i in 16..64 {
            let s0 = {
                let rotations = rotr(&w[i - 15], [7u32, 18]);
                &rotations[0] ^ &rotations[1] ^ (&w[i - 15] >> 3u32)
            };
            let s1 = {
                let rotations = rotr(&w[i - 2], [17u32, 19]);
                &rotations[0] ^ &rotations[1] ^ (&w[i - 2] >> 10u32)
            };
            w[i] = [&w[i - 16], &s0, &w[i - 7], &s1].iter().copied().sum();
        }

        let mut a = hash[0].clone();
        let mut b = hash[1].clone();
        let mut c = hash[2].clone();
        let mut d = hash[3].clone();
        let mut e = hash[4].clone();
        let mut f = hash[5].clone();
        let mut g = hash[6].clone();
        let mut h = hash[7].clone();

        for i in 0..64 {
            let s1 = {
                let rotations = rotr(&e, [6u32, 11, 25]);
                &rotations[0] ^ &rotations[1] ^ &rotations[2]
            };
            let ch = (&e & &f) ^ ((&e ^ &all_ones) & &g);
            // let t1 = [&h, &s1, &ch, &k[i], &w[i]].into_iter().sum::<FheUint32>();
            let t1 = FheUint32::sum([&h, &s1, &ch, &k[i], &w[i]]);
            let s0 = {
                let rotations = rotr(&a, [2u32, 13, 22]);
                &rotations[0] ^ &rotations[1] ^ &rotations[2]
            };
            let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
            let t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + &t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
        println!("Processed in: {:?}", bfr.elapsed());
    }
    println!("Total time: {:?}", total_timer.elapsed());
    hash
}

fn sha256_fhe_parallel(input: Vec<FheUint32>) -> [FheUint32; 8] {
    let k = K.map(|x: u32| FheUint32::encrypt_trivial(x));
    let mut hash = INIT.map(|x: u32| FheUint32::encrypt_trivial(x));
    let all_ones = FheUint32::encrypt_trivial(0xffffffff_u32);
    let mut w: [_; 64] = array::from_fn(|_| FheUint32::encrypt_trivial(0_u32));

    let len = input.len();
    let total_timer = std::time::Instant::now();
    println!("Starting main loop");
    for (chunk_index, mut chunk) in ArrayChunks::<_, 16>::new(input.into_iter()).enumerate() {
        println!("Start chunk: {} / {}", chunk_index + 1, len / 16);
        let bfr = std::time::Instant::now();
        w[0..16].swap_with_slice(&mut chunk);

        for i in 16..64 {
            let (s0_a, s0_b, s1_a, s1_b) = join!(
                || par_rotr(&w[i - 15], [7u32, 18]),
                || (&w[i - 15] >> 3u32),
                || par_rotr(&w[i - 2], [17u32, 19]),
                || (&w[i - 2] >> 10u32),
            );

            let (s0, s1) =
                rayon::join(|| &s0_a[0] ^ &s0_a[1] ^ s0_b, || &s1_a[0] ^ &s1_a[1] ^ s1_b);

            w[i] = [&w[i - 16], &s0, &w[i - 7], &s1].into_iter().sum();
        }

        let mut a = hash[0].clone();
        let mut b = hash[1].clone();
        let mut c = hash[2].clone();
        let mut d = hash[3].clone();
        let mut e = hash[4].clone();
        let mut f = hash[5].clone();
        let mut g = hash[6].clone();
        let mut h = hash[7].clone();

        for i in 0..64 {
            // Please clippy
            let e_rotations = || {
                let rotations = par_rotr(&e, [6u32, 11, 25]);
                &rotations[0] ^ &rotations[1] ^ &rotations[2]
            };
            let a_rotations = || {
                let rotations = par_rotr(&a, [2u32, 13, 22]);
                &rotations[0] ^ &rotations[1] ^ &rotations[2]
            };
            let (s1, ch, s0, maj) = join!(
                e_rotations,
                || (&e & &f) ^ ((&e ^ &all_ones) & &g),
                a_rotations,
                || (&a & &b) ^ (&a & &c) ^ (&b & &c)
            );

            let (t1, t2) = rayon::join(
                || [&h, &s1, &ch, &k[i], &w[i]].into_iter().sum(),
                || s0 + maj,
            );
            let (d_plus_t1, t1_plus_t2) = rayon::join(|| d + &t1, || &t1 + t2);

            h = g;
            g = f;
            f = e;
            e = d_plus_t1;
            d = c;
            c = b;
            b = a;
            a = t1_plus_t2;
        }

        let hash2 = [a, b, c, d, e, f, g, h];
        hash.par_iter_mut()
            .zip(hash2.par_iter())
            .for_each(|(dest, src)| *dest += src);
        println!("Processed in: {:?}", bfr.elapsed());
    }
    println!("Total time: {:?}", total_timer.elapsed());
    hash
}
