# SHA256 with Boolean API

This tutorial guides you to convert a regular SHA-256 function to its homomorphic version, with considerations of optimal performances. You will learn:

1. The basics of the SHA-256 function.
2. The steps to implement SHA-256 homomorphically.

## SHA-256 basics

First, you need to implement the SHA-256 function. You can find the official specification for SHA-256 [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). We summarize the three key aspects of SHA-256 outlined in the document:

### Padding

The SHA-256 function processes the input data in blocks or chunks of 512 bits. Before performing the hash computations, prepare the data as follows:

1. Append a single "1" bit
2. Append "0" bits until exactly 64 bits remain to make the message length a multiple of 512
3. Append the last 64 bits as a binary encoding of the original input length

![](../\_static/sha256.png)

In this diagram, the numbers on the top represent the length of the padded input at each position. The formula L+1+k+64 ensures that the length reaches a multiple of 512, matching the required length of the padded input.

### Operations and functions

We will use bitwise AND, XOR, NOT, addition modulo 2^32, the Rotate Right (ROTR) and Shift Right (SHR) operations as building blocks for functions inside the SHA-256 computation. These operations all use 32-bit words and produce new words.

We combine these operations inside the sigma (with 4 variations), `Ch,` and `Maj` functions. When changing SHA-256 to the homomorphic computation, we will mainly change the code of each operation.

Here is the definition of each function:

```
Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z)
Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)

Σ0(x) = ROTR-2(x) XOR ROTR-13(x) XOR ROTR-22(x)
Σ1(x) = ROTR-6(x) XOR ROTR-11(x) XOR ROTR-25(x)
σ0(x) = ROTR-7(x) XOR ROTR-18(x) XOR SHR-3(x)
σ1(x) = ROTR-17(x) XOR ROTR-19(x) XOR SHR-10(x)
```

We simplify `Maj` using the Boolean distributive law: (x AND y) XOR (x AND z) = x AND (y XOR z), as shown below:

```
Maj(x, y, z) = (x AND (y XOR z)) XOR (y AND z)
```

We simplify `Ch` using a single bitwise multiplexer. Here's the truth table of the `Ch` expression.

| x | y | z | Result |
| - | - | - | ------ |
| 0 | 0 | 0 | 0      |
| 0 | 0 | 1 | 1      |
| 0 | 1 | 0 | 0      |
| 0 | 1 | 1 | 1      |
| 1 | 0 | 0 | 0      |
| 1 | 0 | 1 | 0      |
| 1 | 1 | 0 | 1      |
| 1 | 1 | 1 | 1      |

This table shows that the result equals to `z` when `x = 0`, and the result equals to `y` when `x = 1`, which means `if x {y} else {z}`. Hence we can replace the 4 bitwise operations of `Ch` by a single bitwise multiplexer.

All these operations can be evaluated homomorphically:

* ROTR and SHR: They can be evaluated by changing the index of each ecrypted bit of the word without using any homomorphic operation.
* Bitwise AND, XOR and multiplexer: They can be computed homomorphically
* Addition modulo 2^32: It can be broken down into boolean homomorphic operations.

### SHA-256 computation

The SHA-256 function processes data in 512-bit chunks. Here is what happens during computation:

1. The 512-bit chunk is computed into 16 words, each containing 32 bits.
2. Another 48 words are computed using the previous function.
3. After computing the 64 words, within the same chunk, a compression loop will compute a hash value (8 32-bit words) using the previous functions and some constants to mix everything up.
4. This entire process iterate through each 512-bit chunk of your data.
5. When we finish the last chunk iteration, the resulting hash values will be the output of the SHA-256 function.

Here is an example of this function using arrays of 32 bools to represent words:

```rust
fn sha256(padded_input: Vec<bool>) -> [bool; 256] {

    // Initialize hash values with constant values
    let mut hash: [[bool; 32]; 8] = [
        hex_to_bools(0x6a09e667), hex_to_bools(0xbb67ae85),
        hex_to_bools(0x3c6ef372), hex_to_bools(0xa54ff53a),
        hex_to_bools(0x510e527f), hex_to_bools(0x9b05688c),
        hex_to_bools(0x1f83d9ab), hex_to_bools(0x5be0cd19),
    ];

    let chunks = padded_input.chunks(512);

    for chunk in chunks {
        let mut w = [[false; 32]; 64];

        // Copy first 16 words from current chunk
        for i in 0..16 {
            w[i].copy_from_slice(&chunk[i * 32..(i + 1) * 32]);
        }

        // Compute the other 48 words
        for i in 16..64 {
            w[i] = add(add(add(sigma1(&w[i - 2]), w[i - 7]), sigma0(&w[i - 15])), w[i - 16]);
        }

        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];

        // Compression loop, each iteration uses a specific constant from K
        for i in 0..64 {
            let temp1 = add(add(add(add(h, ch(&e, &f, &g)), w[i]), hex_to_bools(K[i])), sigma_upper_case_1(&e));
            let temp2 = add(sigma_upper_case_0(&a), maj(&a, &b, &c));
            h = g;
            g = f;
            f = e;
            e = add(d, temp1);
            d = c;
            c = b;
            b = a;
            a = add(temp1, temp2);
        }

        hash[0] = add(hash[0], a);
        hash[1] = add(hash[1], b);
        hash[2] = add(hash[2], c);
        hash[3] = add(hash[3], d);
        hash[4] = add(hash[4], e);
        hash[5] = add(hash[5], f);
        hash[6] = add(hash[6], g);
        hash[7] = add(hash[7], h);
    }

    // Concatenate the final hash values to produce a 256-bit hash
    let mut output = [false; 256];
    for i in 0..8 {
        output[i * 32..(i + 1) * 32].copy_from_slice(&hash[i]);
    }
    output
}
```

## Homomorphic SHA-256 on encrypted data

To convert SHA-256 to a homomorphic version, you can replace each bit of `padded_input` with a fully homomorphic encryption of the same bit value and operate on the encrypted value using homomorphic operations.

While the structure of the SHA-256 function remains the same, there are some important considerations in the code:

* The function signature and the borrowing rules should adapt to the ciphertext type (representing the encrypted bits).
* Implementing SHA-256 operations with homomorphic encryption uses homomorphic boolean operations internally.

Homomorphic operations on encrypted data can be very expensive. Consider these options for better speed:

* Remove unnecessary use of homomorphic operations and maximize parallelization.
* Simplify the code with Rayon crate that parallelizes iterators and manages threads efficiently.

The final code is available [here](https://github.com/zama-ai/tfhe-rs/tree/main/tfhe/examples/sha256\_bool).

Now let's dive into details of each SHA256 operation.

#### Rotate Right and Shift Right

Rotate Right and Shift Right can be evaluated by changing the position of each encrypted bit in the word, requiring no homomorphic operations. Here is the implementation:

```rust
fn rotate_right(x: &[Ciphertext; 32], n: usize) -> [Ciphertext; 32] {
    let mut result = x.clone();
    result.rotate_right(n);
    result
}

fn shift_right(x: &[Ciphertext; 32], n: usize, sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = x.clone();
    result.rotate_right(n);
    result[..n].fill_with(|| sk.trivial_encrypt(false));
    result
}
```

#### Bitwise XOR, AND, Multiplexer

To implement these operations, we will use the `xor`, and `mux` methods from the **TFHE-rs** library to perform each boolean operation homomorphically.

For better efficiency, we can parallelize the homomorphic computations because we operate bitwise. It means that we can homomorphically XOR the bits at index 0 of two words using one thread while XORing the bits at index 1 using another thread, and so on. This approach allows for the computation of bitwise operations using up to 32 concurrent threads, corresponding to the 32-bit words used.

Here is the implementation of the bitwise homomorphic XOR operation. The `par_iter` and `par_iter_mut` methods create a parallel iterator that we use to compute each XOR efficiently. The other two bitwise operations are implemented in the same way.

```rust
fn xor(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut result = a.clone();
    result.par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.xor(lhs, rhs));
    result
}
```

#### Addition modulo 2^32

This might be the trickiest operation to efficiently implement in a homomorphic manner. A naive implementation could use the Ripple Carry Adder algorithm, which is straightforward but cannot be parallelized because each step depends on the previous one.

A better choice is to use Carry Lookahead Adder, which allows us to use the parallelized AND and XOR bitwise operations. With this design, our adder is around 50% faster than the Ripple Carry Adder.

```rust
pub fn add(a: &[Ciphertext; 32], b: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let propagate = xor(a, b, sk); // Parallelized bitwise XOR
    let generate = and(a, b, sk); // Parallelized bitwise AND

    let carry = compute_carry(&propagate, &generate, sk);
    let sum = xor(&propagate, &carry, sk); // Parallelized bitwise XOR

    sum
}

fn compute_carry(propagate: &[Ciphertext; 32], generate: &[Ciphertext; 32], sk: &ServerKey) -> [Ciphertext; 32] {
    let mut carry = trivial_bools(&[false; 32], sk);
    carry[31] = sk.trivial_encrypt(false);

    for i in (0..31).rev() {
        carry[i] = sk.or(&generate[i + 1], &sk.and(&propagate[i + 1], &carry[i + 1]));
    }

    carry
}
```

To further optimize performance, we use parallel prefix algorithms to parallelize the function that computes the carry signals. These algorithms involve more (homomorphic) boolean operations and their parallel nature speeds up the processing. We have implemented the Brent-Kung and Ladner-Fischer algorithms with different tradeoffs:

* Brent-Kung has the least amount of boolean operations we could find (140 when using grey cells, for 32-bit numbers), which makes it suitable when we can't process many operations concurrently and fast. Our results confirm that it's indeed faster than both the sequential algorithm and Ladner-Fischer when run on regular computers.
* On the other hand, Ladner-Fischer performs more boolean operations (209 using grey cells) than Brent-Kung, but they are performed in larger batches. Hence we can compute more operations in parallel and finish earlier, but we need more fast threads available or they will slow down the carry signals computation. Ladner-Fischer can be suitable when using cloud-based computing services, which offer many high-speed threads.

Our implementation uses Brent-Kung by default, but you can enable Ladner-Fischer by using the `--ladner-fischer` command line argument.

For more information about parallel prefix adders, you can read [this paper](https://www.iosrjournals.org/iosr-jece/papers/Vol6-Issue1/A0610106.pdf) or [this other paper](https://www.ijert.org/research/design-and-implementation-of-parallel-prefix-adder-for-improving-the-performance-of-carry-lookahead-adder-IJERTV4IS120608.pdf).

Finally, with all these SHA-256 operations working homomorphically, our functions will be homomomorphic as well along with the whole SHA-256 function (after adapting the code to work with the Ciphertext type).

### More parallel processing

Let's talk about other performance improvements we can make before we finish.

In the main `sha256_fhe`, you can perform some functions in parallel. For example, in the compression loop, `temp1` and `temp2` can be computed in parallel by using the `rayon::join()` function when there is a CPU available. The two temporary values in the compression loop are the result of multiple additions, so you can use nested calls to `rayon::join()` to parallelize more operations.

Another way to speed up consecutive additions would be using the Carry Save Adder, a very efficient adder that takes 3 numbers and returns a sum and a carry sequence. If our inputs are A, B, and C, we can construct a CSA with our previously implemented Maj function and the bitwise XOR operation as follows:

```
Carry = Maj(A, B, C)
Sum = A XOR B XOR C
```

By chaining CSAs, we can input the sum and carry from a preceding stage along with another number into a new CSA. Finally, to get the result of the additions we add the sum and carry sequences using a conventional adder. In the end, we are performing the same number of additions, but some of them are now CSAs, speeding up the process. Below is the illustration of this process in the `temp1` and `temp2` computations.

```rust
let (temp1, temp2) = rayon::join(
    || {
        let ((sum, carry), s1) = rayon::join(
            || {
                let ((sum, carry), ch) = rayon::join(
                    || csa(&h, &w[i], &trivial_bools(&hex_to_bools(K[i]), sk), sk),
                    || ch(&e, &f, &g, sk),
                );
                csa(&sum, &carry, &ch, sk)
            },
            || sigma_upper_case_1(&e, sk)
        );

        let (sum, carry) = csa(&sum, &carry, &s1, sk);
        add(&sum, &carry, sk)
    },
    || {
        add(&sigma_upper_case_0(&a, sk), &maj(&a, &b, &c, sk), sk)
    },
);
```

The first closure of the outer call to join will return `temp1` and the second `temp2`.

Inside the first outer closure, we call join recursively until we add the value `h`, the current word `w[i],` and the current constant `K[i]` by using the CSA, while potentially computing the `ch` function in parallel. Then we take the sum, carry, and ch values and add them again using the CSA.

All this is done while potentially computing the `sigma_upper_case_1` function. Finally we input the previous sum, carry, and sigma values to the CSA and perform the final addition with `add`. Once again, this is done while potentially computing `sigma_upper_case_0` and `maj` and adding them to get `temp2`, in the second outer closure.

With these types of changes, we finally get a homomorphic SHA256 function that doesn't leave unused computational resources.

## How to use SHA256\_bool

First, use the `--release` flag when running the program. Considering the implementation of `encrypt_bools` and `decrypt_bools`, the use of SHA-256 will be as follows:

```rust
fn main() {
    let matches = Command::new("Homomorphic sha256")
        .arg(Arg::new("ladner_fischer")
            .long("ladner-fischer")
            .help("Use the Ladner Fischer parallel prefix algorithm for additions")
            .action(ArgAction::SetTrue))
        .get_matches();

    // If set using the command line flag "--ladner-fischer" this algorithm will be used in additions
    let ladner_fischer: bool = matches.get_flag("ladner_fischer");

    // INTRODUCE INPUT FROM STDIN

    let mut input = String::new();
    println!("Write input to hash:");

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    input = input.trim_end_matches('\n').to_string();

    println!("You entered: \"{}\"", input);

    // CLIENT PADS DATA AND ENCRYPTS IT

    let (ck, sk) = gen_keys();

    let padded_input = pad_sha256_input(&input);
    let encrypted_input = encrypt_bools(&padded_input, &ck);

    // SERVER COMPUTES OVER THE ENCRYPTED PADDED DATA

    println!("Computing the hash");
    let encrypted_output = sha256_fhe(encrypted_input, ladner_fischer, &sk);

    // CLIENT DECRYPTS THE OUTPUT

    let output = decrypt_bools(&encrypted_output, &ck);
    let outhex = bools_to_hex(output);

    println!("{}", outhex);
}
```

We can supply the data to hash using a file instead of the command line by using `stdin` . For example, if the file `input.txt` is in the same directory as the project, we can use the following shell command after building with `cargo build --release`:

```sh
./target/release/examples/sha256_bool < input.txt
```

The program accepts hexadecimal inputs. The input must start with "0x" and contain only valid hex digits, otherwise it will be interpreted as text.

Finally， padding is performed on the client side. This has the advantage of hiding the exact length of the input content from the server, thus avoiding the server extracting information from the length, even though the content is fully encrypted.

It is also feasible to perform padding on the server side. The padding function would take the encrypted input and pad it with trivial bit encryptions. We can then integrate the padding function into the `sha256_fhe` function computed by the server.
