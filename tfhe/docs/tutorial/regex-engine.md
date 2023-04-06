# regex-engine
a homomorphic regex matcher for encrypted test strings on plaintext regex

Regex matching is typically accomplished in the clear by building a [deterministic finite automaton (DFA)](https://en.wikipedia.org/wiki/Deterministic_finite_automaton) that represents the input regex, taking an input alphabet of characters, and accepting the string (by reaching a final state in the DFA) as it is fed into the DFA in sequence if and only if the regex should match the string.
The mechanics behind this are quite interesting, but outside of the scope of this tutorial. Here is [a good resource](https://swtch.com/~rsc/regexp/regexp1.html).

Given plaintext regex and encrypted test strings, this homomorphic regex matcher builds a DFA based on the given input regex, utilizing the well-known library [`regex-automata`](https://docs.rs/regex-automata/0.1.10/regex_automata/) (that mirrors the syntax and main mechanics of Rust's even more well-known [`regex`](https://docs.rs/regex/latest/regex/) library, but exposes more low-level features that are useful to us) to build the minimal DFA.

Then, it converts the DFA, originally taking an input alphabet of ASCII characters, into a "binary" DFA. The binary DFA associated with the `regex-automata`'s ASCII DFA is the DFA that takes an input alphabet of only 0s and 1s that accepts the same language as the ASCII dfa, when each character is in its binary deceomposition.
For example, if `abc` is accepted by the ASCII DFA, the big-endian equivalent of this string (each character, as an ASCII character, gets 7 bits) will be accepted by the binary DFA, that is, `1100001 1100010 1100011` (note: the choice of endianness is irrelevant here, big-endian was chosen arbitrarily).
The binary DFA is then minimized piecewise using a variation of Hopcroft's algorithm, to minimize the number of states needed to match bit string.
This proves to be a huge optimization when evaluating the DFA homomorphically, as is done here, since each additional state represents another expensive homomorphic operation in the evaluation.

Once the equivalent minimal binary DFA is built for a given regex, the encrypted test string is simply fed into the DFA and the DFA is evaluated homomorphically based on Algorithm 6 (and Remark 6) of [TFHE: Fast Fully Homomorphic Encryption over the Torus](https://eprint.iacr.org/2018/421.pdf) (in fact, this is the whole reason a binary DFA is built instead of just using the ASCII DFA, as to evaluate a DFA homomorphically, it must take a binary input alphabet in order to use CMUXes), producing a single ciphertext that encrypts the result of the DFA evaluation: in particular, it encrypts either `true` for acceptance of the bit string (the regex matches the string), or `false` for rejection of the bit string (the regex does not match the string).
Note that here, it is required that the encrypted test string is a list of `7n` boolean ciphertexts, each encrypting a bit of the big-endian binary decompositions of the characters of the string (`n` is the length of the ASCII test string).
This conversion can be done homomorphically on an input list of ASCII ciphertexts (take each ASCII ciphertext and perform homomorphic bitwise operations to extract the bit ciphertext) or as pre-processing on an input ASCII string (take each ASCII character and convert to a big-endian bit array, and encrypt each bit individually).
Note that due to this requirement, this approach will almost always be almost one order of magnitude (8) slower than a bytewise solution.
However, this approach is still implemented for learning purposes and the reasons expanded on in [Discussion](#discussion).

## Supported Regex

Everything supported by `regex-automata`, a list of which can be found in their [syntax document](https://docs.rs/regex-automata/latest/regex_automata/dfa/index.html#syntax), i.e. [everything that `regex` supports](https://docs.rs/regex/1.7.3/regex/#syntax) minus capturing groups and Unicode word boundaries. This is a superset of:

- Contains matching: `/abc/` only matches with strings containing abc (e.g., abc, 123abc, abc123, 123abc456)
- Start matching: `/^abc/` only matches strings starting with abc (e.g., abc, abc123)
- End matching: `/abc$/` only matches strings ending with abc (e.g., abc, 123abc)
- Exact matching: `/^abc$/` only matches the string abc
- Case-insensitive matching: `/^abc$/i` only matches with abc, Abc, aBc, abC, ABc, aBC, AbC, ABC
- Optional matching: `/^ab?c$/` only matches with abc, ac
- Zero or more matching: `/^ab*c$/` only matches with ac, abc, abbc, abbbc and so on
- One or more matching: /^ab+c$/ only matches with abc, abbc, abbbc and so on
- Numbered matching: 
  * `/^ab{2}c$/` only matches with abbc
  * `/^ab{3,}c$/` only matches with abbbc, abbbbc, abbbbbc and so on
  * `/^ab{2,4}c$/` only matches with abbc, abbbc, abbbbc
- Alternative matching: `/^ab|cd$/` only matches with ab and cd
- Any character matching: `/^.$/` only matches with a, b, A, B, ? and so on
- Character range matching: 
  * `/^[abc]$/` only matches with a, b and c
  * `/^[a-d]$/` only matches with a, b, c and d
- Character range not matching: 
  * `/^[^abc]$/` only doesn't match with a, b and c
  * `/^[^a-d]$/` only doesn't match with a, b, c and d
- Escaping special characters: 
  * `/^\.$/` only matches with .
  * `/^\*$/` only matches with *
  * Same for all special characters used above (e.g., [, ], $ and so on)
- and any combination of the features above

## Tutorial

`regex-engine` is a full-featured CLI built with [`clap`](https://docs.rs/clap/latest/clap/) and supports two modes: test and execution.

In test mode, the engine takes a plaintext regex and a plaintext test string, generates TFHE keys and encrypts the test string bitwise, homomorphically evaluates the regex checker on it, and then decrypts the result and checks correctness of the result against `regex::Regex`'s determination. An example input:

```sh
cargo run --example regex-engine --features=boolean -- '/^abc$/' test 'abc'
```

Here `/^abc$/` is used to build the binary DFA, and it is evaluated homomorphically on the encryption of `abc`. If successful, 

```
Test passed, expected result true matches actual result true
```

will be printed.

In execution mode, the engine takes a plaintext regex, a TFHE server key `tfhe::boolean::CompressedServerKey` Bincode-encoded as a binary file, the encrypted test bit string `Vec<tfhe::boolean::CompressedCiphertext>` Bincode-encoded as a binary file, and optionally, the client key `tfhe::boolean::ClientKey` Bincode-encoded as a binary file. It homomorphically evaluates the regex checker on the plaintext regex with the server key and encrypted string, output the ciphertext as the result of the execution in base64, and if provided, the client key will decrypt the ciphertext and output the plaintext answer. An example input:

```sh
cargo run --example regex-engine --features=boolean -- '/^abc$/' execution 'server_key.bin' 'encrypted_string.bin' --client-key-file 'client_key.bin'
```

Note that in both modes, the time taken to build the binary DFA and evaluate it on the test string is displayed to the user at the end. Note that this does not include the time it takes to encrypt the plaintext test string, if in test mode, as the input test string is already assumed to be encrypted.

## Discussion

As briefly mentioned, this approach can be viewed as the "naive" approach to homomorphic regex matching, as it takes the standard approach for regex matching in the clear (DFAs) and attempts to directly translate the algorithm into its encrypted analogue that can directly be used by Algorithm 6. While this works, it can be up to one order of magnitude slower than a bytewise solution (slowdown by a factor of 8). Here are some reasons for how this approach, I argue, can still be useful:

1. Shows a case of binary dfa (Algorithm 6) which there hasn't been an example for in the repo up to this point. It also exemplifies a general parallel algorithm for converting any ascii dfa into a binary dfa which can then be homomorphically evaluated using CMUXes in Alg 6, which would be useful for the general case where one needs to evaluate a dfa that takes ASCII characters. Also extensible to any number of bytes, i.e. the algorithm can convert any DFA on an input alphabet of `n` bits into an equivalent minimal binary DFA.
2. It matches more regular expressions for free, based on the underlying DFA construction algorithm. `regex-automata` constructs a dfa that recognizes not only the expressions required in the bounty, but other regexprs too (i.e. almost every regexpr recognized by the `regex` crate, see https://docs.rs/regex-automata/latest/regex_automata/dfa/index.html#syntax), and it reuses this functionality, so that this example and the DFA construction can develop independently.
3. Testing for non-ASCII characters comes for free, since, if a non-ASCII character was decomposed into bits it would produce an unexpected number of bit ciphertexts (number of bit ciphertexts must divide 7), and if by chance it divides 7, the binary DFA would still reject it.
4. Good learning step to a bytewise optimized implementation.

## Future Work

- Evaluate an ASCII DFA directly, without translating to the equivalent binary DFA, based on CMUXing on the encrypted bit `input_char == a` for each character `a` in the ASCII input alphabet and or-ing the results of the CMUXes together
- Encrypted regex

