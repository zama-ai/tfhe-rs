# How Integers are represented


In `concrete-integer`, the encrypted data is split amongst many ciphertexts
encrypted using the `concrete-shortint` library.

This crate implements two ways to represent an integer:
  - the Radix representation
  - the CRT (Chinese Reminder Theorem) representation

## Radix based Integers
The first possibility to represent a large integer is to use a radix-based decomposition on the 
plaintexts. Let $$B \in \mathbb{N}$$ be a basis such that the size of $$B$$ is smaller (or equal)
to four bits. 
Then, an integer $$m \in \mathbb{N}$$ can be written as $$m = m_0 + m_1*B + m_2*B^2 + ... $$, where 
each $$m_i$$ is strictly smaller than $$B$$. Each $$m_i$$ is then independently encrypted. In 
the end, an Integer ciphertext is defined as a set of Shortint ciphertexts. 

In practice, the definition of an Integer requires the basis and the number of blocks. This is 
done at the key creation step.
```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);
}
```

In this example, the keys are dedicated to Integers decomposed as four blocks using the basis 
$$B=2^2$$. Otherwise said, they allow to work on Integers modulus $$(2^2)^4 = 2^8$$. 


In this representation, the correctness of operations requires to propagate the carries 
between the ciphertext. This operation is costly since it relies on the computation of many 
programmable bootstrapping over Shortints. 


## CRT based Integers
The second approach to represent large integers is based on the Chinese Remainder Theorem. 
In this cases, the basis $$B$$ is composed of several integers $$b_i$$, such that there are 
pairwise coprime, and each b_i has a size smaller than four bits. Then, the Integer will be 
defined modulus $$\prod b_i$$. For an integer $$m$$, its CRT decomposition is simply defined as 
$$m % b_0, m % b_1, ...$$. Each part is then encrypted as a Shortint ciphertext. In
the end, an Integer ciphertext is defined as a set of Shortint ciphertexts.

An example of such a basis 
could be $$B = [2, 3, 5]$$. This means that the Integer is defined modulus $$2*3*5 = 30$$. 

This representation has many advantages: no carry propagation is required, so that only cleaning 
the carry buffer of each ciphertexts is enough. This implies that operations can easily be 
parallelized. Moreover, it allows to efficiently compute PBS in the case where the function is 
CRT compliant. 

A variant of the CRT is proposed, where each block might be associated to a different key couple. 
In the end, a keychain is required to the computations, but performance might be improved. 



# Types of operations


Much like `concrete-shortint`, the operations available via a `ServerKey` may come in different variants:

  - operations that take their inputs as encrypted values.
  - scalar operations take at least one non-encrypted value as input.

For example, the addition has both variants:

  - `ServerKey::unchecked_add` which takes two encrypted values and adds them.
  - `ServerKey::unchecked_scalar_add` which takes an encrypted value and a clear value (the 
     so-called scalar) and adds them.

Each operation may come in different 'flavors':

  - `unchecked`: Always does the operation, without checking if the result may exceed the capacity of 
     the plaintext space.
  - `checked`: Checks are done before computing the operation, returning an error if operation 
      cannot be done safely.
  - `smart`: Always does the operation, if the operation cannot be computed safely, the smart operation
             will propagate the carry buffer to make the operation possible.

Not all operations have these 3 flavors, as some of them are implemented in a way that the operation
is always possible without ever exceeding the plaintext space capacity.
