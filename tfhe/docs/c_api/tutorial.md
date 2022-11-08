# Tutorial: using the C API

Welcome to this `tfhe.rs` C API tutorial!

This library exposes a C binding to the `tfhe.rs` primitives to implement _Fully Homomorphic Encryption_ (FHE) programs.

# First steps using `tfhe.rs` C API

## Setting-up `tfhe.rs` C API for use in a C program.

 `tfhe.rs` C API can be built on a Unix x86_64 machine using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo build --release --features=x86_64-unix,booleans-c-api,shortints-c-api -p tfhe
```

All features are opt-in, but for simplicity here, the C API is enabled for booleans and shortints.

The `tfhe.h` header as well as the static (.a) and dynamic (.so) `libtfhe` binaries can then be found  in "${REPO_ROOT}/target/release/"

The build system needs to be set-up so that the C or C++ program links against `tfhe.rs` C API 
binaries.

Here is a minimal CMakeLists.txt allowing to do just that:

```cmake
project(my-project)

cmake_minimum_required(VERSION 3.16)

set(TFHE_C_API "/path/to/tfhe-rs/binaries/and/header")

include_directories(${TFHE_C_API})
add_library(tfhe STATIC IMPORTED)
set_target_properties(tfhe PROPERTIES IMPORTED_LOCATION ${TFHE_C_API}/libtfhe.a)

if(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    if (NOT SECURITY_FRAMEWORK)
        message(FATAL_ERROR "Security framework not found")
    endif()
endif()

set(EXECUTABLE_NAME my-executable)
add_executable(${EXECUTABLE_NAME} main.c)
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC tfhe m pthread dl)
if(APPLE)
    target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC ${SECURITY_FRAMEWORK})
endif()
target_compile_options(${EXECUTABLE_NAME} PRIVATE -Werror)
```

## Commented code of a PBS doubling a 2 bits encrypted message using `tfhe.rs C API`

The steps required to perform the mutiplication by 2 of a 2 bits ciphertext 
using a PBS are detailed.
This is NOT the most efficient way of doing this operation, 
but it allows to show the management required to run a PBS manually using the C API.

WARNING: The following example does not have proper memory management in the error case to make it easier to fit the code on this page.

To run the example below, the above CMakeLists.txt and main.c files need to be in the same 
directory. The commands to run are:
```shell
# /!\ Be sure to update CMakeLists.txt to give the absolute path to the compiled tfhe library
$ ls
CMakeLists.txt  main.c
$ mkdir build && cd build
$ cmake .. -DCMAKE_BUILD_TYPE=RELEASE
...
$ make
...
$ ./my-executable
Result: 2
$
```

```c
#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

uint64_t double_accumulator_2_bits_message(uint64_t in) { return (in * 2) % 4; }

uint64_t get_max_value_of_accumulator_generator(uint64_t (*accumulator_func)(uint64_t),
                                                size_t message_bits)
{
    uint64_t max_value = 0;
    for (size_t idx = 0; idx < (1 << message_bits); ++idx)
    {
        uint64_t acc_value = accumulator_func((uint64_t)idx);
        max_value = acc_value > max_value ? acc_value : max_value;
    }

    return max_value;
}

int main(void)
{
    ShortintPBSAccumulator *accumulator = NULL;
    ShortintClientKey *cks = NULL;
    ShortintServerKey *sks = NULL;
    ShortintParameters *params = NULL;

    // Get the parameters for 2 bits messages with 2 bits of carry
    int get_params_ok = shortints_get_parameters(2, 2, &params);
    assert(get_params_ok == 0);

    // Generate the keys with the parameters
    int gen_keys_ok = shortints_gen_keys_with_parameters(params, &cks, &sks);
    assert(gen_keys_ok == 0);

    // Generate the accumulator for the PBS
    int gen_acc_ok = shortints_server_key_generate_pbs_accumulator(
        sks, double_accumulator_2_bits_message, &accumulator);
    assert(gen_acc_ok == 0);

    ShortintCiphertext *ct = NULL;
    ShortintCiphertext *ct_out = NULL;

    // We will compute 1 * 2 using a PBS, it's not the recommended way to perform a multiplication,
    // but it shows how to manage a PBS manually in the C API
    uint64_t in_val = 1;

    // Encrypt the input value
    int encrypt_ok = shortints_client_key_encrypt(cks, in_val, &ct);
    assert(encrypt_ok == 0);

    // Check the degree is set to the maximum value that can be encrypted on 2 bits, i.e. 3
    // This check is not required and is just added to show, the degree information can be retrieved
    // in the C APi
    size_t degree = -1;
    int get_degree_ok = shortints_ciphertext_get_degree(ct, &degree);
    assert(get_degree_ok == 0);

    assert(degree == 3);

    // Apply the PBS on our encrypted input
    int pbs_ok = shortints_server_key_programmable_bootstrap(sks, accumulator, ct, &ct_out);
    assert(pbs_ok == 0);

    // Set the degree to keep consistency for potential further computations
    // Note: This is only required for the PBS
    size_t degree_to_set =
        (size_t)get_max_value_of_accumulator_generator(double_accumulator_2_bits_message, 2);

    int set_degree_ok = shortints_ciphertext_set_degree(ct_out, degree_to_set);
    assert(set_degree_ok == 0);

    // Decrypt the result
    uint64_t result = -1;
    int decrypt_non_assign_ok = shortints_client_key_decrypt(cks, ct_out, &result);
    assert(decrypt_non_assign_ok == 0);

    // Check the result is what we expect i.e. 2
    assert(result == double_accumulator_2_bits_message(in_val));
    printf("Result: %ld\n", result);

    // Destroy entities from the C API
    destroy_shortint_ciphertext(ct);
    destroy_shortint_ciphertext(ct_out);
    destroy_shortint_pbs_accumulator(accumulator);
    destroy_shortint_client_key(cks);
    destroy_shortint_server_key(sks);
    destroy_shortint_parameters(params);
    return EXIT_SUCCESS;
}
```

# Audience

Programmers wishing to use `tfhe.rs` but unable to use Rust (for various reasons) can use these bindings in their language of choice as long as it can interface with C code to bring `tfhe.rs` functionalities to said language.

You can reach out here: https://community.zama.ai/c/concrete-lib/5, or on the concrete channel or the https://fhe.org discord server that you can join from here: https://discord.fhe.org/
