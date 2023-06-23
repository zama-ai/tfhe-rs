# High-Level API in C 

This library exposes a C binding to the high-level TFHE-rs primitives to implement _Fully Homomorphic Encryption_ (FHE) programs.

## Setting-up TFHE-rs C API for use in a C program.

TFHE-rs C API can be built on a Unix x86\_64 machine using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release --features=x86_64-unix,high-level-c-api -p tfhe
```

or on a Unix aarch64 machine using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo build +nightly --release --features=aarch64-unix,high-level-c-api -p tfhe
```

The `tfhe.h` header as well as the static (.a) and dynamic (.so) `libtfhe` binaries can then be found in "${REPO\_ROOT}/target/release/"

The build system needs to be set up so that the C or C++ program links against TFHE-rs C API binaries.

Here is a minimal CMakeLists.txt to do just that:

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

## Commented code of a uint128 subtraction using `TFHE-rs C API`.

{% hint style="warning" %}
WARNING: The following example does not have proper memory management in the error case to make it easier to fit the code on this page.
{% endhint %}

To run the example below, the above CMakeLists.txt and main.c files need to be in the same directory. The commands to run are:

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
#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    int ok = 0;
    // Prepare the config builder for the high level API and choose which types to enable
    ConfigBuilder *builder;
    Config *config;

    // Put the builder in a default state without any types enabled
    config_builder_all_disabled(&builder);
    // Enable the uint128 type using the small LWE key for encryption
    config_builder_enable_default_uint128_small(&builder);
    // Populate the config
    config_builder_build(builder, &config);

    ClientKey *client_key = NULL;
    ServerKey *server_key = NULL;

    // Generate the keys using the config
    generate_keys(config, &client_key, &server_key);
    // Set the server key for the current thread
    set_server_key(server_key);

    FheUint128 *lhs = NULL;
    FheUint128 *rhs = NULL;
    FheUint128 *result = NULL;

    // Encrypt a u128 using 64 bits words, we encrypt 20 << 64 | 10
    ok = fhe_uint128_try_encrypt_with_client_key_u128(10, 20, client_key, &lhs);
    assert(ok == 0);

    // Encrypt a u128 using words, we encrypt 2 << 64 | 1
    ok = fhe_uint128_try_encrypt_with_client_key_u128(1, 2, client_key, &rhs);
    assert(ok == 0);

    // Compute the subtraction
    ok = fhe_uint128_sub(lhs, rhs, &result);
    assert(ok == 0);

    uint64_t w0, w1;
    // Decrypt
    ok = fhe_uint128_decrypt(result, client_key, &w0, &w1);
    assert(ok == 0);

    // Here the subtraction allows us to compare each word
    assert(w0 == 9);
    assert(w1 == 18);

    // Destroy the ciphertexts
    fhe_uint128_destroy(lhs);
    fhe_uint128_destroy(rhs);
    fhe_uint128_destroy(result);

    // Destroy the keys
    client_key_destroy(client_key);
    server_key_destroy(server_key);
    return EXIT_SUCCESS;
}
```
