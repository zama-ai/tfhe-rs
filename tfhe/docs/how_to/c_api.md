# High-Level API in C 

This library exposes a C binding to the high-level TFHE-rs primitives to implement _Fully Homomorphic Encryption_ (FHE) programs.

## Setting-up TFHE-rs C API for use in a C program.

TFHE-rs C API can be built on a Unix x86\_64 machine using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release --features=x86_64-unix,high-level-c-api -p tfhe && make symlink_c_libs_without_fingerprint
```

or on a Unix aarch64 machine using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo build +nightly --release --features=aarch64-unix,high-level-c-api -p tfhe && make symlink_c_libs_without_fingerprint
```

The `tfhe.h` header as well as the static (.a) and dynamic (.so) `libtfhe` binaries can then be found in "${REPO\_ROOT}/target/release/".

The `tfhe-c-api-dynamic-buffer.h` header and the static (.a) and dynamic (.so) libraries will be found in "${REPO\_ROOT}/target/release/deps/".

The build system needs to be set up so that the C or C++ program links against TFHE-rs C API binaries and the dynamic buffer library.

Here is a minimal CMakeLists.txt to do just that:

```cmake
project(my-project)

cmake_minimum_required(VERSION 3.16)

set(TFHE_C_API "/path/to/tfhe-rs/target/release")

include_directories(${TFHE_C_API})
include_directories(${TFHE_C_API}/deps)
add_library(tfhe STATIC IMPORTED)
set_target_properties(tfhe PROPERTIES IMPORTED_LOCATION ${TFHE_C_API}/libtfhe.a)
add_library(tfheDynamicBuffer STATIC IMPORTED)
set_target_properties(tfheDynamicBuffer PROPERTIES IMPORTED_LOCATION ${TFHE_C_API}/deps/libtfhe_c_api_dynamic_buffer.a)

if(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    if (NOT SECURITY_FRAMEWORK)
        message(FATAL_ERROR "Security framework not found")
    endif()
endif()

set(EXECUTABLE_NAME my-executable)
add_executable(${EXECUTABLE_NAME} main.c)
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${EXECUTABLE_NAME} LINK_PUBLIC tfhe tfheDynamicBuffer m pthread dl)
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
FHE computation successful!
$
```

```c

#include <tfhe.h>
#include <assert.h>
#include <stdio.h>

int main(void)
{
    int ok = 0;
    // Prepare the config builder for the high level API and choose which types to enable
    ConfigBuilder *builder;
    Config *config;

    // Put the builder in a default state without any types enabled
    config_builder_default(&builder);
    // Use the small LWE key for encryption
    config_builder_default_with_small_encryption(&builder);
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
    // A 128-bit unsigned integer containing value: 20 << 64 | 10
    U128 clear_lhs = { .w0 = 10, .w1 = 20 };
    // A 128-bit unsigned integer containing value: 2 << 64 | 1
    U128 clear_rhs = { .w0 = 1, .w1 = 2 };

    ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_lhs, client_key, &lhs);
    assert(ok == 0);

    ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_rhs, client_key, &rhs);
    assert(ok == 0);

    // Compute the subtraction
    ok = fhe_uint128_sub(lhs, rhs, &result);
    assert(ok == 0);

    U128 clear_result;
    // Decrypt
    ok = fhe_uint128_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    // Here the subtraction allows us to compare each word
    assert(clear_result.w0 == 9);
    assert(clear_result.w1 == 18);

    // Destroy the ciphertexts
    fhe_uint128_destroy(lhs);
    fhe_uint128_destroy(rhs);
    fhe_uint128_destroy(result);

    // Destroy the keys
    client_key_destroy(client_key);
    server_key_destroy(server_key);

    printf("FHE computation successful!\n");
    return EXIT_SUCCESS;
}
```
