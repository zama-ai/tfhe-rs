# High-level API in C

This document describes the C bindings to the **TFHE-rs** high-level primitives for creating Fully Homomorphic Encryption (FHE) programs.

## Setting up TFHE-rs C API for C programming.

You can build **TFHE-rs** C API using the following command:

```shell
RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release --features=high-level-c-api -p tfhe
```

Locate files in the right path:

* In `${REPO\_ROOT}/target/release/`, you can find:
  * The `tfhe.h` header
  * The static (.a) and dynamic (.so) `libtfhe` binaries
* In `${REPO\_ROOT}/target/release/deps/`, you can find:
  * The `tfhe-c-api-dynamic-buffer.h` header
  * The static (.a) and dynamic (.so) libraries

Ensure your build system configures the C or C++ program links against **TFHE-rs** C API binaries and the dynamic buffer library.

The following is a minimal `CMakeLists.txt` configuration example:

```cmake
project(my-project)

cmake_minimum_required(VERSION 3.16)

set(TFHE_C_API "/path/to/tfhe-rs/target/release")

include_directories(${TFHE_C_API})
include_directories(${TFHE_C_API}/deps)
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

The following example demonstrates uint128 subtraction using the **TFHE-rs** C API:

{% hint style="warning" %}
**WARNING**: this example omits proper memory management in the error case to improve code readability.
{% endhint %}

Ensure the above `CMakeLists.txt` and `main.c` files are in the same directory. Use the following commands to execute the example:

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

#include "tfhe.h"
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
