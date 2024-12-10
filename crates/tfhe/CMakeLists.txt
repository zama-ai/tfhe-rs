# tfhe/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(tfhe-c-api C)
set(SOURCE tests/c_api/*.c)
enable_testing()
add_subdirectory(tests/c_api)
