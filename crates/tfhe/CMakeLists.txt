# tfhe/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(tfhe-c-api C)
set(SOURCE c_api_tests/*.c)
enable_testing()
add_subdirectory(c_api_tests)
