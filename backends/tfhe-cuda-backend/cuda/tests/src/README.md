# test_tfhe_cuda_backend

This test tool is written over GoogleTest library. It tests the correctness of basic 
cryptographic primitives accelerated using CUDA and helps identify arithmetic flaws. 
The output format can be adjusted according to the user's interest. 

A particular function will be executed for each test case, and the result will be verified considering the expected behavior. This will be repeated for multiple encryption keys and samples per key. These can be modified by changing `REPETITIONS` and `SAMPLES` variables at the beginning of each test file.

## How to Compile

The first step in compiling code with CMake is to create a build directory. This directory will 
contain all the files generated during the build process, such as object files and executables. 
We recommend creating this directory outside of the source directory, but inside the 
implementation folder,  to keep the source directory clean.

```bash
$ cd tfhe-rs/backends/tfhe-cuda-backend/cuda
$ mkdir build
$ cd build
```

Run CMake to generate the build files and then use make to compile the project.

```bash
$ cmake ..
$ make
```

The binary will be found in
`ctfhe-rs/backends/tfhe-cuda-backend/cuda/build/tests/src`.

## How to Run Tests

To run tests, you can simply execute the `test_tfhe_cuda_backend` executable with no arguments:

```bash
$ tests/src/test_tfhe_cuda_backend
```

This will run all the available tests.

## How to Filter Tests

You can select a subset of sets by specifying a filter for the name of the tests of interest  as 
an argument. Only tests whose full name matches the filter will be executed.

For example, to run only tests whose name starts with the word "Bootstrap", you can execute:

```bash
$ tests/src/test_tfhe_cuda_backend --gtest_filter=Bootstrap*
```

The parameter `--gtest_list_tests` can be used to list all the available tests, and a better 
description on how to select a subset of tests can be found in
[GoogleTest documentation](http://google.github.io/googletest/advanced.html#running-a-subset-of-the-tests).

## Conclusion

With these options, you can easily verify the correctness of concrete-cuda's implementations. If 
you have any questions or issues, please feel free to contact us.
To learn more about GoogleTest library, please refer to the [official user guide](http://google.github.io/googletest/). 
