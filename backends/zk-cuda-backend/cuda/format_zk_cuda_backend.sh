#!/usr/bin/env bash

set -e

while getopts ":c" option; do
  case $option in
    c)
      # code to execute when flag1 is provided
      find ./{include,src,tests_and_benchmarks/tests,tests_and_benchmarks/benchmarks} -iregex '^.*\.\(cpp\|cu\|h\|cuh\)$' -print | xargs clang-format-15 --dry-run --Werror -style='file'
      cmake-format -i CMakeLists.txt -c .cmake-format-config.py
      find ./{include,src,tests_and_benchmarks/tests,tests_and_benchmarks/benchmarks} -type f -name "CMakeLists.txt" | xargs -I % sh -c 'cmake-format -i % -c .cmake-format-config.py'
      git diff --exit-code
      exit
      ;;
  esac
done
find ./{include,src,tests_and_benchmarks/tests,tests_and_benchmarks/benchmarks} -iregex '^.*\.\(cpp\|cu\|h\|cuh\)$' -print | xargs clang-format-15 -i -style='file'
cmake-format -i CMakeLists.txt -c .cmake-format-config.py
find ./{include,src,tests_and_benchmarks/tests,tests_and_benchmarks/benchmarks} -type f -name "CMakeLists.txt" | xargs -I % sh -c 'cmake-format -i % -c .cmake-format-config.py'
