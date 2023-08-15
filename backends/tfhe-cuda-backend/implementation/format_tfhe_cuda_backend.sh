#!/bin/bash

find ./{include,src} -iregex '^.*\.\(cpp\|cu\|h\|cuh\)$' -print | xargs clang-format-15 -i -style='file'
cmake-format -i CMakeLists.txt -c .cmake-format-config.py

find ./{include,src} -type f -name "CMakeLists.txt" | xargs -I % sh -c 'cmake-format -i % -c .cmake-format-config.py'
