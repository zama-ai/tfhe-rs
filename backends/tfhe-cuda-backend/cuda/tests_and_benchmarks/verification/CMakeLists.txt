# Verification trace tools, built with VERIFICATION_TRACE (which compiles the
# hooks and the entry points into the backend):
# - verification_trace records the traces of the integer ops (needs a GPU);
# - verification_replay replays them on plaintexts. It is plain C++ with no
#   CUDA dependency, so it also builds standalone:
#     g++ -std=c++17 -O3 -fopenmp -I<cuda>/include replay_main.cpp
add_executable(verification_trace trace_main.cpp)
target_link_libraries(verification_trace PRIVATE tfhe_cuda_backend)
target_include_directories(verification_trace PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_executable(verification_replay replay_main.cpp)
target_include_directories(verification_replay PRIVATE ${CMAKE_SOURCE_DIR}/include)
# Replays the inputs on all cores (serial when built without OpenMP).
target_link_libraries(verification_replay PRIVATE OpenMP::OpenMP_CXX)
