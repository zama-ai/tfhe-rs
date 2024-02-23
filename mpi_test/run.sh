#!/bin/bash
set -e

cargo build --profile=release
source /etc/profile.d/modules.sh
module load mpi/openmpi-x86_64
# export LD_LIBRARY_PATH="/usr/lib64/mpich/lib/"
export LD_LIBRARY_PATH="/usr/lib64/openmpi/lib/"
export RUSTFLAGS="-Ctarget-cpu=native"

mpirun -n 6 ../target/devo/mpi_test
