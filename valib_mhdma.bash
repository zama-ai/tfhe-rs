cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1 --integer-w 8 --iop ADD --tput --force-reload
# src/dst sync - swap MSB/LSB
cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 100 --integer-w 8 --iop IOP[32] --user-proto "[2]<N,N>::<N,N><0>" --check-res 
# identity - internal notify vHPU0 to vHPU1
cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 100 --integer-w 8 --iop IOP[33] --user-proto "[2]<N>::<N><0>" --check-res
# Add 8 (manual)
cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 100 --integer-w 8 --iop IOP[34] --user-proto "[2]<N>::<N,N><0>" --check-res
# identity - internal notify vHPU1 to vHPU0
cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 100 --integer-w 8 --iop IOP[35] --user-proto "[2]<N>::<N><0>" --check-res
# Mul 8 (manual)
cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 100 --integer-w 8 --iop IOP[36] --user-proto "[2]<N>::<N,N><0>" --check-res
