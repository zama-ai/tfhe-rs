cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1 --integer-w 8 --iop ADD --tput --force-reload
# src/dst sync - swap MSB/LSB
echo "Testing x1000 IOP 32"
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1000 --integer-w 8 --iop IOP[32] --user-proto "[2]<N,N>::<N,N><0>" --check-res 2>&1 | grep -q "Score 0/1000"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x1000 IOP 33"
# identity - internal notify vHPU0 to vHPU1
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1000 --integer-w 8 --iop IOP[33] --user-proto "[2]<N>::<N><0>" --check-res 2>&1 | grep -q "Score 0/1000"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x1000 IOP 34 (ADD8)"
# Add 8 (manual)
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1000 --integer-w 8 --iop IOP[34] --user-proto "[2]<N>::<N,N><0>" --check-res 2>&1 | grep -q "Score 0/1000"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x1000 IOP 35"
# identity - internal notify vHPU1 to vHPU0
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1000 --integer-w 8 --iop IOP[35] --user-proto "[2]<N>::<N><0>" --check-res 2>&1 | grep -q "Score 0/1000"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x1000 IOP 36 (MUL8)"
# Mul 8 (manual)
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 1000 --integer-w 8 --iop IOP[36] --user-proto "[2]<N>::<N,N><0>" --check-res 2>&1 | grep -q "Score 0/1000"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x256 IOP 40 (MUL32)"
# Mul 32 (manual)
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 256 --integer-w 32 --iop IOP[40] --user-proto "[2]<H,H>::<N,N><0>" --check-res 2>&1 | grep -q "Score 0/256"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x120 IOP 40 (MUL64)"
# Mul 64 (manual)
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 120 --integer-w 64 --iop IOP[40] --user-proto "[2]<H,H>::<N,N><0>" --check-res 2>&1 | grep -q "Score 0/120"; then
    echo "No error !!"
else
    exit 1
fi
echo "Testing x10 chain of IOp 33 & 40 (64b & 32b)"
if cargo run --profile devo --features=integer,internal-keycache,hw-v80,hpu --example hpu_bench -- --iter 10 --integer-w 64 --iop IOP[40] --user-proto "[2]<H,H>::<N,N><0>" --check-res --chain-iop 2>&1 | grep -q "Score 0/10"; then
    echo "No error !!"
else
    exit 1
fi
