# CUST_HPU0_33 for VirtualHpu 1
# WARNING: Prototype must be `--user-proto "[2]<N>::<N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp has two actors: one consumer and one producer.
# Consumer read the IOp source and send them through explicit xfer toward the producer
# Producer retrieved value with explicit lb_b2b and generate the output
# Focus on explicit xfer between HPU
# Below producer code

# Issue read value from Node0
LD_B2B F1 TH.10
LD_B2B F2 TH.11
LD_B2B F3 TH.12
LD_B2B F4 TH.13

# Wait for B2b load end and load in reg
WAIT F1 TH.10
LD R0 TH.10
WAIT F2 TH.11
LD R1 TH.11
WAIT F3 TH.12
LD R2 TH.12
WAIT F4 TH.13
LD R3 TH.13

# Store in Dst variable
ST TD[0].0 R0 
ST TD[0].1 R1 
ST TD[0].2 R2 
ST TD[0].3 R3 
