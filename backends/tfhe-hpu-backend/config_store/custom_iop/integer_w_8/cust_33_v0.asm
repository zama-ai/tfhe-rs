# CUST_HPU0_33 for VirtualHpu 0
# WARNING: Prototype must be `--user-proto "[2]<N>::<N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp has two actors: one consumer and one producer.
# Consumer read the IOp source and send them through explicit xfer toward the producer
# Producer retrieved value with explicit lb_b2b and generate the output
# Focus on explicit xfer between HPU
# Below consumer code

# Read input value
LD R0 TS[0].0
LD R1 TS[0].1
LD R2 TS[0].2
LD R3 TS[0].3

# Stock localy
ST TH.0 R0
ST TH.1 R1
ST TH.2 R2
ST TH.3 R3

# Notify Node1
NOTIFY N1 F0 TH.0
NOTIFY N1 F1 TH.1
NOTIFY N1 F2 TH.2
NOTIFY N1 F3 TH.3
