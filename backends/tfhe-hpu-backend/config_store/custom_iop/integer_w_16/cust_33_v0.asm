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
LD R4 TS[0].4
LD R5 TS[0].5
LD R6 TS[0].6
LD R7 TS[0].7
# Stock locally
ST TH.0 R0
SUB R0 R0 R0
NOTIFY N1 F1 TH.0
ST TH.1 R1
SUB R1 R1 R1
NOTIFY N1 F2 TH.1
ST TH.2 R2
SUB R2 R2 R2
NOTIFY N1 F3 TH.2
ST TH.3 R3
SUB R3 R3 R3
NOTIFY N1 F4 TH.3
ST TH.4 R4
SUB R4 R4 R4
NOTIFY N1 F5 TH.4
ST TH.5 R5
SUB R5 R5 R5
NOTIFY N1 F6 TH.5
ST TH.6 R6
SUB R6 R6 R6
NOTIFY N1 F7 TH.6
ST TH.7 R7
SUB R7 R7 R7
NOTIFY N1 F8 TH.7
