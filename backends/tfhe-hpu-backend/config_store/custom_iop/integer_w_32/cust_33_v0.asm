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
LD R8 TS[0].8
LD R9 TS[0].9
LD R10 TS[0].10
LD R11 TS[0].11
LD R12 TS[0].12
LD R13 TS[0].13
LD R14 TS[0].14
LD R15 TS[0].15
# Stock localy
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
ST TH.8 R8
SUB R8 R8 R8
NOTIFY N1 F9 TH.8
ST TH.9 R9
SUB R9 R9 R9
NOTIFY N1 F10 TH.9
ST TH.10 R10
SUB R10 R10 R10
NOTIFY N1 F11 TH.10
ST TH.11 R11
SUB R11 R11 R11
NOTIFY N1 F12 TH.11
ST TH.12 R12
SUB R12 R12 R12
NOTIFY N1 F13 TH.12
ST TH.13 R13
SUB R13 R13 R13
NOTIFY N1 F14 TH.13
ST TH.14 R14
SUB R14 R14 R14
NOTIFY N1 F15 TH.14
ST TH.15 R15
SUB R15 R15 R15
NOTIFY N1 F16 TH.15
