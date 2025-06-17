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
LD_B2B F5 TH.14
LD_B2B F6 TH.15
LD_B2B F7 TH.16
LD_B2B F8 TH.17
LD_B2B F9 TH.18
LD_B2B F10 TH.19
LD_B2B F11 TH.20
LD_B2B F12 TH.21
LD_B2B F13 TH.22
LD_B2B F14 TH.23
LD_B2B F15 TH.24
LD_B2B F16 TH.25


# Wait for B2b load end and load in reg
WAIT F1 TH.10
LD R0 TH.10
ST TD[0].0 R0   
WAIT F2 TH.11
LD R1 TH.11
ST TD[0].1 R1
WAIT F3 TH.12
LD R2 TH.12
ST TD[0].2 R2
WAIT F4 TH.13
LD R3 TH.13
ST TD[0].3 R3
WAIT F5 TH.14
LD R4 TH.14
ST TD[0].4 R4
WAIT F6 TH.15
LD R5 TH.15
ST TD[0].5 R5
WAIT F7 TH.16
LD R6 TH.16
ST TD[0].6 R6
WAIT F8 TH.17
LD R7 TH.17
ST TD[0].7 R7
WAIT F9 TH.18
LD R8 TH.18
ST TD[0].8 R8
WAIT F10 TH.19
LD R9 TH.19
ST TD[0].9 R9
WAIT F11 TH.20
LD R10 TH.20
ST TD[0].10 R10
WAIT F12 TH.21
LD R11 TH.21
ST TD[0].11 R11
WAIT F13 TH.22
LD R12 TH.22
ST TD[0].12 R12
WAIT F14 TH.23
LD R13 TH.23
ST TD[0].13 R13
WAIT F15 TH.24
LD R14 TH.24
ST TD[0].14 R14
WAIT F16 TH.25
LD R15 TH.25
ST TD[0].15 R15
