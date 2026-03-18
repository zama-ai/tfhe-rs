# CUST_HPU0_32 for VirtualHpu 0
# WARNING: Prototype must be `--user-proto "[2]<N,N>::<N,N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp take two sources and generate two destination (one written by each node)
# Focus on LD templated Op from other Hpu
# HPU0 construct B[1]B[0]A[1]A[0]
# HPU1 construct B[3]B[2]A[3]A[3]
LD R0 TS[0].0
LD R1 TS[0].1
LD R2 TS[1].0
LD R3 TS[1].1

SUB R4 R4 R4
ST TH.0 R4
NOTIFY N1 F0 TH.0

ST TD[0].0 R0 
ST TD[0].1 R1 
ST TD[0].2 R2 
ST TD[0].3 R3 
