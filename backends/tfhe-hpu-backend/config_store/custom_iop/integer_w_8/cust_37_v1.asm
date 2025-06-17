# CUST_HPU0_32 for VirtualHpu 1
# WARNING: Prototype must be `--user-proto "[2]<N,N>::<N,N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp take two sources and generate two destination (one written by each node)
# Focus on LD templated Op from other Hpu
# HPU0 construct B[1]B[0]A[1]A[0]
# HPU1 construct B[3]B[2]A[3]A[2]
LD_B2B F1 TH.0

LD_B2B F0 TS[0].2
LD_B2B F0 TS[0].3
LD_B2B F0 TS[1].2
LD_B2B F0 TS[1].3

LD R0 TS[0].2
LD R1 TS[0].3
LD R2 TS[1].2
LD R3 TS[1].3

PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone
PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone
PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone

WAIT F1 TH.0
LD R4 TH.0
PBS_F R4 R4 PbsNone

ST TH.1 R0
NOTIFY N2 F2 TH.1
ST TH.2 R1 
NOTIFY N2 F3 TH.2
ST TH.3 R2 
NOTIFY N2 F4 TH.3
ST TH.4 R3 
NOTIFY N2 F5 TH.4
