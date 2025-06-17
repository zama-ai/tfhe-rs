# CUST_HPU0_32 for VirtualHpu 1
# WARNING: Prototype must be `--user-proto "[2]<N,N>::<N,N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp take two sources and generate two destination (one written by each node)
# Focus on LD templated Op from other Hpu
# HPU0 construct B[1]B[0]A[1]A[0]
# HPU1 construct B[3]B[2]A[3]A[2]
LD_B2B F6 TH.0
LD_B2B F7 TH.1
LD_B2B F8 TH.2
LD_B2B F9 TH.3

WAIT F6 TH.0
LD R0 TH.0
WAIT F7 TH.1
LD R1 TH.1
WAIT F8 TH.2
LD R2 TH.2
WAIT F9 TH.3
LD R3 TH.3

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

ST TD[1].0 R0 
ST TD[1].1 R1 
ST TD[1].2 R2 
ST TD[1].3 R3 
