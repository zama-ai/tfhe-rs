# CUST_17
# Simple IOp to check PBS behavior
# Dest <- PBSNone(Src_a)
LD    R0   TS[0].0
PBS   R0   R0    PbsNone
ST    TD[0].0 R0 
LD    R1   TS[0].1
PBS   R1   R1    PbsNone
ST    TD[0].1 R1 
LD    R2   TS[0].2
PBS   R2   R2    PbsNone
ST    TD[0].2 R2 
LD    R3   TS[0].3
PBS_F R3   R3    PbsNone
ST    TD[0].3 R3 
