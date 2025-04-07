# CUST_3
# Simple IOp to check isc behavior
# Generate obvious deps and check that isc correctly issued the dop
# Correct result must bu Dest <- Src[0]
LD R0   TS[0].0
LD R1   TS[0].1
LD R2   TS[0].2
LD R3   TS[0].3
PBS R4 R0 PbsNone
ST TD[0].0 R4 
PBS R4 R1 PbsNone
ST TD[0].1 R4 
PBS R4 R2 PbsNone
ST TD[0].2 R4 
PBS_F R4 R3 PbsNone
ST TD[0].3 R4 
