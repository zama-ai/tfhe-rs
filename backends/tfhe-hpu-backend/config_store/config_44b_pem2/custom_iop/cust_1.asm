# CUST_1
# Simple IOp to check the xfer between Hpu/Cpu
# Dest <- Src_a
LD R0   TA.0
LD R1   TA.1
LD R2   TA.2
LD R3   TA.3
ST TD.0 R0 
ST TD.1 R1 
ST TD.2 R2 
ST TD.3 R3 
