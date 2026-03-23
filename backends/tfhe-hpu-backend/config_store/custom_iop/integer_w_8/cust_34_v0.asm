# CUST_HPU0_33 for VirtualHpu 0
# WARNING: Prototype must be `--user-proto "[2]<N>::<N><0>"`
# IOp to debug multi-hpu data xfer and sync
# This IOp has two actors: one consumer and one producer.
# Consumer read the IOp source and send them through explicit xfer toward the producer
# Producer retrieved value with explicit lb_b2b and generate the output
# Focus on explicit xfer between HPU
# Below consumer code
LD        R0               TS[0].0             
LD        R1               TS[1].0             
LD        R3               TS[0].1             
LD        R4               TS[1].1             
LD        R8               TS[0].2             
LD        R9               TS[1].2             
ADD       R2               R0               R1               
PBS_ML2   R6               R2               PbsManyGenProp   
LD        R11              TS[0].3             
LD        R14              TS[1].3             
ADD       R5               R3               R4               
PBS_ML2   R12              R5               PbsManyGenProp   
ADD       R10              R8               R9               
PBS_ML2   R16              R10              PbsManyGenProp   
ADD       R15              R11              R14              
PBS_ML2_F R18              R15              PbsManyGenProp   
MULS      R20              R6               2                
ADDS      R25              R7               0                
ST TH.0 R25
NOTIFY N1 F1 TH.0 
ADDS      R20              R20              0                
#ST TH.1 R20
#NOTIFY N1 F1 TH.1 
PBS       R22              R20              PbsReduceCarry2  
MAC       R21              R12              R20              4                
#ST TH.2 R21
#NOTIFY N1 F2 TH.2 
PBS       R24              R21              PbsReduceCarry3  
MAC       R23              R16              R21              8                
#ST TH.3 R23
#NOTIFY N1 F3 TH.3 
PBS_F       R26              R23              PbsReduceCarryPad 
#PBS_F     R27              R25              PbsGenPropAdd    
#ST        TD[0].0          R27              
#LB_B2B F4 TH.4
#LB_B2B F5 TH.5
#LB_B2B F6 TH.6
#WAIT F5 TH.4
#LD R22 TH.4
#WAIT F5 TH.5
#LD R24 TH.5
#WAIT F5 TH.6
#LD R26 TH.6
MAC       R32              R22              R13              4                
MAC       R30              R24              R17              4                
PBS       R33              R30              PbsGenPropAdd    
ADDS      R28              R26              1                
MAC       R29              R28              R19              4                
PBS       R31              R29              PbsGenPropAdd    
PBS_F     R34              R32              PbsGenPropAdd    
ST        TD[0].2          R33              
ST        TD[0].3          R31              
ST        TD[0].1          R34              
