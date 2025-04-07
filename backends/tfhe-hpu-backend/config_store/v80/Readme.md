NB: Versal don't have the pdi embedded in the configuration. Instead user is in charge of pdi upload in FPGA flash.
Thus, a given configuration could works on multiple pdi.

# Fpga version @250MHz
This configuration as based on the following Fpga commit:
```
commit ad668f931eff0c281a0848d43360da0b8813539a (HEAD -> dev/hpu_v80, origin/dev/hpu_v80, origin/baroux/dev/hpu_v80, baroux/dev/hpu_v80)
Merge: 1489024a f308f067
Author: Baptiste Roux <baptiste.roux@zama.ai>
Date:   Fri Feb 14 19:02:53 2025 +0100

    [MERGE] 'dev/hpu' into baroux/dev/hpu_v80

    Retrieved CI bugfix from dev/hpu
```
Tagged as `aved_v1.0`

Built with the following command: (i.e. versal/run_syn_hpu_msplit_3parts_psi32.sh)
```
TOP=top_hpu_assembly
TOP_MSPLIT=TOP_MSPLIT_1
TOP_BATCH=TOP_BATCH_TOPhpu_BPBS12_TPBS32
TOP_PCMAX=TOP_PCMAX_pem2_glwe1_bsk16_ksk16
TOP_PC=TOP_PC_pem2_glwe1_bsk8_ksk16
APPLICATION=APPLI_msg2_carry2_pfail64_132b_gaussian_1f72dba
NTT_MOD=NTT_MOD_goldilocks
NTT_CORE_ARCH=NTT_CORE_ARCH_gf64
NTT_CORE_R_PSI=NTT_CORE_R2_PSI32
NTT_CORE_RDX_CUT=NTT_CORE_RDX_CUT_n5c6
NTT_CORE_DIV=NTT_CORE_DIV_1
BSK_SLOT_CUT=BSK_SLOT8_CUT8
KSK_SLOT_CUT=KSK_SLOT8_CUT16
KSLB=KSLB_x3y64z3
HPU_PART=HPU_PART_gf64
AXI_DATA_W=AXI_DATA_W_256
FPGA=FPGA_v80

just build $TOP new "-F TOP_MSPLIT $TOP_MSPLIT -F TOP_BATCH $TOP_BATCH -F TOP_PCMAX  $TOP_PCMAX -F TOP_PC $TOP_PC -F APPLICATION $APPLICATION -F NTT_MOD $NTT_MOD -F NTT_CORE_ARCH $NTT_CORE_ARCH -F NTT_CORE_R_PSI $NTT_CORE_R_PSI -F NTT_CORE_RDX_CUT $NTT_CORE_RDX_CUT -F NTT_CORE_DIV $NTT_CORE_DIV -F BSK_SLOT_CUT $BSK_SLOT_CUT -F KSK_SLOT_CUT $KSK_SLOT_CUT -F KSLB $KSLB -F HPU_PART $HPU_PART -F AXI_DATA_W $AXI_DATA_W -F FPGA $FPGA" | tee build_out.log
```

# Fpga version @350MHz
This configuration as based on the following Fpga commit:
```
commit d29dbeaccf09adfe0ee13e326f4633e14726b020 (HEAD -> baroux/dev/hpu_v80_2024.2, origin/baroux/dev/hpu_v80_2024.2)
Author: pgardratzama <pierre.gardrat@zama.ai>
Date:   Tue Feb 11 16:12:10 2025 +0100

    adds script to synthetize HPU 1 part PSI32
```
Mainly the that commit as above with flow modification from Pierre Gardrat to support Vivado 2024.2.
NB: Based on unofficial branch and thus not tagged

Built with the following command: (i.e. versal/run_syn_hpu_1part_psi32.sh)
```
TOP=fpga_top_hpu
TOP_MSPLIT=TOP_MSPLIT_1
TOP_BATCH=TOP_BATCH_TOPhpu_BPBS12_TPBS32
TOP_PCMAX=TOP_PCMAX_pem2_glwe1_bsk16_ksk16
TOP_PC=TOP_PC_pem2_glwe1_bsk8_ksk16
APPLICATION=APPLI_msg2_carry2_pfail64_132b_gaussian_1f72dba
NTT_MOD=NTT_MOD_goldilocks
NTT_CORE_ARCH=NTT_CORE_ARCH_gf64
NTT_CORE_R_PSI=NTT_CORE_R2_PSI32
NTT_CORE_RDX_CUT=NTT_CORE_RDX_CUT_n5c6
NTT_CORE_DIV=NTT_CORE_DIV_1
BSK_SLOT_CUT=BSK_SLOT8_CUT8
KSK_SLOT_CUT=KSK_SLOT8_CUT16
KSLB=KSLB_x3y64z3
HPU_PART=HPU_PART_gf64
AXI_DATA_W=AXI_DATA_W_256
FPGA=FPGA_v80

just build $TOP new "-F TOP_MSPLIT $TOP_MSPLIT -F TOP_BATCH $TOP_BATCH -F TOP_PCMAX  $TOP_PCMAX -F TOP_PC $TOP_PC -F APPLICATION $APPLICATION -F NTT_MOD $NTT_MOD -F NTT_CORE_ARCH $NTT_CORE_ARCH -F NTT_CORE_R_PSI $NTT_CORE_R_PSI -F NTT_CORE_RDX_CUT $NTT_CORE_RDX_CUT -F NTT_CORE_DIV $NTT_CORE_DIV -F BSK_SLOT_CUT $BSK_SLOT_CUT -F KSK_SLOT_CUT $KSK_SLOT_CUT -F KSLB $KSLB -F HPU_PART $HPU_PART -F AXI_DATA_W $AXI_DATA_W -F FPGA $FPGA" | tee build_out.log
```
