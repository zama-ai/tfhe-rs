# Fpga version

Built with the following command: (i.e. xrt/run_syn_hpu_msplit_3parts_64b.sh)
```
just zaxl-build hpu_msplit_3parts 3 "0:300" "-F TOP_MSPLIT TOP_MSPLIT_1 -F TOP_BATCH TOP_BATCH_TOPhpu_BPBS8_TPBS32 -F TOP_PCMAX  TOP_PCMAX_pem2_glwe1_bsk8_ksk8 -F TOP_PC TOP_PC_pem2_glwe1_bsk4_ksk4 -F APPLICATION APPLI_msg2_carry2 -F NTT_MOD NTT_MOD_goldilocks -F NTT_CORE_ARCH NTT_CORE_ARCH_gf64 -F NTT_CORE_R_PSI NTT_CORE_R2_PSI16 -F NTT_CORE_RDX_CUT NTT_CORE_RDX_CUT_n5c5c1 -F NTT_CORE_DIV NTT_CORE_DIV_1 -F BSK_SLOT_CUT BSK_SLOT8_CUT4 -F KSK_SLOT_CUT KSK_SLOT8_CUT4 -F KSLB KSLB_x2y32z3 -F HPU_PART HPU_PART_gf64 -F AXI_DATA_W AXI_DATA_W_512" "1:${PROJECT_DIR}/hw/output/micro_code/ucore_fw.elf" 'D:MEMORY_FILE_PATH=\\\"${PROJECT_DIR}/hw/\\\"' | tee build_out.log
```
