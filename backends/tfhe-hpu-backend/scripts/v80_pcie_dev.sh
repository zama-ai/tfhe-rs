#!/usr/bin/env bash
# Define list of plugged V80 board with PcieId and SerialNumber
# Also provide some utility function to display it correctly and export it
# to ease parsing in tfhe-rs backend
# Value expressed in an associative array and export in a String with custom separator for exchange with the backend
#
# This file should be updated with correct pcie_id/serial number and placed within
# `/etc/profile.d/v80_pcie_dev.sh` with exec right.
# By this way all user will have access to those environment

###############################################################################
# USER EDIT HERE ONLY
###############################################################################
declare -gA V80_BOARDS_MAP=(
["0,pcie_id"]="PcieIdOfBoard0"
["0,serial_number"]="SerialNumberOfBoard0"
["0,mac_address"]="0x123400"

["1,pcie_id"]="PcieIdOfBoard1"
["1,serial_number"]="SerialNumberOfBoard1"
["1,mac_address"]="0x123401"

["2,pcie_id"]="PcieIdOfBoard2"
["2,serial_number"]="SerialNumberOfBoard2"
["2,mac_address"]="0x123402"

["3,pcie_id"]="PcieIdOfBoard3"
["3,serial_number"]="SerialNumberOfBoard3"
["3,mac_address"]="0x123403"

["4,pcie_id"]="PcieIdOfBoard4"
["4,serial_number"]="SerialNumberOfBoard4"
["4,mac_address"]="0x123404"

["5,pcie_id"]="PcieIdOfBoard5"
["5,serial_number"]="SerialNumberOfBoard5"
["5,mac_address"]="0x123405"

["6,pcie_id"]="PcieIdOfBoard6"
["6,serial_number"]="SerialNumberOfBoard6"
["6,mac_address"]="0x123406"

["7,pcie_id"]="PcieIdOfBoard7"
["7,serial_number"]="SerialNumberOfBoard7"
["7,mac_address"]="0x123407"
)
export V80_BOARDS_NB=8
###############################################################################

# Utility function to export board map in parseable fashion
_export_board_map_in_raw_string_fmt() {
  local v80_boards_rawmap=()
  for((b=0; b<V80_BOARDS_NB; b++)); do
     v80_boards_rawmap+=("${V80_BOARDS_MAP[$b,pcie_id]}:${V80_BOARDS_MAP[$b,serial_number]}:${V80_BOARDS_MAP[$b,mac_address]}")
  done
  export V80_BOARDS_RAWMAP=$(IFS='|'; echo "${v80_boards_rawmap[*]}")
}

_export_board_map_in_raw_string_fmt

# Utility function to export display board map in friendly fashion
display_v80_board_map() {
  for((b=0; b<V80_BOARDS_NB; b++)); do
     echo "@${b}: pcie_id:${V80_BOARDS_MAP[$b,pcie_id]}, serial_number:${V80_BOARDS_MAP[$b,serial_number]}, mac_address:${V80_BOARDS_MAP[$b,mac_address]}";
  done
}
