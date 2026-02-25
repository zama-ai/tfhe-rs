#! /usr/bin/env bash

# Find current script directory. This should be PROJECT_DIR
CUR_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
HPU_BACKEND_DIR=$CUR_SCRIPT_DIR/backends/tfhe-hpu-backend
HPU_MOCKUP_DIR=$CUR_SCRIPT_DIR/mockups/tfhe-hpu-mockup

# Default default bitstream
# Available options are:
#  * sim: use with the mockup (i.e simulation)
#  * v80: use with v80 (i.e should specify pcie-dev flag [zamav80: 01, srvzama: 21]
HPU_CONFIG="sim"

# Default log verbosity
RUST_LOG="info"

# Setting PCI device variable: depends on the machine
if command -v lscpi &> /dev/null; then
    mapfile -t DEVICE< <(lspci -d 10ee:50b5)
else
    DEVICE=()
fi
V80_PCIE_DEV="unselected"

# V80 bitstream refresh rely on XilinxVivado tools
XILINX_VIVADO=${XILINX_VIVADO:-"/opt/amd/Vivado/2024.2"}

# V80 bitstream refresh require insmod of ami.ko module
AMI_PATH=${AMI_PATH:-"/opt/v80/ami/e55d02d"}

# Parse user CLI ##############################################################
opt_short="hc:l:p:"
opt_long="help,config:,rust-log:pcie-dev"
OPTS=$(getopt -o "$opt_short" -l "$opt_long" -- "$@")

while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help)
            echo "Available options are:"
            echo " * --config: target configuration [sim, v80]"
            echo " * --rust-log: Specify rust verbosity [Cf. tracing]"
            echo " * --pcie-dev: target pcie device [Warn: v80 only]"
            return 0
            ;;
        -c|--config)
            if [ -n "${2}" ] && [[ ! ${2} =~ ^- ]]; then
                HPU_CONFIG="${2}"
            else
                echo "Error: --config requires a value"
                return 1
            fi
            shift 2
            ;;
        -l|--rust_log)
            if [ -n "${2}" ] && [[ ! ${2} =~ ^- ]]; then
                RUST_LOG="${2}"
                ((i++))
            else
                echo "Error: --rust-log requires a value"
                return 1
            fi
            shift 2
            ;;
        -p|--pcie-dev)
            if [ -n "${2:-}" ] && [[ ! ${2:-} =~ ^- ]]; then
                V80_PCIE_DEV="${2}"
                ((i++))
                shift 1
            elif [[ ${#DEVICE[@]} -eq 1 ]]; then
                V80_PCIE_DEV=${DEVICE[0]%%:*}
            else
                echo "Please select a device in following list (1st two digits):"
                for item in "${DEVICE[@]}"; do
                    echo "$item"
                done
                return 1
            fi
            shift 1
            ;;
        "") # End of input reading
            break ;;
        *)
            echo "Unknown flag: $1"
            echo " use -h|--help for available options"
            return 1
            ;;
    esac
done

echo "###############################################################################"
echo "###                          Setup Hpu Backend                              ###"
echo "###############################################################################"
echo "# * Config: ${HPU_CONFIG}"
echo "# * Backend directory: ${HPU_BACKEND_DIR}"
if [[ "$HPU_CONFIG" == sim* ]]; then
echo "# * Mockup directory: ${HPU_MOCKUP_DIR}"
elif [[ "$HPU_CONFIG" == v80* ]]; then
echo "# * PCIe id: ${V80_PCIE_DEV} [V80 only]"
echo "# * XilinxVivado: ${XILINX_VIVADO} [V80 only]"
echo "# * AmiPath: ${AMI_PATH} [V80 only]"
fi
echo "# * Rust verbosity: ${RUST_LOG}"
echo "###############################################################################"

# Common init #################################################################
# -> Create config simlink and some exports
export HPU_BACKEND_DIR
export HPU_CONFIG
export RUST_LOG

# Sim specific init ###########################################################
if [[ "$HPU_CONFIG" == sim* ]]; then
    export HPU_MOCKUP_DIR
fi

# V80 specific init ###########################################################
if [[ "$HPU_CONFIG" == v80* ]]; then
    export V80_PCIE_DEV
    export XILINX_VIVADO
    export AMI_PATH
fi
