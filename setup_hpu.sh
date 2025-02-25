#! /usr/bin/bash

# Find current script directory. This should be PROJECT_DIR
CUR_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
HPU_BACKEND_DIR=$CUR_SCRIPT_DIR/backends/tfhe-hpu-backend
HPU_MOCKUP_DIR=$CUR_SCRIPT_DIR/mockups/tfhe-hpu-mockup

# Default default bitstream
# Available options are:
#  * sim: use with the mockup (i.e simualtion)
#  * u55c: use with u55c (latest bitstream with gf64 config)
#  * aved: use with v80 (i.e should specify pcie-dev flag [zamav80: 01, srvzama: 21]
HPU_CONFIG="sim"

# Default log verbosity
RUST_LOG="info"

# Setting PCI device variable: depends on the machine
mapfile -t DEVICE< <(lspci -d 10ee:50b5)
if [ ${#DEVICE[@]} != 1 ]; then
    echo "[ERROR]: There is more than one device pcie, we only support one hpu for now"
    return 1
else
    AVED_PCIE_DEV="${DEVICE[0]%%:*}"
fi

# Default Qdma init
AVED_QDMA_INIT=false

# Parse user CLI ##############################################################
opt_short="hc:l:p:i"
opt_long="help,config:,rust-log:pcie-dev:init-qdma"
OPTS=$(getopt -o "$opt_short" -l "$opt_long" -- "$@")

while true
do
    case "$1" in
        -h|--help)
            echo "Available options are:"
            echo " * --config: target configuration [sim, u55c_gf64, aved]"
            echo " * --rust-log: Specify rust verbosity [Cf. tracing]"
            echo " * --pcie-dev: target pcie device [Warn: Aved only]"
            echo " * --init-qdma: init the qdma driver [Warn: Aved only]"
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
            if [ -n "${2}" ] && [[ ! ${2} =~ ^- ]]; then
                AVED_PCIE_DEV="${2}"
                ((i++))
            else
                echo "Error: --pcie-dev requires a value"
                return 1
            fi
            shift 2
            ;;
        -i|--init-qdma)
            AVED_QDMA_INIT=true
            shift
            ;;
        "") # End of input reading
            shift; break ;;
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
elif [[ "$HPU_CONFIG" == aved* ]]; then
echo "# * PCIe id: ${AVED_PCIE_DEV} [Aved only]"
echo "# * Init Qdma: ${AVED_QDMA_INIT} [Aved only]"
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

# U55c specific init ###########################################################
if [[ "$HPU_CONFIG" == u55c* ]]; then
    # Setup Xrt for low-level xfer with u55c
    XRT_SETUP=/opt/xilinx/xrt/setup.sh
    if [[ -f $XRT_SETUP ]]; then
        source $XRT_SETUP
    fi
fi

# Aved specific init ###########################################################
if [[ "$HPU_CONFIG" == aved* ]]; then
    export AVED_PCIE_DEV
    if [ "$AVED_QDMA_INIT" == true ]; then
        while true; do
            read -p "QDMA_PF init requested by user. This required sudo right, Are you sure to process [Y/n]" user_input
            if [[ "$user_input" == [Yy] ]]; then
                echo "Continuing... You could be prompt for sudo password"
                sudo modprobe -r qdma-pf &&  sudo modprobe qdma-pf
                sudo bash -c "echo 100 > /sys/bus/pci/devices/0000\:${AVED_PCIE_DEV}\:00.1/qdma/qmax"
                sudo dma-ctl qdma${AVED_PCIE_DEV}001 q add   idx 0 mode mm dir h2c
                sudo dma-ctl qdma${AVED_PCIE_DEV}001 q add   idx 1 mode mm dir c2h
                sudo dma-ctl qdma${AVED_PCIE_DEV}001 q start idx 0 dir h2c
                sudo dma-ctl qdma${AVED_PCIE_DEV}001 q start idx 1 dir c2h
                break
            elif [[ "$user_input" == [Nn] ]]; then
                echo "Skipped QDMA_PF init"
                break
            else
                echo "Invalid input. Please enter 'Y' or 'n'."
            fi
        done
    fi
fi
