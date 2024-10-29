#! /usr/bin/bash

# Find current script directory. This should be PROJECT_DIR
CUR_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
export HPU_BACKEND_DIR=$CUR_SCRIPT_DIR/backends/tfhe-hpu-backend

# Default default bitstream
# export HPU_CONFIG="config_44b_pem2"
export HPU_CONFIG="sim_pem2"

# Default verbosity
export RUST_LOG=info


# Setup Xrt for low-level xfer with u55c
source /opt/xilinx/xrt/setup.sh

# Update configuration symlink
rm -f ${HPU_BACKEND_DIR}/config
ln -s ${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG} ${HPU_BACKEND_DIR}/config


echo "###############################################################################"
echo "###                          Setup Hpu Backend                              ###"
echo "###############################################################################"
echo "# * Config: ${HPU_CONFIG}"
echo "###############################################################################"

