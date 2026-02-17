#!/usr/bin/env bash

set -e

# Prepare container with the required content
mkdir app && cd app/
cp -R /repo_src/lattice-estimator/ .
cp -R /repo_src/ci/ .

# Run Sage script
PYTHONPATH=lattice_estimator sage ci/lattice_estimator.sage
