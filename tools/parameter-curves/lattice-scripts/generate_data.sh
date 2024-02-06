#!/bin/sh 

set -e

output_dir=""
old_models=""
while :
do
    case $1 in
    --help) 
        echo "generate_data.sh -o [output_dir] [security_levels]"
        exit 2
        ;;
    --output)
        output_dir="$2"
        shift 2
        ;;
    --old-models)
        old_models="$2"
        shift 2
        ;;
    --)
        break;
        ;;
    "")
        break
        ;;
    *)
        security_levels="$security_levels $1"
        shift;
        ;;
    esac
done

for security_level in $security_levels; do
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level --sd-min 2 --sd-max 12 --margin 0
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level  --sd-min 12 --sd-max 22 --margin 0
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level  --sd-min 22 --sd-max 32 --margin 0
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level  --sd-min 32 --sd-max 42 --margin 0
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level  --sd-min 42 --sd-max 52 --margin 0
    sage lattice-scripts/generate_data.py --output $output_dir/$security_level.sobj --old-models $old_models --security-level $security_level  --sd-min 52 --sd-max 59 --margin 0
done
