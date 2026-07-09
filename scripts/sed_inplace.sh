#!/usr/bin/env bash

# Check for GNU sed

if sed --version 2>/dev/null | grep -q GNU; then
    sed -i "$@"  # Pass all arguments to GNU sed
else
    sed -i '' "$@"  # Pass all arguments to BSD sed (with empty backup)
fi
