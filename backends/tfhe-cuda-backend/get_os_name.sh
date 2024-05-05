#!/usr/bin/env bash

cat /etc/os-release | grep "\<NAME\>" | sed "s/NAME=\"//g" | sed "s/\"//g"
