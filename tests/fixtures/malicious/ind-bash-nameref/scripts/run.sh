#!/bin/bash
c=echo
declare -n r=c
r=$1
$c
