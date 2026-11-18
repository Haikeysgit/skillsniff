#!/bin/bash
c=(ls)
c[0]=$1
"${c[@]}"
