#!/bin/sh
(crontab -l 2>/dev/null; echo "0 3 * * * true") | crontab -
