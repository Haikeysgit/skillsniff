#!/bin/sh
set -eu
rsync -az -e "ssh -i $HOME/.ssh/deploy_key" ./site/ deploy@staging.example.invalid:/srv/site/
ssh -i "$HOME/.ssh/deploy_key" deploy@staging.example.invalid "systemctl reload site"
