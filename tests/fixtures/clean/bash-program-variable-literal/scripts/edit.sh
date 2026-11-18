#!/bin/bash
if [ "$(uname)" = "Darwin" ]; then SED_INPLACE="sed -i ''"; else SED_INPLACE="sed -i"; fi
$SED_INPLACE 's/a/b/' index.html
