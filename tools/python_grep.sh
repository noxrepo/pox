#!/bin/bash

# Invoke from the top level:
# ./tools/python_grep.sh <expression to grep for>

find . -name "*py" | xargs grep --color=auto "$@"
