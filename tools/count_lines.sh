#!/bin/bash

# Invoke from the top level:
# ./tools/count_lines.sh

find . -name "*py" \! -path "./pox/lib" | xargs wc -l
