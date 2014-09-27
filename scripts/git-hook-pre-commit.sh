#!/bin/bash

OUTPUT=`pep8 python3/strict_pgs.py | grep -v "E501"`
if [ -n "$OUTPUT" ]; then
    echo $OUTPUT
    exit 1
fi
