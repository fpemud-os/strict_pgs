#!/bin/bash

FILES="python3/strict_pgs.py"
ERRFLAG=0

OUTPUT1=`pyflakes "${FILES}"`
OUTPUT2=`pep8 "${FILES}" | grep -v "E501"`

if [ -n "$OUTPUT1" ] ; then
    echo "pyflake errors:"
    echo "$OUTPUT1"
    ERRFLAG=1
fi

if [ -n "$OUTPUT2" ] ; then
    echo "pep8 errors:"
    echo "$OUTPUT2"
    ERRFLAG=1
fi

if [ "${ERRFLAG}" == 1 ] ; then
    exit
fi
