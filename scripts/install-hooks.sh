#!/bin/bash

if [ -e "../.git" ] ; then
    echo "Installing Git hooks..."
    ln -sf "../../scripts/git-hook-pre-commit.sh" "../.git/hooks/pre-commit"
    echo "Done."
    exit 0
fi

echo "Error: Unknown CVS system!"
exit 1
