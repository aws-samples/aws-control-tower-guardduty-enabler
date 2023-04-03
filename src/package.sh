#!/usr/bin/env bash
# Builds a lambda package, a zip with a single Python file

set -e
set -x

# https://stackoverflow.com/a/246128
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $SCRIPT_DIRECTORY > /dev/null

rm -f guardduty_enabler.zip > /dev/null 2>&1

zip guardduty_enabler.zip guardduty_enabler.py

popd > /dev/null
