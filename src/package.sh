#!/usr/bin/env bash
# Builds a lambda package from a single Python 3 module with pip dependencies.
# This is a modified version of the AWS packaging instructions:
# https://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html#python-package-dependencies

set -e
set -x

# https://stackoverflow.com/a/246128
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

rm -rf ${SCRIPT_DIRECTORY}/dist

mkdir ${SCRIPT_DIRECTORY}/dist
cp ${SCRIPT_DIRECTORY}/guardduty_enabler.py ${SCRIPT_DIRECTORY}/dist
cp ${SCRIPT_DIRECTORY}/requirements.txt ${SCRIPT_DIRECTORY}/dist

docker run -w /build/src/dist -v ${PWD}:/build -ti python:3.7 /usr/local/bin/pip3 install --target . -r requirements.txt
 
pushd ${SCRIPT_DIRECTORY}/dist > /dev/null

zip --grow  guardduty_enabler.zip *
 
popd > /dev/null
