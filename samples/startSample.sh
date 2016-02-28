#!/bin/sh

# Will run a sample without requiring an install of the library.
PYTHONPATH="$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))"
export PYTHONPATH=$PYTHONPATH
python "$@"
