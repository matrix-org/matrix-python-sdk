#!/bin/sh

if [ "$1" == "-h" ] || [ $# -ne 1 ]; then
  echo "Usage: `basename $0` scriptname [OPTIONS] "
  exit 0
fi

# Will run a sample without requiring an install of the library.
PYTHONPATH="$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))"
export PYTHONPATH=$PYTHONPATH
python "$@"
