#!/bin/sh -

# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# If you have PyPy in a directory called pypy alongside pox.py, we
# use it.
# Otherwise, we try to use a Python interpreter called python3, which
# is a good idea if it's there.
# We fall back to just "python" and hope that works.

''''true
#export OPT="-u -O"
export OPT="-u"
export FLG=""
if [ "$(basename $0)" = "debug-pox.py" ]; then
  export OPT=""
  export FLG="--debug"
fi

if [ -x pypy/bin/pypy ]; then
  exec pypy/bin/pypy $OPT "$0" $FLG "$@"
fi

if type python3 > /dev/null 2> /dev/null; then
  exec python3 $OPT "$0" $FLG "$@"
fi

exec python $OPT "$0" $FLG "$@"
'''

from pox.boot import boot

if __name__ == '__main__':
  boot()
