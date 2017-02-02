#!/usr/bin/env python3

import sys
from skyscraper import *

is_binary = not "eml" in sys.argv[1]
is_encrypted = not "dec" in sys.argv[1]

dump=Dump(open(sys.argv[1], ['r', 'rb'][is_binary]).read(), fmt=[EML, BIN][is_binary], encrypted=is_encrypted)
dump.validate()
