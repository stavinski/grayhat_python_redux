from ctypes import *

import ctypes.util
import time

msvcrt = cdll[ctypes.util.find_msvcrt()]
counter = 0

while 1:
    msvcrt.printf("Loop iteration %d!\n",counter)
    time.sleep(2)
    counter += 1