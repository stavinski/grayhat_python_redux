import struct
import random
import ctypes.util

from winappdbg import Debug, EventHandler, HexDump

# keep this for reference
MSVCRT_DLL = ctypes.util.find_msvcrt()

def printf_bp_handler(evt):
    thread = evt.get_thread()
    counter = thread.get_register("Rdx")  # counter is on th Rdx register for x64
    print "counter: %d" % counter

    rand_counter = random.randint(1, 100)
    #rand_counter = struct.pack("L", rand_counter)[0]
    thread.set_register("Rdx", rand_counter)  # update to the random counter

class PrintfRandomizerEventHandler(EventHandler):

    def load_dll(self, evt):
        module = evt.get_module()
        if module.match_name(MSVCRT_DLL):
            addr = module.resolve("printf")
            if addr:
                pid = evt.get_pid()
                evt.debug.break_at(pid, addr, printf_bp_handler)
                print "[+] added bp for printf: 0x%08x" % addr


pid = raw_input("Enter print_loop.py PID: ")

with Debug(PrintfRandomizerEventHandler()) as debug:
    debug.attach(int(pid))

    try:
        debug.loop()
    except KeyboardInterrupt:
        debug.stop()