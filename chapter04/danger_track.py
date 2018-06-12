import ctypes.util

from winappdbg import Debug, EventHandler, Crash, CrashDump, HexDump

# keep a reference to this
MSVCRT_DLL = ctypes.util.find_msvcrt()

MAX_INSTRUCTIONS = 10

# plenty more to add to this!
dangerous_funcs = [
    "strcpy",
    "strncpy",
    "sprintf",
    "vsprintf"
]


class DangerousFunctionEventHandler(EventHandler):

    def __init__(self):
        self.resolved_funcs = {}
        self.snapshot = None
        self.crash_encountered = False
        self.instruction_count = 0

    def load_dll(self, evt):
        module = evt.get_module()
        if not module.match_name(MSVCRT_DLL):
            return

        for func in dangerous_funcs:
            addr = module.resolve(func)
            if addr:
                self.resolved_funcs[addr] = func
                evt.debug.break_at(evt.get_pid(), addr, self.danger_handler)
                print "[*] resolved dangerous func: %s -> %d" % (func, addr)

    def danger_handler(self, evt):
        thread = evt.get_thread()
        proc = evt.get_process()
        pc = thread.get_pc()
        registers = thread.get_context()

        if pc in self.resolved_funcs:
            print "[*] hit %s" % self.resolved_funcs[pc]

            CrashDump.dump_registers(registers)

            # record process memory
            try:
                proc.suspend()
                self.snapshot = proc.take_memory_snapshot()
            finally:
                proc.resume()

    def access_violation(self, evt):
        if evt.is_first_chance():
            return

        #crash = Crash(evt)
        #crash.fetch_extra_data(evt)
        #print crash.fullReport()

        proc = evt.get_process()

        if not self.crash_encountered:
            proc.restore_memory_snapshot(self.snapshot)
            self.crash_encountered = True

            evt.debug.start_tracing_process(proc.get_pid())
        else:
            proc.kill()

    def single_step(self, evt):
        if not self.crash_encountered:
            return

        print "single step"

        proc = evt.get_process()

        if self.instruction_count == MAX_INSTRUCTIONS:
            evt.debug.stop_tracing_process(proc.get_pid())
        else:
            thread = evt.get_thread()
            pc = thread.get_pc()
            code = proc.disassemble(pc, 0x10)
            print CrashDump.dump_code(code, pc)
            self.instruction_count += 1

pid = raw_input("Enter PID of process to monitor: ")

with Debug(DangerousFunctionEventHandler(), bKillOnExit=True) as debug:
    debug.attach(int(pid))

    try:
        debug.loop()
    except KeyboardInterrupt:
        debug.stop()
