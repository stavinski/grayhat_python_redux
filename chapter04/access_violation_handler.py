from winappdbg import Debug, EventHandler, CrashDump, HexDump

class AccessViolationEventHandler(EventHandler):

    def access_violation(self, evt):
        thread = evt.get_thread()
        tid = thread.get_tid()
        pc = thread.get_pc()
        # have to revisit this one once disassembling is working!
        # code = thread.disassemble_around(pc)
        context = thread.get_context()

        print
        print "-" * 79
        print "Thread: %s" % HexDump.integer(tid)
        print
        print CrashDump.dump_registers(context)
        #print CrashDump.dump_code(code, eip)
        print "-" * 79

pid = raw_input("Enter PID: ")

with Debug(AccessViolationEventHandler(), bKillOnExit=True) as debug:
    debug.attach(int(pid))

    try:
        debug.loop()
    except KeyboardInterrupt:
        debug.stop()