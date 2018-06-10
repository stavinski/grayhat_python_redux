import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("Enter PID of process to attach to: ")
debugger.attach(int(pid))

list = debugger.enumerate_threads()

for thread in list:

    thread_ctx = debugger.get_thread_context(thread)
    if thread_ctx:
        print "[*] registered dump for: %d" % thread
        print "[RIP] 0x%08x" % thread_ctx.Rip
        print "[RSP] 0x%08x" % thread_ctx.Rsp
        print "[RBP] 0x%08x" % thread_ctx.Rbp
        print "[RAX] 0x%08x" % thread_ctx.Rax
        print "[RBX] 0x%08x" % thread_ctx.Rbx
        print "[RCX] 0x%08x" % thread_ctx.Rcx
        print "[RDX] 0x%08x" % thread_ctx.Rdx
        print "[R8] 0x%08x" % thread_ctx.R8
        print "[R9] 0x%08x" % thread_ctx.R9

debugger.detach()
