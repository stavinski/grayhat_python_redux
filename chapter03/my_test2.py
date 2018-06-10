import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("Enter PID of process to attach to: ")
debugger.attach(int(pid))
debugger.detach()
