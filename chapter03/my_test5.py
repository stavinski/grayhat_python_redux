import ctypes.util
import my_debugger

debugger = my_debugger.debugger()

pid = raw_input("Enter PID of process to attach to: ")
debugger.attach(int(pid))

msvcrt_dll = ctypes.util.find_msvcrt()
printf_addr = debugger.func_resolve(msvcrt_dll, "printf")
print "[*] address of printf: 0x%08x" % printf_addr
debugger.bp_set(printf_addr)
debugger.run()