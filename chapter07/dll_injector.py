import sys
from ctypes import *
from win_defines import *

kernel32 = windll.kernel32
pid      = sys.argv[1]
dll_path = sys.argv[2] + '\x00'
dll_len  = len(dll_path)

# Get a handle to the process we are injecting into.
h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )

if not h_process:
    print "[*] Couldn't acquire a handle to PID: %s" % pid
    sys.exit(0)


# allocate some space for the dll path
kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
kernel32.VirtualAllocEx.restype  = LPVOID
arg_address = kernel32.VirtualAllocEx( h_process, None, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

print "[*] alloc address: 0x%08x" % arg_address

# write the dll path into the allocated space
written = c_ulonglong(0)

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
kernel32.WriteProcessMemory.restype  = bool
if not kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written)):
    raise WinError()

# We need to resolve the address for LoadLibraryA
kernel32.GetModuleHandleA.argtypes = [LPSTR]
kernel32.GetModuleHandleA.restype  = HMODULE
h_kernel32 = kernel32.GetModuleHandleA("kernel32")

if not h_kernel32:
    raise WinError()
    
print "[*] Kernel32 Address: 0x%08x" % h_kernel32

kernel32.GetProcAddress.argtypes = [HMODULE, LPVOID]
kernel32.GetProcAddress.restype  = LPVOID
h_loadlib  = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")

if not h_loadlib:
    raise WinError()

print "[*] LoadLibrary Address: 0x%08x" % h_loadlib

# Now we try to create the remote thread, with the entry point set
# to LoadLibraryA and a pointer to the DLL path as it's single parameter
thread_id = DWORD()

kernel32.CreateRemoteThread.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD]
kernel32.CreateRemoteThread.restype  = HANDLE

if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
    raise WinError()

print "[+] Thread created: %d" % thread_id.value
