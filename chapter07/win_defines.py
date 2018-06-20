from ctypes import *
from ctypes.wintypes import *

# map wintypes

SBYTE       = c_byte
SWORD       = c_int16
SDWORD      = c_int32
QWORD       = c_uint64
SQWORD      = c_int64
LPDWORD     = POINTER(DWORD)

# Map size_t to SIZE_T
try:
    SIZE_T  = c_size_t
    SSIZE_T = c_ssize_t
except AttributeError:
    # Size of a pointer
    SIZE_T  = {1:BYTE, 2:WORD, 4:DWORD, 8:QWORD}[sizeof(LPVOID)]
    SSIZE_T = {1:SBYTE, 2:SWORD, 4:SDWORD, 8:SQWORD}[sizeof(LPVOID)]


PAGE_READWRITE     =     0x04
PROCESS_ALL_ACCESS =     ( 0x000F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM        =     ( 0x1000 | 0x2000 )

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength',                 DWORD),
        ('lpSecurityDescriptor',    LPVOID),
        ('bInheritHandle',          BOOL),
    ]
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
