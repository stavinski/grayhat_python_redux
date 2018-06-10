from ctypes import *
from ctypes.wintypes import BYTE, WORD, DWORD, HANDLE, LPVOID, ULONG, LONG

# Let's map the Microsoft types to ctypes for clarity
# common types now imported from ctypes.wintypes
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char)
PVOID     = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong
DWORD64   = c_ulonglong
LONGLONG  = c_longlong

# Constants
DEBUG_PROCESS               = 0x00000001
CREATE_NEW_CONSOLE          = 0x00000010
PROCESS_ALL_ACCESS          = 0x001F0FFF
INFINITE                    = 0xFFFFFFFF
DBG_CONTINUE                = 0x00010002
DBG_EXCEPTION_NOT_HANDLED   = 0x80010001


# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004


# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL                   = 0x00010007
CONTEXT_DEBUG_REGISTERS        = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE         = 0x00000040

# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400


# Structures for CreateProcessA() function
# STARTUPINFO describes how to spawn the process
class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]

# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

# When the dwDebugEventCode is evaluated
# forward declaration to be able to use in _fields_ after
class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",        DWORD),
    ("ExceptionFlags",       DWORD),
    ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",     PVOID),
    ("NumberParameters",     DWORD),
    ("ExceptionInformation", LPVOID * 15),
]


# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]

# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]   

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]

# 32bit

# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
   _fields_ = [
   
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]

# The CONTEXT structure which holds all of the 
# register values after a GetThreadContext() call
class CONTEXT(Structure):
    _fields_ = [
    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]

# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]


# 64bit
class M128A(Structure):
    _fields_ =[
        ("High",    DWORD64),
        ("Low",     LONGLONG)
    ]


class XSAVE_FORMAT(Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord",         WORD),
        ("StatusWord",          WORD),
        ("TagWord",             BYTE),
        ("Reserved1",           BYTE),
        ("ErrorOpcode",         WORD),
        ("ErrorOffset",         DWORD),
        ("ErrorSelector",       WORD),
        ("Reserved2",           WORD),
        ("DataOffset",          DWORD),
        ("DataSelector",        WORD),
        ("Reserved3",           WORD),
        ("MxCsr",               DWORD),
        ("MxCsr_Mask",          DWORD),
        ("FloatRegisters",      M128A * 8),
        ("XmmRegisters",        M128A * 16),
        ("Reserved4",           BYTE * 96),
    ]

class DUMMYSTRUCTNAME(Structure):
    _fields_ = [
        ("Header",              M128A * 2),
        ("Legacy",              M128A * 8),
        ("Xmm0",                M128A),
        ("Xmm1",                M128A),
        ("Xmm2",                M128A),
        ("Xmm3",                M128A),
        ("Xmm4",                M128A),
        ("Xmm5",                M128A),
        ("Xmm6",                M128A),
        ("Xmm7",                M128A),
        ("Xmm8",                M128A),
        ("Xmm9",                M128A),
        ("Xmm10",               M128A),
        ("Xmm11",               M128A),
        ("Xmm12",               M128A),
        ("Xmm13",               M128A),
        ("Xmm14",               M128A),
        ("Xmm15",               M128A),
    ]

class DUMMYUNION(Union):
    _fields_ = [
        ("FltSave",             XSAVE_FORMAT),
        ("DUMMYSTRUCT",          DUMMYSTRUCTNAME)
    ]

class CONTEXT64(Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home",              DWORD64),
        ("P2Home",              DWORD64),
        ("P3Home",              DWORD64),
        ("P4Home",              DWORD64),
        ("P5Home",              DWORD64),
        ("P6Home",              DWORD64),

        ("ContextFlags",        DWORD),
        ("MxCsr",               DWORD),

        ("SegCs",               WORD),
        ("SegDs",               WORD),
        ("SegEs",               WORD),
        ("SegFs",               WORD),
        ("SegGs",               WORD),
        ("SegSs",               WORD),
        ("EFlags",              DWORD),

        ("Dr0",                 DWORD64),
        ("Dr1",                 DWORD64),
        ("Dr2",                 DWORD64),
        ("Dr3",                 DWORD64),
        ("Dr6",                 DWORD64),
        ("Dr7",                 DWORD64),

        ("Rax",                 DWORD64),
        ("Rcx",                 DWORD64),
        ("Rdx",                 DWORD64),
        ("Rbx",                 DWORD64),
        ("Rsp",                 DWORD64),
        ("Rbp",                 DWORD64),
        ("Rsi",                 DWORD64),
        ("Rdi",                 DWORD64),
        ("R8",                  DWORD64),
        ("R9",                  DWORD64),
        ("R10",                 DWORD64),
        ("R11",                 DWORD64),
        ("R12",                 DWORD64),
        ("R13",                 DWORD64),
        ("R14",                 DWORD64),
        ("R15",                 DWORD64),

        ("Rip",                 DWORD64),

        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExpcetionToRip", DWORD64),
        ("LastExpcetionFromRip", DWORD64),

        ("DUMMYUNION",          DUMMYUNION),

        ("VectorRegister",      M128A * 26),
        ("VectorControl",       DWORD64),
    ]

# Supporting struct for the SYSTEM_INFO_UNION union
class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture",    WORD),
        ("wReserved",                 WORD),
]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId",    DWORD),
        ("sProcStruc", PROC_STRUCT),
]
# SYSTEM_INFO structure is populated when a call to 
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints
class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
]

# MEMORY_BASIC_INFORMATION contains information about a 
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]
    