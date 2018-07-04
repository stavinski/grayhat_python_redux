# Chapter 7 - DLL and Code Injection

This one had me stumped for a bit the OOTB the code from the book in this chapter as you might expect does not work on x64
I looked around for other python dll injectors and found this one based off the book (https://github.com/infodox/python-dll-injection)
but this had the same issue. Thankfully the WinAppDbg has already implemented a DLL injection routine so I could use this
as a baseline.

## DLL for x64

The first issue is that the DLL provided is compiled for x86 so first task was to use the x64 compiler to compile the 
ghp_inject.c code for x64:

```commandline
// open developer command line prompt
// navigate to the VC subdirectory
vcvarsall amd64
cl /LD gph_inject.c
```

I have added the x64 DLL to the chapter folder so this can be used for testing with.

Once I had this DLL in place I then tried the code as-is but it wasn't playing ball my suspicions were around permissions
or maybe latest Windows 10 locks this down however once I used the WinAppDbg DLL injection example with the compiled DLL
and it worked I knew it was possible.

## ctypes

I then just had to compare the differences between the wrapped `win32` library that WinAppDbg utilises vs. using `ctypes` 
directly the major difference being that the `argtypes` and `restype` being explicitly set before the call as soon as these
were specified the calls worked :)

## Shellcodes

TBA
