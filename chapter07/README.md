# Chapter 7 - DLL and Code Injection

This chapter was by far the most challenging to work on and get working running examples, alot of what is written in the
book simply does not work on x64 modern windows so I had to spend a lot of time researching and learning (x64 assembly!)
just to be able to get things together.

## Antivirus

Given what is in this chapter I found stuff getting flagged by AV all the time, so be warned! :)

## DLL for x64

The first issue is that the DLL provided is compiled for x86 so first task was to use the x64 compiler to compile the 
ghp_inject.c code for x64:

```commandline
// open developer command line prompt
// navigate to the VC subdirectory
vcvarsall.bat amd64
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

# Shellcode

This one caused more of nightmare to try and get working than the DLL section! First issue is that the shellcode provided
is for x86 no x64 so will not work against a x64 target, the second issue is that if you use msfvenom to generate the
shellcode it will more than likely get flagged by AV.

## Handcrafting Assembly

Given the above it was then on a voyage of discovery in how to craft shellcode using assembly, turns out that creating 
assembly code that will execute in a separate process on windows is a lot harder than in linux as you cannot make `syscall`'s
like you would in linux instead you have to got through the Win32 API and specifically `kernel32.dll`, this causes an
issue because in modern windows you have [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) which
basically means that the address in memory of DLL's will change and therefore cannot be relied on, in normal assembly
programming this is not an issue as the linker takes care of this for you but for shellcode you have to handle it yourself,
cue hours spent trawling through for how this is done, anyway turns out the solution is to read the in memory data structure
of the PE and then the read the data structure of the DLL, I tried a few examples however than only one I could get working
was from here (http://mcdermottcybersecurity.com/articles/windows-x64-shellcode). 

Once the assembly for looking up DLL's was in place the rest was just tweaking for our purposes and getting 
my head round making calls in x64 assembly. I have added both raw shellcodes and the accompanying asm code.

to compile the assembly you will want to use `ml64`:

```commandline
// open developer command line prompt
// navigate to the VC subdirectory
vcvarsall amd64
ml64 calc.asm /link /entry:main
// details about Header #1 for knowing where in the exe to grab the shellcode without the PE format data
dumpbin /headers calc.exe
```

You can then use a hex editor to grab the raw shellcode from the exe.

I did not get chance to craft together a full reversible tcp shell, this was just beyond my newly found assembly-fu
capabilities and time! So instead the backdoor simply displays a message box.

# py2exe

I didn't have much luck trying to bundle an exe with x64 using py2exe it moaned that this is not supported yet, so instead
i used [pyinstaller](https://pyinstaller.readthedocs.io/en/v3.3.1/index.html) and this worked fine with the following:

```commandline
pyinstaller backdoor.py --onefile --windowed
```

Due to calc.exe being pretty locked down now in windows I didn't get chance to try this whole scenario.