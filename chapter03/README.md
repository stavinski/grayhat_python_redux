# Chapter 3 Building a Windows x64 Debugger

In the original it was based of the x86 win32 API calls this version will work 
against the x64 version by utilising the `CONTEXT64` and `Wow64GetThreadContext/Wow64SetThreadContext` plus also referring
to the AMD64 registers.

