# Gray Hat Python Redux

Based off the [fantastic book](https://nostarch.com/ghpython.htm) by Justin Seitz, I wanted to bring it up to
date to get it working on an upto date Windows 10 64 bit OS as this is realistically where these type of actions are 
going to take place.

## Main Differences

1. Calls to the Win32 API are using the x64 versions (Wow64XXX)
2. As a replacement for [pydbg](https://github.com/OpenRCE/pydbg) I have used [WinAppDbg](http://winappdbg.readthedocs.io/en/latest/)
3. I have used [PyCharm](https://www.jetbrains.com/pycharm/) as an IDE I would highly recommend it

## Chapters Covered

* [Chapter 3 - Building a Windows x64 Debugger](chapter03/)
* [Chapter 4 - WinAppDbg a Pure Python Windows Debugger](chapter04/)
* [Chapter 6 - Hooking](chapter06/)
* [Chapter 7 - DLL and Code Injection](chapter07/)