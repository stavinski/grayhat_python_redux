# Chapter 4  - WinAppDbg a Pure Python Windows Debugger

## Pydbg to WinAppDbg

In the original the [pydbg debugger](https://github.com/OpenRCE/pydbg) was used, this is a great library and I used it
while following along with the book but I found 2 main issues:

1. Not been maintained for a while so is lacking support for x64
2. Bit of a hack to get it installed had to google around a bit to get it working
3. Lack of documentation, most of the time either using the books as reference or docstrings

As a replacement I came across an awesome library called [WinAppDbg](http://winappdbg.readthedocs.io/en/latest/), as 
you'll see in the examples it does not have these shortcomings.
