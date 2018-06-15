# Chapter 6  - Hooking

## Firefox changes

In the book the is reference to the nspr4.dll DLL this is no longer what is used instead there is a nss3.dll DLL and this is now
where the `PR_Write` function lives so this is what the focus will be on.

We will be running firefox as 64bit and using the excellent [WinAppDbg](http://winappdbg.readthedocs.io/en/latest/)
library to achieve this and unlike the book this library will be used for both soft hooking and hard hooking.

### PR_Write

The documentation for this method can be found on the 
[Mozilla Dev site](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PR_Write) luckily for us this
makes it easier to work out how the call will look at runtime:

```c
PRInt32 PR_Write(
  PRFileDesc *fd,
  const void *buf,
  PRInt32 amount);
```

Due to us running as 64bit with MS fastcall convention this means that these parameters will be put into different
registers rather than in just `ESP` and because the data can be anythin we can't rely on it being a null terminated string
which means we need to capture the `amount` to work out the size of the `buf` parameter.

## Soft Hooking Limitation

You'll see that if you run the examples that the `PR_Write` function is not only used for sending data over the wire and
is used all over the place so you get a massive amount of calls which means that firefox has a tendency to hang, making
soft hooking not really a practical option (as mentioned they are not much good for intensive I/O operations)

## Credit to [Parsia's Den](https://parsiya.net/)

A lot of the information in this repo was gained using the fantastic set of posts on WinAppDbg on this blog 
https://parsiya.net/categories/winappdbg/ I highly recommend that you work your way through them, this 
[post](https://parsiya.net/blog/2017-11-11-winappdbg---part-2---function-hooking-and-others/) in particular is applicable
for this chapter.
