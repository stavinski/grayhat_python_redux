
from threading import Thread
from winappdbg import Process


class Snapshotter(object):

    def __init__(self, pid):
        self.pid = pid
        self.proc = None
        self.running = False
        self.snapshot = None

    def monitor(self):

        while self.running:
            input = raw_input("Enter: 'snap', 'restore' or 'quit': ")

            if input == "quit":
                print "[!] exiting snapshotter"
                self.running = False
                self.proc.close_handle()
            elif input == "snap":
                try:
                    print "[*] suspending process"
                    self.proc.suspend()
                    self.snapshot = self.proc.take_memory_snapshot()
                    print "[+] snapshot taken"
                finally:
                    print "[*] resuming process"
                    self.proc.resume()
            elif input == "restore":
                if not self.snapshot:
                    print "[!] no snapshot to restore please tale snapshot first"
                    continue

                try:
                    print "[*] suspending process"
                    self.proc.suspend()
                    # this seems to work some of the time :-/
                    self.proc.restore_memory_snapshot(self.snapshot)
                finally:
                    print "[*] resuming process"
                    self.proc.resume()

        self.proc.close_handle()

    def start(self):
        self.proc = Process(self.pid)
        self.running = True
        self.monitor()

pid = raw_input("Enter PID: ")
snapper = Snapshotter(int(pid))
snapper.start()