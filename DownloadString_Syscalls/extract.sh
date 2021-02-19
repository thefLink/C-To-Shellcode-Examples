#!/bin/bash
for i in $(objdump -d DownloadString_Syscall.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done >> DownloadString_Syscall.bin
