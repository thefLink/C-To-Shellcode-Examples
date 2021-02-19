#!/bin/bash
for i in $(objdump -d CreateProcess.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done >> CreateProcess.bin
