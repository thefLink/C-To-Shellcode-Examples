#!/bin/bash
for i in $(objdump -d HelloWorld.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done >> HelloWorld.bin
