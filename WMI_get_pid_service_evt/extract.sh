#!/bin/bash
for i in $(objdump -d WMI_get_pid_service_evt.exe | grep "^ " | cut -f2); do echo -e -n "\x$i"; done >> WMI_get_pid_service_evt.bin
