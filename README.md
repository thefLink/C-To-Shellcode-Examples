# C-To-Shellcode-Examples

This repository contains examples on how to write C code which compiles down to an executable living fully in its text segment.
Thus, when extracting the text segment you will obtain position independent code which you can encode with your favourite shellcode encoder.

The **DownloadString_Syscalls** program, makes use of direct syscalls to obtain memory. Syscalls were generated using [Inline Whisperer](https://github.com/outflanknl/InlineWhispers) 

The idea has been well described by various researchers and is nothing new, please see:

- https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf
- http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
- https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
