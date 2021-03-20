# C-To-Shellcode-Examples

This repository contains examples on how to write C code which compiles down to an executable living fully in its text segment.
Thus, when extracting the text segment you will obtain position independent code which you can encode with your favourite shellcode encoder.

The **DownloadString_Syscalls** program, makes use of direct syscalls to obtain memory. Syscalls were generated using [Inline Whisperer](https://github.com/outflanknl/InlineWhispers) 
Sample files are provided as .bin (raw extracted text segment) and .bin.sgn (text segment encoded with [sgn](https://github.com/EgeBalci/sgn/). You can execute them using any shellcode loader.

## Loader Creation

Since the output is 100% position independent, there are multiple ways to execute the code. One is to use traditional shellcode loaders / injectors.
Another way is to simply take an existing **.exe** file and overwrite the part of the **.text** segment to which the entrypoint in **optional_header** points with the PIC.
I have added **loaderbuilder.py** to automate this.

```
python loaders\loaderbuilder.py -shellcode .\HelloWorld\HelloWorld.bin -loader C:\Users\user\Desktop\notepad.exe -output C:\Users\user\Desktop\cool.exe
```

Obviously this doesnt work with encoded PIC, since the .text segment is not writable by default.    
**Please note**, that the .exe file needs to be copied from system32 to somewhere else before patching. This appears to be a bug in python-lief, but I can't narrow it down :'(.

## Credits

The idea has been well described by various researchers and is nothing new, please see:

- https://vxug.fakedoma.in/papers/VXUG/Exclusive/FromaCprojectthroughassemblytoshellcodeHasherezade.pdf
- http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
- https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
