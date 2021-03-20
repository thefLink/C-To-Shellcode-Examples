# based on https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc DownloadString_Syscall.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o DownloadString_Syscall.o -Wl,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o ApiResolve.o DownloadString_Syscall.o -o DownloadString_Syscall.exe
