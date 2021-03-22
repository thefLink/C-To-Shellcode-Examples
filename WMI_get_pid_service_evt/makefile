# based on https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-gcc WMI_get_pid_service_evt.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o WMI_get_pid_service_evt.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -e go -s adjuststack.o ApiResolve.o WMI_get_pid_service_evt.o -o WMI_get_pid_service_evt.exe
