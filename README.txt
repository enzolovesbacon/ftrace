
Ftrace V0.1 [ryan.oneill@leviathansecurity.com]

DESCRIPTION:

ftrace is a reverse engineering tool designed to help map out the execution flow
of ELF executables (32bit and 64bit). Instead of printing system calls or library
function calls, it prints out the local function calls as they are happening,
and attempts to retrieve the function arguments and determine whether they are
immediate or pointer type. As of version 0.1, function arguments are only shown
for 64bit executables. This program is useful when wanting to see the function flow of
a given executable during runtime without having to set incremental breakpoints
and backtraces in a debugger like gdb.


COMPILE:

gcc ftrace.c -o ftrace

USAGE:

ftrace [-p <pid>] [-tsrve] <prog> <args>

ARCHITECTURE: 

For 32bit executables set FTRACE_ARCH=32, it defaults to 64.


OPTIONS: 

[-v] Verbose output, print symbol table info etc.

[-p] This option is used to attach to an existing process ID.

[-s] This option will show strings as they are passed through functions (As best it knows how)

[-e] This will show certain ELF info such as symbols, and lists the shared library deps.

ftrace -p <pid>

[-t] Type detection will guess what pointer type a function argument is, if it is a pointer.
It will detect pointers that are within the range of the text segment, data segment, heap and the stack.

EXAMPLE:


elfmaster@Ox31337:~/code/ftrace/ftrace$ ./ftrace -t /usr/bin/whoami

[+] Function tracing begins here:
LOCAL_call@0x401380: __libc_start_main()
PLT_call@0x401320: strrchr(0x2f)
PLT_call@0x401470: __printf_chk(0x6,(text_ptr *)0x404444)
PLT_call@0x4012b0: bindtextdomain((text_ptr *)0x40448a,(text_ptr *)0x404498,(text_ptr *)0x40448a,(text_ptr *)0x404498)
PLT_call@0x401280: textdomain((text_ptr *)0x40448a,(text_ptr *)0x40448a,0x7f6197f75b90,(text_ptr *)0x40448a)
PLT_call@0x401300: getopt_long((text_ptr *)0x404444)
LOCAL_call@0x401220: __errno_location()
LOCAL_call@0x401350: geteuid()
LOCAL_call@0x4012a0: getpwuid()
LOCAL_call@0x401270: puts()
elfmaster
LOCAL_call@0x4014d0: fwrite()
LOCAL_call@0x401260: __fpending()
LOCAL_call@0x4013f0: malloc()
LOCAL_call@0x401440: realloc()
LOCAL_call@0x401440: realloc()
LOCAL_call@0x401260: __fpending()
LOCAL_call@0x4013f0: malloc()
LOCAL_call@0x401440: realloc()
LOCAL_call@0x401440: realloc()

OPTIONS

[-r] Unfinished

 
BUGS:

* Semi Rare EIO ptrace error (In progress to fix)
* Memory leak with -s (In progress to fix)

FUTURE:

* Add support for function arguments on 32bit
* Add support for following fork'd children of target process
* Extend heuristics of 64bit procedure prologue calling convention for function args.
* Port to FreeBSD




