# WinDbg and x86 Architecture

```bash
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /size:1900x880 /u:Offsec /p:lab /v:192.168.181.10 /drive:EXP-301,/home/kali/OffSec/EXP-301
```

## x86 Architecture

Process memory is allocated in Windows between the lowest memory address (0x00000000) and the highest memory address (**0x7FFFFFFF**).

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


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```



```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

```

```nasm

```


```nasm

```


```nasm

```


```nasm

```


```nasm

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