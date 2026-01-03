### Windows Forensics - PowerShell Techniques Collection

**Windows Forensics** involves collecting, preserving, and analyzing digital evidence from Windows systems. PowerShell is a powerful tool for forensic investigations due to its deep integration with Windows and ability to access system artifacts.

* **Primary Use:** Incident response, data recovery, malware analysis, and legal investigations.
* **PowerShell Benefits:** Native Windows tool, no external dependencies, extensive system access, and script automation.
* **Common Scenarios:** Data breach investigations, insider threat detection, ransomware analysis, compliance audits.
* **Key Principles:** Maintain evidence integrity, document chain of custody, minimize system alteration.

-----

### System Information Collection

Collecting comprehensive system information provides context for forensic investigations. This data helps understand the environment and identify anomalies.

#### Basic System Info

```powershell
# Get all system information in one command
Get-ComputerInfo | Select-Object -Property *

# Compact version
systeminfo

# PowerShell specific
$env:COMPUTERNAME;$env:USERNAME;Get-WmiObject Win32_OperatingSystem | Select Caption,Version

# Get system uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

* **Why it's used:** Establish baseline system configuration and identify OS details.
* **Artifacts captured:** OS version, install date, system uptime, hardware details.

#### User and Session Information

```powershell
# Current user and session info
whoami /all
quser

# PowerShell version
$PSVersionTable

# Network users
net users
net localgroup administrators

# Recent logons
Get-EventLog Security -InstanceId 4624 -Newest 10
```

* **Why it's used:** Identify active users, privileges, and session details.
* **Artifacts captured:** User SIDs, group memberships, login history, privileges.

-----

### Memory and Process Analysis

Memory analysis reveals running processes, loaded modules, and volatile evidence that disappears on shutdown.

#### Process Enumeration

```powershell
# Get all processes with full details
Get-Process | Select-Object Id,Name,CPU,WS,PM,Path,StartTime,CommandLine

# Compact one-liner
ps | select Id,Name,Path,StartTime

# Suspicious process detection
Get-Process | Where-Object {$_.Path -notlike "C:\Windows\*" -and $_.Path -notlike "C:\Program Files*"}

# Process tree
Get-WmiObject Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine
```

* **Why it's used:** Identify malicious processes, parent-child relationships, and process injection.
* **Artifacts captured:** Running processes, memory usage, command lines, execution times.

#### Memory Dump

```powershell
# Dump specific process memory
$proc = Get-Process notepad
& "C:\Tools\procdump64.exe" -ma $proc.Id "$env:USERPROFILE\Desktop\dump.dmp"

# PowerShell memory capture (requires admin)
Get-Process lsass | ForEach-Object {Add-Type -AssemblyName System.DirectoryServices;$ds=New-Object System.DirectoryServices.DirectoryEntry;New-Object System.DirectoryServices.DirectorySearcher($ds,"(objectCategory=user)")}
```

* **Why it's used:** Capture volatile memory for malware analysis and credential extraction.
* **Artifacts captured:** Process memory, encryption keys, passwords, loaded modules.

-----

### File System Forensics

File system analysis uncovers file creation, modification, access patterns, and hidden data.

#### Timeline Analysis

```powershell
# Get file timeline (MACE times)
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
Select-Object FullName, CreationTime, LastAccessTime, LastWriteTime, Length | 
Export-Csv -Path timeline.csv -NoTypeInformation

# Recent files (last 7 days)
$date = (Get-Date).AddDays(-7)
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | 
Where-Object {$_.LastWriteTime -gt $date} | 
Select-Object FullName, LastWriteTime
```

* **Why it's used:** Identify suspicious file activity and timeline reconstruction.
* **Artifacts captured:** File timestamps, access patterns, recently modified files.

#### Prefetch Analysis

```powershell
# Analyze Prefetch files
$prefetchPath = "C:\Windows\Prefetch"
Get-ChildItem $prefetchPath -Filter *.pf | 
Select-Object Name, LastWriteTime, @{Name='Executable';Expression={[System.Text.Encoding]::Unicode.GetString((Get-Content $_.FullName -Encoding Byte)[0x10..0x200])}}

# Compact version
ls C:\Windows\Prefetch\*.pf | select Name,LastWriteTime
```

* **Why it's used:** Track program execution history and frequency.
* **Artifacts captured:** Execution counts, run times, loaded modules.

-----

### Registry Forensics

Windows Registry contains configuration data, user activity, and system settings crucial for investigations.

#### Auto-Start Locations

```powershell
# Common persistence locations
$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$paths | ForEach-Object {
    if (Test-Path $_) {
        Get-ItemProperty $_ | Select-Object -Property *
    }
}

# Services
Get-WmiObject Win32_Service | Select-Object Name,DisplayName,State,PathName,StartMode
```

* **Why it's used:** Identify persistence mechanisms and auto-start programs.
* **Artifacts captured:** Startup programs, services, scheduled tasks, browser extensions.

#### User Activity

```powershell
# Recent documents
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue

# Typed URLs in browsers
Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" -ErrorAction SilentlyContinue

# USB device history
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*" -ErrorAction SilentlyContinue | 
Select-Object FriendlyName,DeviceDesc
```

* **Why it's used:** Reconstruct user activities and device usage.
* **Artifacts captured:** Document history, browser activity, USB connections.

-----

### Network Forensics

Network analysis reveals connections, listening ports, and network configuration.

#### Active Connections

```powershell
# All network connections
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | 
Where-Object {$_.State -eq "Established"}

# Compact version
netstat -ano | findstr ESTABLISHED

# Process to connection mapping
Get-NetTCPConnection | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Process = $proc.Name
        PID = $_.OwningProcess
        Local = "$($_.LocalAddress):$($_.LocalPort)"
        Remote = "$($_.RemoteAddress):$($_.RemotePort)"
        State = $_.State
    }
}
```

* **Why it's used:** Identify suspicious connections and data exfiltration.
* **Artifacts captured:** Active connections, listening ports, process relationships.

#### DNS Cache

```powershell
# View DNS cache
Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,DataLength

# Clear and monitor (for live analysis)
Clear-DnsClientCache
Start-Sleep -Seconds 10
Get-DnsClientCache
```

* **Why it's used:** Identify domain names accessed by the system.
* **Artifacts captured:** DNS queries, resolved domains, C2 communications.

-----

### Security Log Analysis

Windows Event Logs contain security events, authentication attempts, and system changes.

#### Security Event Logs

```powershell
# Failed login attempts
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50 | 
Select-Object TimeCreated,Message

# Successful logins
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 20

# Account changes
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720,4722,4725,4726} -MaxEvents 20
```

* **Why it's used:** Detect brute force attacks, account compromises, and privilege escalation.
* **Artifacts captured:** Authentication events, account changes, policy modifications.

#### System and Application Logs

```powershell
# Service changes
Get-WinEvent -FilterHashtable @{LogName='System';ID=7036} -MaxEvents 20

# PowerShell logging
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';ID=400,800} -MaxEvents 20 -ErrorAction SilentlyContinue

# Process creation (requires Sysmon)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1} -MaxEvents 20
```

* **Why it's used:** Track system changes and PowerShell execution.
* **Artifacts captured:** Service events, PowerShell commands, process creation.

-----

### Malware Artifact Hunting

Specific techniques to identify malware artifacts and indicators of compromise.

#### Suspicious File Locations

```powershell
# Check common malware locations
$suspiciousPaths = @(
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:TEMP",
    "C:\Windows\Temp",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks"
)

$suspiciousPaths | ForEach-Object {
    Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {$_.Name -match "\.(exe|dll|vbs|ps1|js)$"} | 
    Select-Object FullName,LastWriteTime,Length
}
```

* **Why it's used:** Find malware in common hiding spots.
* **Artifacts captured:** Executables in temp folders, suspicious scripts.

#### File Hash Analysis

```powershell
# Calculate file hashes
Get-FileHash -Path "C:\suspicious.exe" -Algorithm SHA256

# Batch hash calculation
Get-ChildItem -Path "C:\Windows\System32" -Filter *.exe | 
ForEach-Object {Get-FileHash $_.FullName -Algorithm MD5} | 
Select-Object Hash,Path

# Compare against known bad hashes
$badHashes = @("hash1","hash2")
Get-ChildItem -Path C:\ -Filter *.exe -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    if ($badHashes -contains $hash) {Write-Host "Malware found: $($_.FullName)"}
}
```

* **Why it's used:** Identify known malware and verify file integrity.
* **Artifacts captured:** File hashes, IOC matches, compromised files.

-----

### PowerShell Logging

Capture and analyze PowerShell activity for evidence of malicious scripts.

#### Enable PowerShell Logging

```powershell
# Enable Script Block Logging (requires admin)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable Module Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType String

# View PowerShell logs
Get-WinEvent -LogName "Windows PowerShell" | Select-Object TimeCreated,Message | Format-List
```

* **Why it's used:** Capture PowerShell commands and scripts executed on system.
* **Artifacts captured:** Command history, script blocks, module loading.

#### Extract PowerShell History

```powershell
# Get PowerShell console history
Get-History | Export-Csv -Path "$env:USERPROFILE\Desktop\PSHistory.csv"

# Alternative history locations
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# Event logs for PowerShell
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell';ID=4103,4104} | 
Select-Object TimeCreated,@{Name='Message';Expression={$_.Message -replace "`n"," "}}
```

* **Why it's used:** Reconstruct PowerShell activities and commands.
* **Artifacts captured:** Command history, executed scripts, remote sessions.

-----

### Disk and Volume Analysis

Analyze disk partitions, volumes, and recover deleted data.

#### Disk Information

```powershell
# Disk and volume information
Get-Disk | Select-Object Number,FriendlyName,Size,PartitionStyle
Get-Volume | Select-Object DriveLetter,FileSystemLabel,Size,SizeRemaining

# BitLocker status
Manage-bde -status

# Disk usage analysis
Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace,@{Name='PercentFree';Expression={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}}
```

* **Why it's used:** Understand disk configuration and encryption status.
* **Artifacts captured:** Disk partitions, free space, encryption status.

#### Shadow Copies

```powershell
# List volume shadow copies
vssadmin list shadows

# Create shadow copy (requires admin)
vssadmin create shadow /for=C:

# Access shadow copy data
$shadow = (vssadmin list shadows | Select-String "Shadow Copy Volume:" | Select-Object -First 1).ToString().Split(":")[1].Trim()
cmd /c "mklink /d C:\ShadowCopy $shadow"
```

* **Why it's used:** Access previous versions of files and system state.
* **Artifacts captured:** File history, deleted files, system restore points.

-----

### Browser Forensics

Extract browsing history, downloads, and saved credentials.

#### Chrome Artifacts

```powershell
# Chrome history location
$chromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (Test-Path $chromeHistory) {
    Copy-Item $chromeHistory "$env:USERPROFILE\Desktop\chrome_history.db"
}

# Chrome cache analysis
$chromeCache = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
Get-ChildItem $chromeCache -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime,Length
```

* **Why it's used:** Reconstruct web browsing activity.
* **Artifacts captured:** Browsing history, downloads, cookies, cache.

#### Internet Explorer/Edge

```powershell
# IE/Edge history
$ieHistory = "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\WebCacheV01.dat"
if (Test-Path $ieHistory) {
    Copy-Item $ieHistory "$env:USERPROFILE\Desktop\webcache.dat"
}

# Index.dat files (older IE)
Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\Windows\*" -Filter index.dat -Recurse -ErrorAction SilentlyContinue
```

* **Why it's used:** Extract Edge/IE browsing data.
* **Artifacts captured:** URL history, form data, visited sites.

-----

### Live Response Collection

Automated collection of forensic artifacts during live response.

#### Comprehensive Collector

```powershell
# Create output directory
$outputDir = "C:\Forensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputDir -Force

# Collection commands array
$commands = @(
    "systeminfo > `"$outputDir\systeminfo.txt`"",
    "netstat -ano > `"$outputDir\netstat.txt`"",
    "tasklist /v > `"$outputDir\tasklist.txt`"",
    "ipconfig /all > `"$outputDir\ipconfig.txt`"",
    "whoami /all > `"$outputDir\whoami.txt`"",
    "net user > `"$outputDir\net_user.txt`"",
    "net localgroup > `"$outputDir\net_localgroup.txt`""
)

# Execute all commands
$commands | ForEach-Object {cmd /c $_}

# Copy important files
Copy-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\*" "$outputDir\RecentFiles\" -ErrorAction SilentlyContinue
Copy-Item "C:\Windows\Prefetch\*" "$outputDir\Prefetch\" -ErrorAction SilentlyContinue
```

* **Why it's used:** Rapid evidence collection during incident response.
* **Artifacts captured:** Multiple system artifacts in organized structure.

#### Minimal Collector

```powershell
# One-liner collection
$d="C:\Forensics";ni $d -ItemType Directory -Force;systeminfo>"$d\si.txt";netstat -ano>"$d\ns.txt";tasklist>"$d\tl.txt"
```

* **Why it's used:** Quick collection with minimal footprint.
* **Artifacts captured:** Essential system information in compact format.

-----

### Timeline Creation

Create integrated timelines from multiple evidence sources.

#### Integrated Timeline

```powershell
# Combine multiple timelines
$outputFile = "C:\timeline.csv"

# File system timeline
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | 
Select-Object @{Name='Timestamp';Expression={$_.LastWriteTime}}, 
              @{Name='Source';Expression={'FileSystem'}},
              @{Name='Event';Expression={'FileModified'}},
              @{Name='Details';Expression={$_.FullName}} | 
Export-Csv -Path $outputFile -NoTypeInformation -Append

# Event log timeline (simplified)
Get-WinEvent -LogName Security -MaxEvents 100 | 
Select-Object @{Name='Timestamp';Expression={$_.TimeCreated}},
              @{Name='Source';Expression={'EventLog'}},
              @{Name='Event';Expression={$_.Id}},
              @{Name='Details';Expression={$_.Message}} | 
Export-Csv -Path $outputFile -NoTypeInformation -Append
```

* **Why it's used:** Correlate events from different sources.
* **Artifacts captured:** Integrated timeline for forensic analysis.

-----

### Anti-Forensics Detection

Identify attempts to hide or destroy evidence.

#### Timestomping Detection

```powershell
# Detect timestamp anomalies
Get-ChildItem -Path C:\Windows\System32\*.exe | 
Where-Object {$_.LastWriteTime -lt $_.CreationTime -or $_.LastAccessTime -lt $_.CreationTime} | 
Select-Object Name, CreationTime, LastWriteTime, LastAccessTime

# Check for time inconsistencies
Get-EventLog -LogName System -Newest 10 | 
Select-Object TimeGenerated, EntryType, Message | 
Where-Object {$_.TimeGenerated -gt (Get-Date)}
```

* **Why it's used:** Identify file timestamp manipulation.
* **Artifacts captured:** Timestamp inconsistencies, system time changes.

#### Evidence Destruction

```powershell
# Check for mass deletion
$recycleBin = "$env:SystemDrive`\$Recycle.Bin"
Get-ChildItem $recycleBin -Recurse -ErrorAction SilentlyContinue | 
Measure-Object | Select-Object Count

# Large number of deleted files
if ((Get-ChildItem $recycleBin -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count -gt 1000) {
    Write-Host "Suspicious: High number of files in Recycle Bin" -ForegroundColor Red
}
```

* **Why it's used:** Detect attempts to destroy evidence.
* **Artifacts captured:** Mass deletions, clearing of logs, evidence removal.

-----

### Defensive PowerShell Scripts

Proactive PowerShell scripts for monitoring and defense.

#### File Monitor

```powershell
# Monitor critical files for changes
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Windows\System32"
$watcher.Filter = "*.exe"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$action = {
    $path = $Event.SourceEventArgs.FullPath
    $changeType = $Event.SourceEventArgs.ChangeType
    $timestamp = Get-Date
    "$timestamp - $changeType - $path" | Out-File "C:\file_monitor.log" -Append
}

Register-ObjectEvent $watcher "Changed" -Action $action
Register-ObjectEvent $watcher "Created" -Action $action
Register-ObjectEvent $watcher "Deleted" -Action $action
```

* **Why it's used:** Monitor critical system files for unauthorized changes.
* **How it works:** Watches file system events and logs changes.

#### Process Monitor

```powershell
# Monitor new process creation
while ($true) {
    $current = Get-Process | Select-Object -ExpandProperty Id
    if ($global:last -ne $null) {
        $new = Compare-Object $global:last $current | Where-Object SideIndicator -eq "=>"
        foreach ($pid in $new.InputObject) {
            $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($proc) {
                "$(Get-Date) - New Process: $($proc.Name) ($pid) - $($proc.Path)" | Out-File "C:\proc_monitor.log" -Append
            }
        }
    }
    $global:last = $current
    Start-Sleep -Seconds 5
}
```

* **Why it's used:** Detect new process creation in real-time.
* **How it works:** Compares process lists periodically to identify new processes.

-----

### Evidence Cleanup Scripts

Scripts to securely remove evidence (for authorized testing only).

#### Basic Cleanup

```powershell
# Clear event logs (requires admin)
wevtutil el | ForEach-Object {wevtutil cl $_}

# Clear PowerShell history
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
Clear-History

# Clear recent documents
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -ErrorAction SilentlyContinue

# Clear recycle bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
```

* **Why it's used:** Remove traces of activity (authorized testing only).
* **How it works:** Clears various artifacts that store user activity.

#### Advanced Cleanup

```powershell
# Overwrite and delete files
function Secure-Delete {
    param($Path)
    if (Test-Path $Path) {
        $stream = [IO.File]::OpenWrite($Path)
        $bytes = New-Object byte[] 4096
        (New-Object Random).NextBytes($bytes)
        for ($i=0; $i -lt 3; $i++) {
            $stream.Seek(0, 'Begin')
            $stream.Write($bytes, 0, $bytes.Length)
        }
        $stream.Close()
        Remove-Item $Path -Force
    }
}

# Usage
Secure-Delete "C:\sensitive_file.txt"
```

* **Why it's used:** Secure file deletion (authorized use only).
* **How it works:** Overwrites file content before deletion.

-----

### Quick Reference Commands

Compact PowerShell one-liners for rapid forensics.

#### System Snapshot

```powershell
# Complete system snapshot
$d="C:\Snap_$(Get-Date -Format 'HHmm')";ni $d -Force;systeminfo>"$d\sys.txt";netstat -ano>"$d\net.txt";tasklist>"$d\tasks.txt";ps>"$d\ps.txt"
```

#### User Activity

```powershell
# Recent user activity
ls "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent"|select Name,LastWriteTime|ft
```

#### Network Quick Check

```powershell
# Quick network check
netstat -ano|findstr ESTAB|Select-String -Pattern "(0.0.0.0|127.0.0.1)" -NotMatch
```

#### Process Quick Analysis

```powershell
# Suspicious process check
ps|where{$_.Path -notmatch "C:\\Windows|C:\\Program Files"}|select Name,Id,Path
```

-----

### References and Tools

Essential tools and references for Windows forensics.

#### Microsoft Tools

```
Sysinternals Suite
Windows Event Viewer
PowerShell
Windows Forensic Environment (WinFE)
```

#### Third-Party Tools

```
Autopsy
FTK Imager
Volatility
Wireshark
```

#### PowerShell Modules

```
Kansa - Incident response framework
PowerForensics - PowerShell forensics module
Get-LogParser - Parse Windows logs
```

#### Learning Resources

```
SANS FOR500 - Windows Forensic Analysis
Windows Forensic Analysis Toolkit, 4th Ed.
Microsoft Docs - PowerShell documentation
```

-----

**Made with love by VIsh0k**