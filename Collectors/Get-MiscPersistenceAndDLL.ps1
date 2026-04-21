#requires -Version 5.1



$ctx = $global:BR2.Context

# Helper: writable-by-non-admin test
function Test-DirectoryWritableByNonAdmin {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $risky = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|CreateFiles|AppendData') { continue }
            $id = "$($ace.IdentityReference)"
            if ($id -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
            if ($id -match 'Users$|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                $risky += $id
            }
        }
        if ($risky.Count -gt 0) { return ($risky | Sort-Object -Unique) }
    } catch {}
    return $null
}

# ======================================================================
# Active Setup
# ======================================================================

# HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}
# StubPath runs ONCE per user on first logon. Used historically for
# per-user app initialisation. Adding a new GUID here = persistence
# that triggers next time any new user logs in.

$activeSetup = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
$activeSetupWow64 = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components'

$suspicious = @()
foreach ($path in @($activeSetup, $activeSetupWow64)) {
    if (-not (Test-Path $path)) { continue }
    $entries = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
    foreach ($entry in $entries) {
        try {
            $props = Get-ItemProperty -Path $entry.PSPath -ErrorAction Stop
            $stub = $props.StubPath
            $ver = $props.Version
            # StubPath pointing at cmd.exe, powershell, rundll32 with unusual args,
            # or any path in user-writable location = suspicious
            if ($stub -and $stub -match '(?i)(powershell|pwsh|cmd\.exe.*\/c|mshta|rundll32|regsvr32|wmic|msbuild)') {
                # Legitimate built-ins do exist - filter known-safe patterns
                if ($stub -match 'Windows Portable Device|DirectDrawEx|Themes Setup|Internet Explorer Customization|Microsoft Windows Live') {
                    continue
                }
                $suspicious += [PSCustomObject]@{
                    GUID    = $entry.PSChildName
                    Key     = $entry.PSPath
                    StubPath = $stub
                    Version  = $ver
                }
            }
        } catch {}
    }
}

if ($suspicious.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-ACTSET-001' `
        -Category 'Persistence' `
        -Title "Active Setup entry with scripting-interpreter StubPath ($($suspicious.Count) entry)" `
        -Severity 'High' `
        -Exploitability 'Medium' `
        -AttackPath 'Active Setup StubPath runs once per user on first logon - new user logon triggers payload in that user context' `
        -MITRE 'T1547.014' `
        -Evidence @{ Entries = $suspicious } `
        -Remediation 'Review entries for legitimacy. Remove via reg delete under the offending GUID.' `
        -OperatorNotes 'Less common than Run keys but far less monitored. StubPath with Version < user profile version = triggers on logon. Use a Version of "1,0,0,0" to ensure first-time fire on every new profile, or bump to invalidate existing user profiles. Landing as admin: lock target account + wait for next logon = payload fires.' `
        -References @(
            'https://attack.mitre.org/techniques/T1547/014/',
            'https://pentestlab.blog/2019/10/30/persistence-active-setup/'
        )
    ))
}

# ======================================================================
# Logon Scripts (HKCU\Environment)
# ======================================================================

# UserInitMprLogonScript runs on user logon before shell starts.
$userInitScript = Get-RegistryValueSafe -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript'
if ($userInitScript) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LOGON-001' `
        -Category 'Persistence' `
        -Title "HKCU Environment UserInitMprLogonScript is set: $userInitScript" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Runs before shell on every interactive logon as the user - per-user persistence without admin' `
        -MITRE 'T1037.001' `
        -Evidence @{ Script = $userInitScript } `
        -Remediation "Delete unless documented. Run reg delete HKCU\Environment /v UserInitMprLogonScript /f." `
        -OperatorNotes 'Classic user-only persistence. Any user can write HKCU\Environment. Value can be a full command line - e.g. "cmd.exe /c start C:\Users\Public\pay.lnk". Each logon fires.' `
        -References @('https://attack.mitre.org/techniques/T1037/001/')
    ))
}

# Machine-wide logon scripts via GPO - enumerated in GPOAppliedState.

# ======================================================================
# Screensaver persistence
# ======================================================================

# HKCU\Control Panel\Desktop\SCRNSAVE.EXE triggers on idle. Classic
# user-level persistence that fires on keyboard-idle timeout.

$scrnsave = Get-RegistryValueSafe -Path 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE'
$scrnsaveActive = Get-RegistryValueSafe -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive'

if ($scrnsave -and $scrnsaveActive -eq '1') {
    # Check if path is unusual
    $expanded = [Environment]::ExpandEnvironmentVariables("$scrnsave")
    $isSystem32 = $expanded -match [regex]::Escape("$env:SystemRoot\System32")
    if (-not $isSystem32) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SCRN-001' `
            -Category 'Persistence' `
            -Title "Non-System32 screensaver configured: $scrnsave" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Custom screensaver EXE triggers on user idle - per-user persistence' `
            -MITRE 'T1546.002' `
            -Evidence @{
                SCRNSAVE_EXE     = $scrnsave
                ScreenSaveActive = $scrnsaveActive
            } `
            -Remediation 'Reset to System32 screensaver or None.' `
            -OperatorNotes 'Any PE renamed to .scr can be set. Useful when you want persistence that fires on inactivity rather than logon, this is a quieter event pattern.' `
            -References @('https://attack.mitre.org/techniques/T1546/002/')
        ))
    }
}

# ======================================================================
# BITS jobs (Background Intelligent Transfer Service)
# ======================================================================

# Admin-level BITS jobs can persist transfers (both upload and download)
# across reboots. Historic adversary C2 channel - also valid admin tool.

if ($ctx.Elevated) {
    try {
        $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        $suspiciousJobs = $bitsJobs | Where-Object {
            $_.DisplayName -notmatch 'Windows Update|Defender|Microsoft' -and
            $_.TransferType -eq 'Download' -and
            $_.State -in 'Suspended','Queued','Transferring'
        }

        $BR2.Raw.BITSJobs = @{
            TotalCount       = $bitsJobs.Count
            SuspiciousCount  = $suspiciousJobs.Count
        }

        if ($suspiciousJobs.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-BITS-001' `
                -Category 'Persistence' `
                -Title "$($suspiciousJobs.Count) non-Microsoft BITS job(s) in active state" `
                -Severity 'Medium' `
                -Exploitability 'Medium' `
                -AttackPath 'BITS download jobs persist across reboot - adversary C2 via /transfer resume, or staged payload delivery' `
                -MITRE 'T1197' `
                -Evidence @{
                    Jobs = @($suspiciousJobs | Select-Object -First 5 DisplayName, TransferType, State, RemoteName)
                } `
                -Remediation 'Review jobs. Remove with Remove-BitsTransfer if suspicious. Confirm against expected backup / update tooling.' `
                -OperatorNotes 'Start-BitsTransfer is a classic low-footprint download primitive. Job with /SETNOTIFYCMDLINE pointing at your payload = persistence via BITS callback on transfer state change. Check notificationCmdLine of each job - often where the interesting payload lives.' `
                -References @('https://attack.mitre.org/techniques/T1197/')
            ))
        }
    } catch {}
}

# ======================================================================
# Explorer shell extensions (HKLM\...\Shell Extensions\Approved)
# ======================================================================

# Shell extension DLLs load into explorer.exe. Writable DLL path =
# shell-level code exec as user.

$shellExtRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
if (Test-Path $shellExtRoot) {
    $approvedExts = Get-ItemProperty -Path $shellExtRoot -ErrorAction SilentlyContinue
    $writableExts = @()
    $checked = 0
    foreach ($p in $approvedExts.PSObject.Properties) {
        if ($p.Name -match 'PS(Path|ParentPath|ChildName|Provider|Drive)') { continue }
        $checked++
        if ($checked -gt 100) { break }   # performance cap
        # Resolve CLSID -> InprocServer32 -> DLL path
        $clsid = $p.Name
        $inproc = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
        if (-not (Test-Path $inproc)) { continue }
        $dll = (Get-ItemProperty -Path $inproc -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
        if (-not $dll) { continue }
        $dll = [Environment]::ExpandEnvironmentVariables($dll).Trim('"')
        if (-not (Test-Path -LiteralPath $dll)) { continue }

        $writers = Test-DirectoryWritableByNonAdmin -Path (Split-Path $dll -Parent)
        if ($writers) {
            $writableExts += [PSCustomObject]@{
                CLSID = $clsid; DLL = $dll; WritableDirBy = $writers
            }
        }
    }

    if ($writableExts.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SHELL-001' `
            -Category 'Persistence' `
            -Title "$($writableExts.Count) Explorer shell extension(s) in non-admin-writable dirs" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Shell extension DLLs load into explorer.exe when triggered (context menu, column providers, icon overlays) - drop DLL for user-session code exec' `
            -MITRE 'T1547.014' `
            -Evidence @{ Extensions = $writableExts } `
            -Remediation 'Fix directory ACLs on the listed paths. Shell extension DLLs should be in Program Files or System32, not user-writable locations.' `
            -OperatorNotes 'Classic third-party vendor install mistake. Drop an updated DLL with the same name; explorer loads it on next shell launch / context menu trigger. Persistent and triggered by normal user activity.' `
            -References @('https://attack.mitre.org/techniques/T1547/014/')
        ))
    }
}

# ======================================================================
# PATH environment variable with writable entries
# ======================================================================

$systemPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$userPath   = [Environment]::GetEnvironmentVariable('PATH', 'User')

$pathEntries = @(($systemPath -split ';') + ($userPath -split ';')) | Where-Object { $_ -and $_.Trim() }
$pathEntries = $pathEntries | Sort-Object -Unique

$writablePathEntries = @()
foreach ($entry in $pathEntries) {
    $expanded = [Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $expanded)) { continue }
    $writers = Test-DirectoryWritableByNonAdmin -Path $expanded
    if ($writers) {
        $writablePathEntries += [PSCustomObject]@{
            Entry      = $entry
            WritableBy = $writers
        }
    }
}

if ($writablePathEntries.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PATH-001' `
        -Category 'ServicePermissions' `
        -Title "PATH contains $($writablePathEntries.Count) non-admin-writable director" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Phantom DLL / EXE planting - drop a binary named the same as a commonly-loaded module in a writable PATH entry earlier in the search order' `
        -MITRE 'T1574.007' `
        -Evidence @{ WritableEntries = $writablePathEntries } `
        -Remediation 'Remove user-writable directories from machine PATH. Or restrict ACL on listed paths to admins only.' `
        -OperatorNotes 'CWD-search DLL hijack: drop version.dll / cryptsp.dll / shell32.dll / VERSION.dll there. Any admin process that inherits PATH and dynamically loads by name hits the DLL first. Scheduled tasks and services that start via short-name exe invocation (not fully qualified) also resolve via PATH.' `
        -References @(
            'https://attack.mitre.org/techniques/T1574/007/',
            'https://itm4n.github.io/windows-dll-hijacking-clarified/'
        )
    ))
}

# ======================================================================
# KnownDLLs - normally admin-only, check for additions
# ======================================================================

$knownDLLs = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
if (Test-Path $knownDLLs) {
    $kdList = Get-ItemProperty -Path $knownDLLs -ErrorAction SilentlyContinue
    # Legitimate KnownDLLs are ~30-40 core system DLLs
    # Additions could redirect well-known DLL loads
    $kdCount = @($kdList.PSObject.Properties | Where-Object { $_.Name -notmatch 'PS(Path|ParentPath|ChildName|Provider|Drive)' }).Count
    $BR2.Raw.KnownDLLs = @{ Count = $kdCount }
    # Over 100 entries would be highly unusual - but we don't have a firm baseline
    # so leave as informational
}

# ======================================================================
# Task Scheduler folder writability (task creation without admin)
# ======================================================================

# Historic: users could sometimes write to the Tasks folder for low-privilege
# task persistence. Check base folder ACL.

$tasksFolder = "$env:windir\System32\Tasks"
if (Test-Path $tasksFolder) {
    $writers = Test-DirectoryWritableByNonAdmin -Path $tasksFolder
    if ($writers) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-TSK-030' `
            -Category 'Persistence' `
            -Title "Task Scheduler Tasks folder is writable by non-admin: $tasksFolder" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'Write task XML directly to Tasks folder - bypass Register-ScheduledTask admin requirement' `
            -MITRE 'T1053.005' `
            -Evidence @{ WritableBy = $writers } `
            -Remediation 'Reset ACLs to default - only SYSTEM, Administrators, and Network Service should have write.' `
            -OperatorNotes 'sc start trick - drop task XML into the folder. If Task Scheduler service picks it up without registration, task runs without admin. Rare on modern Windows but worth checking.' `
            -References @()
        ))
    }
}

# ======================================================================
# IE / Edge Browser Helper Objects (BHOs) - writable BHO DLL
# ======================================================================

# Mostly obsolete (IE-focused) but legacy hosts may still have BHO surface.
$bhoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
if (Test-Path $bhoRoot) {
    $bhos = Get-ChildItem -Path $bhoRoot -ErrorAction SilentlyContinue
    $BR2.Raw.BHOs = @{
        Count = $bhos.Count
        CLSIDs = @($bhos.PSChildName)
    }
    # Not a finding by default - informational only. BHO is dying tech.
}

# ======================================================================
# AutoLogger - Windows Event Tracing autologger DLL
# ======================================================================

# HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger - boot-time ETW
# providers. Compromised entries can result in persistence via ETW
# provider DLLs. Admin-only writable, but check ACL for deviations.

$autoLogger = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
if (Test-Path $autoLogger) {
    $writers = Test-DirectoryWritableByNonAdmin -Path $autoLogger  # registry key, not dir, but reuses principle
    # Skip - registry ACL needs different tool. Left as informational.
    $BR2.Raw.AutoLoggerCount = (Get-ChildItem -Path $autoLogger -ErrorAction SilentlyContinue).Count
}
