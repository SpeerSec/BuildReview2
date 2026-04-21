#requires -Version 5.1

$ctx = $global:BR2.Context

# Trust groups - members of these can legitimately modify service state.
# Everything else flagged as a finding if present in the service DACL.
$trustedSids = @(
    'S-1-5-18',           # NT AUTHORITY\SYSTEM
    'S-1-5-32-544',       # BUILTIN\Administrators
    'S-1-5-19',           # NT AUTHORITY\LOCAL SERVICE
    'S-1-5-20',           # NT AUTHORITY\NETWORK SERVICE
    'S-1-5-32-549',       # BUILTIN\Server Operators (expected DC admin)
    'S-1-5-32-557'        # BUILTIN\Incoming Forest Trust Builders
)

# Directories where write access by non-admins is expected and not a finding.
# We want to catch, e.g., C:\CustomApp writable by Authenticated Users.
$systemDirs = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot",
    "${env:ProgramFiles}",
    "${env:ProgramFiles(x86)}"
)

function Test-PathWritableByNonAdmin {
<#
.SYNOPSIS
    Heuristic check: is the given filesystem path writable by a principal
    that isn't a trusted admin / system group? Returns the list of
    offending principals or $null if path is safe/missing.

.NOTES
    Uses Get-Acl; slow on UNC paths. Skips if path doesn't exist.
#>
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    } catch { return $null }

    $writeRights = 'Write|Modify|FullControl|CreateFiles|AppendData|WriteData'
    $risky = @()

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.FileSystemRights -notmatch $writeRights) { continue }

        $idRef = "$($ace.IdentityReference)"
        # Resolve to SID if possible for reliable trust check
        $sid = $null
        try {
            $sid = (New-Object System.Security.Principal.NTAccount($idRef)).Translate(
                        [System.Security.Principal.SecurityIdentifier]).Value
        } catch {}

        if ($sid -and ($trustedSids -contains $sid)) { continue }

        # Well-known risky principals by name (covers cases where SID lookup fails)
        if ($idRef -match 'Everyone|Authenticated Users|Users$|INTERACTIVE|NT AUTHORITY\\Authenticated Users|BUILTIN\\Users|Domain Users') {
            $risky += $idRef
            continue
        }

        # Any other non-trusted principal with write is potentially interesting
        if (-not $sid -or -not ($trustedSids -contains $sid)) {
            # Be slightly conservative - only flag Users-like or named users.
            # Skip trusted-installer / service accounts that may also appear.
            if ($idRef -notmatch 'TrustedInstaller|CREATOR OWNER|NT SERVICE') {
                $risky += $idRef
            }
        }
    }

    if ($risky.Count -gt 0) { return ($risky | Sort-Object -Unique) }
    return $null
}

function Get-ServiceDaclRisky {
<#
.SYNOPSIS
    Parses a service's DACL via sc.exe sdshow and reports non-trusted
    principals holding reconfigure / start / stop rights.
#>
    param([string]$ServiceName)
    try {
        $sddl = & sc.exe sdshow $ServiceName 2>$null | Out-String
        if (-not $sddl -or $sddl -notmatch 'D:') { return $null }
        $sddl = ($sddl -replace '[\r\n]').Trim()

        $sd = ConvertFrom-SddlString -Sddl $sddl -ErrorAction SilentlyContinue
        if (-not $sd) { return $null }

        # Dangerous service access masks when granted to non-trusted principals:
        #   SERVICE_CHANGE_CONFIG (CC) - reconfigure ImagePath -> privesc
        #   SERVICE_START / STOP       - enough for certain chained attacks
        #   WRITE_DAC / WRITE_OWNER    - full takeover
        $risky = @()
        foreach ($ace in $sd.DiscretionaryAcl) {
            $principal = "$($ace -replace '.*: (.+)','$1')"
            if ($principal -match 'Administrators|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|TrustedInstaller|NT SERVICE') { continue }
            if ($ace -match 'Users|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                # Check for dangerous rights in the ACE string
                if ($ace -match 'ChangeConfig|WriteDac|WriteOwner|AllAccess|FullControl') {
                    $risky += $ace
                }
            }
        }
        if ($risky.Count -gt 0) { return $risky }
    } catch {}
    return $null
}

# Unquoted service paths with writable intermediate dirs
$services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
$BR2.Raw.Services = @{
    Count = @($services).Count
}

foreach ($svc in $services) {
    if (-not $svc.PathName) { continue }

    # PathName examples:
    #   C:\Program Files\App\svc.exe -k arg   (unquoted with space)
    #   "C:\Program Files\App\svc.exe" -k arg (quoted - safe)
    $path = $svc.PathName.Trim()
    if ($path.StartsWith('"')) { continue }         # quoted - safe
    if ($path -notmatch ' ')  { continue }          # no space - nothing to hijack

    # Parse out the candidate intermediate paths
    # For "C:\Program Files\App\svc.exe -k arg" the dangerous intermediates are:
    #   C:\Program.exe
    #   C:\Program Files\App.exe
    $exeStart = $path.IndexOf('.exe')
    if ($exeStart -lt 0) { continue }
    $exeOnly = $path.Substring(0, $exeStart + 4)

    # Walk back through parents to check writability
    $parent = Split-Path -Path $exeOnly -Parent
    $leaves = @()
    while ($parent -and $parent.Length -gt 3) {
        $leaves += $parent
        $parent = Split-Path -Path $parent -Parent
    }

    foreach ($dir in $leaves) {
        $writers = Test-PathWritableByNonAdmin -Path $dir
        if ($writers) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID "BR-SVC-010" `
                -Category 'ServicePermissions' `
                -Title "Unquoted service path '$($svc.Name)' with writable intermediate directory" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Unquoted path privesc - drop a malicious EXE in an intermediate directory; Service Control Manager launches it as the service identity on start' `
                -MITRE 'T1574.009' `
                -Evidence @{
                    Service        = $svc.Name
                    DisplayName    = $svc.DisplayName
                    PathName       = $svc.PathName
                    WritableDir    = $dir
                    WritableBy     = $writers
                    RunsAs         = $svc.StartName
                } `
                -Remediation "Quote the PathName: sc.exe config $($svc.Name) binpath= '`"$exeOnly`" <args>'. Alternatively tighten the writable directory DACL." `
                -OperatorNotes "Drop $dir\$((Split-Path $exeOnly -Leaf).Split(' ')[0].Substring(0,(Split-Path $exeOnly -Leaf).Split(' ')[0].IndexOf('.exe'))).exe with your payload. On service restart (Restart-Service, reboot, or if you can trigger stop/start via DACL), the SCM (Service Control Manager) launches your EXE as $($svc.StartName). Classic privesc that still works on legacy app installs." `
                -References @('https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens')
            ))
            break  # one finding per service is enough
        }
    }
}

# ---- Service binary writable by non-admin ---------------------------------

foreach ($svc in $services) {
    if (-not $svc.PathName) { continue }
    # Extract the binary path without args/quotes
    $bin = $svc.PathName.Trim().Trim('"')
    $exeIdx = $bin.IndexOf('.exe')
    if ($exeIdx -gt 0) { $bin = $bin.Substring(0, $exeIdx + 4) }
    # Strip leading quote if any leftover
    $bin = $bin.TrimStart('"')

    $writers = Test-PathWritableByNonAdmin -Path $bin
    if ($writers) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SVC-011' `
            -Category 'ServicePermissions' `
            -Title "Service binary for '$($svc.Name)' is writable by non-admin" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'Overwrite the service EXE; on restart SCM launches your binary as the service account' `
            -MITRE 'T1574.010' `
            -Evidence @{
                Service     = $svc.Name
                BinaryPath  = $bin
                WritableBy  = $writers
                RunsAs      = $svc.StartName
            } `
            -Remediation 'Tighten NTFS ACLs on the service binary to SYSTEM/Administrators write only. Move to Program Files if currently in an application-specific writable directory.' `
            -OperatorNotes 'Direct: copy payload.exe over the service binary, restart service. For silent persistence, wrap the legitimate service logic (via e.g. dllmain or a compiled wrapper that execs the original). Many third-party agents (backup, monitoring, industrial) drop binaries to C:\<vendor>\ with vulnerable ACLs.' `
            -References @('https://pentestlab.blog/2019/10/21/persistence-modify-existing-service/')
        ))
    }
}

# ---- Service registry ImagePath writable by non-admin ---------------------

foreach ($svc in $services) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    if (-not (Test-Path $regPath)) { continue }
    try {
        $regAcl = Get-Acl -Path $regPath -ErrorAction Stop
        $risky = @()
        foreach ($ace in $regAcl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.RegistryRights -notmatch 'FullControl|SetValue|TakeOwnership|ChangePermissions|WriteKey') { continue }
            $idRef = "$($ace.IdentityReference)"
            if ($idRef -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
            if ($idRef -match 'Users|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                $risky += $idRef
            }
        }
        if ($risky.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-SVC-014' `
                -Category 'ServicePermissions' `
                -Title "Service registry key for '$($svc.Name)' allows non-admin write" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Rewrite ImagePath registry value to point at attacker-controlled binary; service restart launches it' `
                -MITRE 'T1543.003' `
                -Evidence @{
                    Service     = $svc.Name
                    RegPath     = $regPath
                    WritableBy  = ($risky | Sort-Object -Unique)
                } `
                -Remediation 'Reset registry ACLs on the service key to default (SYSTEM/Administrators FullControl, Users Read).' `
                -OperatorNotes 'reg add HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ /v ImagePath /t REG_EXPAND_SZ /d "C:\payload.exe" /f. Persistence variant: point ImagePath at a wrapper that runs payload then transfers to original binary.' `
                -References @('https://attack.mitre.org/techniques/T1543/003/')
            ))
        }
    } catch {}
}

# ---- Weak service DACL (non-admin can reconfigure/stop/start) -------------

foreach ($svc in $services) {
    $risky = Get-ServiceDaclRisky -ServiceName $svc.Name
    if ($risky) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SVC-013' `
            -Category 'ServicePermissions' `
            -Title "Service '$($svc.Name)' has weak DACL permitting non-admin reconfiguration" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Non-admin runs sc.exe config to change binpath to attacker command; SCM executes as service account on start' `
            -MITRE 'T1543.003' `
            -Evidence @{
                Service   = $svc.Name
                RiskyACEs = $risky
                RunsAs    = $svc.StartName
            } `
            -Remediation 'Use sc.exe sdset to reset the service SDDL to a secure default. Default template for most services: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)' `
            -OperatorNotes 'sc.exe config <svc> binpath= "cmd.exe /c net user USER PASSWORD /add && net localgroup administrators USER /add", then sc.exe start <svc>. If the service runs as LocalSystem youve got SYSTEM. Sometimes found on custom/vendor services installed with overly-permissive ACLs.' `
            -References @('https://pentestlab.blog/2020/01/14/persistence-modify-existing-service/')
        ))
    }
}

# AlwaysInstallElevated (MSI runs as SYSTEM)
$aieHKLM = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
$aieHKCU = Get-RegistryValueSafe -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'

$BR2.Raw.AlwaysInstallElevated = @{
    HKLM = $aieHKLM
    HKCU = $aieHKCU
}

if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-SVC-015' `
        -Category 'ServicePermissions' `
        -Title 'AlwaysInstallElevated enabled in both HKLM and HKCU - MSI installs as SYSTEM' `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Any user-authored MSI is executed as SYSTEM on install - direct privesc' `
        -MITRE 'T1548.002' `
        -Evidence @{
            HKLM = $aieHKLM
            HKCU = $aieHKCU
        } `
        -Remediation 'Set both values to 0 or delete them. This is almost never a legitimate enterprise configuration - policy intended for per-app elevation should use UAC policies instead.' `
        -OperatorNotes 'msfvenom -p windows/x64/exec CMD="net user USER PASSWORD /add" -f msi > evil.msi; msiexec /quiet /qn /i evil.msi. Instantly SYSTEM. If only HKLM or only HKCU is set, the escalation does not work as both are required.' `
        -References @('https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated')
    ))
}

# AppPath hijack surface
$appPathsRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
if (Test-Path $appPathsRoot) {
    $appPaths = Get-ChildItem $appPathsRoot -ErrorAction SilentlyContinue
    foreach ($app in $appPaths) {
        try {
            $default = (Get-ItemProperty -Path $app.PSPath -Name '(default)' -ErrorAction Stop).'(default)'
            if (-not $default) { continue }
            $writers = Test-PathWritableByNonAdmin -Path $default
            if ($writers) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-SVC-020' `
                    -Category 'ServicePermissions' `
                    -Title "App Path entry '$($app.PSChildName)' points to non-admin-writable binary" `
                    -Severity 'Medium' `
                    -Exploitability 'Medium' `
                    -AttackPath 'Writable App Path target - overwriting the binary affects anything launched via Start > Run or ShellExecute with the app name' `
                    -MITRE 'T1574.010' `
                    -Evidence @{
                        AppName    = $app.PSChildName
                        Target     = $default
                        WritableBy = $writers
                    } `
                    -Remediation 'Tighten ACLs on the target binary or remove the App Path entry.' `
                    -OperatorNotes 'Less common but pops up on vendor installs. Replacing the binary persists until the app is reinstalled.' `
                    -References @('https://learn.microsoft.com/en-us/windows/win32/shell/app-registration')
                ))
            }
        } catch {}
    }
}

# Binary write of running driver
# Running kernel drivers - same hijack model as services but harder to reload.
# Flag only if the driver file is user-writable.
$drivers = Get-CimInstance -ClassName Win32_SystemDriver -Filter "State='Running'" -ErrorAction SilentlyContinue
foreach ($drv in $drivers) {
    if (-not $drv.PathName) { continue }
    $drvPath = $drv.PathName -replace '^\\\\\?\\',''
    $drvPath = $drvPath -replace '^\\SystemRoot\\',"$env:SystemRoot\"
    $drvPath = $drvPath -replace '^\??\\',''
    if (-not (Test-Path -LiteralPath $drvPath)) { continue }
    $writers = Test-PathWritableByNonAdmin -Path $drvPath
    if ($writers) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SVC-030' `
            -Category 'ServicePermissions' `
            -Title "Loaded kernel driver '$($drv.Name)' binary is writable by non-admin" `
            -Severity 'Critical' `
            -Exploitability 'Medium' `
            -AttackPath 'Replace driver binary; next boot or reload runs attacker code in kernel mode' `
            -MITRE 'T1068' `
            -Evidence @{
                Driver     = $drv.Name
                Path       = $drvPath
                WritableBy = $writers
            } `
            -Remediation 'Reset ACLs on the driver file. Driver paths should generally be SYSTEM/Admins only.' `
            -OperatorNotes 'Rarer but higher-impact than service hijack as kernel code execution on boot. Most driver directories have correct ACLs by default; this usually indicates a bad vendor install.' `
            -References @()
        ))
    }
}
