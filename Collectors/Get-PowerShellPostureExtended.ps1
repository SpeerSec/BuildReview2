#requires -Version 5.1


$ctx = $global:BR2.Context

# Module Logging
$moduleLogKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$moduleLogging = Get-RegistryValueSafe -Path $moduleLogKey -Name 'EnableModuleLogging'

$BR2.Raw.PSModuleLogging = $moduleLogging

if ($moduleLogging -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PS-003' `
        -Category 'ExecutionControl' `
        -Title 'PowerShell Module Logging is not enabled' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'No module pipeline event logging (Event ID 4103) - in-memory module loads and cmdlet usage pattern not captured' `
        -MITRE 'T1562.002' `
        -Evidence @{ EnableModuleLogging = $moduleLogging } `
        -Remediation 'Enable Module Logging for * (all modules) via Group Policy: Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging.' `
        -OperatorNotes 'Module logging records every cmdlet call into Microsoft-Windows-PowerShell/Operational event 4103 including bound parameters. Without it, even if Script Block Logging (4104) is on, in-memory IEX chains avoid scripted module loads from being correlated. Expect to see plaintext credentials in 4103 event bodies on misconfigured hosts - grep logs for -Credential, -AsPlainText, etc.' `
        -References @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows')
    ))
}

# Transcription
$transKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
$transEnabled = Get-RegistryValueSafe -Path $transKey -Name 'EnableTranscripting'
$transPath    = Get-RegistryValueSafe -Path $transKey -Name 'OutputDirectory'
$transInvoc   = Get-RegistryValueSafe -Path $transKey -Name 'EnableInvocationHeader'

$BR2.Raw.PSTranscription = @{
    Enabled = $transEnabled
    Path    = $transPath
    Header  = $transInvoc
}

if ($transEnabled -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PS-004' `
        -Category 'ExecutionControl' `
        -Title 'PowerShell Transcription is not enabled' `
        -Severity 'Low' `
        -Exploitability 'Medium' `
        -AttackPath 'No on-disk session transcripts - no full interactive history preserved for forensics' `
        -MITRE 'T1562.002' `
        -Evidence @{ EnableTranscripting = $transEnabled } `
        -Remediation 'Enable transcription to a centralised, write-only share with append-only ACLs. Do not output to a local path that the session user can modify.' `
        -OperatorNotes 'Less relevant than ScriptBlock + Module logging combined. However, transcripts catch things those event-log-only channels miss like stdout of launched processes. If transcript path is locally writable, can truncate/rewrite after use.' `
        -References @('https://adamtheautomator.com/powershell-transcript/')
    ))
} elseif ($transPath) {
    # If enabled, is the target writable by non-admins?
    try {
        $acl = Get-Acl -LiteralPath $transPath -ErrorAction Stop
        $dangerWriters = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|Delete') { continue }
            $idRef = "$($ace.IdentityReference)"
            if ($idRef -match 'Administrators|SYSTEM|TrustedInstaller|NT SERVICE') { continue }
            if ($idRef -match 'Users|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                $dangerWriters += $idRef
            }
        }
        if ($dangerWriters.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-PS-004b' `
                -Category 'ExecutionControl' `
                -Title "PowerShell transcript output directory is writable by non-admins: $transPath" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Transcripts can be truncated / rewritten / deleted after the fact - evasion of session forensics' `
                -MITRE 'T1070.001' `
                -Evidence @{
                    OutputDirectory = $transPath
                    WritableBy      = $dangerWriters
                } `
                -Remediation 'Change transcript destination to a write-only share (deny delete, allow append). Consider forwarding event logs to SIEM as the authoritative trail.' `
                -OperatorNotes 'After executing tooling: dir listing + Remove-Item on own transcript file. Or simpler: append a clean re-execution transcript on top. Evasion works as long as EventLog forwarding is not also on.' `
                -References @()
            ))
        }
    } catch {}
}

# Constrained Language Mode (CLM) enforcement
# CLM restricts PowerShell to a subset of .NET types - no Add-Type,
# no direct WinAPI, no custom classes. Enforced automatically under
# WDAC policy in Audit or Enforce mode. Can be overridden via
# __PSLockdownPolicy env var (defender-side hardening flag).

$lockdownEnv = [Environment]::GetEnvironmentVariable('__PSLockdownPolicy','Machine')
$systemLockdownPath = "$env:SystemRoot\System32\SystemLockdownPolicy.exe"
$wdacEnforced = $false
try {
    $devGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $wdacEnforced = ($devGuard.CodeIntegrityPolicyEnforcementStatus -eq 2)
} catch {}

$BR2.Raw.PowerShellCLM = @{
    LockdownEnvVar  = $lockdownEnv
    WDACEnforced    = $wdacEnforced
}

# Test current session language mode - if we're in CLM, many red-team
# tools simply cant run. FullLanguage = unconstrained.
$currentMode = $ExecutionContext.SessionState.LanguageMode
$BR2.Raw.PowerShellCLM.CurrentMode = "$currentMode"

# Only emit finding if WDAC is expected (build-review defender perspective)
# and CLM is not forced. No false positive on typical admin workstations.
if (-not $wdacEnforced -and $currentMode -eq 'FullLanguage' -and $ctx.IsServer) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PS-005' `
        -Category 'ExecutionControl' `
        -Title 'PowerShell runs in FullLanguage mode with no WDAC/AppLocker enforcement' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'No Constrained Language Mode boundary - Add-Type, reflection, P/Invoke, unrestricted .NET all available' `
        -MITRE 'T1059.001' `
        -Evidence @{
            CurrentMode  = "$currentMode"
            WDACEnforced = $wdacEnforced
        } `
        -Remediation 'Deploy WDAC in Enforce mode. Adding policy that triggers CLM is the single most impactful PowerShell-surface hardening. Complementary: AppLocker + PS__ExecutionPolicy is a weaker but easier first step.' `
        -OperatorNotes 'No CLM = Rubeus, Seatbelt, SharpHound, any Nuget-loaded tooling works directly via Add-Type or [Reflection.Assembly]::Load. Under CLM these all fail, must use alternative execution (CLM-bypass payloads, external binaries, or constrained-compatible scripts).' `
        -References @(
            'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes',
            'https://posts.specterops.io/constrained-language-mode-bypass-1d8e7d4d4398'
        )
    ))
}

# AMSI provider DLL hijack surface
# AMSI providers are registered under HKLM\SOFTWARE\Microsoft\AMSI\Providers
# Each {CLSID} entry points to an InprocServer32 DLL. If any provider DLL
# path is writable by non-admin, replacing the DLL bypasses AMSI for
# every consumer (PowerShell, Windows Script Host, Office macros, etc.)

$amsiProvRoot = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
if (Test-Path $amsiProvRoot) {
    $providers = Get-ChildItem -Path $amsiProvRoot -ErrorAction SilentlyContinue
    foreach ($p in $providers) {
        $clsid = $p.PSChildName
        # Look up the CLSID's InprocServer32
        $clsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
        if (-not (Test-Path $clsidKey)) {
            $clsidKey = "HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID\$clsid\InprocServer32"
        }
        if (-not (Test-Path $clsidKey)) { continue }

        $dllPath = (Get-ItemProperty -Path $clsidKey -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
        if (-not $dllPath) { continue }
        $dllPath = [Environment]::ExpandEnvironmentVariables($dllPath).Trim('"')
        if (-not (Test-Path -LiteralPath $dllPath)) { continue }

        # Reuse Test-PathWritableByNonAdmin if it was loaded by
        # ServicePermissions collector; else inline simple check
        $risky = @()
        try {
            $acl = Get-Acl -LiteralPath $dllPath
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|CreateFiles|AppendData') { continue }
                $idRef = "$($ace.IdentityReference)"
                if ($idRef -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
                if ($idRef -match 'Users$|Everyone|Authenticated Users|INTERACTIVE|Domain Users') { $risky += $idRef }
            }
        } catch {}

        if ($risky.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-PS-006' `
                -Category 'ExecutionControl' `
                -Title "AMSI provider DLL $dllPath is writable by non-admin" `
                -Severity 'Critical' `
                -Exploitability 'High' `
                -AttackPath 'Replace AMSI provider DLL - after next consumer process start, AMSI is effectively bypassed system-wide' `
                -MITRE 'T1562.001' `
                -Evidence @{
                    CLSID       = $clsid
                    Provider    = $dllPath
                    WritableBy  = ($risky | Sort-Object -Unique)
                } `
                -Remediation 'Fix ACLs on the AMSI provider DLL. Third-party AV AMSI providers sometimes install with lax ACLs - vendor issue to escalate.' `
                -OperatorNotes 'Stealthy AMSI bypass: replace the provider DLL with a proxy that forwards all calls but returns AMSI_RESULT_CLEAN for specific strings. Persists across reboots and process restarts. Much quieter than in-memory patches to amsi.dll. Often only Defenders own Windows Defender provider is present so compromising this DLL is kernel-level high impact.' `
                -References @(
                    'https://github.com/rasta-mouse/AmsiScanBufferBypass',
                    'https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/'
                )
            ))
        }
    }
}

# ---- PowerShell 7 side-by-side detection -----------------------------

$ps7Paths = @(
    "$env:ProgramFiles\PowerShell",
    "${env:ProgramFiles(x86)}\PowerShell"
)
$ps7Installed = $false
foreach ($p in $ps7Paths) {
    if (Test-Path $p) {
        $pwshBin = Get-ChildItem -Path $p -Recurse -Filter 'pwsh.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pwshBin) { $ps7Installed = $true; break }
    }
}

$BR2.Raw.PowerShell7Installed = $ps7Installed

if ($ps7Installed) {
    # PowerShell 7 has its own logging policies under
    # HKLM\SOFTWARE\Policies\Microsoft\PowerShellCore\
    $ps7LogKey = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
    $ps7SBL = Get-RegistryValueSafe -Path $ps7LogKey -Name 'EnableScriptBlockLogging'

    if ($ps7SBL -ne 1) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-PS-007' `
            -Category 'ExecutionControl' `
            -Title 'PowerShell 7+ installed but PowerShellCore logging not configured' `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'PowerShell 7 uses a separate policy tree; enterprise policies for Windows PowerShell (5.1) do not apply. Operator uses pwsh.exe to evade the well-configured 5.1 logging.' `
            -MITRE 'T1059.001' `
            -Evidence @{
                PS7Installed         = $true
                PS7ScriptBlockLogging = $ps7SBL
            } `
            -Remediation 'Deploy mirrored ScriptBlockLogging / ModuleLogging / Transcription policies under HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\. Administrative template available from Microsoft.' `
            -OperatorNotes 'If Windows PowerShell 5.1 is locked down but pwsh.exe sits unmanaged, switching to pwsh for tradecraft bypasses the 5.1 hardening. Check Get-PSReadLineOption in pwsh for history path which is different from 5.1 profile.' `
            -References @('https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-logging')
        ))
    }
}
