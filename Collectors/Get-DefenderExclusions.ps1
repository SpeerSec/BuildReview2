#requires -Version 5.1

$ctx = $global:BR2.Context

# Existence + active mode check
$winDefend = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
if (-not $winDefend) {
    # Defender not present at all (e.g. Server Core without AV role)
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DEF-000' `
        -Category 'ExecutionControl' `
        -Title 'Windows Defender is not installed on this host' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'No AV/EDR present from the OS - unless third-party covers, arbitrary tooling runs unscanned' `
        -MITRE 'T1562.001' `
        -Evidence @{ WinDefendPresent = $false } `
        -Remediation 'Confirm third-party AV/EDR is present and active. If not, install and enable Defender or an enterprise equivalent.' `
        -OperatorNotes 'Server roles can have Defender removed. Check Win32_Product / Get-Service for MsSense (Defender for Endpoint), CrowdStrike, SentinelOne, Sophos, Carbon Black, etc. before concluding the host is unprotected.' `
        -References @()
    ))
    # Still check for third-party in the raw data even though Defender is gone
}

# Get Defender state
$mpStatus = $null
$mpPref   = $null
try { $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}
try { $mpPref   = Get-MpPreference -ErrorAction SilentlyContinue } catch {}

# Third-party AV enumeration via SecurityCenter2 (workstation only)
$thirdPartyAV = $null
if (-not $ctx.IsServer) {
    try {
        $thirdPartyAV = Get-CimInstance -Namespace 'root\SecurityCenter2' `
                                        -ClassName 'AntiVirusProduct' `
                                        -ErrorAction SilentlyContinue |
            Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' }
    } catch {}
}

$defenderActive = $mpStatus -and $mpStatus.AMServiceEnabled -and $mpStatus.AntivirusEnabled -and -not $mpStatus.IsVirtualMachine -eq $null -and -not ($thirdPartyAV -and $thirdPartyAV.Count -gt 0 -and -not $mpStatus.RealTimeProtectionEnabled)

$BR2.Raw.AVStack = @{
    DefenderInstalled       = [bool]$winDefend
    DefenderRealtime        = if ($mpStatus) { $mpStatus.RealTimeProtectionEnabled } else { $null }
    DefenderAMEngine        = if ($mpStatus) { $mpStatus.AMEngineVersion } else { $null }
    DefenderSigsUpToDate    = if ($mpStatus) { -not $mpStatus.AntispywareSignatureLastUpdated -lt (Get-Date).AddDays(-7) } else { $null }
    ThirdPartyAV            = @($thirdPartyAV | Select-Object -ExpandProperty displayName -ErrorAction SilentlyContinue)
}

# If Defender is passive (third-party installed), many of our checks don't
# apply - third-party decides policy. Flag the situation and move on.
if ($thirdPartyAV -and $thirdPartyAV.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DEF-TPAV' `
        -Category 'ExecutionControl' `
        -Title ('Third-party AV detected: ' + (($thirdPartyAV.displayName) -join ', ')) `
        -Severity 'Info' `
        -Exploitability 'Theoretical' `
        -AttackPath 'Defender becomes passive when third-party AV registers - evasion techniques differ per product' `
        -MITRE 'T1562.001' `
        -Evidence @{ ThirdParty = @($thirdPartyAV.displayName) } `
        -Remediation 'Not a finding - informational. Review third-party product configuration separately.' `
        -OperatorNotes 'Check the specific product - Carbon Black, CrowdStrike, SentinelOne, Cortex XDR, etc. each have their own known bypass surfaces. Loldrivers, EDRSandblast, and product-specific unhookers apply. The checks below may still surface residual Defender config.' `
        -References @()
    ))
}

# Only do detailed exclusion analysis if Defender appears to be the active AV
if (-not $winDefend) { return }

# ---- Real-time protection state ---------------------------------------

if ($mpStatus -and $mpStatus.RealTimeProtectionEnabled -ne $true) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DEF-020' `
        -Category 'ExecutionControl' `
        -Title 'Defender real-time protection disabled' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'On-access scanning disabled; binaries land without interception' `
        -MITRE 'T1562.001' `
        -Evidence @{ RealTimeProtectionEnabled = $false } `
        -Remediation 'Enable real-time protection. If disabled for a performance reason, scope the exclusion rather than disabling the whole engine.' `
        -OperatorNotes 'Drop any unscanned, land tooling, execute. No AMSI scan on file-drop either. Worth double-checking Tamper Protection state - if tamper is off, you can disable via Set-MpPreference from admin context too.' `
        -References @()
    ))
}

# Tamper Protection
if ($mpStatus -and -not $mpStatus.IsTamperProtected) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DEF-004' `
        -Category 'ExecutionControl' `
        -Title 'Defender Tamper Protection is disabled' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Defender can be disabled / reconfigured from admin context' `
        -MITRE 'T1562.001' `
        -Evidence @{ IsTamperProtected = $false } `
        -Remediation 'Enable Tamper Protection via Intune Security Baseline, M365 Defender portal, or Windows Security UI. Default on for new Windows 10 2004+ installs.' `
        -OperatorNotes 'As local admin: Set-MpPreference -DisableRealtimeMonitoring $true, or direct reg writes under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender. With Tamper Protection on these calls silently no-op.' `
        -References @('https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection')
    ))
}

# Exclusions (requires admin for HKLM)
if ($ctx.Elevated) {
    $exclBase = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    $exclPols = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'

    $pathExcl    = @()
    $processExcl = @()
    $extExcl     = @()

    foreach ($base in @($exclBase, $exclPols)) {
        if (-not (Test-Path $base)) { continue }
        try {
            $paths = (Get-Item -Path "$base\Paths" -ErrorAction SilentlyContinue).Property
            if ($paths) { $pathExcl += $paths }
            $procs = (Get-Item -Path "$base\Processes" -ErrorAction SilentlyContinue).Property
            if ($procs) { $processExcl += $procs }
            $exts  = (Get-Item -Path "$base\Extensions" -ErrorAction SilentlyContinue).Property
            if ($exts) { $extExcl += $exts }
        } catch {}
    }
    # Also pull from Get-MpPreference (runtime-applied, including Intune)
    if ($mpPref) {
        $pathExcl    += $mpPref.ExclusionPath
        $processExcl += $mpPref.ExclusionProcess
        $extExcl     += $mpPref.ExclusionExtension
    }

    $pathExcl    = @($pathExcl    | Where-Object { $_ } | Sort-Object -Unique)
    $processExcl = @($processExcl | Where-Object { $_ } | Sort-Object -Unique)
    $extExcl     = @($extExcl     | Where-Object { $_ } | Sort-Object -Unique)

    $BR2.Raw.DefenderExclusions = @{
        Paths      = $pathExcl
        Processes  = $processExcl
        Extensions = $extExcl
    }

    $total = $pathExcl.Count + $processExcl.Count + $extExcl.Count
    if ($total -gt 0) {
        # Flag broad/dangerous exclusions specifically
        $dangerousPaths = $pathExcl | Where-Object {
            $_ -match '^[A-Z]:\\?$' -or                                     # root of drive
            $_ -match '\\Users\\[^\\]+\\?$' -or                              # whole user profile
            $_ -match '^C:\\ProgramData\\?$' -or                            # ProgramData root
            $_ -match '^C:\\Windows\\Temp\\?$' -or                          # Windows Temp root
            $_ -match '^C:\\Temp\\?$' -or
            $_ -match '\\Downloads\\?$'
        }

        $sev = if ($dangerousPaths) { 'Critical' } else { 'High' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-DEF-001' `
            -Category 'ExecutionControl' `
            -Title "$total Defender exclusions configured (paths: $($pathExcl.Count), processes: $($processExcl.Count), extensions: $($extExcl.Count))" `
            -Severity $sev `
            -Exploitability 'High' `
            -AttackPath 'Stage and execute tooling from excluded paths, or with excluded process names; skip on-access scanning and DLP-style content detection' `
            -MITRE 'T1562.001' `
            -Evidence @{
                Paths          = $pathExcl
                Processes      = $processExcl
                Extensions     = $extExcl
                DangerousPaths = $dangerousPaths
            } `
            -Remediation 'Audit each exclusion against business justification. Replace broad path exclusions with narrow file-specific ones. Common offenders: SCCM agent temp, third-party backup agents, SQL Server data, line-of-business app working dirs.' `
            -OperatorNotes 'Exclusions visible to Defender telemetry but hidden from non-admin Get-MpPreference. Dropping tooling into an excluded path stops on-access AV scanning (AMSI still applies for PowerShell unless process-excluded). Process exclusion on powershell.exe or rundll32.exe are dangerous if present - any behaviour from those names is unscanned.' `
            -References @(
                'https://github.com/rad9800/bootlicker',
                'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
            )
        ))
    }
} else {
    $BR2.Skipped.Add([PSCustomObject]@{
        Collector = 'DefenderExclusions'
        Reason    = 'Path/process/extension exclusions require elevation to read from HKLM reliably. Re-run elevated for full coverage.'
    })
}

# ---- Cloud-delivered protection & MAPS membership -----------------------

if ($mpPref) {
    if ($mpPref.MAPSReporting -eq 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-DEF-008' `
            -Category 'ExecutionControl' `
            -Title 'Defender MAPS reporting disabled (no cloud lookup)' `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Cloud-only indicators never queried; new/unknown tooling not scored against Microsoft Intelligent Security Graph' `
            -MITRE 'T1562.001' `
            -Evidence @{ MAPSReporting = 0 } `
            -Remediation 'Set MAPSReporting=2 (Advanced MAPS) via Set-MpPreference or Group Policy.' `
            -OperatorNotes 'Known-bad hashes still match local signatures; but novel loaders, packers, and variants that rely on cloud-scored reputation sail through. Loaders like Donut-Loader, Freeze, recent maldev work benefit.' `
            -References @()
        ))
    }

    if ($mpPref.SubmitSamplesConsent -eq 2) {
        # 2 = never send - defender cant submit samples to cloud
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-DEF-006' `
            -Category 'ExecutionControl' `
            -Title 'Defender sample submission disabled' `
            -Severity 'Low' `
            -Exploitability 'Low' `
            -AttackPath 'Defender cannot submit suspicious samples for analysis; persists detection gaps against novel loaders' `
            -MITRE 'T1562.001' `
            -Evidence @{ SubmitSamplesConsent = 2 } `
            -Remediation 'Set SubmitSamplesConsent=1 (safe samples only) or 3 (all samples). Default is 1.' `
            -OperatorNotes 'Indirect benefit - your custom loader is less likely to fingerprint in MISG and burn cross-engagement.' `
            -References @()
        ))
    }

    # Controlled Folder Access state
    if ($mpPref.EnableControlledFolderAccess -eq 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-DEF-004b' `
            -Category 'ExecutionControl' `
            -Title 'Controlled Folder Access disabled (ransomware protection off)' `
            -Severity 'Low' `
            -Exploitability 'Theoretical' `
            -AttackPath 'Ransomware-style mass file modification not blocked by CFA' `
            -MITRE 'T1486' `
            -Evidence @{ EnableControlledFolderAccess = 0 } `
            -Remediation 'Enable CFA in audit mode first to assess impact, then enforce. Particularly recommended on workstations with user profiles holding important data.' `
            -OperatorNotes 'CFA blocks untrusted process writes to protected folders (Documents, Desktop, etc.). Not a red-team-relevant finding unless engagement scope includes ransomware emulation.' `
            -References @()
        ))
    }

    # Network Protection / SmartScreen
    if ($mpPref.EnableNetworkProtection -ne 1) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-DEF-007' `
            -Category 'ExecutionControl' `
            -Title "Defender Network Protection is in $($mpPref.EnableNetworkProtection) state (1=block, 2=audit, 0=off)" `
            -Severity 'Low' `
            -Exploitability 'Medium' `
            -AttackPath 'Outbound to known-malicious hosts not blocked at the OS layer' `
            -MITRE 'T1562.001' `
            -Evidence @{ EnableNetworkProtection = $mpPref.EnableNetworkProtection } `
            -Remediation 'Set EnableNetworkProtection=1 after audit-mode validation.' `
            -OperatorNotes 'Affects known-bad URL/IP reputation blocking at the SmartScreen layer. Custom C2 infra with no reputation history will bypass regardless.' `
            -References @()
        ))
    }
}
