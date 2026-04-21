#requires -Version 5.1


$ctx = $global:BR2.Context

# Only applicable to Windows 11 22H2+ and Server 2025
if (-not (Test-OSPrecondition -Requirements @{ MinBuild = 22621 })) {
    return
}

# Smart App Control (SAC)
# Win11 22H2+ only, must be enrolled at clean install - can't be turned on later. State: 0 = off, 1 = enforce, 2 = evaluation.
if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'SmartAppControl' }) {
    $sacState = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState'

    $BR2.Raw.SmartAppControl = @{ State = $sacState }

    # Only meaningful on non-domain-joined Win11 Home/Pro - Enterprise
    # typically uses WDAC policies instead. SAC is disabled on domain-joined.
    if (-not $ctx.IsDomainJoined -and $sacState -ne 1) {
        $stateDesc = switch ($sacState) {
            0 { 'Off (cannot be re-enabled on this install)' }
            1 { 'Enforce' }
            2 { 'Evaluation' }
            $null { 'Not configured' }
            default { "Unknown ($sacState)" }
        }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WIN11-001' `
            -Category 'ExecutionControl' `
            -Title "Smart App Control is in state: $stateDesc" `
            -Severity 'Low' `
            -Exploitability 'Theoretical' `
            -AttackPath 'Reduced reputation-based execution blocking on untrusted binaries' `
            -MITRE 'T1562.001' `
            -Evidence @{ State = $sacState } `
            -Remediation 'SAC state is install-time; this cannot be changed post-install. For new device provisioning, ensure clean-install profiles enrol SAC. Enterprise fleets should deploy WDAC instead.' `
            -OperatorNotes 'SAC disabled on most domain-joined / enterprise-managed Windows 11 installs by design. Informational finding for non-domain-joined hosts; not a gating control.' `
            -References @('https://learn.microsoft.com/en-us/windows/security/application-security/application-control/smart-app-control')
        ))
    }
}

# Personal Data Encryption (PDE)
# PDE encrypts user data files (e.g. Documents) with a key bound to Windows
# Hello credentials. Only available on Enterprise/Education 22H2+.
if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'PDE' }) {
    $pdeFolderPolicy = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PDE' -Name 'EnablePersonalDataEncryption'

    if ($pdeFolderPolicy -ne 1) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WIN11-002' `
            -Category 'BootIntegrity' `
            -Title 'Personal Data Encryption not enabled on a PDE-capable host' `
            -Severity 'Low' `
            -Exploitability 'Theoretical' `
            -AttackPath 'Files protected with BitLocker only are exposed once the volume is unlocked (e.g. during user session with stolen creds)' `
            -MITRE 'T1552' `
            -Evidence @{
                FriendlyVersion = $ctx.FriendlyVersion
                Edition         = $ctx.Edition
                EnablePDE       = $pdeFolderPolicy
            } `
            -Remediation 'Enable PDE via Intune configuration profile. Requires Windows Hello for Business. Bonus: protects data when the user is logged out even on an unlocked machine.' `
            -OperatorNotes 'PDE is an additional layer beyond BitLocker as files are additionally encrypted to Hello credentials. Absent = BitLocker is the only file-level protection.' `
            -References @('https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/personal-data-encryption/')
        ))
    }
}

# ---- Hardware-enforced Stack Protection (CET shadow stack) -------------

# Uses Intel CET / AMD equivalent. Enabled via mitigation policy in Win11.
# Queried via Get-ProcessMitigation / Windows Defender Exploit Guard.

try {
    $mitigation = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    $cetState = if ($mitigation.UserShadowStack) { "$($mitigation.UserShadowStack.UserShadowStack)" } else { 'Unknown' }

    $BR2.Raw.ShadowStack = @{ UserShadowStack = $cetState }

    if ($cetState -ne 'ON') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WIN11-003' `
            -Category 'ExecutionControl' `
            -Title "Hardware-enforced Stack Protection (CET) not enabled system-wide" `
            -Severity 'Low' `
            -Exploitability 'Low' `
            -AttackPath 'ROP / JOP (Return-Oriented / Jump-Oriented Programming) gadget chains not mitigated at the CPU level for processes without per-process opt-in' `
            -MITRE 'T1055' `
            -Evidence @{ UserShadowStack = $cetState } `
            -Remediation 'Set-ProcessMitigation -System -Enable UserShadowStack, UserShadowStackStrictMode. Requires CPU support (Intel 11th gen+ / AMD Zen 3+). Default off because not all software compatible.' `
            -OperatorNotes 'Reduces classic ROP-chain exploit reliability. Loaders (Donut, sRDI) and process injection techniques are not ROP-dependent, so direct impact on common evasion techniques is limited. More relevant for browser / Office exploit defence.' `
            -References @('https://learn.microsoft.com/en-us/windows/win32/secbp/hsp-secbp')
        ))
    }
} catch {}

# ASR rule: "Block abuse of exploited vulnerable signed drivers"
# ASR rule ID 56a863a9-875e-4185-98a7-b882c64b5ce5
# Available on Windows 10 1903+ but essential alongside Vulnerable Driver
# Blocklist. Check if enforced.

$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
    $vdrvASR = '56a863a9-875e-4185-98a7-b882c64b5ce5'
    $idx = [Array]::IndexOf($mpPref.AttackSurfaceReductionRules_Ids.ToLower(), $vdrvASR)
    if ($idx -ge 0) {
        $action = $mpPref.AttackSurfaceReductionRules_Actions[$idx]
        if ($action -ne 1) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-WIN11-004' `
                -Category 'ExecutionControl' `
                -Title ("ASR rule 'Block abuse of exploited vulnerable signed drivers' is in action $action (1 = block)") `
                -Severity 'Medium' `
                -Exploitability 'High' `
                -AttackPath 'BYOVD (Bring Your Own Vulnerable Driver) not blocked - loading signed-but-vulnerable drivers for kernel-mode code exec' `
                -MITRE 'T1068' `
                -Evidence @{
                    RuleId = $vdrvASR
                    Action = $action
                } `
                -Remediation 'Set the rule to action=1 (block). Combine with VulnerableDriverBlocklistEnable=1 for belt-and-braces.' `
                -OperatorNotes 'BYOVD chain: find a signed driver with a vulnerable IOCTL (loldrivers.io), load it via SeLoadDriverPrivilege or sc create, exploit to read/write kernel memory. EDRSandblast automates this against EDR callbacks and LSASS protection. With the ASR rule on, driver load is blocked at the ASR layer before the driver blocklist even evaluates.' `
                -References @(
                    'https://www.loldrivers.io/',
                    'https://github.com/wavestone-cdt/EDRSandblast'
                )
            ))
        }
    }
}



$plutonTPM = $null
try {
    $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        $plutonTPM = ($tpm.ManufacturerIdTxt -match 'MSFT|Pluton')
    }
} catch {}

$BR2.Raw.Pluton = @{ IsPlutonTPM = $plutonTPM }

# Informational only - no finding

# ---- Config Lock (Windows 11 22H2+ Secured-core) -----------------------

$configLock = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ConfigLock' -Name 'Enabled'
$BR2.Raw.ConfigLock = @{ Enabled = $configLock }

# Config Lock is only expected on Secured-core PCs; absence is not a finding
# but presence with misconfiguration would be. Leave as informational raw
# data unless specific misconfigurations surface in future research.
