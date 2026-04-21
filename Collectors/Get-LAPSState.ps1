#requires -Version 5.1



$ctx = $global:BR2.Context

# Only meaningful on domain-joined clients and member servers as DCs typically don't have LAPS applied to themselves.
if (-not $ctx.IsDomainJoined -or $ctx.IsDC) {
    return
}

# Legacy LAPS detection
$legacyLAPSPaths = @(
    "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll",
    "${env:ProgramFiles(x86)}\LAPS\CSE\AdmPwd.dll"
)
$legacyLAPSInstalled = $false
foreach ($p in $legacyLAPSPaths) {
    if (Test-Path $p) { $legacyLAPSInstalled = $true; break }
}

# Legacy LAPS policy applied via GPO
$legacyPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
$legacyPolicyEnabled = Get-RegistryValueSafe -Path $legacyPolicyPath -Name 'AdmPwdEnabled'

# ---- Windows LAPS (built-in) detection ---------------------------------

# Built-in LAPS module
$builtinModule = Get-Module -ListAvailable -Name LAPS -ErrorAction SilentlyContinue
$builtinLAPSAvailable = [bool]$builtinModule

# Built-in LAPS policy
$builtinPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
$builtinPolicyPathPolicies = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'

$builtinConfigured = $false
$builtinBackupDir  = $null
$builtinPwdAgeDays = $null
$builtinComplexity = $null
$builtinEncState   = $null

foreach ($regRoot in @($builtinPolicyPath, $builtinPolicyPathPolicies)) {
    if (-not (Test-Path $regRoot)) { continue }
    $backup = Get-RegistryValueSafe -Path $regRoot -Name 'BackupDirectory'
    if ($null -ne $backup) {
        $builtinConfigured = $true
        $builtinBackupDir  = switch ($backup) {
            0 { 'Disabled' }
            1 { 'AzureAD' }
            2 { 'AD' }
            default { "Unknown ($backup)" }
        }
        $builtinPwdAgeDays = Get-RegistryValueSafe -Path $regRoot -Name 'PasswordAgeDays'
        $builtinComplexity = Get-RegistryValueSafe -Path $regRoot -Name 'PasswordComplexity'
        $builtinEncState   = Get-RegistryValueSafe -Path $regRoot -Name 'ADPasswordEncryptionEnabled'
        break
    }
}

$BR2.Raw.LAPS = @{
    LegacyInstalled   = $legacyLAPSInstalled
    LegacyPolicyEnabled = $legacyPolicyEnabled
    BuiltInAvailable  = $builtinLAPSAvailable
    BuiltInConfigured = $builtinConfigured
    BackupDirectory   = $builtinBackupDir
    PasswordAgeDays   = $builtinPwdAgeDays
    PasswordComplexity = $builtinComplexity
    EncryptionEnabled = $builtinEncState
}

# Neither LAPS configured: shared local admin risk
if (-not $legacyLAPSInstalled -and -not $builtinConfigured -and -not ($legacyPolicyEnabled -eq 1)) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LAPS-001' `
        -Category 'LAPS' `
        -Title 'No LAPS configuration detected (neither legacy LAPS nor Windows LAPS)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Static / shared local Administrator password across the estate enables PtH lateral movement from any compromised host' `
        -MITRE 'T1078.003' `
        -Evidence @{
            LegacyInstalled   = $legacyLAPSInstalled
            BuiltInConfigured = $builtinConfigured
        } `
        -Remediation 'Deploy Windows LAPS (built-in, requires April 2023 cumulative on Server 2019 / Windows 10 or newer). Configure ADPasswordEncryptionEnabled=1 so the AD-stored password is encrypted. Password age 30 days, complexity 4.' `
        -OperatorNotes ('On estates without LAPS, dump one hosts SAM via secretsdump or reg save HKLM\SAM. The NT hash of the local Administrator (RID-500) typically works on every other host - because the golden image set the password once and it never rotates. Pass-the-Hash via impacket wmiexec / psexec / smbexec to sweep. Sometimes helpful to grep Get-HotFix output or creation dates to identify imaging batch sets that likely share passwords.') `
        -References @(
            'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview',
            'https://www.harmj0y.net/blog/redteaming/local-admin-password-solution-laps/'
        )
    ))
    # Short-circuit further LAPS analysis - nothing to check
    return
}

# ---- Legacy LAPS on a Windows-LAPS-capable host -------------------------

if ($legacyLAPSInstalled -and -not $builtinConfigured) {
    if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'WindowsLAPS_Builtin' }) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LAPS-002' `
            -Category 'LAPS' `
            -Title 'Legacy LAPS in use on a host that supports Windows LAPS (built-in)' `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Legacy LAPS stores passwords in cleartext in ms-Mcs-AdmPwd; built-in LAPS adds optional AD-level encryption and better audit' `
            -MITRE 'T1555' `
            -Evidence @{
                LegacyInstalled = $true
                OSSupportsBuiltIn = $true
            } `
            -Remediation 'Migrate from legacy LAPS MSI to built-in Windows LAPS. Microsoft provides an in-place migration path - Import the LAPS module, run Update-LapsADSchema, then remove the legacy CSE.' `
            -OperatorNotes 'Even if already exploited legacy LAPS access patterns, worth flagging because the migration often introduces ACL permutations (transient window where both systems write to AD). Check if the legacy ms-Mcs-AdmPwd attribute is still readable by any principal that lost the right after migration which is a common oversight.' `
            -References @('https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-migration-from-legacy-laps')
        ))
    }
}

# ---- Built-in LAPS: encryption disabled ---------------------------------

if ($builtinConfigured -and $builtinBackupDir -eq 'AD' -and $builtinEncState -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LAPS-004' `
        -Category 'LAPS' `
        -Title 'Windows LAPS AD backup in use but password encryption not enabled' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Cleartext password in msLAPS-Password attribute - any principal with ExtendedRight on the computer object can read' `
        -MITRE 'T1555' `
        -Evidence @{
            BackupDirectory           = $builtinBackupDir
            ADPasswordEncryptionEnabled = $builtinEncState
        } `
        -Remediation 'Set ADPasswordEncryptionEnabled=1. Requires Windows Server 2016+ domain functional level. The encryption binds the password blob to a principal (usually Domain Admins), so only that principal can decrypt.' `
        -OperatorNotes 'Without encryption: Get-ADComputer -Identity <host> -Properties msLAPS-Password returns cleartext to anyone with the right ACE. With encryption: the blob is DPAPI-NG encrypted to the authorised principal SID. Operators still path-find via BloodHound for LAPS read rights on target hosts. The encrypted LAPS just narrows who the read actually helps.' `
        -References @('https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview#password-encryption')
    ))
}

# ---- Built-in LAPS: password age excessive ------------------------------

if ($builtinConfigured -and $builtinPwdAgeDays -gt 30) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LAPS-005' `
        -Category 'LAPS' `
        -Title "Windows LAPS password rotation set to $builtinPwdAgeDays days (>30 days recommended)" `
        -Severity 'Low' `
        -Exploitability 'Low' `
        -AttackPath 'Stale LAPS passwords extend the useful window of any captured local admin credential' `
        -MITRE 'T1078.003' `
        -Evidence @{ PasswordAgeDays = $builtinPwdAgeDays } `
        -Remediation 'Set PasswordAgeDays to 30 (default) or lower. Use post-authentication action "reset the password and logoff" for higher-risk tiers.' `
        -OperatorNotes 'Less about direct exploitation and more about how long a captured LAPS password remains useful. Worth noting in the writeup but not a priority finding.' `
        -References @()
    ))
}

# ---- Built-in LAPS: BackupDirectory=Disabled ----------------------------

if ($builtinConfigured -and $builtinBackupDir -eq 'Disabled') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LAPS-006' `
        -Category 'LAPS' `
        -Title 'Windows LAPS installed but BackupDirectory=Disabled (password not stored, recovery impossible)' `
        -Severity 'Medium' `
        -Exploitability 'Low' `
        -AttackPath 'Not directly exploitable but indicates half-deployed LAPS - operational risk that admins bypass the random password via reset-on-logon' `
        -MITRE 'T1078.003' `
        -Evidence @{ BackupDirectory = $builtinBackupDir } `
        -Remediation 'Set BackupDirectory=2 (AD) or 1 (Entra) so passwords are recoverable. Otherwise LAPS is just a password randomiser with no recovery path.' `
        -OperatorNotes 'Administrative pain usually causes this to get reverted to a shared password in practice. Worth flagging for the defender.' `
        -References @()
    ))
}
