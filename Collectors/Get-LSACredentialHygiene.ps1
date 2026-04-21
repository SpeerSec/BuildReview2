#requires -Version 5.1

$ctx = $global:BR2.Context

$wdigestPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$useLogonCred = Get-RegistryValueSafe -Path $wdigestPath -Name 'UseLogonCredential'

$BR2.Raw.WDigest = @{
    UseLogonCredential = $useLogonCred
    Path               = $wdigestPath
}

# On Windows 7 / Server 2008 R2, WDigest defaults to caching even without the
# flag set - that's a separate finding because the attack path differs.
if ($ctx.BuildNumber -lt 9600) {
    # Pre-2012 R2: WDigest is on by default regardless of UseLogonCredential
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-001-Legacy' `
        -Category 'LSA' `
        -Title 'WDigest caches plaintext credentials by default on this OS version' `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'WDigest plaintext extraction from LSASS (default behaviour pre-2012 R2)' `
        -MITRE 'T1003.001' `
        -Evidence @{
            FriendlyVersion = $ctx.FriendlyVersion
            Note            = 'UseLogonCredential flag is not required on this OS; WDigest caches by default.'
        } `
        -Remediation 'Install KB2871997 (March 2014) and set UseLogonCredential=0, or migrate. Best answer: migrate - this host is already past EOL.' `
        -OperatorNotes 'mimikatz sekurlsa::logonpasswords returns plaintext by default on these builds. No reg flip required, no waiting for new logons.' `
        -References @('https://support.microsoft.com/en-us/topic/kb2871997')
    ))
} elseif ($useLogonCred -eq 1) {
    # 2012 R2 and later: flag is required for caching
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-001' `
        -Category 'LSA' `
        -Title 'WDigest plaintext credential caching is enabled' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'WDigest plaintext extraction from LSASS' `
        -MITRE 'T1003.001' `
        -Evidence @{
            UseLogonCredential = $useLogonCred
            Path               = $wdigestPath
        } `
        -Remediation 'Set UseLogonCredential to 0 (DWORD). Default since Windows 8.1 / Server 2012 R2.' `
        -OperatorNotes 'Once set, the flag does not retroactively cache credentials for already-logged-on users. You must wait for a new logon or coerce one (e.g. Run-As, scheduled task). Dump LSASS with nanodump / MiniDumpWriteDump via BOF after.' `
        -References @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/credentials-protection-and-management')
    ))
}

if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'RunAsPPL' }) {
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $runAsPPL     = Get-RegistryValueSafe -Path $lsaPath -Name 'RunAsPPL'
    $runAsPPLBoot = Get-RegistryValueSafe -Path $lsaPath -Name 'RunAsPPLBoot'

    $BR2.Raw.LSAProtection = @{
        RunAsPPL     = $runAsPPL
        RunAsPPLBoot = $runAsPPLBoot
    }

    if (-not $runAsPPL -or $runAsPPL -eq 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LSA-002' `
            -Category 'LSA' `
            -Title 'LSASS is not running as a Protected Process Light (PPL)' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'LSASS memory dump for credential extraction' `
            -MITRE 'T1003.001' `
            -Evidence @{
                RunAsPPL     = $runAsPPL
                RunAsPPLBoot = $runAsPPLBoot
            } `
            -Remediation 'Set RunAsPPL=1. Enable RunAsPPLBoot=1 to UEFI-lock the flag so it survives boot-time tampering on supported hardware.' `
            -OperatorNotes 'Without PPL, LSASS can be dumped with any admin process. PPL bypasses exist (signed vulnerable drivers via BYOVD, Mimikatz !+ driver) but creates a decent amount of noise.' `
            -References @(
                'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection',
                'https://itm4n.github.io/lsass-runasppl/'
            )
        ))
    }

    # PPLWithSigner is a stronger mode only available on Win11 22H2+ / Server 2025
    if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'PPLWithSigner' }) {
        if ($runAsPPL -ne 2) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-LSA-002b' `
                -Category 'LSA' `
                -Title 'LSA Protection is not in PPLWithSigner mode on a capable OS' `
                -Severity 'Medium' `
                -Exploitability 'Medium' `
                -AttackPath 'Weaker LSA protection allows a broader range of signer certificates to open LSASS' `
                -MITRE 'T1003.001' `
                -Evidence @{
                    RunAsPPL      = $runAsPPL
                    FriendlyVersion = $ctx.FriendlyVersion
                    Note          = 'RunAsPPL=2 restricts permitted signers beyond the default set.'
                } `
                -Remediation 'Set RunAsPPL=2 on Windows 11 22H2+ or Server 2025 to enforce PPLWithSigner.' `
                -OperatorNotes 'With RunAsPPL=1, any signed binary meeting the default PPL signer requirements can open LSASS. RunAsPPL=2 narrows this further. A handful of real-world BYOVD drivers will no longer pass.' `
                -References @('https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection')
            ))
        }
    }
}

if (Test-OSPrecondition -Requirements @{ RequiresCapability = 'CredentialGuard' }) {
    $cgFlags = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags'
    $BR2.Raw.CredentialGuard = @{ LsaCfgFlags = $cgFlags }

    # Also check VBS is actually running (Credential Guard is useless without it)
    $cgRunning = ($ctx.VBSEnabled -eq $true)

    if (-not $cgFlags -or $cgFlags -eq 0 -or -not $cgRunning) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LSA-003' `
            -Category 'LSA' `
            -Title 'Credential Guard is not enabled on a Credential-Guard-capable host' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'NTLM hash and TGT extraction from LSASS' `
            -MITRE 'T1003.001' `
            -Evidence @{
                LsaCfgFlags     = $cgFlags
                VBSRunning      = $cgRunning
                Edition         = $ctx.Edition
                FriendlyVersion = $ctx.FriendlyVersion
            } `
            -Remediation 'Enable VBS + Credential Guard via Group Policy. Requires Secure Boot and TPM 2.0. Default on in Windows 11 22H2 Enterprise with supported hardware.' `
            -OperatorNotes 'With Credential Guard on, NTLM hashes and TGT session keys are isolated in LSAIso (an isolated user-mode process in VTL1 - Virtual Trust Level 1). Mimikatz returns blanks. Workarounds: capture creds before LSAIso (keylogger, SSP hook), phishing a fresh prompt, or downgrade via RDP without Restricted Admin to a host without CG.' `
            -References @(
                'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/',
                'https://itm4n.github.io/credential-guard-bypasses/'
            )
        ))
    }
}

if (Test-OSPrecondition -Requirements @{ DomainJoined = $true }) {
    $cachedCount = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
    $cachedCountInt = 10
    if ($cachedCount) { [int]::TryParse($cachedCount, [ref]$cachedCountInt) | Out-Null }

    $BR2.Raw.CachedLogons = $cachedCountInt

    # Laptops reasonably need 1-4; servers should be 0; workstations 0-4
    $threshold = if ($ctx.IsServer) { 0 } else { 4 }
    if ($cachedCountInt -gt $threshold) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LSA-005' `
            -Category 'LSA' `
            -Title "CachedLogonsCount is $cachedCountInt (threshold $threshold for $($ctx.HostRole))" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Offline DCC2 hash cracking after SAM/SECURITY hive extraction' `
            -MITRE 'T1003.005' `
            -Evidence @{
                CachedLogonsCount = $cachedCountInt
                HostRole          = $ctx.HostRole
                RecommendedMax    = $threshold
            } `
            -Remediation "Set CachedLogonsCount to $threshold or lower for a $($ctx.HostRole)." `
            -OperatorNotes 'Cached creds stored as DCC2 (PBKDF2-HMAC-SHA1, 10,240 iterations). Slow to crack but feasible with a weak password. reg save HKLM\SECURITY / SYSTEM, then impacket secretsdump or mimikatz lsadump::cache. Works offline.' `
            -References @('https://openwall.info/wiki/john/MSCash2')
        ))
    }
}

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$defaultPw   = Get-RegistryValueSafe -Path $winlogon -Name 'DefaultPassword'
$defaultUser = Get-RegistryValueSafe -Path $winlogon -Name 'DefaultUserName'
$defaultDom  = Get-RegistryValueSafe -Path $winlogon -Name 'DefaultDomainName'

if ($defaultPw) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-008' `
        -Category 'LSA' `
        -Title 'Plaintext autologon credentials present in registry' `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Direct credential recovery from HKLM\...\Winlogon' `
        -MITRE 'T1552.002' `
        -Evidence @{
            DefaultUserName    = $defaultUser
            DefaultDomainName  = $defaultDom
            DefaultPasswordSet = $true
            Path               = $winlogon
        } `
        -Remediation 'Configure autologon via Sysinternals autologon.exe which stores the password in an LSA secret, or eliminate autologon.' `
        -OperatorNotes "Any authenticated user on this host can read this value. Confirmed credential for $defaultDom\$defaultUser. Try against SMB, RDP, Entra ID. Reuse is common." `
        -References @('https://attack.mitre.org/techniques/T1552/002/')
    ))
}

$credPaths = @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Credentials'),
    (Join-Path $env:APPDATA      'Microsoft\Credentials'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\Vault')
)
$credFiles = foreach ($p in $credPaths) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue }
}
$credFiles = @($credFiles)

if ($credFiles.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-010' `
        -Category 'LSA' `
        -Title "$($credFiles.Count) stored credentials in Credential Manager / Vault" `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'DPAPI credential recovery from current user context' `
        -MITRE 'T1555.004' `
        -Evidence @{
            FileCount = $credFiles.Count
            Paths     = $credFiles | Select-Object -First 10 -ExpandProperty FullName
        } `
        -Remediation 'Audit stored credentials; remove unused RDP, SMB and web credentials.' `
        -OperatorNotes "As the owning user: SharpDPAPI credentials. From SYSTEM: need the user's DPAPI master key (HKCU\SOFTWARE\Microsoft\Protect or %APPDATA%\Microsoft\Protect\<SID>). Watch for TERMSRV/* (cached RDP) and MicrosoftOffice16_Data (cached O365)." `
        -References @('https://github.com/GhostPack/SharpDPAPI')
    ))
}

if (Test-OSPrecondition -Requirements @{ DC = $false }) {
    $lsaSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $latfp = Get-RegistryValueSafe -Path $lsaSys -Name 'LocalAccountTokenFilterPolicy'

    if ($latfp -eq 1) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LAT-003' `
            -Category 'LateralMovement' `
            -Title 'LocalAccountTokenFilterPolicy=1 permits remote connections with full local admin token' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Pass-the-Hash with non-RID-500 local admin accounts' `
            -MITRE @('T1550.002','T1078.003') `
            -Evidence @{ LocalAccountTokenFilterPolicy = 1; Path = $lsaSys } `
            -Remediation 'Set LocalAccountTokenFilterPolicy=0. Prefer LAPS-managed local admin per host.' `
            -OperatorNotes 'With LATFP=1 any local admin (not just RID-500) works for remote admin over SMB/WMI with its NT hash. Combined with shared local admin passwords across the estate this is one of the fastest lateral-movement methods.' `
            -References @(
                'https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction',
                'https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/'
            )
        ))
    }
}
