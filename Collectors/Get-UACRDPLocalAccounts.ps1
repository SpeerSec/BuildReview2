#requires -Version 5.1


$ctx = $global:BR2.Context

# ------------------------------------------------------------------------
# UAC STATE
# ------------------------------------------------------------------------

$uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

$enableLUA           = Get-RegistryValueSafe -Path $uacKey -Name 'EnableLUA'
$consentAdmin        = Get-RegistryValueSafe -Path $uacKey -Name 'ConsentPromptBehaviorAdmin'
$filterAdminToken    = Get-RegistryValueSafe -Path $uacKey -Name 'FilterAdministratorToken'
$promptSecureDesktop = Get-RegistryValueSafe -Path $uacKey -Name 'PromptOnSecureDesktop'
$localAccountTokenFP = Get-RegistryValueSafe -Path $uacKey -Name 'LocalAccountTokenFilterPolicy'

$BR2.Raw.UAC = @{
    EnableLUA                   = $enableLUA
    ConsentPromptBehaviorAdmin  = $consentAdmin
    FilterAdministratorToken    = $filterAdminToken
    PromptOnSecureDesktop       = $promptSecureDesktop
    LocalAccountTokenFilterPolicy = $localAccountTokenFP
}

if ($enableLUA -eq 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-UAC-001' `
        -Category 'UAC' `
        -Title 'UAC is fully disabled (EnableLUA=0)' `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Every admin process runs with full token - no split-token isolation, no elevation prompts' `
        -MITRE 'T1548.002' `
        -Evidence @{ EnableLUA = 0 } `
        -Remediation 'Set EnableLUA=1 and reboot. Disabling UAC is almost never a legitimate enterprise configuration.' `
        -OperatorNotes 'With EnableLUA=0, any admin-context code execution has the full admin token. No bypass needed. Combined with LocalAccountTokenFilterPolicy=1, remote local-admin accounts land with full rights over SMB/WMI.' `
        -References @('https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control/')
    ))
}

if ($consentAdmin -eq 0 -and $enableLUA -ne 0) {
    # ConsentPromptBehaviorAdmin=0: no prompt for admins, auto-elevate
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-UAC-002' `
        -Category 'UAC' `
        -Title 'UAC admin prompt set to ElevateWithoutPrompting (ConsentPromptBehaviorAdmin=0)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Any operation requiring elevation auto-elevates without user interaction - no user awareness of privilege escalation' `
        -MITRE 'T1548.002' `
        -Evidence @{ ConsentPromptBehaviorAdmin = 0 } `
        -Remediation 'Set ConsentPromptBehaviorAdmin=2 (secure desktop consent) or 5 (default - consent for non-Windows binaries).' `
        -OperatorNotes 'Tool requiring admin rights elevates silently, e.g. UAC bypass techniques become unnecessary because elevation is automatic.' `
        -References @()
    ))
}

if ($filterAdminToken -eq 0 -and $enableLUA -eq 1) {
    # FilterAdministratorToken=0: RID-500 Administrator bypasses UAC entirely
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-UAC-003' `
        -Category 'UAC' `
        -Title 'RID-500 Administrator account bypasses UAC (FilterAdministratorToken=0)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Built-in Administrator (RID-500) remote logon returns unfiltered admin token over SMB/WMI' `
        -MITRE 'T1078.003' `
        -Evidence @{ FilterAdministratorToken = $filterAdminToken } `
        -Remediation 'Set FilterAdministratorToken=1 (default). Disable or rename the built-in Administrator account where policy permits.' `
        -OperatorNotes 'With the built-in Administrator NT hash, pass-the-hash to this host works even without LocalAccountTokenFilterPolicy=1 as RID-500 bypasses UAC natively. Combined with a shared RID-500 password (pre-LAPS), this is tone of the fastest lateral movement methods on Windows.' `
        -References @()
    ))
}

# ------------------------------------------------------------------------
# RDP POSTURE
# ------------------------------------------------------------------------

# Feature existence - Terminal Services svc must exist
$tsSvc = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue

if ($tsSvc) {
    # RDP enabled state - HKLM\...\Terminal Server\fDenyTSConnections = 0 means enabled
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpDisabled = Get-RegistryValueSafe -Path $rdpKey -Name 'fDenyTSConnections'
    $rdpEnabled = ($rdpDisabled -eq 0)

    $BR2.Raw.RDP = @{
        ServicePresent = $true
        ServiceState   = $tsSvc.Status
        fDenyTSConnections = $rdpDisabled
        RDPEnabled     = $rdpEnabled
    }

    if ($rdpEnabled) {
        # NLA (Network Level Authentication) enforcement
        $nlaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $userAuth = Get-RegistryValueSafe -Path $nlaKey -Name 'UserAuthentication'
        $secLayer = Get-RegistryValueSafe -Path $nlaKey -Name 'SecurityLayer'
        $minEncLevel = Get-RegistryValueSafe -Path $nlaKey -Name 'MinEncryptionLevel'

        $BR2.Raw.RDP.UserAuthentication = $userAuth
        $BR2.Raw.RDP.SecurityLayer      = $secLayer
        $BR2.Raw.RDP.MinEncryptionLevel = $minEncLevel

        if ($userAuth -ne 1) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-RDP-001' `
                -Category 'RemoteAccess' `
                -Title 'RDP Network Level Authentication not enforced (UserAuthentication=0)' `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Pre-authentication RDP vulnerabilities (BlueKeep class), no credential verification before allocating session resources' `
                -MITRE 'T1021.001' `
                -Evidence @{ UserAuthentication = $userAuth } `
                -Remediation 'Set UserAuthentication=1 to require NLA. Windows 10 1607+ and Server 2012 R2+ support this by default.' `
                -OperatorNotes 'Without NLA, the host accepts pre-auth connections to the logon surface with BlueKeep (CVE-2019-0708) the archetypal example. Also exposes RDP to brute force and password spray. With NLA on, all those attacks still happen but they get auth-pipelined.' `
                -References @()
            ))
        }

        # Restricted Admin mode - prevents credential landing on target host
        $restrictedAdmin = Get-RegistryValueSafe -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'DisableRestrictedAdmin'
        if ($restrictedAdmin -eq 1) {
            # 1 = disabled (i.e. PtH via RDP not allowed from this host)
            # 0 or missing = Restricted Admin allowed - operator can pass-the-hash via RDP
            # Nuance: finding depends on perspective. Target-side we want DisableRestrictedAdmin=0 for defense,
            # source-side operator want it enabled. The registry key controls outgoing not incoming.
            # Actually: DisableRestrictedAdmin on client controls client-side initiation.
            # For server protection, it's "DisableRestrictedAdmin" at same path.
            # Keep as informational
            $BR2.Raw.RDP.DisableRestrictedAdmin = $restrictedAdmin
        }

        # Shadow session without consent
        $shadowMode = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'Shadow'
        if ($shadowMode -eq 2 -or $shadowMode -eq 4) {
            # 2 = full control without user's permission, 4 = view without permission
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-RDP-006' `
                -Category 'RemoteAccess' `
                -Title "RDP session shadowing permitted without user consent (Shadow=$shadowMode)" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Admin silently takes over active RDP session - credential observation, active session hijack' `
                -MITRE 'T1021.001' `
                -Evidence @{ Shadow = $shadowMode } `
                -Remediation 'Set Shadow=1 (view with permission) or 3 (full control with permission). User consent should be required for session shadow unless specific operational need.' `
                -OperatorNotes 'As admin: mstsc /shadow:<sessionid> /control /noConsentPrompt. Silent takeover of a logged-in admin session. Particularly devastating on jump hosts.' `
                -References @()
            ))
        }
    }
}

# ------------------------------------------------------------------------
# LOCAL ACCOUNTS AND GROUPS
# ------------------------------------------------------------------------

$localAdmins = @()
try {
    $localAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
} catch {
    # Fallback to net.exe
    $netOut = & net.exe localgroup Administrators 2>$null
    if ($netOut) {
        $localAdmins = $netOut | Select-Object -Skip 6 | Where-Object { $_ -and $_ -ne 'The command completed successfully.' } |
                       ForEach-Object { [PSCustomObject]@{ Name = $_.Trim() } }
    }
}

$BR2.Raw.LocalAdmins = @($localAdmins | Select-Object -ExpandProperty Name)

# Flag non-standard admin memberships
foreach ($member in $localAdmins) {
    $name = $member.Name
    # Standard: BUILTIN Administrator (RID-500), Domain Admins, local SYSTEM
    if ($name -match '\\Administrator$' -or $name -match 'Domain Admins$' -or $name -match 'Enterprise Admins$' -or $name -match '\\SYSTEM$') { continue }
    # Well-known accepted groups
    if ($name -match 'Organization Management|M365 Admin') { continue }

    # Look for "user" type (not group) memberships - those are less common / flaggable
    $type = try { "$($member.ObjectClass)" } catch { 'Unknown' }
    if ($type -eq 'User' -or $type -eq 'Group') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LOC-001' `
            -Category 'LocalAccounts' `
            -Title "Non-standard principal in local Administrators: $name" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Broader local admin surface than necessary - compromise of this principal yields host admin' `
            -MITRE @('T1078.003','T1136.001') `
            -Evidence @{
                Member = $name
                Type   = $type
            } `
            -Remediation 'Audit local admin membership against tiered admin model. Local admin should be limited to LAPS-rotated built-in account + domain-level groups approved per tier.' `
            -OperatorNotes 'Path-find via BloodHound to identify the members of any flagged group and what their other reachable admin rights look like. Orphaned user accounts (left over from staff leavers) are common.' `
            -References @()
        ))
    }
}

# Privileged legacy groups - flag any non-empty membership
$legacyGroups = @{
    'Backup Operators'  = 'SeBackupPrivilege + SeRestorePrivilege = read/write SAM + SECURITY hives offline'
    'Server Operators'  = 'Can install services, shutdown DCs, manipulate file shares on DCs'
    'Account Operators' = 'Create/modify non-privileged accounts; has write on most OU objects'
    'Print Operators'   = 'Load printer drivers = kernel code execution'
}

foreach ($groupName in $legacyGroups.Keys) {
    try {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
        $nonBuiltinMembers = $members | Where-Object { "$($_.Name)" -notmatch 'NT AUTHORITY|BUILTIN\\' }
        if ($nonBuiltinMembers.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID ("BR-LOC-002-" + ($groupName -replace '\s')) `
                -Category 'LocalAccounts' `
                -Title "$groupName has non-default membership ($($nonBuiltinMembers.Count) principals)" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath $legacyGroups[$groupName] `
                -MITRE 'T1078.002' `
                -Evidence @{
                    Group   = $groupName
                    Members = @($nonBuiltinMembers.Name)
                } `
                -Remediation "Remove non-essential members from $groupName. These legacy operator groups carry privileges equivalent to admin in most cases but are frequently overlooked." `
                -OperatorNotes (switch ($groupName) {
                    'Backup Operators'  { 'reg save HKLM\SAM, HKLM\SECURITY, HKLM\SYSTEM via SeBackupPrivilege; impacket secretsdump offline for NT hashes + cached DCC2.' }
                    'Server Operators'  { 'Create new service pointing at payload as LocalSystem; sc.exe create / start. On DCs this is effectively SYSTEM on the DC.' }
                    'Account Operators' { 'Create a new user and add to Administrators; or modify target user attributes (shadow credentials, SPN for roast).' }
                    'Print Operators'   { 'Load a malicious driver via spool service - kernel code exec. Particularly dangerous on print servers.' }
                }) `
                -References @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory')
            ))
        }
    } catch {}
}

# Guest account state
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LOC-007' `
            -Category 'LocalAccounts' `
            -Title 'Guest account is enabled' `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Null/guest SMB access, anonymous enumeration of local resources' `
            -MITRE 'T1078' `
            -Evidence @{ GuestEnabled = $true } `
            -Remediation 'Disable the Guest account. Default-disabled since Windows XP SP2 but sometimes re-enabled for specific legacy scenarios.' `
            -OperatorNotes 'Occasionally re-enabled on kiosks, shared-display systems, or forgotten from lab builds. If enabled, anonymous enumeration via RPC now a viable path.' `
            -References @()
        ))
    }
} catch {}

# Local accounts with password never expires
try {
    $neverExpire = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and $_.PasswordNeverExpires }
    # Exclude RID-500 built-in Administrator (common by design)
    $neverExpire = @($neverExpire | Where-Object { $_.SID.Value -notmatch 'S-1-5-21-.*-500$' })
    if ($neverExpire.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-LOC-006' `
            -Category 'LocalAccounts' `
            -Title "$($neverExpire.Count) enabled local account(s) with PasswordNeverExpires (excluding built-in Administrator)" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Stale credentials that never rotate - high reuse across estate, static hash targets for PtH' `
            -MITRE 'T1078.003' `
            -Evidence @{
                Accounts = @($neverExpire.Name)
            } `
            -Remediation 'Disable these accounts or rotate passwords regularly. Prefer LAPS for any locally-privileged account.' `
            -OperatorNotes 'These are usually vendor service accounts or legacy "utility" accounts. NT hashes extracted once remain valid indefinitely. High PtH reuse value.' `
            -References @()
        ))
    }
} catch {}
