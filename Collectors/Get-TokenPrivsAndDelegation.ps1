#requires -Version 5.1


$ctx = $global:BR2.Context

function Get-TokenPrivileges {
    $sig = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref int cchName);

[StructLayout(LayoutKind.Sequential)]
public struct LUID { public uint LowPart; public int HighPart; }
[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
[DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
'@
    try {
        Add-Type -MemberDefinition $sig -Name 'PrivHelper' -Namespace 'BR2' -ErrorAction SilentlyContinue
    } catch {}

    # Simpler: parse whoami /priv output - reliable, no P/Invoke fragility
    $privs = & whoami /priv /fo csv 2>$null | ConvertFrom-Csv
    return $privs
}

$tokenPrivs = Get-TokenPrivileges
$BR2.Raw.TokenPrivileges = $tokenPrivs

# The "golden privileges" - each maps to a known privesc class.
# Evaluated against the *current* user context. Rules fire if the current
# user is a non-administrator but holds a dangerous privilege.
$goldenPrivs = @{
    'SeImpersonatePrivilege'         = 'Potato family privesc (JuicyPotato/PrintSpoofer/GodPotato/SweetPotato)'
    'SeAssignPrimaryTokenPrivilege'  = 'Primary token substitution privesc'
    'SeDebugPrivilege'                = 'Open handle to any process including LSASS'
    'SeBackupPrivilege'               = 'Read SAM/SECURITY hives offline (->NT hashes, DCC2)'
    'SeRestorePrivilege'              = 'Write privileged registry paths (add admin via SAM direct write)'
    'SeTakeOwnershipPrivilege'        = 'Take ownership of any object -> DACL rewrite'
    'SeLoadDriverPrivilege'           = 'Load arbitrary drivers (BYOVD primitive)'
    'SeManageVolumePrivilege'         = 'Read raw volume - VSS shadow copy of NTDS.dit on a DC'
    'SeTcbPrivilege'                  = 'Act as part of OS - effectively SYSTEM'
    'SeCreateTokenPrivilege'          = 'Forge arbitrary access tokens'
}

$isAdmin = $ctx.Elevated
foreach ($priv in $goldenPrivs.Keys) {
    $held = $tokenPrivs | Where-Object { $_.'Privilege Name' -eq $priv }
    if ($held) {
        # Only fire if the user isn't already admin - otherwise it's expected
        if (-not $isAdmin) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID ("BR-TOK-" + $priv) `
                -Category 'TokenPrivileges' `
                -Title "Non-admin holds $priv" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath $goldenPrivs[$priv] `
                -MITRE @('T1134.001','T1078.003') `
                -Evidence @{
                    Privilege   = $priv
                    State       = $held.State
                    Description = $held.Description
                    User        = "$env:USERDOMAIN\$env:USERNAME"
                } `
                -Remediation 'Audit User Rights Assignment (secpol.msc) for the relevant privilege. Remove from any non-privileged group or service account.' `
                -OperatorNotes (switch ($priv) {
                    'SeImpersonatePrivilege'        { 'Potato family: GodPotato (2023, works on Server 2012-2022) is the current best starting point. For RPC coercion primitives, CoercedPotato. SweetPotato for Server 2019+. Requires only interactive or service login type; commonly held by IIS AppPool, MSSQL service accounts.' }
                    'SeBackupPrivilege'             { 'reg save HKLM\SAM sam.save; reg save HKLM\SECURITY security.save; reg save HKLM\SYSTEM system.save - then impacket secretsdump offline. No LSASS touched.' }
                    'SeRestorePrivilege'            { 'Combine with SeBackup to rewrite hive files. Also: reg add HKLM\...\Run for persistence without admin.' }
                    'SeDebugPrivilege'              { 'Often held by LocalSystem services. If a service runs as a user with SeDebug, impersonate or duplicate its token to access LSASS.' }
                    'SeManageVolumePrivilege'       { 'On a DC, create a VSS shadow copy and copy NTDS.dit out. DiskCryptor abuse documented by Decoder/Antonio Cocomazzi.' }
                    'SeLoadDriverPrivilege'         { 'Load a signed vulnerable driver (loldrivers.io) for kernel-mode code execution. Bypasses WDAC driver rules if the driver was signed before blocklist entry.' }
                    default                         { 'Privileged user rights assignment; verify necessary for role. See known abuse references.' }
                }) `
                -References @(
                    'https://github.com/BeichenDream/GodPotato',
                    'https://decoder.cloud/2020/05/11/from-network-service-to-system/',
                    'https://www.loldrivers.io/'
                )
            ))
        }
    }
}

if (Test-OSPrecondition -Requirements @{ DomainJoined = $true }) {
    $hasADModule = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
    if ($hasADModule) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $comp = Get-ADComputer -Identity $ctx.ComputerName -Properties `
                userAccountControl, msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, `
                servicePrincipalName, nTSecurityDescriptor -ErrorAction Stop

            $uac = [int]$comp.userAccountControl
            $isUnconstrained = ($uac -band 0x80000) -ne 0     # TRUSTED_FOR_DELEGATION
            $isProtocolTrans = ($uac -band 0x1000000) -ne 0   # TRUSTED_TO_AUTH_FOR_DELEGATION
            $kcdTo           = $comp.'msDS-AllowedToDelegateTo'
            $rbcd            = $comp.'msDS-AllowedToActOnBehalfOfOtherIdentity'

            $BR2.Raw.Delegation = @{
                UAC_TRUSTED_FOR_DELEGATION         = $isUnconstrained
                UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = $isProtocolTrans
                MsDS_AllowedToDelegateTo           = $kcdTo
                RBCD_Entries                       = if ($rbcd) { 'Present' } else { 'None' }
            }

            if ($isUnconstrained -and -not $ctx.IsDC) {
                # Unconstrained delegation on a non-DC = classic exfil-to-DC path
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-DEL-001' `
                    -Category 'Delegation' `
                    -Title 'Unconstrained delegation enabled on this non-DC computer account' `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Capture any principal TGT that authenticates to this host, incl. forced DC auth via PrinterBug/PetitPotam' `
                    -MITRE 'T1550' `
                    -Evidence @{ UAC = $uac; UAC_Flags = 'TRUSTED_FOR_DELEGATION (0x80000)' } `
                    -Remediation 'Remove TRUSTED_FOR_DELEGATION. Replace with RBCD (Resource-Based Constrained Delegation) or KCD (Kerberos Constrained Delegation) scoped to specific services. Also add sensitive accounts to Protected Users and flag as "Account is sensitive and cannot be delegated".' `
                    -OperatorNotes 'As admin on this host, Rubeus monitor (captures new TGTs). Coerce a DC auth with PrinterBug/PetitPotam/Coercer against this host so the DC machine account TGT lands in memory. Use it with Rubeus asktgs or directly via DCSync. Domain compromise.' `
                    -References @(
                        'https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/',
                        'https://github.com/GhostPack/Rubeus'
                    )
                ))
            }

            if ($rbcd) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-DEL-002' `
                    -Category 'Delegation' `
                    -Title 'RBCD entries present on this computer (msDS-AllowedToActOnBehalfOfOtherIdentity)' `
                    -Severity 'High' `
                    -Exploitability 'Medium' `
                    -AttackPath 'If the principal allowed to delegate is compromised, impersonate any user to this host via S4U2Self + S4U2Proxy' `
                    -MITRE 'T1550' `
                    -Evidence @{ RBCDConfigured = $true } `
                    -Remediation 'Review the principals in msDS-AllowedToActOnBehalfOfOtherIdentity and confirm they are intentional and necessary.' `
                    -OperatorNotes 'Rubeus s4u /user:<controlled_principal> /impersonateuser:<target> /msdsspn:<spn_on_this_host> yields a service ticket valid against this host as the target user. Works for any SPN class (CIFS, HOST, HTTP, etc.).' `
                    -References @('https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html')
                ))
            }

            if ($kcdTo -and $isProtocolTrans) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-DEL-003' `
                    -Category 'Delegation' `
                    -Title 'Constrained delegation with protocol transition (msDS-AllowedToDelegateTo + TRUSTED_TO_AUTH_FOR_DELEGATION)' `
                    -Severity 'High' `
                    -Exploitability 'Medium' `
                    -AttackPath 'S4U2Self without needing the target user credential - KCD "any" variant' `
                    -MITRE 'T1550' `
                    -Evidence @{
                        AllowedTo      = $kcdTo
                        ProtocolTrans  = $true
                    } `
                    -Remediation 'Remove TRUSTED_TO_AUTH_FOR_DELEGATION unless protocol transition is explicitly required. Constrain to the minimum set of SPNs.' `
                    -OperatorNotes 'If this host''s machine account is compromised: Rubeus s4u /self + /altservice to any SPN class in msDS-AllowedToDelegateTo, impersonating any user. Lateral movement to those specific target services.' `
                    -References @('https://posts.specterops.io/s4u2pwnage-360556c8d0f8')
                ))
            }
        } catch {
            $BR2.Skipped.Add([PSCustomObject]@{
                Collector = 'DelegationAndTokenPrivs'
                Reason    = "Could not query delegation state: $($_.Exception.Message)"
            })
        }
    }
}

if (Test-OSPrecondition -Requirements @{ DomainJoined = $true }) {
    $hasADModule = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
    if ($hasADModule) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $computerDN = (Get-ADComputer -Identity $ctx.ComputerName).DistinguishedName
            $acl = Get-Acl -Path "AD:\$computerDN" -ErrorAction Stop

            # Privileged SIDs we ignore: Domain Admins, Enterprise Admins, SYSTEM, SELF, Account Operators (expected)
            $expectedSids = @(
                'S-1-5-18',          # SYSTEM
                'S-1-5-10',          # SELF
                'S-1-5-32-544',      # BUILTIN\Administrators
                'S-1-5-32-548',      # Account Operators
                'S-1-5-32-549'       # Server Operators
            )

            # High-risk rights on a computer object
            $dangerousRights = @(
                'GenericAll',
                'GenericWrite',
                'WriteDacl',
                'WriteOwner'
            )

            $risky = @()
            foreach ($ace in $acl.Access) {
                # Skip inherited privileged entries
                try {
                    $idRef = $ace.IdentityReference
                    $sid = try { (New-Object System.Security.Principal.NTAccount($idRef)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
                    if ($sid -and ($expectedSids -contains $sid)) { continue }
                    if ($idRef -match 'Domain Admins|Enterprise Admins|BUILTIN\\Administrators') { continue }

                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right) {
                            $risky += [PSCustomObject]@{
                                Principal = $idRef
                                Rights    = $ace.ActiveDirectoryRights
                                Type      = $ace.AccessControlType
                            }
                            break
                        }
                    }
                } catch {}
            }

            $BR2.Raw.ComputerObjectACL = $risky

            if ($risky.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-ACL-001' `
                    -Category 'DelegationACL' `
                    -Title "$($risky.Count) non-privileged principal(s) hold dangerous AD rights on this computer object" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Shadow Credentials (msDS-KeyCredentialLink), RBCD self-takeover, or targeted Kerberoast via SPN write' `
                    -MITRE @('T1098','T1550') `
                    -Evidence @{
                        PrincipalCount = $risky.Count
                        Principals     = @($risky | Select-Object -First 10)
                    } `
                    -Remediation 'Audit and remove unnecessary write ACLs on the computer object. Use LAPS and Tiered Admin model.' `
                    -OperatorNotes 'Three primary attacks when you control a principal with GenericAll/GenericWrite: (1) Shadow Credentials - Whisker.exe add /target:<this_host>$ - write msDS-KeyCredentialLink, then PKINIT as the computer. (2) RBCD self-takeover - Set-DomainObject -Set @{"msds-allowedtoactonbehalfofotheridentity"=<SD>} then Rubeus s4u. (3) Targeted Kerberoast - add an SPN, request a service ticket, crack offline. Shadow Credentials is usually the cleanest.' `
                    -References @(
                        'https://github.com/eladshamir/Whisker',
                        'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'
                    )
                ))
            }
        } catch {
            $BR2.Skipped.Add([PSCustomObject]@{
                Collector = 'ComputerObjectACL'
                Reason    = "Could not read ACL: $($_.Exception.Message)"
            })
        }
    }
}

if ($ctx.Elevated) {
    $exclPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    if (Test-Path $exclPath) {
        $pathExcl    = @()
        $processExcl = @()
        $extExcl     = @()
        try {
            $pathExcl    = @((Get-Item -Path "$exclPath\Paths"      -ErrorAction SilentlyContinue).Property)
            $processExcl = @((Get-Item -Path "$exclPath\Processes"  -ErrorAction SilentlyContinue).Property)
            $extExcl     = @((Get-Item -Path "$exclPath\Extensions" -ErrorAction SilentlyContinue).Property)
        } catch {}

        $BR2.Raw.DefenderExclusions = @{
            Paths      = $pathExcl
            Processes  = $processExcl
            Extensions = $extExcl
        }

        $total = $pathExcl.Count + $processExcl.Count + $extExcl.Count
        if ($total -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-DEF-001' `
                -Category 'ExecutionControl' `
                -Title "Defender has $total exclusions configured (paths: $($pathExcl.Count), processes: $($processExcl.Count), extensions: $($extExcl.Count))" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Stage and execute tooling from excluded paths or as excluded process names to evade Defender' `
                -MITRE 'T1562.001' `
                -Evidence @{
                    PathExclusions      = $pathExcl
                    ProcessExclusions   = $processExcl
                    ExtensionExclusions = $extExcl
                } `
                -Remediation 'Review each exclusion against business justification. Avoid broad path exclusions (C:\, user-writable directories). Common offender: C:\Windows\Temp or user profile folders added for SCCM / legacy line-of-business apps.' `
                -OperatorNotes 'Exclusions are visible to Defender telemetry but hidden from Get-MpPreference for non-admins. As SYSTEM/admin: reg query HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions. If a user-writable path is excluded, drop tooling there and AMSI still scans PowerShell but on-access disk scanning is off. Process exclusions (e.g. powershell.exe if admins were lazy) mean all behaviour from that process is unscanned.' `
                -References @('https://github.com/rad9800/bootlicker')
            ))
        }
    }
}
