#requires -Version 5.1


$ctx = $global:BR2.Context

# WinRM (Windows Remote Management)
$winrmSvc = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
    # Pre-flight: WSMan: provider access probe. If the listener is not
    # configured, subsequent WSMan: reads or winrm.cmd calls trigger the
    # interactive "enable WinRM" prompt.
    $wsmanReady = $false
    try {
        $null = Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction Stop
        $wsmanReady = $true
    } catch {}

    $BR2.Raw.WinRM = @{
        ServiceState = "$($winrmSvc.Status)"
        WSManReady   = $wsmanReady
    }

    if (-not $wsmanReady) {
        $BR2.Skipped.Add([PSCustomObject]@{
            Collector = 'RemoteAccessServices'
            Check     = 'WinRM'
            Reason    = 'WinRM service running but listeners not configured - skipping deeper checks to avoid enable-prompt.'
        })
    }
    else {
    try {
        $listeners = winrm enumerate winrm/config/Listener 2>$null
        $hasHttp = [bool]($listeners | Select-String -Pattern 'Transport = HTTP\b')
        $hasHttps = [bool]($listeners | Select-String -Pattern 'Transport = HTTPS')
        $BR2.Raw.WinRM.HasHttp  = $hasHttp
        $BR2.Raw.WinRM.HasHttps = $hasHttps

        # HTTP listener present without HTTPS = weakness
        if ($hasHttp -and -not $hasHttps) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-WINRM-001' `
                -Category 'RemoteAccess' `
                -Title 'WinRM listening on HTTP only (no HTTPS listener)' `
                -Severity 'Medium' `
                -Exploitability 'Medium' `
                -AttackPath 'WinRM HTTP accepts NTLM - relay target for coerced machine account auth' `
                -MITRE @('T1021.006','T1557.001') `
                -Evidence @{ HasHttp = $true; HasHttps = $false } `
                -Remediation 'Configure an HTTPS listener (winrm quickconfig -transport:https) with a valid cert. Disable the HTTP listener after migration.' `
                -OperatorNotes 'HTTP WinRM uses Message-level encryption via NTLM/Kerberos, not confidentiality broken, but the NTLM auth surface is a relay-target. ntlmrelayx -t http://target:5985/wsman --no-http-server.' `
                -References @()
            ))
        }
    } catch {}

    # Service config values
    $allowUnencrypted = (Get-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -ErrorAction SilentlyContinue).Value
    $basicAuthServer  = (Get-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -ErrorAction SilentlyContinue).Value
    $basicAuthClient  = (Get-Item -Path 'WSMan:\localhost\Client\Auth\Basic' -ErrorAction SilentlyContinue).Value
    $trustedHosts     = (Get-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction SilentlyContinue).Value

    $BR2.Raw.WinRM.AllowUnencrypted = $allowUnencrypted
    $BR2.Raw.WinRM.BasicAuthServer  = $basicAuthServer
    $BR2.Raw.WinRM.BasicAuthClient  = $basicAuthClient
    $BR2.Raw.WinRM.TrustedHosts     = $trustedHosts

    if ($allowUnencrypted -eq 'true') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINRM-002' `
            -Category 'RemoteAccess' `
            -Title 'WinRM AllowUnencrypted=true on server config' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Unencrypted WinRM traffic - credentials in-path readable via MITM' `
            -MITRE 'T1040' `
            -Evidence @{ AllowUnencrypted = 'true' } `
            -Remediation 'winrm set winrm/config/service @{AllowUnencrypted="false"}. Enforce HTTPS listener.' `
            -OperatorNotes 'AllowUnencrypted + Basic auth = plaintext password in-path. Packet capture on any intermediate host recovers credentials. Rare outside lab setups but sometimes found.' `
            -References @()
        ))
    }

    if ($basicAuthServer -eq 'true') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINRM-003' `
            -Category 'RemoteAccess' `
            -Title 'WinRM server accepts Basic authentication' `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'Basic auth sends base64 credentials - if also AllowUnencrypted=true, plaintext in-path' `
            -MITRE 'T1078' `
            -Evidence @{ BasicAuthServer = 'true' } `
            -Remediation 'winrm set winrm/config/service/auth @{Basic="false"}. Default to Kerberos + NTLM only.' `
            -OperatorNotes 'Basic auth enables simple credential spray tooling. nxc winrm with -u <user> -p <password>. Combined with default password policies, spray surface is high.' `
            -References @()
        ))
    }

    if ($trustedHosts -and $trustedHosts -eq '*') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINRM-004' `
            -Category 'RemoteAccess' `
            -Title 'WinRM client TrustedHosts=* (accepts any host)' `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Host will auth to any other WinRM endpoint without cert validation - MITM risk when operator runs Enter-PSSession to attacker-controlled name' `
            -MITRE 'T1557' `
            -Evidence @{ TrustedHosts = '*' } `
            -Remediation 'Set TrustedHosts to a specific management range or fully-qualified list.' `
            -OperatorNotes 'Low-probability attack but worth noting. Host is client-side weak; if this is a jump host, administrator sessions could be redirected.' `
            -References @()
        ))
    }
    }  # end else (wsmanReady)
}

# Remote Registry
$remoteReg = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
if ($remoteReg -and $remoteReg.StartType -ne 'Disabled') {
    $BR2.Raw.RemoteRegistry = @{
        Status    = "$($remoteReg.Status)"
        StartType = "$($remoteReg.StartType)"
    }

    if ($remoteReg.Status -eq 'Running') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-REMREG-001' `
            -Category 'RemoteAccess' `
            -Title 'Remote Registry service running' `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'Remote registry read enables enumeration of host state (installed software, users, services) from domain context without admin' `
            -MITRE 'T1012' `
            -Evidence @{ Status = 'Running' } `
            -Remediation 'Set Remote Registry service to Disabled / Manual unless specifically needed (e.g. monitoring tools).' `
            -OperatorNotes 'From a domain user context: reg query \\target\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion returns version info. Also used by SecretsDump -just-dc-ntlm for remote SAM/SECURITY hive read when caller has admin. Not a privesc but a reconnaissance enabler.' `
            -References @()
        ))
    }
}

# OpenSSH Server for Windows
$sshdSvc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
if ($sshdSvc) {
    $BR2.Raw.OpenSSHServer = @{
        Status    = "$($sshdSvc.Status)"
        StartType = "$($sshdSvc.StartType)"
    }

    if ($sshdSvc.Status -eq 'Running') {
        # Read sshd_config for key settings
        $sshdConfig = "$env:ProgramData\ssh\sshd_config"
        if (Test-Path $sshdConfig) {
            $cfg = Get-Content $sshdConfig -Raw -ErrorAction SilentlyContinue
            $permitRoot     = if ($cfg -match '(?im)^\s*PermitRootLogin\s+(\w+)') { $Matches[1] } else { 'default' }
            $passwordAuth   = if ($cfg -match '(?im)^\s*PasswordAuthentication\s+(\w+)') { $Matches[1] } else { 'default' }
            $pubkeyAuth     = if ($cfg -match '(?im)^\s*PubkeyAuthentication\s+(\w+)') { $Matches[1] } else { 'default' }

            $BR2.Raw.OpenSSHServer.PermitRootLogin         = $permitRoot
            $BR2.Raw.OpenSSHServer.PasswordAuthentication  = $passwordAuth

            if ($passwordAuth -match 'yes') {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-SSH-001' `
                    -Category 'RemoteAccess' `
                    -Title 'OpenSSH server allows password authentication' `
                    -Severity 'Medium' `
                    -Exploitability 'High' `
                    -AttackPath 'SSH password spray - domain creds reuse against Windows SSH, less logged than SMB/WinRM by default' `
                    -MITRE 'T1110.003' `
                    -Evidence @{ PasswordAuthentication = $passwordAuth } `
                    -Remediation 'Set PasswordAuthentication no in sshd_config. Require public-key or GSSAPI (Kerberos).' `
                    -OperatorNotes 'OpenSSH for Windows accepts domain credentials by default, so a domain user brute/spray lands user context on the host. Less intrusively logged than other protocols because sshd logs go to Application event log under OpenSSH/Operational which is often not forwarded. Hydra, medusa, msf auxiliary/scanner/ssh/ssh_login.' `
                    -References @('https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration')
                ))
            }
        }
    }
}

# WebDAV (WebClient service)
$webClient = Get-Service -Name 'WebClient' -ErrorAction SilentlyContinue
if ($webClient) {
    $BR2.Raw.WebClient = @{
        Status    = "$($webClient.Status)"
        StartType = "$($webClient.StartType)"
    }

    # If WebClient is running or manual, user can trigger outbound WebDAV auth
    if ($webClient.Status -eq 'Running' -or $webClient.StartType -in 'Manual','Automatic') {
        # Manual + service auto-start when referenced = full NTLM authentication trigger path
        $sev = if ($webClient.Status -eq 'Running') { 'High' } else { 'Medium' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WEBDAV-001' `
            -Category 'RemoteAccess' `
            -Title "WebClient (WebDAV) service in state '$($webClient.Status)' (StartType: $($webClient.StartType))" `
            -Severity $sev `
            -Exploitability 'High' `
            -AttackPath 'WebDAV coercion - trigger outbound HTTP auth from the machine account via \\target@SSL\path or Manual Trigger Start (SearchConnector-ms etc)' `
            -MITRE @('T1187','T1557.001') `
            -Evidence @{
                Status    = "$($webClient.Status)"
                StartType = "$($webClient.StartType)"
            } `
            -Remediation 'Disable WebClient service if no business need. Or block outbound to untrusted hosts via WFP/firewall.' `
            -OperatorNotes 'Primary modern relay primitive for non-DC hosts when Coercer/PetitPotam blocked. File explorer / searchConnector-ms / schtasks referring \\attacker@SSL\share will auto-start WebClient and send NTLM over HTTP. Relay to LDAP for RBCD self-takeover. Works even with SMB signing enforced because it is HTTP not SMB.' `
            -References @(
                'https://github.com/Hackndo/WebclientServiceScanner',
                'https://posts.specterops.io/the-webdav-ticket-granting-service-trick-4b55d97c66e9'
            )
        ))
    }
}

# ---- CredSSP - delegation of credentials ------------------------------

# CredSSP: enables credential delegation to remote hosts. Used for RDP
# with remote credential access, and sometimes WinRM. Configured
# insecurely it allows delegating Plaintext credentials via Group Policy.
# CVE-2018-0886 was the classic CredSSP RCE.

$credSSPClient = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
if (Test-Path $credSSPClient) {
    $allowFresh = Get-RegistryValueSafe -Path $credSSPClient -Name 'AllowFreshCredentials'
    $allowDefault = Get-RegistryValueSafe -Path $credSSPClient -Name 'AllowDefaultCredentials'
    $allowSaved = Get-RegistryValueSafe -Path $credSSPClient -Name 'AllowSavedCredentials'
    # NTLM-only variants
    $allowFreshNtlm = Get-RegistryValueSafe -Path $credSSPClient -Name 'AllowFreshCredentialsWhenNTLMOnly'
    $allowDefaultNtlm = Get-RegistryValueSafe -Path $credSSPClient -Name 'AllowDefaultCredentialsWhenNTLMOnly'
    # AllowEncryption level - CVE-2018-0886 mitigation
    $encOracle = Get-RegistryValueSafe -Path "$credSSPClient\Parameters" -Name 'AllowEncryptionOracle'

    $BR2.Raw.CredSSP = @{
        AllowFreshCredentials = $allowFresh
        AllowDefaultCredentials = $allowDefault
        AllowSavedCredentials = $allowSaved
        AllowFreshCredentialsWhenNTLMOnly = $allowFreshNtlm
        AllowDefaultCredentialsWhenNTLMOnly = $allowDefaultNtlm
        AllowEncryptionOracle = $encOracle
    }

    # Check for * wildcard in AllowSaved/AllowFresh target lists
    foreach ($section in @('AllowFreshCredentials','AllowDefaultCredentials','AllowSavedCredentials')) {
        $sectionPath = "$credSSPClient\$section"
        if (-not (Test-Path $sectionPath)) { continue }
        try {
            $props = Get-ItemProperty -Path $sectionPath -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match 'PS(Path|ParentPath|ChildName|Provider|Drive)') { continue }
                if ($p.Value -match '\*') {
                    $BR2.Findings.Add( (New-Finding `
                        -CheckID 'BR-CREDSSP-001' `
                        -Category 'RemoteAccess' `
                        -Title "CredSSP $section list contains wildcard '*' target: $($p.Value)" `
                        -Severity 'High' `
                        -Exploitability 'Medium' `
                        -AttackPath 'Credentials delegated to any host matching wildcard - rogue host impersonation harvests delegated creds' `
                        -MITRE 'T1528' `
                        -Evidence @{
                            Section = $section
                            Name    = $p.Name
                            Value   = $p.Value
                        } `
                        -Remediation 'Restrict CredSSP delegation targets to specific FQDNs or limited wildcards scoped to management domains.' `
                        -OperatorNotes 'If users use mstsc /restrictedAdmin or specific flags that delegate fresh credentials, a rogue RDP host can collect the plaintext credentials. Less common nowadays but still surfaces. AllowFreshCredentials/NTLMOnly specifically was the primary CVE-2018-0886 exposure.' `
                        -References @('https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0886')
                    ))
                }
            }
        } catch {}
    }

    if ($encOracle -and $encOracle -ne 0) {
        # 0 = Force Updated Clients (safest), 1 = Mitigated, 2 = Vulnerable
        $sev = if ($encOracle -eq 2) { 'Critical' } else { 'High' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CREDSSP-002' `
            -Category 'RemoteAccess' `
            -Title "CredSSP AllowEncryptionOracle is set to $encOracle (0=safe, 1=mitigated, 2=vulnerable to CVE-2018-0886)" `
            -Severity $sev `
            -Exploitability 'Medium' `
            -AttackPath 'CredSSP remote code execution via Encryption Oracle Remediation flag set to Vulnerable / Mitigated' `
            -MITRE 'T1190' `
            -Evidence @{ AllowEncryptionOracle = $encOracle } `
            -Remediation 'Set AllowEncryptionOracle to 0 (Force Updated Clients). Only increase temporarily for migration scenarios.' `
            -OperatorNotes 'CVE-2018-0886: attacker in NTLM path between client and CredSSP target can achieve RCE. Still works against hosts with Mitigated or Vulnerable setting. Metasploit has a module (auxiliary/scanner/rdp/cve_2018_0886).' `
            -References @('https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-0886')
        ))
    }
}

# NetBIOS over TCP/IP bindings
# Covered in NetworkAndPatchPosture; skipped here to avoid duplicate.

# Anonymous SID enumeration (LSA: RestrictAnonymous, RestrictAnonymousSAM)
$lsaSys = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$restrictAnon     = Get-RegistryValueSafe -Path $lsaSys -Name 'RestrictAnonymous'
$restrictAnonSAM  = Get-RegistryValueSafe -Path $lsaSys -Name 'RestrictAnonymousSAM'
$everyoneIncAnon  = Get-RegistryValueSafe -Path $lsaSys -Name 'EveryoneIncludesAnonymous'

$BR2.Raw.AnonymousEnum = @{
    RestrictAnonymous         = $restrictAnon
    RestrictAnonymousSAM      = $restrictAnonSAM
    EveryoneIncludesAnonymous = $everyoneIncAnon
}

if ($restrictAnonSAM -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-ANON-001' `
        -Category 'NetworkPosture' `
        -Title 'RestrictAnonymousSAM is not enforced (anonymous SAM enumeration possible)' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Null session RPC to LSA / SAMR returns local user list, group memberships' `
        -MITRE 'T1087.001' `
        -Evidence @{ RestrictAnonymousSAM = $restrictAnonSAM } `
        -Remediation 'Set RestrictAnonymousSAM=1. Default 1 on modern Windows; if set to 0, explicit reduction.' `
        -OperatorNotes 'enum4linux / rpcclient / impacket lookupsid.py allows anonymous SID brute against SAMR yields local account names. Pre-auth reconnaissance without credentials.' `
        -References @()
    ))
}

if ($everyoneIncAnon -eq 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-ANON-002' `
        -Category 'NetworkPosture' `
        -Title 'EveryoneIncludesAnonymous=1 - anonymous users gain Everyone-group access' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Anonymous / null sessions inherit Everyone ACEs - read shares / registry / RPC resources granted to Everyone' `
        -MITRE 'T1078' `
        -Evidence @{ EveryoneIncludesAnonymous = 1 } `
        -Remediation 'Set EveryoneIncludesAnonymous=0. Default 0.' `
        -OperatorNotes 'Rare but bad if picked up. Null session can read all share contents accessible to Everyone which could lead to finding creds in config files, legacy shares, etc.' `
        -References @()
    ))
}

# SMB null session pipes and shares
$nullSessionPipes  = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionPipes' -ErrorAction SilentlyContinue).NullSessionPipes
$nullSessionShares = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionShares' -ErrorAction SilentlyContinue).NullSessionShares
$restrictNullSession = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess'

$BR2.Raw.NullSession = @{
    NullSessionPipes     = $nullSessionPipes
    NullSessionShares    = $nullSessionShares
    RestrictNullSessAccess = $restrictNullSession
}

if ($nullSessionPipes -and $nullSessionPipes.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-SMB-001' `
        -Category 'NetworkPosture' `
        -Title "SMB NullSessionPipes configured: $($nullSessionPipes -join ',')" `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Named pipes accessible without authentication - attack surface for the services bound to those pipes' `
        -MITRE 'T1021.002' `
        -Evidence @{ Pipes = $nullSessionPipes } `
        -Remediation 'Empty NullSessionPipes unless specifically required. Modern Windows defaults to empty.' `
        -OperatorNotes 'Pipe content determines risk. SPOOLSS pipe (PrintNightmare, coerce authentication), NETLOGON pipe (pre-auth enumeration). If listed here, anonymous reachable.' `
        -References @()
    ))
}

# ---- Link-Local IPsec auth and RPC filters ----------------------------

# Emerging best-practice: RPC filters for blocking spooler coercion, etc.
# Check for rpcfilter entries - hard to enumerate without admin, skip for now.

# MSRPC / DCOM permissions
# DefaultLaunchPermission and DefaultAccessPermission under HKLM\SOFTWARE\Microsoft\Ole
# If overly broad, allows remote DCOM activation. Rare to misconfigure;
# default is sane. Skip detailed parse - flag only if obviously permissive.

$dcomPath = 'HKLM:\SOFTWARE\Microsoft\Ole'
$enableDcom = Get-RegistryValueSafe -Path $dcomPath -Name 'EnableDCOM'
$BR2.Raw.DCOM = @{ EnableDCOM = $enableDcom }

# DCOM disabled is a defensive posture - only flag if the inverse (explicitly
# enabled when it used to be disabled) is surprising. Informational raw only.
