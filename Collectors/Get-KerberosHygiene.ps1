#requires -Version 5.1


$role = Get-HostRole

# Per-host KDC default
$kerbParams = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
$supportedEncTypes = Get-RegistryValueSafe -Path $kerbParams -Name 'SupportedEncryptionTypes'

# Per-DC KDC default (2026+ Microsoft adds this)
$kdcParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
$defaultDomainSupported = Get-RegistryValueSafe -Path $kdcParams -Name 'DefaultDomainSupportedEncTypes'
$rc4DisablePhase = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name 'RC4DefaultDisablementPhase'

# Bit flags for msDS-SupportedEncryptionTypes:
#   0x1  DES_CBC_CRC
#   0x2  DES_CBC_MD5
#   0x4  RC4_HMAC_MD5          <-- the target
#   0x8  AES128_HMAC_SHA1
#   0x10 AES256_HMAC_SHA1
#   0x20 AES256_HMAC_SHA1 SK
function Get-EncTypeDescription {
    param([int]$Value)
    if ($null -eq $Value) { return 'Not set (implicit default)' }
    $desc = @()
    if ($Value -band 0x1)  { $desc += 'DES_CBC_CRC' }
    if ($Value -band 0x2)  { $desc += 'DES_CBC_MD5' }
    if ($Value -band 0x4)  { $desc += 'RC4_HMAC_MD5' }
    if ($Value -band 0x8)  { $desc += 'AES128_HMAC_SHA1' }
    if ($Value -band 0x10) { $desc += 'AES256_HMAC_SHA1' }
    if ($Value -band 0x20) { $desc += 'AES256_HMAC_SHA1_SK' }
    return ($desc -join ', ')
}

$BR2.Raw.KerberosEncTypes = @{
    SupportedEncryptionTypes         = $supportedEncTypes
    DefaultDomainSupportedEncTypes   = $defaultDomainSupported
    RC4DefaultDisablementPhase       = $rc4DisablePhase
    Decoded_SupportedEncryptionTypes = Get-EncTypeDescription $supportedEncTypes
    Decoded_DefaultDomainSupported   = Get-EncTypeDescription $defaultDomainSupported
}

# RC4 permitted on host
if ($supportedEncTypes -eq $null -or ($supportedEncTypes -band 0x4)) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-KRB-001' `
        -Category 'Kerberos' `
        -Title 'RC4 Kerberos encryption type is available on this host' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Kerberoasting with RC4 - offline hash cracking of service account passwords' `
        -MITRE 'T1558.003' `
        -Evidence @{
            Raw     = $supportedEncTypes
            Decoded = Get-EncTypeDescription $supportedEncTypes
            Path    = $kerbParams
        } `
        -Remediation 'Set SupportedEncryptionTypes to 0x18 (AES128 + AES256). Microsoft is enforcing this as the default in April 2026 for DCs; get ahead of the change. Audit with Get-KerbEncryptionUsage.ps1 first.' `
        -OperatorNotes 'Kerberoast with Rubeus.exe kerberoast /nowrap /format:hashcat. RC4-encrypted tickets crack at roughly 10x the rate of AES256 on the same GPU. The request for the RC4-etype ticket is the operator choice - specify /rc4opsec to only request tickets for accounts whose AES keys are absent, avoiding the 4769 event spike that /tgtdeleg would cause.' `
        -References @(
            'https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos',
            'https://github.com/GhostPack/Rubeus',
            'https://blog.admindroid.com/microsoft-deprecates-rc4-encryption-for-kerberos-authentication/'
        )
    ))
}

# DC with no RC4 disablement phase set (January 2026 update onward)
if ($role -eq 'DomainController' -and -not $rc4DisablePhase) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-KRB-003' `
        -Category 'Kerberos' `
        -Title 'RC4DefaultDisablementPhase not configured on domain controller' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Continued Kerberoasting using RC4 downgrade until April 2026 enforcement' `
        -MITRE 'T1558.003' `
        -Evidence @{
            RC4DefaultDisablementPhase = $rc4DisablePhase
            Role                       = $role
            Guidance                   = 'Post-Jan 2026 update, set to 2 (enforce) after audit-mode confirms no RC4 dependencies. Pre-Jan update, install the cumulative first.'
        } `
        -Remediation 'Install the January 2026 cumulative update on all DCs. Monitor KDCSVC event IDs 201-209 for RC4 dependency audit events. Once clean, set RC4DefaultDisablementPhase=2.' `
        -OperatorNotes 'This is the tell that the DC admin has not engaged with the RC4 deprecation timeline. Kerberoasting remains viable until enforcement lands. Also a defensive gap indicator - the org is likely behind on wider Kerberos hygiene.' `
        -References @(
            'https://www.cayosoft.com/blog/kerberos-rc4-hardening-what-microsoft-s-cve-2026-20833-update-really-means-for-active-directory-admins/'
        )
    ))
}

# Requires the RSAT AD module to be loaded. Fall back gracefully.
$hasADModule = $null -ne (Get-Module -ListAvailable -Name ActiveDirectory)

if ($hasADModule -and $role -ne 'Standalone') {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        $maq = (Get-ADObject -Identity $domain.DistinguishedName `
                             -Properties 'ms-DS-MachineAccountQuota' `
                             -ErrorAction Stop).'ms-DS-MachineAccountQuota'

        $BR2.Raw.MachineAccountQuota = $maq

        if ($maq -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-KRB-005' `
                -Category 'Kerberos' `
                -Title "ms-DS-MachineAccountQuota is $maq (any domain user can create $maq computer accounts)" `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Machine account creation -> RBCD (Resource-Based Constrained Delegation) self-takeover of this host' `
                -MITRE @('T1136.002','T1550') `
                -Evidence @{
                    MachineAccountQuota = $maq
                    Domain              = $domain.DNSRoot
                } `
                -Remediation 'Set ms-DS-MachineAccountQuota to 0. Machine account creation should be a delegated privilege held by a small group, not granted to every Domain User.' `
                -OperatorNotes 'With MAQ>0 and any domain user, the classic RBCD self-takeover: create a computer account (Powermad New-MachineAccount), set the target computer msDS-AllowedToActOnBehalfOfOtherIdentity to allow your new computer, then S4U2Self + S4U2Proxy via Rubeus to obtain a service ticket to the target as any user (including a domain admin). Works even if the target is a DC under the right conditions (unconstrained delegation not required). Defender does not detect New-MachineAccount by default, but SACLs on the CN=Computers container would surface the event.' `
                -References @(
                    'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html',
                    'https://github.com/Kevin-Robertson/Powermad',
                    'https://github.com/GhostPack/Rubeus'
                )
            ))
        }
    } catch {
        $BR2.Skipped.Add([PSCustomObject]@{
            Collector = 'KerberosHygiene'
            Check     = 'BR-KRB-005'
            Reason    = "Could not query ms-DS-MachineAccountQuota: $($_.Exception.Message)"
        })
    }
}

if ($hasADModule -and $role -ne 'Standalone') {
    try {
        $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' `
                                 -Properties DoesNotRequirePreAuth, servicePrincipalName `
                                 -ErrorAction Stop
        $BR2.Raw.ASREPRoastable = @($asrepUsers | Select-Object -ExpandProperty SamAccountName)

        if ($asrepUsers.Count -gt 0) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-KRB-004' `
                -Category 'Kerberos' `
                -Title ("$($asrepUsers.Count) AS-REP roastable user account(s) in the domain") `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'AS-REP roasting - request AS-REP without pre-auth, crack offline' `
                -MITRE 'T1558.004' `
                -Evidence @{
                    Count    = $asrepUsers.Count
                    Accounts = @($asrepUsers | Select-Object -First 25 -ExpandProperty SamAccountName)
                } `
                -Remediation 'Enable Kerberos pre-authentication for all user accounts. The DONT_REQ_PREAUTH UAC flag is almost never needed on a modern estate.' `
                -OperatorNotes 'Rubeus.exe asreproast /nowrap /format:hashcat. Hashcat mode 18200. Unlike Kerberoasting, AS-REP roasting does not require even a domain credential - just network access to the DC.' `
                -References @(
                    'https://github.com/GhostPack/Rubeus',
                    'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/'
                )
            ))
        }
    } catch {
        $BR2.Skipped.Add([PSCustomObject]@{
            Collector = 'KerberosHygiene'
            Check     = 'BR-KRB-004'
            Reason    = "Could not enumerate AS-REP roastable users: $($_.Exception.Message)"
        })
    }
}

if ($role -eq 'DomainController') {
    $kdcStrongBinding = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement'
    # 0 = disabled (pre-patch behaviour), 1 = compatibility mode, 2 = full enforcement
    $certMapMethods = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name 'CertificateMappingMethods'

    $BR2.Raw.CertBinding = @{
        StrongCertificateBindingEnforcement = $kdcStrongBinding
        CertificateMappingMethods           = $certMapMethods
    }

    if ($kdcStrongBinding -ne 2) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-KRB-007' `
            -Category 'Kerberos' `
            -Title 'StrongCertificateBindingEnforcement < 2 (Certifried-vulnerable certificate mapping)' `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'CVE-2022-26923 Certifried - certificate identity spoofing via dNSHostName' `
            -MITRE 'T1649' `
            -Evidence @{
                StrongCertificateBindingEnforcement = $kdcStrongBinding
                Path                                = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
            } `
            -Remediation 'Set StrongCertificateBindingEnforcement=2. Microsoft intended full enforcement in Feb 2025 but pushed this back - verify no legacy cert-auth dependencies first (particularly third-party NAC, wireless auth, and MFA solutions that use EAP-TLS).' `
            -OperatorNotes 'Combined with MAQ>0, this is one of the better escalation vectors. Create a computer, rewrite its dNSHostName to match a DC, request a certificate from the Machine template (or any client-auth template), then authenticate as the DC. Certipy account create / update / req does the whole chain. ESC9 / ESC10 / ESC16 are related techniques all dependent on this binding being weak.' `
            -References @(
                'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16',
                'https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4'
            )
        ))
    }

    # CertificateMappingMethods: bit 0x4 (UPN), 0x8 (S4U2Self) are weak
    if ($certMapMethods -and ($certMapMethods -band 0x4) -or ($certMapMethods -band 0x8)) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-KRB-008' `
            -Category 'Kerberos' `
            -Title 'CertificateMappingMethods permits weak mappings (UPN or S4U2Self)' `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'ESC9/ESC10 - weak certificate-to-account mapping via altered UPN' `
            -MITRE 'T1649' `
            -Evidence @{ CertificateMappingMethods = $certMapMethods } `
            -Remediation 'Set CertificateMappingMethods=0x18 (issuer+subject+serialnumber AND SKI only - strong mappings only).' `
            -OperatorNotes 'If UPN mapping is allowed: change a user''s UPN to match a target admin, enrol a cert, revert, authenticate. Certipy handles all three steps. Affects ESC9 and ESC10 paths.' `
            -References @(
                'https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6'
            )
        ))
    }
}
