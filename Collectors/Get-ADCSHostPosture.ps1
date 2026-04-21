#requires -Version 5.1


$ctx = $global:BR2.Context

# Existence gate
$certSvc = Get-Service -Name 'CertSvc' -ErrorAction SilentlyContinue
if (-not $certSvc) { return }

$BR2.Raw.ADCS = @{
    IsCA          = $true
    ServiceState  = "$($certSvc.Status)"
}

# Identify CA name and type
$caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$caNames = @()
try {
    $caNames = @((Get-ChildItem -Path $caRoot -ErrorAction SilentlyContinue).PSChildName) | Where-Object { $_ }
} catch {}

if ($caNames.Count -eq 0) {
    # CertSvc present but not configured - rare edge case (template-imaged server)
    return
}

foreach ($caName in $caNames) {
    $caKey = Join-Path $caRoot $caName
    if (-not (Test-Path $caKey)) { continue }

    $editFlags   = Get-RegistryValueSafe -Path $caKey -Name 'EditFlags'
    $crlConfigs  = Get-RegistryValueSafe -Path $caKey -Name 'CRLPublicationURLs'
    $caType      = Get-RegistryValueSafe -Path $caKey -Name 'CAType'

    $BR2.Raw.ADCS.CA = @{
        Name       = $caName
        EditFlags  = $editFlags
        CAType     = $caType
    }

    # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
    # Flag value 0x00040000 = EDITF_ATTRIBUTESUBJECTALTNAME2
    # If set, any enroller can specify an arbitrary SAN (Subject Alternative
    # Name) in their request - request as low-priv user, include
    # UPN=administrator@domain.local, get a client-auth cert for Administrator.

    if ($editFlags -and ($editFlags -band 0x00040000)) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CA-008' `
            -Category 'ADCS' `
            -Title "CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 set - ESC6 vulnerable" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'ESC6 - request certificate on any enrolee-allowed template; embed arbitrary SAN/UPN in the request; receive client-auth cert for impersonated identity' `
            -MITRE 'T1649' `
            -Evidence @{
                CA           = $caName
                EditFlags    = ('0x{0:X}' -f $editFlags)
                Flag         = 'EDITF_ATTRIBUTESUBJECTALTNAME2'
            } `
            -Remediation 'certutil -config "<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 && net stop certsvc && net start certsvc. Should not enable this flag in production.' `
            -OperatorNotes 'Certipy req -ca <CA> -template User -upn administrator@domain.local. Receives a client-auth cert for the domain admin. Certipy auth -pfx <cert>.pfx to convert to TGT.' `
            -References @(
                'https://posts.specterops.io/certified-pre-owned-d95910965cd2',
                'https://github.com/ly4k/Certipy'
            )
        ))
    }

    # ESC16: DisableExtensionList
    # KB5014754 added szOID_NTDS_CA_SECURITY_EXT = 1.3.6.1.4.1.311.25.2
    # into issued client-auth certs to bind SID/OID. If CA is configured
    # to suppress this OID, the binding is missing and StrongCertificate
    # BindingEnforcement can be downgraded per KB5014754 phase.

    $disableList = Get-RegistryValueSafe -Path "$caKey\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy" -Name 'DisableExtensionList'
    # Value is a REG_MULTI_SZ with OID entries

    if ($disableList -and ($disableList -contains '1.3.6.1.4.1.311.25.2')) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CA-009' `
            -Category 'ADCS' `
            -Title "CA '$caName' has szOID_NTDS_CA_SECURITY_EXT in DisableExtensionList (ESC16)" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'ESC16 - issued client-auth certs lack the SID binding extension, making StrongCertificateBindingEnforcement on DCs ineffective' `
            -MITRE 'T1649' `
            -Evidence @{
                CA            = $caName
                DisableList   = $disableList
            } `
            -Remediation 'Remove 1.3.6.1.4.1.311.25.2 from DisableExtensionList. This OID is essential for the Certifried mitigation chain.' `
            -OperatorNotes 'Combined with a weak template, ESC16 reopens the Certifried-family primitive even on otherwise-patched DCs. Certipy has checks for this specific condition.' `
            -References @(
                'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-7e771f6c1ec1'
            )
        ))
    }

    # CA private key storage provider
    $csp = Get-RegistryValueSafe -Path "$caKey\CSP" -Name 'Provider'
    $BR2.Raw.ADCS.CA.CSP = $csp
    # If the CA private key is stored in a software CSP rather than
    # hardware HSM, extraction is possible by admin on this host.
    if ($csp -and $csp -match 'Software') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CA-020' `
            -Category 'ADCS' `
            -Title "CA '$caName' private key is protected by a software CSP" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Admin on this host can extract the CA private key via certutil -exportpfx or DPAPI unwrap; forge arbitrary certs offline' `
            -MITRE 'T1649' `
            -Evidence @{
                CA  = $caName
                CSP = $csp
            } `
            -Remediation 'Migrate the CA to an HSM (Hardware Security Module). Microsoft has procedures for rekey-to-HSM. Interim: restrict admin on the CA host to tier-0 minimum.' `
            -OperatorNotes 'Once the CA private key is exfiltrated, Certipy forge --ca-pfx <pfx> --upn administrator@domain --subject "CN=...", converts to TGT via Certipy auth. Persists across password rotations and works across all child domains in the forest.' `
            -References @(
                'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
            )
        ))
    }
}

# ESC8: Web Enrolment / CES exposure
# CA web enrolment (CES/CEP) uses IIS with NTLM auth by default.
# NTLM relay to these endpoints yields client-auth certs.

$iisSvc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
if ($iisSvc -and $iisSvc.Status -eq 'Running') {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $certSrvApp = Get-WebApplication -Site 'Default Web Site' -Name 'CertSrv' -ErrorAction SilentlyContinue
        $cesApp    = Get-WebApplication | Where-Object { $_.Path -match 'CES$' } | Select-Object -First 1

        if ($certSrvApp -or $cesApp) {
            # Check for EPA (Extended Protection for Authentication)
            # Conservative: assume not enforced unless proven otherwise
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-CA-010' `
                -Category 'ADCS' `
                -Title 'Web Enrolment / CES virtual application present - ESC8 relay surface' `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'ESC8 - NTLM relay from coerced machine account auth to /certsrv/ - receive client-auth cert for DC machine account' `
                -MITRE @('T1557.001','T1649') `
                -Evidence @{
                    CertSrvApplication = [bool]$certSrvApp
                    CESApplication     = [bool]$cesApp
                } `
                -Remediation 'Enable Extended Protection for Authentication on all certsrv / CES applications. Require HTTPS. Kerberos-only where possible. Microsoft has published guidance (KB5005413).' `
                -OperatorNotes 'Coerce (PetitPotam/Coercer) the target machine account auth against attacker host, relay to http://<ca>/certsrv/certfnsh.asp - receive client-auth cert for that machine account. Use Certipy auth to convert to TGT. If target is DC, directly DCSync. If target is a member server with SPN, takeover that server. ESC8 still works against EPA-not-enforced installs (default before April 2024).' `
                -References @(
                    'https://github.com/ly4k/Certipy',
                    'https://support.microsoft.com/en-us/topic/kb5005413'
                )
            ))
        }
    } catch {}
}
