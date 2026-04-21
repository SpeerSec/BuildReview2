#requires -Version 5.1

$ctx = $global:BR2.Context

# Trusted Root store
$rootCerts = @()
try {
    $rootCerts = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue
} catch {}

$BR2.Raw.TrustedRoot = @{
    TotalCount = $rootCerts.Count
}

if ($rootCerts.Count -gt 0) {
    # Heuristic 1: self-signed certs with extremely short validity (< 2 years)
    # Legitimate enterprise CAs are usually 5-20 years. Adversary planted
    # certs are often sloppy with a default 1-year validity.
    $suspiciousShortValidity = @()
    foreach ($cert in $rootCerts) {
        $years = ($cert.NotAfter - $cert.NotBefore).TotalDays / 365
        if ($years -lt 2 -and $cert.Subject -eq $cert.Issuer) {
            $suspiciousShortValidity += $cert
        }
    }

    if ($suspiciousShortValidity.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CERT-001' `
            -Category 'Persistence' `
            -Title "$($suspiciousShortValidity.Count) self-signed root CA cert(s) with <2 year validity (unusual for legitimate CAs)" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Adversary-planted root CA - makes attacker-signed code, certs, and TLS interception trusted system-wide' `
            -MITRE @('T1553.004','T1606.001') `
            -Evidence @{
                Count = $suspiciousShortValidity.Count
                Samples = @($suspiciousShortValidity | ForEach-Object {
                    @{
                        Subject    = $_.Subject
                        Thumbprint = $_.Thumbprint
                        NotBefore  = "$($_.NotBefore)"
                        NotAfter   = "$($_.NotAfter)"
                    }
                } | Select-Object -First 5)
            } `
            -Remediation 'Review each cert for business justification. Remove unrecognised ones: Remove-Item "Cert:\LocalMachine\Root\<thumbprint>". Typical legitimate CAs: Microsoft, DigiCert, Sectigo, Let\u0027s Encrypt (on some modern systems), enterprise CA name.' `
            -OperatorNotes 'Long-term persistence via certutil -addstore root attacker.crt. After that, any payload signed with the matching private key is recognised as "trusted publisher" for AppLocker publisher rules, WDAC PcaCertificate rules, and SmartScreen. Also enables silent TLS MITM for the user.' `
            -References @(
                'https://attack.mitre.org/techniques/T1553/004/',
                'https://docs.microsoft.com/en-us/security/trusted-root/'
            )
        ))
    }

    # Heuristic 2: count unusually high - baseline Windows ships with ~20-60 root CAs
    # Enterprise will have several more (their CA chain). Over 300 = possibly old/legacy
    # or adversary stuffing. Informational only.
    if ($rootCerts.Count -gt 300) {
        $BR2.Raw.TrustedRoot.Unusual = "Over 300 root CAs - enterprise baseline is typically 50-200"
    }

    # Heuristic 3: specific subject patterns adversaries have used
    $suspiciousPatterns = 'DO_NOT_TRUST|Superfish|Komodia|eDellRoot|DSDTestProvider|uprobe|CaTroublE|hacker|test.*ca'
    $patternHits = $rootCerts | Where-Object { $_.Subject -match $suspiciousPatterns }
    if ($patternHits) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CERT-002' `
            -Category 'Persistence' `
            -Title "Known-problematic root CA pattern matched: $($patternHits.Subject -join ', ')" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'Superfish-class adware CA or adversary-test CA left in place - MITM capability, signed payload trust' `
            -MITRE 'T1553.004' `
            -Evidence @{ Certs = @($patternHits | Select-Object Subject, Thumbprint) } `
            -Remediation 'Remove immediately: Remove-Item "Cert:\LocalMachine\Root\<thumbprint>".' `
            -OperatorNotes 'Superfish (Lenovo 2015), eDellRoot (Dell 2015), Komodia SDK - OEM-preload adware that installed root CAs with known private keys. Still present on some old images. Anyone with the private key MITMs the machine.' `
            -References @()
        ))
    }
}

# Trusted Publishers store
$trustedPub = @()
try {
    $trustedPub = Get-ChildItem -Path 'Cert:\LocalMachine\TrustedPublisher' -ErrorAction SilentlyContinue
} catch {}

$BR2.Raw.TrustedPublisher = @{
    TotalCount = $trustedPub.Count
}

# Trusted Publisher store is usually small or empty on clean systems.
# Enterprise may pre-populate with their code-signing cert.
# Self-signed certs here are always suspicious.
$selfSignedPub = $trustedPub | Where-Object { $_.Subject -eq $_.Issuer }
if ($selfSignedPub.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-CERT-003' `
        -Category 'Persistence' `
        -Title "$($selfSignedPub.Count) self-signed cert(s) in TrustedPublisher store" `
        -Severity 'High' `
        -Exploitability 'Medium' `
        -AttackPath 'Self-signed TrustedPublisher enables attacker-signed code to appear trusted to Office (macros), ClickOnce, and PS ExecutionPolicy AllSigned' `
        -MITRE 'T1553.002' `
        -Evidence @{
            Count = $selfSignedPub.Count
            Certs = @($selfSignedPub | ForEach-Object {
                @{ Subject = $_.Subject; Thumbprint = $_.Thumbprint }
            } | Select-Object -First 5)
        } `
        -Remediation 'Review and remove unrecognised entries. Legitimate enterprise code-signing certs are typically issued by an internal CA (not self-signed).' `
        -OperatorNotes 'Sign your payload with a self-signed cert, add that cert to TrustedPublisher via certutil -addstore trustedpublisher. Now your signed PowerShell runs under AllSigned execution policy, your signed Office macro is "trusted publisher" (bypasses macro prompt even with strict settings), and your signed MSIX is installable.' `
        -References @(
            'https://attack.mitre.org/techniques/T1553/002/',
            'https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-publisher-certificate-store'
        )
    ))
}

# Enterprise Trust / Disallowed
# Enterprise Trust (HKLM\...\Enterprise Trust) normally empty.
# Disallowed store blocks known-bad (normally populated automatically).

$enterpriseTrust = @()
try {
    $enterpriseTrust = Get-ChildItem -Path 'Cert:\LocalMachine\Trust' -ErrorAction SilentlyContinue
} catch {}
if ($enterpriseTrust.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-CERT-004' `
        -Category 'Persistence' `
        -Title "$($enterpriseTrust.Count) cert(s) in Enterprise Trust CTL store" `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Enterprise Trust CTL extends trust to non-Microsoft roots for this host - check that entries are legitimate enterprise policy' `
        -MITRE 'T1553.004' `
        -Evidence @{ Count = $enterpriseTrust.Count } `
        -Remediation 'Review entries against documented enterprise policy. Each CTL should be traceable to deployment source.' `
        -OperatorNotes 'CTLs are less scrutinised than root store additions. Quieter alternative to full root install for adding trust.' `
        -References @()
    ))
}

# ---- Personal (My) store with code-signing EKU (potential key to extract) ----

try {
    $personal = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
                Where-Object { $_.HasPrivateKey -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing' }
    if ($personal.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-CERT-005' `
            -Category 'Credentials' `
            -Title "$($personal.Count) code-signing cert(s) with private key in LocalMachine\My" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Exportable code-signing private key - exfiltrate and sign attacker binaries under legitimate enterprise publisher identity' `
            -MITRE 'T1553.002' `
            -Evidence @{
                Count = $personal.Count
                Subjects = @($personal.Subject | Select-Object -First 5)
            } `
            -Remediation 'Store code-signing keys in HSM or Azure Key Vault with hardware-backed signing. Remove exportable private key copies from local machine stores.' `
            -OperatorNotes 'Export with Export-PfxCertificate if CSP allows. If marked non-exportable: DPAPI + RPC to CAPI/CNG via Mimikatz crypto::capi or crypto::cng - sometimes succeeds, sometimes not. If exported, sign your tooling with the enterprise publisher name - bypasses every AllowSigned rule in the environment.' `
            -References @(
                'https://posts.specterops.io/blatantly-circumventing-controls-certificate-based-tradecraft-f0a9b55aa8c4',
                'https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto'
            )
        ))
    }
} catch {}

# ---- Sysmon AuthRoot DLL-signing variants ----------------------------

# AuthRoot store contents update via Microsoft CTL automatic download.
# Gaps indicate isolated network or policy disabling updates.
$authRoot = @()
try {
    $authRoot = Get-ChildItem -Path 'Cert:\LocalMachine\AuthRoot' -ErrorAction SilentlyContinue
} catch {}

$BR2.Raw.AuthRoot = @{
    Count = $authRoot.Count
}
# No finding - just raw context. Baseline is 200-400 on a freshly updated modern host.
