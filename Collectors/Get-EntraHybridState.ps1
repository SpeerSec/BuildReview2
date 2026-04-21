#requires -Version 5.1


$ctx = $global:BR2.Context

# Hard exit if not Entra-joined
if (-not $ctx.IsAzureADJoined -and -not $ctx.IsHybridJoined) {
    return
}

# dsregcmd deep parse
$dsregOutput = & dsregcmd.exe /status 2>$null
if (-not $dsregOutput) {
    $BR2.Skipped.Add([PSCustomObject]@{
        Collector = 'EntraHybridState'
        Reason    = 'dsregcmd returned no output; may require admin or interactive session.'
    })
    return
}

function Parse-DsregLine {
    param([string[]]$Lines, [string]$Field)
    $line = $Lines | Select-String -Pattern "^\s*$Field\s*:\s*(.+)\s*$" | Select-Object -First 1
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    return $null
}

$tenantId         = Parse-DsregLine -Lines $dsregOutput -Field 'TenantId'
$tenantName       = Parse-DsregLine -Lines $dsregOutput -Field 'TenantName'
$deviceId         = Parse-DsregLine -Lines $dsregOutput -Field 'DeviceId'
$thumbprint       = Parse-DsregLine -Lines $dsregOutput -Field 'Thumbprint'
$deviceCertValidity = Parse-DsregLine -Lines $dsregOutput -Field 'DeviceCertificateValidity'
$keyProvider      = Parse-DsregLine -Lines $dsregOutput -Field 'KeyProvider'
$tpmProtected     = Parse-DsregLine -Lines $dsregOutput -Field 'TpmProtected'
$ngcSet           = Parse-DsregLine -Lines $dsregOutput -Field 'NgcSet'                    # Windows Hello state
$canReset         = Parse-DsregLine -Lines $dsregOutput -Field 'CanReset'
$workplaceJoined  = Parse-DsregLine -Lines $dsregOutput -Field 'WorkplaceJoined'
$mdmUrl           = Parse-DsregLine -Lines $dsregOutput -Field 'MdmUrl'
$mdmTouUrl        = Parse-DsregLine -Lines $dsregOutput -Field 'MdmTouUrl'
$mdmComplianceUrl = Parse-DsregLine -Lines $dsregOutput -Field 'MdmComplianceUrl'

# Tests
$ssoState = @{}
foreach ($k in 'AzureAdPrt','AzureAdPrtUpdateTime','AzureAdPrtExpiryTime','WamDefaultSet','WamDefaultGUID','AzureAdPrtAuthority') {
    $ssoState[$k] = Parse-DsregLine -Lines $dsregOutput -Field $k
}

$BR2.Raw.Entra = @{
    TenantId         = $tenantId
    TenantName       = $tenantName
    DeviceId         = $deviceId
    Thumbprint       = $thumbprint
    KeyProvider      = $keyProvider
    TpmProtected     = $tpmProtected
    NgcSet           = $ngcSet
    WorkplaceJoined  = $workplaceJoined
    MdmUrl           = $mdmUrl
    PRTState         = $ssoState
    IsHybridJoined   = $ctx.IsHybridJoined
    IsAzureADJoined  = $ctx.IsAzureADJoined
}

# Device certificate TPM protection
if ($tpmProtected -and $tpmProtected -notmatch 'YES') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AAD-005' `
        -Category 'Entra' `
        -Title 'Entra device certificate is not TPM-protected' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Device certificate private key is software-stored; exfiltrate and reuse on attacker-controlled host to forge PRT' `
        -MITRE @('T1528','T1552.004') `
        -Evidence @{
            TpmProtected = $tpmProtected
            KeyProvider  = $keyProvider
            Thumbprint   = $thumbprint
        } `
        -Remediation 'Ensure the device has a functioning TPM and that Windows Hello for Business / device registration is configured to require TPM-backed keys. Re-register the device after TPM is activated.' `
        -OperatorNotes 'With a software-protected device key, the private key can be exported (DPAPI + TokenBroker context) and imported on an attacker host. Then roadtx / TokenSmith can obtain a PRT for this device ID and impersonate. TPM protection binds the key to hardware - exfil is materially harder.' `
        -References @(
            'https://dirkjanm.io/digging-further-into-the-primary-refresh-token/',
            'https://github.com/dirkjanm/ROADtools',
            'https://github.com/SecureHats/TokenSmith'
        )
    ))
}

# PRT cookie extraction surface
# If PRT is present and the user context is accessible, roadtoken / roadtx
# can request a PRT cookie usable for SSO to any Entra app.
if ($ssoState.AzureAdPrt -eq 'YES') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AAD-001' `
        -Category 'Entra' `
        -Title 'Primary Refresh Token present in LSA - extractable for Entra SSO abuse' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'PRT cookie extraction yields SSO to all Entra-connected apps the user has access to (Graph, Exchange, SharePoint, custom SAML apps)' `
        -MITRE 'T1528' `
        -Evidence @{
            PRTPresent       = $true
            PRTUpdateTime    = $ssoState.AzureAdPrtUpdateTime
            PRTExpiryTime    = $ssoState.AzureAdPrtExpiryTime
        } `
        -Remediation 'Defence depends on protecting the logged-on user context. Enforce Windows Hello for Business with attested keys, enable Credential Guard, and require device compliance + risk-based Conditional Access. For the session: disabling LSA key cache is not a general recommendation but worth considering for high-privilege admin hosts.' `
        -OperatorNotes "Admin/SYSTEM on this host: roadtx prtenrich /prt-sso / BrowserCore.exe IPC hijack / mimikatz sekurlsa::cloudap to extract PRT, proof-of-possession key, and session key. Combine with TokenSmith for FOCI refresh token acquisition - broader app coverage than roadtx alone. With TPM protection + Windows Hello, the proof-of-possession signing still has to happen on-box; remote PRT replay requires the key material, which means either browser cookie theft or live on-host signing." `
        -References @(
            'https://github.com/dirkjanm/ROADtools',
            'https://github.com/SecureHats/TokenSmith',
            'https://github.com/leechristensen/SpoolSample'
        )
    ))
}

# TokenBroker cache
$tokenBrokerPath = Join-Path $env:LOCALAPPDATA 'Microsoft\TokenBroker'
if (Test-Path $tokenBrokerPath) {
    $tokenFiles = Get-ChildItem -Path $tokenBrokerPath -Recurse -File -ErrorAction SilentlyContinue
    $BR2.Raw.TokenBroker = @{
        FileCount = @($tokenFiles).Count
        Path      = $tokenBrokerPath
    }

    if ($tokenFiles.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-AAD-004' `
            -Category 'Entra' `
            -Title "TokenBroker cache contains $($tokenFiles.Count) file(s) - cached Entra tokens" `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'Extract cached refresh tokens from TokenBroker store; replay for extended SSO access' `
            -MITRE 'T1528' `
            -Evidence @{
                Path      = $tokenBrokerPath
                FileCount = $tokenFiles.Count
            } `
            -Remediation 'Not directly configurable. Defence: enforce short refresh token lifetimes via CA policy, require sign-in frequency, and monitor for anomalous MFA-exempt refresh events.' `
            -OperatorNotes 'TokenBroker holds WAM (Web Account Manager) tokens for desktop apps. Decrypt via DPAPI as the user; the cached tokens include refresh tokens for Teams, Office, OneDrive. FOCI tokens (Family of Client IDs) expand reach beyond the originating app - a Teams refresh token can mint tokens for Graph and other Microsoft apps.' `
            -References @(
                'https://github.com/0xrajneesh/TokenTactics',
                'https://github.com/f-bader/TokenTacticsV2'
            )
        ))
    }
}

# Windows Hello for Business state
if ($ngcSet -eq 'YES') {
    $BR2.Raw.WHfB = @{ Enrolled = $true }

    # Pull WHfB keys from HKCU - these can be a persistence vector
    $ngcKeys = 'HKCU:\Software\Microsoft\Ngc'
    if (Test-Path $ngcKeys) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-AAD-003' `
            -Category 'Entra' `
            -Title 'Windows Hello for Business keys present in user registry - potential persistence surface' `
            -Severity 'Low' `
            -Exploitability 'Low' `
            -AttackPath 'Attacker-registered WHfB key via msDS-KeyCredentialLink (Shadow Credentials variant for Entra) persists even after password reset' `
            -MITRE 'T1098.004' `
            -Evidence @{
                NgcSet       = $ngcSet
                KeyProvider  = $keyProvider
                RegistryPath = $ngcKeys
            } `
            -Remediation 'Routinely audit msDS-KeyCredentialLink on all user and computer objects in the domain / directory. Remove unexpected entries. Monitor directory events for KeyCredentialLink additions.' `
            -OperatorNotes "Shadow Credentials applies to users and computers. Whisker / Pywhisker / ntlmrelayx --shadow-credentials against a target msDS-KeyCredentialLink. For Entra-only, attacker-registered WHfB keys are similarly durable. As admin on this host: review HKCU\Software\Microsoft\Ngc for unexpected entries." `
            -References @(
                'https://github.com/eladshamir/Whisker',
                'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'
            )
        ))
    }
}

# Intune / MDM enrolment state
if ($mdmUrl) {
    $BR2.Raw.Intune = @{
        MdmUrl           = $mdmUrl
        MdmComplianceUrl = $mdmComplianceUrl
    }

    $ime = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
    if ($ime) {
        $BR2.Raw.Intune.IMEState = $ime.Status

        # IME scripts cache - readable to admins, often contains embedded creds
        $imeScripts = "$env:ProgramData\Microsoft\IntuneManagementExtension\Policies\Scripts"
        $imeResults = "$env:ProgramData\Microsoft\IntuneManagementExtension\Policies\Results"

        if ($ctx.Elevated -and (Test-Path $imeScripts)) {
            $scripts = Get-ChildItem -Path $imeScripts -File -ErrorAction SilentlyContinue
            if ($scripts.Count -gt 0) {
                # Scan for hardcoded credentials in deployed scripts
                $credMatches = @()
                foreach ($s in $scripts) {
                    try {
                        $c = Get-Content $s.FullName -Raw -ErrorAction Stop
                        if ($c -match 'password\s*=|ConvertTo-SecureString.*-AsPlainText|"P@ssw|apikey|api_key|-Credential') {
                            $credMatches += $s.FullName
                        }
                    } catch {}
                }

                if ($credMatches.Count -gt 0) {
                    $BR2.Findings.Add( (New-Finding `
                        -CheckID 'BR-AAD-006' `
                        -Category 'Entra' `
                        -Title "Intune-deployed PowerShell scripts on disk contain potential embedded credentials ($($credMatches.Count) file(s))" `
                        -Severity 'High' `
                        -Exploitability 'High' `
                        -AttackPath 'Intune Management Extension caches deployed scripts unencrypted on disk; admins can read' `
                        -MITRE 'T1552.001' `
                        -Evidence @{
                            ScriptDir  = $imeScripts
                            Matches    = @($credMatches | Select-Object -First 5)
                        } `
                        -Remediation 'Remove embedded credentials from Intune platform scripts. Use Key Vault retrieval at runtime or managed identities.' `
                        -OperatorNotes 'IME downloads scripts to %ProgramData%\Microsoft\IntuneManagementExtension\Policies\Scripts and executes as SYSTEM. Cached copy readable to any admin after deployment. Frequent finding: service account credentials hardcoded for domain-join or software-deployment scripts.' `
                        -References @('https://github.com/mrwadams/intune-assessment')
                    ))
                }
            }
        }
    }
}

# Device compliance state
# dsregcmd parses CompliantWithMDM indirectly - check the common location
$compliant = Parse-DsregLine -Lines $dsregOutput -Field 'IsDeviceJoined'
# Not perfect, but captures workgroup-registered vs properly-compliant

# Seamless SSO detection
# If Seamless SSO is enabled the AZUREADSSOACC machine account exists in AD.
# From a local host, best signal is successful AAD PRT without WHfB prompt combined with the AD join state. Record as raw data.
