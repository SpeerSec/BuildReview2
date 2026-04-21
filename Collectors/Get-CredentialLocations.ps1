#requires -Version 5.1


$ctx = $global:BR2.Context

# Browser: Chrome
$chromeData = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
if (Test-Path $chromeData) {
    $profiles = Get-ChildItem -Path $chromeData -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(Default|Profile \d+)$' }

    $loginDatas = @()
    $cookies    = @()
    foreach ($p in $profiles) {
        $ld = Join-Path $p.FullName 'Login Data'
        $ck = Join-Path $p.FullName 'Network\Cookies'
        if (Test-Path $ld) { $loginDatas += $ld }
        if (Test-Path $ck) { $cookies    += $ck }
    }

    if ($loginDatas.Count -gt 0 -or $cookies.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BRW-001' `
            -Category 'Credentials' `
            -Title "Chrome credential stores present in user profile ($($loginDatas.Count) Login Data, $($cookies.Count) Cookie store(s))" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'DPAPI-protected Chrome Login Data and cookie DBs extractable from current user context - session hijack and plaintext password recovery' `
            -MITRE @('T1555.003','T1539') `
            -Evidence @{
                LoginDataPaths = $loginDatas
                CookiePaths    = $cookies
            } `
            -Remediation 'User-level credential store. Organisational mitigations: enforce hardware-backed SSO (FIDO2), block password manager usage via GPO, or deploy DLP with browser isolation.' `
            -OperatorNotes 'As the owning user: SharpChrome logins / SharpChrome cookies decrypt via user DPAPI. Since Chrome v127 (mid-2024), App-Bound Encryption wraps the Chrome master key in a SYSTEM DPAPI blob via the elevation service - needs SYSTEM context to decrypt, not just user. Chlonium / Donut-Chrome / the newer SharpChromeV2 handle App-Bound Encryption (2024+). For cookies: pull the ESCAPE cookie + the AAD / Office365 cookies and then pass-the-cookie into browser for SSO to tenant apps.' `
            -References @(
                'https://github.com/GhostPack/SharpDPAPI',
                'https://embracethered.com/blog/posts/2024/chrome-app-bound-encryption-bypass/',
                'https://posts.specterops.io/chrome-cookie-theft-app-bound-encryption-and-how-to-bypass-it-a3b2a5a2c9b6'
            )
        ))
    }

    $BR2.Raw.BrowserChrome = @{
        Profiles   = @($profiles.Name)
        HasLoginData = ($loginDatas.Count -gt 0)
    }
}

# Browser: Edge
$edgeData = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
if (Test-Path $edgeData) {
    $edgeProfiles = Get-ChildItem -Path $edgeData -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(Default|Profile \d+)$' }

    $edgeLogins = @()
    $edgeCookies = @()
    foreach ($p in $edgeProfiles) {
        $ld = Join-Path $p.FullName 'Login Data'
        $ck = Join-Path $p.FullName 'Network\Cookies'
        if (Test-Path $ld) { $edgeLogins += $ld }
        if (Test-Path $ck) { $edgeCookies += $ck }
    }

    if ($edgeLogins.Count -gt 0 -or $edgeCookies.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BRW-002' `
            -Category 'Credentials' `
            -Title "Edge credential stores present ($($edgeLogins.Count) Login Data, $($edgeCookies.Count) Cookie store(s))" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'DPAPI-protected Edge stores; enterprise SSO cookies often bind to Entra ID session - high-value cookie for tenant access' `
            -MITRE @('T1555.003','T1539') `
            -Evidence @{
                LoginDataPaths = $edgeLogins
                CookiePaths    = $edgeCookies
            } `
            -Remediation 'Enforce Edge enterprise policies - prevent password manager where SSO is mandated, require hardware-backed WebAuthn. Chromium Edge shares the App-Bound Encryption model since late 2024.' `
            -OperatorNotes 'Edge is often the primary enterprise browser - its cookie jar typically has Office 365, Azure Portal, and tenant-app sessions. Steal the ESTSAUTH / ESTSAUTHPERSISTENT cookies + device-bound AAD PRT cookie for full tenant SSO.' `
            -References @('https://github.com/Mr-Un1k0d3r/EDRs/blob/main/EdgePasswords.cs')
        ))
    }
}

# Browser: Firefox
$firefoxData = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if (Test-Path $firefoxData) {
    $ffProfiles = Get-ChildItem -Path $firefoxData -Directory -ErrorAction SilentlyContinue
    $hasLogins = $false
    foreach ($p in $ffProfiles) {
        if ((Test-Path (Join-Path $p.FullName 'logins.json')) -or
            (Test-Path (Join-Path $p.FullName 'key4.db'))) {
            $hasLogins = $true; break
        }
    }

    if ($hasLogins) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BRW-003' `
            -Category 'Credentials' `
            -Title 'Firefox credential store present in user profile' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Firefox logins.json + key4.db combination recoverable; if no Master Password set, plaintext recovery is immediate' `
            -MITRE 'T1555.003' `
            -Evidence @{
                ProfilePath  = $firefoxData
                ProfileCount = $ffProfiles.Count
            } `
            -Remediation 'Enforce a Firefox Primary Password (previously Master Password) via enterprise policy. Better: prevent Firefox password storage entirely in managed environments.' `
            -OperatorNotes 'firefox_decrypt.py or the numerous Go/Rust ports. key4.db + logins.json + (if set) primary password yields plaintexts. No DPAPI protection by default, just NSS-wrapped.' `
            -References @('https://github.com/unode/firefox_decrypt')
        ))
    }
}

# Unattend / sysprep / provisioning
$unattendPaths = @(
    "$env:SystemDrive\unattend.xml",
    "$env:SystemDrive\unattend.txt",
    "$env:SystemRoot\Panther\unattend.xml",
    "$env:SystemRoot\Panther\unattended.xml",
    "$env:SystemRoot\System32\sysprep\unattend.xml",
    "$env:SystemRoot\System32\sysprep\sysprep.xml",
    "$env:SystemRoot\System32\sysprep\sysprep.inf",
    "$env:SystemRoot\Panther\Setup\Scripts\SetupComplete.cmd",
    "$env:SystemRoot\Provisioning\Autopilot",
    "$env:ProgramData\Microsoft\Provisioning"
)

$foundUnattend = @()
foreach ($p in $unattendPaths) {
    if (Test-Path $p) {
        # Quick check for password content
        if ($p.EndsWith('.xml') -or $p.EndsWith('.inf') -or $p.EndsWith('.txt') -or $p.EndsWith('.cmd')) {
            try {
                $c = Get-Content $p -Raw -ErrorAction SilentlyContinue
                if ($c -match '<Password>|<Value>.*</Value>|Password\s*=|AutoLogon') {
                    $foundUnattend += $p
                }
            } catch {}
        } else {
            # Directory - flag presence for manual review
            $foundUnattend += $p
        }
    }
}

if ($foundUnattend.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-MISC-001' `
        -Category 'Credentials' `
        -Title "Unattend / sysprep / provisioning artefacts present with credential patterns ($($foundUnattend.Count) location(s))" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Imaging-time credentials left on disk - typically local Administrator password or domain-join account' `
        -MITRE 'T1552.001' `
        -Evidence @{ Locations = $foundUnattend } `
        -Remediation 'Remove or sanitise post-deployment. Sysprep best practice: generalise then delete Panther logs, unattend.xml, and any provisioning package cache.' `
        -OperatorNotes 'unattend.xml passwords are base64-encoded cleartext. Domain-join credentials sometimes ride the same file and have wider blast radius than local admin. For Autopilot / provisioning packages, the .ppkg files are unencrypted ZIPs, inspect contents with any archive tool.' `
        -References @('https://attack.mitre.org/techniques/T1552/001/')
    ))
}

# PuTTY saved sessions
$puttyRegPath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
if (Test-Path $puttyRegPath) {
    $sessions = Get-ChildItem -Path $puttyRegPath -ErrorAction SilentlyContinue
    if ($sessions.Count -gt 0) {
        # Check for private key auth paths (key file locations)
        $withKeys = @()
        foreach ($s in $sessions) {
            $pkf = (Get-ItemProperty -Path $s.PSPath -Name 'PublicKeyFile' -ErrorAction SilentlyContinue).PublicKeyFile
            if ($pkf) { $withKeys += [PSCustomObject]@{ Session = $s.PSChildName; KeyFile = $pkf } }
        }

        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-MISC-003' `
            -Category 'Credentials' `
            -Title "PuTTY saved sessions present ($($sessions.Count) session(s), $($withKeys.Count) with key files)" `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'Enumerate SSH targets and read referenced private key files directly from user context' `
            -MITRE 'T1552.004' `
            -Evidence @{
                SessionCount = $sessions.Count
                Sessions     = @($sessions.PSChildName | Select-Object -First 10)
                KeyFiles     = $withKeys
            } `
            -Remediation 'Not directly a misconfiguration. Consider enterprise SSH policies: central key management, hardware-token-backed keys, bastion/jump-host model that prevents saved direct-to-target sessions.' `
            -OperatorNotes 'Saved sessions reveal target hosts (internal IPs, non-routable names, test/admin hosts). Key files are usually at %USERPROFILE%\.ssh\ or beside PuTTY. If passphrase-less, direct use. If passphrased, keyloggers / clipboard capture during next use. Also check HKCU\Software\USERNAME\PuTTY\SshHostKeys for host key cache - confirms recent SSH activity.' `
            -References @('https://the.earth.li/~sgtatham/putty/0.80/htmldoc/Chapter4.html')
        ))
    }
}

# SSH keys
$sshDir = Join-Path $env:USERPROFILE '.ssh'
if (Test-Path $sshDir) {
    $keyFiles = Get-ChildItem -Path $sshDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^id_(rsa|ecdsa|ed25519|dsa)$' }
    $configFile = Join-Path $sshDir 'config'

    if ($keyFiles.Count -gt 0 -or (Test-Path $configFile)) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-MISC-004' `
            -Category 'Credentials' `
            -Title "OpenSSH keys / config present in user profile ($($keyFiles.Count) private key(s))" `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'Private key recovery from user context; config file enumerates SSH targets' `
            -MITRE 'T1552.004' `
            -Evidence @{
                Keys     = @($keyFiles.Name)
                HasConfig = (Test-Path $configFile)
                Dir       = $sshDir
            } `
            -Remediation 'Require passphrase protection on private keys. Consider hardware-backed keys (YubiKey, TPM-backed ssh-tpm-agent).' `
            -OperatorNotes 'Copy id_* files out. If passphrased: john ssh2john.py -> hashcat -m 22921. Also check ~/.ssh/known_hosts for recently-connected hosts (grep for internal hostnames). Persistence opportunity: append attacker key to ~/.ssh/authorized_keys on target hosts once pivotted.' `
            -References @()
        ))
    }
}

# WSL (Windows Subsystem for Linux)
$wslService = Get-Service -Name 'LxssManager' -ErrorAction SilentlyContinue
if ($wslService) {
    $wslPackages = Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match 'CanonicalGroupLimited|TheDebianProject|KaliLinux|SUSE' }

    if ($wslPackages.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-MISC-005' `
            -Category 'Credentials' `
            -Title "WSL distributions installed ($($wslPackages.Count)) - Linux home directories accessible" `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'WSL Linux filesystem accessible under %LOCALAPPDATA%\Packages\<distro>\LocalState\rootfs - readable without WSL running' `
            -MITRE 'T1552' `
            -Evidence @{
                Distributions = @($wslPackages.Name)
            } `
            -Remediation 'Treat WSL as part of the Windows attack surface. Apply endpoint controls to WSL vhdx mount points. Avoid storing credentials in WSL home directories that are not also protected on Windows.' `
            -OperatorNotes "WSL2 uses per-distro ext4 vhdx files. Mount them offline from Windows for a full filesystem view. Common finds: ~/.ssh/, ~/.aws/credentials, ~/.azure/, ~/.kube/config, ~/.netrc, git config with tokens. WSL doesn't inherit Defender exclusions, pivoting through WSL bypasses some AV rules." `
            -References @('https://docs.microsoft.com/en-us/windows/wsl/')
        ))
    }
}

# Azure CLI / AWS CLI / gcloud
$cloudPaths = @(
    @{ Path = (Join-Path $env:USERPROFILE '.azure\accessTokens.json');     CLI = 'Azure CLI (legacy)' }
    @{ Path = (Join-Path $env:USERPROFILE '.azure\msal_token_cache.json'); CLI = 'Azure CLI (MSAL)' }
    @{ Path = (Join-Path $env:USERPROFILE '.azure\azureProfile.json');      CLI = 'Azure CLI profile' }
    @{ Path = (Join-Path $env:USERPROFILE '.aws\credentials');              CLI = 'AWS CLI' }
    @{ Path = (Join-Path $env:USERPROFILE '.aws\config');                   CLI = 'AWS CLI config' }
    @{ Path = (Join-Path $env:APPDATA 'gcloud\credentials.db');             CLI = 'gcloud' }
    @{ Path = (Join-Path $env:APPDATA 'gcloud\access_tokens.db');           CLI = 'gcloud access tokens' }
    @{ Path = (Join-Path $env:USERPROFILE '.kube\config');                  CLI = 'kubectl' }
    @{ Path = (Join-Path $env:USERPROFILE '.docker\config.json');           CLI = 'Docker (registry auth)' }
    @{ Path = (Join-Path $env:APPDATA 'GitHub CLI\hosts.yml');              CLI = 'GitHub CLI' }
)

$cloudHits = @()
foreach ($entry in $cloudPaths) {
    if (Test-Path $entry.Path) {
        $cloudHits += $entry
    }
}

if ($cloudHits.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-MISC-007' `
        -Category 'Credentials' `
        -Title "Cloud CLI credential files present ($($cloudHits.Count) location(s))" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Direct credential / token recovery from user-profile CLI caches - pivot from endpoint to cloud tenancy' `
        -MITRE 'T1552.001' `
        -Evidence @{
            Hits = @($cloudHits | ForEach-Object { "$($_.CLI) : $($_.Path)" })
        } `
        -Remediation 'Enforce short-lived tokens, hardware-backed keys where available (IAM Roles Anywhere with TPM for AWS; Workload Identity for GCP). Block long-lived access keys via policy.' `
        -OperatorNotes ('Highest-impact files: .aws/credentials (long-lived access keys), .azure/accessTokens.json (refresh tokens), gcloud/credentials.db (SQLite with refresh tokens). Copy out, use from attacker box with respective CLI. For MSAL token cache: parse with TokenSmith or roadtx tokens --token-file. For kube/config: often includes cluster-admin certs or long-lived tokens - pivot straight into K8s control plane.') `
        -References @(
            'https://hackingthe.cloud/',
            'https://github.com/dirkjanm/ROADtools'
        )
    ))
}

# Credential Manager Vault + RDP cached sessions
# Covered in LSA collector (BR-LSA-010) - avoid duplicate here.

# ---- Generic registry sweep for credential-pattern values -----------

if ($ctx.Elevated) {
    # Look for obvious plaintext in HKLM under Run/RunOnce and Services
    $regTargets = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($t in $regTargets) {
        if (-not (Test-Path $t)) { continue }
        try {
            $props = Get-ItemProperty -Path $t -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -match 'PS(Path|ParentPath|ChildName|Provider|Drive)') { continue }
                $v = "$($p.Value)"
                if ($v -match '(?i)password|pwd=|-p\s+[^\s"]+|token=|apikey=|secret=') {
                    $BR2.Findings.Add( (New-Finding `
                        -CheckID 'BR-MISC-010' `
                        -Category 'Credentials' `
                        -Title "Autorun registry value '$($p.Name)' contains credential-like substring" `
                        -Severity 'High' `
                        -Exploitability 'High' `
                        -AttackPath 'Cleartext credentials in boot-time / login-time registry keys' `
                        -MITRE 'T1552.002' `
                        -Evidence @{
                            Key        = $t
                            ValueName  = $p.Name
                            Pattern    = 'password|pwd|-p|token|apikey|secret'
                        } `
                        -Remediation 'Remove plaintext credentials from autorun commands. Use credential stores or scheduled-task-with-stored-credential (imperfect but better) instead.' `
                        -OperatorNotes 'Frequent pattern: legacy helper apps with mapped drive commands including /user:DOMAIN\svcacct /persistent:no followed by a plaintext password. Also: VPN auto-connect scripts, backup utility runners.' `
                        -References @()
                    ))
                }
            }
        } catch {}
    }
}
