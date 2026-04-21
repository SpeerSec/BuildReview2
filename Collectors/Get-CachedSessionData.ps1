#requires -Version 5.1


$ctx = $global:BR2.Context

# ---- Wi-Fi saved profiles with retrievable PSKs -----------------------

$wifiProfiles = @()
try {
    $allProfiles = & netsh.exe wlan show profiles 2>$null
    foreach ($line in $allProfiles) {
        if ($line -match 'All User Profile\s*:\s*(.+)$') {
            $name = $Matches[1].Trim()
            $wifiProfiles += $name
        }
    }
} catch {}

$retrievablePSKs = @()
foreach ($profile in $wifiProfiles) {
    try {
        # The key=clear flag prints the PSK in plaintext if the running user has admin
        # or ran the command elevated on an earlier session when cached
        $detail = & netsh.exe wlan show profile name="$profile" key=clear 2>$null
        $keyContent = ($detail | Select-String -Pattern 'Key Content\s*:\s*(.+)$' | Select-Object -First 1)
        if ($keyContent) {
            $retrievablePSKs += [PSCustomObject]@{
                Profile = $profile
                PSK     = $keyContent.Matches[0].Groups[1].Value.Trim()
            }
        }
    } catch {}
}

if ($wifiProfiles.Count -gt 0) {
    $BR2.Raw.WiFi = @{
        ProfileCount       = $wifiProfiles.Count
        Profiles           = $wifiProfiles
        RetrievablePSKs    = $retrievablePSKs.Count
    }

    if ($retrievablePSKs.Count -gt 0 -and $ctx.Elevated) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WIFI-001' `
            -Category 'Credentials' `
            -Title "$($retrievablePSKs.Count) Wi-Fi PSK(s) retrievable in plaintext" `
            -Severity 'Low' `
            -Exploitability 'High' `
            -AttackPath 'Wi-Fi PSKs recovered from netsh wlan show profile key=clear - network access from adjacent physical position' `
            -MITRE 'T1555' `
            -Evidence @{
                RetrievableCount = $retrievablePSKs.Count
                Profiles         = @($retrievablePSKs.Profile)
            } `
            -Remediation 'Not directly a build misconfig - but awareness of which networks are pre-provisioned matters for decommissioning lost devices.' `
            -OperatorNotes 'Lost/stolen laptop = attacker gets office Wi-Fi PSK. Adjacent-network pivoting if the corporate Wi-Fi is WPA2-PSK (rather than WPA2-Enterprise). For WPA2-Enterprise, netsh does not show usable creds - check EAP configs separately.' `
            -References @()
        ))
    }
}

# ---- VPN profiles (built-in Windows VPN) -----------------------------

$vpnConfigPath = "$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk"
if (Test-Path $vpnConfigPath) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-VPN-001' `
        -Category 'Credentials' `
        -Title 'Windows built-in VPN profile(s) configured in user context' `
        -Severity 'Low' `
        -Exploitability 'Medium' `
        -AttackPath 'User VPN connection configured - credentials stored via DPAPI if saved' `
        -MITRE 'T1555' `
        -Evidence @{ Path = $vpnConfigPath } `
        -Remediation 'Not directly a finding - user awareness of where credentials are cached matters for incident response.' `
        -OperatorNotes 'As the owning user: rasdial.exe with no args lists connection names. If Remember Password was set, credential stored in Vault (see LSA collector BR-LSA-010). Useful to understand VPN target network.' `
        -References @()
    ))
}

# Cisco AnyConnect / OpenVPN / Global Protect saved profile detection
$vpnClientPaths = @(
    @{ Path = "$env:ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\profile"; Client = 'Cisco AnyConnect' }
    @{ Path = "$env:ProgramData\Palo Alto Networks\GlobalProtect"; Client = 'Palo Alto GlobalProtect' }
    @{ Path = "$env:ProgramData\OpenVPN"; Client = 'OpenVPN' }
    @{ Path = "$env:USERPROFILE\OpenVPN\config"; Client = 'OpenVPN (user config)' }
    @{ Path = "$env:ProgramData\Fortinet\FortiClient"; Client = 'FortiClient' }
)
$vpnClients = @()
foreach ($vp in $vpnClientPaths) {
    if (Test-Path $vp.Path) {
        $vpnClients += $vp.Client
    }
}
if ($vpnClients.Count -gt 0) {
    $BR2.Raw.VPNClients = $vpnClients
    # Informational only - presence is not a finding but pivot-relevant
}

# Saved .rdp files with embedded credentials
$rdpSearchRoots = @(
    [Environment]::GetFolderPath('MyDocuments'),
    [Environment]::GetFolderPath('Desktop'),
    "$env:USERPROFILE\Downloads"
)
$rdpFiles = @()
foreach ($root in $rdpSearchRoots) {
    if (-not (Test-Path $root)) { continue }
    $rdpFiles += Get-ChildItem -Path $root -Recurse -Filter '*.rdp' -ErrorAction SilentlyContinue -Force |
                 Select-Object -First 50
}

if ($rdpFiles.Count -gt 0) {
    $rdpWithCreds = @()
    foreach ($f in $rdpFiles) {
        try {
            $c = Get-Content $f.FullName -Raw -ErrorAction Stop
            if ($c -match '(?m)^password\s+\d+:b:' -or $c -match '(?m)^username:s:') {
                $rdpWithCreds += $f.FullName
            }
        } catch {}
    }

    if ($rdpWithCreds.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-RDP-010' `
            -Category 'Credentials' `
            -Title "$($rdpWithCreds.Count) saved .rdp file(s) contain username or DPAPI-protected password" `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'RDP connection files with saved credentials - DPAPI-protected password blob recoverable as owning user' `
            -MITRE @('T1555','T1021.001') `
            -Evidence @{ Files = @($rdpWithCreds | Select-Object -First 5) }  `
            -Remediation 'User awareness of credential storage. Enterprise policies to disable "Save password" in mstsc.' `
            -OperatorNotes 'Copy .rdp, parse password blob (base64 in the password 51:b: line), decrypt with SharpDPAPI rdg or equivalent. Gives plaintext credential for the named server.' `
            -References @('https://github.com/GhostPack/SharpDPAPI')
        ))
    }

    $BR2.Raw.SavedRDPFiles = $rdpFiles.Count
}

# PowerShell console history via PSReadLine
$psrlHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psrlHistoryPath) {
    try {
        $history = Get-Content $psrlHistoryPath -Raw -ErrorAction Stop
        $lines = ($history -split "`n").Count
        $hasCreds = $history -match '(?i)password|-asplainText|ConvertTo-SecureString|ApiKey|token|secret\s*=|\-p\s+["'']?[^\s"'']+'

        $BR2.Raw.PSHistory = @{
            Path      = $psrlHistoryPath
            LineCount = $lines
            LooksLikeCreds = $hasCreds
        }

        if ($hasCreds) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-PS-020' `
                -Category 'Credentials' `
                -Title 'PowerShell PSReadLine history contains potential credential patterns' `
                -Severity 'Medium' `
                -Exploitability 'High' `
                -AttackPath 'Plaintext history of interactive PowerShell commands - frequently captures credentials typed inline' `
                -MITRE 'T1552.001' `
                -Evidence @{
                    Path      = $psrlHistoryPath
                    LineCount = $lines
                } `
                -Remediation 'Clear via Clear-History -and- delete ConsoleHost_history.txt. For lasting mitigation, configure PSReadLine HistorySaveStyle to SaveNothing or set sensitive-string filter.' `
                -OperatorNotes 'First file I look for on any foothold host. Admin PowerShell profiles are goldmines - domain admin credentials, API keys, secrets typed via -AsPlainText ConvertTo-SecureString patterns all end up here. Also check individual tool histories (e.g. pwsh 7 lives at a different path).' `
                -References @()
            ))
        }
    } catch {}
}

# PowerShell 7 history (separate location)
$ps7History = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"  # usually same for 7, but some configs differ

# Git credential cache
$gitCreds = "$env:USERPROFILE\.git-credentials"
$gitConfig = "$env:USERPROFILE\.gitconfig"
if (Test-Path $gitCreds) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-GIT-001' `
        -Category 'Credentials' `
        -Title 'Git plaintext credentials file present: ~/.git-credentials' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Git credential helper "store" puts tokens/passwords in plaintext - direct read' `
        -MITRE 'T1552.001' `
        -Evidence @{ Path = $gitCreds } `
        -Remediation 'Switch to Git Credential Manager (GCM) or Windows Credential Manager helper. Remove .git-credentials after migration.' `
        -OperatorNotes 'Simple grep pulls Git personal access tokens (PATs). Often include scope for private repos, CI/CD systems. GitHub/GitLab/Bitbucket all write here if "store" helper is configured.' `
        -References @('https://git-scm.com/docs/git-credential-store')
    ))
}

# Git config with useful pivot info
if (Test-Path $gitConfig) {
    $BR2.Raw.GitConfig = @{
        Present = $true
    }
    # Parse email and remote URLs for recon context
    try {
        $gc = Get-Content $gitConfig -Raw
        if ($gc -match '(?i)email\s*=\s*(.+)') {
            $BR2.Raw.GitConfig.Email = $Matches[1].Trim()
        }
    } catch {}
}

# Recent documents and typed paths (pivot / profiling)
$recentFolder = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentFolder) {
    $recentCount = (Get-ChildItem -Path $recentFolder -Filter '*.lnk' -ErrorAction SilentlyContinue).Count
    $BR2.Raw.RecentFiles = @{ Count = $recentCount }
}

# Typed URLs - indicator of user's browsing targets
$typedUrlPath = 'HKCU:\Software\Microsoft\Internet Explorer\TypedURLs'
if (Test-Path $typedUrlPath) {
    $typedUrls = (Get-ItemProperty -Path $typedUrlPath -ErrorAction SilentlyContinue).PSObject.Properties |
                 Where-Object { $_.Name -match '^url\d+$' } | Select-Object -ExpandProperty Value
    $BR2.Raw.TypedURLs = @($typedUrls | Select-Object -First 10)
}

# Typed paths (Run dialog history)
$typedPathPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
if (Test-Path $typedPathPath) {
    $typedPaths = (Get-ItemProperty -Path $typedPathPath -ErrorAction SilentlyContinue).PSObject.Properties |
                  Where-Object { $_.Name -match '^url\d+$' } | Select-Object -ExpandProperty Value
    $BR2.Raw.TypedPaths = @($typedPaths | Select-Object -First 10)
}

# Microsoft Teams / Slack / Discord tokens
# Teams stores cached tokens in a leveldb under Cookies/Local Storage
$teamsPaths = @(
    "$env:APPDATA\Microsoft\Teams\Cookies",
    "$env:LOCALAPPDATA\Microsoft\Teams\current\resources\app\browser"
)
foreach ($tp in $teamsPaths) {
    if (Test-Path $tp) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-APP-001' `
            -Category 'Credentials' `
            -Title "Microsoft Teams application data present: $tp" `
            -Severity 'Low' `
            -Exploitability 'Medium' `
            -AttackPath 'Teams cookies / tokens extractable from Electron cache - pivot to Microsoft Graph / Teams / Office 365 as signed-in user' `
            -MITRE 'T1539' `
            -Evidence @{ Path = $tp } `
            -Remediation 'Not a misconfig per se. For high-value admin hosts, consider PIM (Privileged Identity Management) so long-lived tokens are absent.' `
            -OperatorNotes 'teams-token-stealer / Donut-Token tools parse the Teams Cookies leveldb for skype/graph tokens. Convert to Graph access via TokenSmith. Particularly valuable on admin workstations logged into privileged Teams tenants.' `
            -References @()
        ))
        break
    }
}

$slackPath = "$env:APPDATA\Slack"
if (Test-Path $slackPath) {
    $BR2.Raw.SlackPresent = $true
}

# VSCode secrets / settings
$vscodeSettings = "$env:APPDATA\Code\User\settings.json"
if (Test-Path $vscodeSettings) {
    try {
        $content = Get-Content $vscodeSettings -Raw -ErrorAction SilentlyContinue
        if ($content -match '(?i)token|apikey|api_key|password|secret') {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-VSCODE-001' `
                -Category 'Credentials' `
                -Title 'VSCode settings.json contains credential-like patterns' `
                -Severity 'Medium' `
                -Exploitability 'High' `
                -AttackPath 'Settings file credentials for extensions (GitHub Copilot, Azure, SSH, Docker registries)' `
                -MITRE 'T1552.001' `
                -Evidence @{ Path = $vscodeSettings } `
                -Remediation 'Move credentials to extension-specific secure storage (VSCode secretStorage API) or use environment variables / credential managers.' `
                -OperatorNotes 'Common finds: connection strings in Database Client extensions, tokens in REST Client, registry credentials in Docker. Also worth checking $env:APPDATA\Code\User\globalStorage\ for extension-specific caches.' `
                -References @()
            ))
        }
    } catch {}
}

# Cursor / other Electron IDEs follow same pattern but skipped for brevity
