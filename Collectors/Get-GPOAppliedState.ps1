#requires -Version 5.1


$ctx = $global:BR2.Context

if (-not $ctx.IsDomainJoined) { return }

# SYSVOL reachability
$domainDNS = $ctx.DomainName
$sysvolRoot = "\\$domainDNS\SYSVOL\$domainDNS\Policies"

if (-not (Test-Path $sysvolRoot)) {
    $BR2.Skipped.Add([PSCustomObject]@{
        Collector = 'GPOAppliedState'
        Reason    = "SYSVOL share not reachable at $sysvolRoot - may be offline, or DC disallows the current user to traverse."
    })
    return
}


$gppPatterns = @('Groups.xml','ScheduledTasks.xml','Services.xml','DataSources.xml','Printers.xml','Drives.xml')

$cpasswordHits = @()
try {
    foreach ($pattern in $gppPatterns) {
        $files = Get-ChildItem -Path $sysvolRoot -Recurse -Filter $pattern -ErrorAction SilentlyContinue -Force
        foreach ($f in $files) {
            try {
                $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
                if ($content -match 'cpassword="([^"]+)"') {
                    $cpassword = $Matches[1]
                    if ($cpassword -and $cpassword.Length -gt 0) {
                        $cpasswordHits += [PSCustomObject]@{
                            File      = $f.FullName
                            Cpassword = $cpassword
                            Pattern   = $pattern
                        }
                    }
                }
            } catch {}
        }
    }
} catch {}

$BR2.Raw.GPPcpassword = @{
    HitCount = $cpasswordHits.Count
    Files    = @($cpasswordHits.File)
}

if ($cpasswordHits.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-MISC-002' `
        -Category 'Credentials' `
        -Title "Group Policy Preferences cpassword blobs found in SYSVOL ($($cpasswordHits.Count) file(s))" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'MS14-025 / CVE-2014-1812 - decrypt cpassword using Microsoft-published static AES key; yields plaintext credentials' `
        -MITRE 'T1552.006' `
        -Evidence @{
            HitCount = $cpasswordHits.Count
            Files    = @($cpasswordHits | Select-Object -First 5 -ExpandProperty File)
        } `
        -Remediation 'Delete the offending XML files from SYSVOL (or remove the cpassword attribute). MS14-025 prevents creating new entries but existing ones were never removed. Rotate any credentials that were stored.' `
        -OperatorNotes ('Static key is known since 2014. Get-GPPPassword from PowerSploit, gpp-decrypt, or one-liner: the AES key is 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b hex. Any domain user can sweep SYSVOL and decrypt. Credentials stored were usually the domain-wide local admin password (pre-LAPS era). Example cpassword to decrypt: ' + ($cpasswordHits[0].Cpassword.Substring(0, [Math]::Min(32, $cpasswordHits[0].Cpassword.Length)) + '...')) `
        -References @(
            'https://msrc.microsoft.com/update-guide/vulnerability/MS14-025',
            'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1',
            'https://adsecurity.org/?p=2288'
        )
    ))
}

# gpresult parse: delegated admin & scripts
# gpresult /z /scope:computer gives a detailed XML of applied policies.
# Parse for Restricted Groups / Group Policy Preferences applied locally
# and logon / startup scripts hosted on writable shares.

$gpresultXml = "$env:TEMP\gpresult_$([guid]::NewGuid().ToString('N')).xml"
try {
    & gpresult.exe /scope:computer /x $gpresultXml /f 2>$null | Out-Null
    if (Test-Path $gpresultXml) {
        [xml]$gp = Get-Content $gpresultXml -Raw
        Remove-Item $gpresultXml -Force -ErrorAction SilentlyContinue

        # Startup / logon scripts
        $scripts = $gp.SelectNodes("//*[local-name()='Script']")
        foreach ($script in $scripts) {
            $cmd = $script.Command
            if ($cmd -and ($cmd -like '\\\\*')) {
                # UNC path - check writability
                if (Test-Path -LiteralPath $cmd -ErrorAction SilentlyContinue) {
                    try {
                        $acl = Get-Acl -LiteralPath $cmd
                        $writable = $false
                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -eq 'Allow' -and
                                $ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                                "$($ace.IdentityReference)" -match 'Users|Everyone|Authenticated Users|Domain Users') {
                                $writable = $true
                                break
                            }
                        }
                        if ($writable) {
                            $BR2.Findings.Add( (New-Finding `
                                -CheckID 'BR-GPO-010' `
                                -Category 'GroupPolicy' `
                                -Title "GPO-delivered script at writable UNC path: $cmd" `
                                -Severity 'Critical' `
                                -Exploitability 'High' `
                                -AttackPath 'Overwrite GPO-delivered startup/logon script on writable share; next policy refresh runs attacker code as SYSTEM or user' `
                                -MITRE 'T1574.010' `
                                -Evidence @{
                                    ScriptPath = $cmd
                                    ScriptType = $script.Type
                                } `
                                -Remediation 'Move the script to a properly-ACLed share (SYSVOL is correct). Fix ACLs on the referenced share.' `
                                -OperatorNotes 'gpupdate /force on the victim host triggers re-run. Stealthy: append commands to the existing script rather than replace.' `
                                -References @()
                            ))
                        }
                    } catch {}
                }
            }
        }

        # Restricted Groups policies applying to this host
        $rgs = $gp.SelectNodes("//*[local-name()='RestrictedGroups']")
        if ($rgs.Count -gt 0) {
            $BR2.Raw.RestrictedGroups = $rgs.Count
            # Not automatically bad - but worth capturing
        }
    }
} catch {
    $BR2.Skipped.Add([PSCustomObject]@{
        Collector = 'GPOAppliedState'
        Check     = 'gpresult-parse'
        Reason    = "gpresult /x failed: $($_.Exception.Message)"
    })
}
