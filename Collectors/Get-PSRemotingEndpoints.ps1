#requires -Version 5.1



$ctx = $global:BR2.Context

# Strict gate: service must exist AND be running. Get-PSSessionConfiguration on a stopped WinRM triggers Windows to prompt the user to enable WinRM.
$winrm = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
if (-not $winrm -or $winrm.Status -ne 'Running') { return }

# Verify WSMan provider is queryable before proceeding
try {
    $null = Get-ChildItem -Path 'WSMan:\localhost\Plugin' -ErrorAction Stop
} catch {
    return
}

$sessionConfigs = @()
try {
    $sessionConfigs = Get-PSSessionConfiguration -ErrorAction Stop
} catch {
    $BR2.Skipped.Add([PSCustomObject]@{
        Collector = 'PSRemotingEndpoints'
        Reason    = "Get-PSSessionConfiguration failed: $($_.Exception.Message)"
    })
    return
}

$BR2.Raw.PSSessionConfigurations = @{
    Count = $sessionConfigs.Count
    Names = @($sessionConfigs.Name)
}

$defaultNames = @(
    'Microsoft.PowerShell',
    'Microsoft.PowerShell.Workflow',
    'Microsoft.PowerShell32',
    'Microsoft.WSMan.Management',
    'PowerShell.7'
)

$customConfigs = @()
foreach ($cfg in $sessionConfigs) {
    if ($defaultNames -contains $cfg.Name) { continue }
    if ($cfg.Name -match '^PowerShell\.7\.\d') { continue }
    $customConfigs += $cfg
}

foreach ($cfg in $customConfigs) {
    $runAs = $null
    try { $runAs = (Get-PSSessionConfiguration -Name $cfg.Name -ErrorAction SilentlyContinue).RunAsUser } catch {}

    $sddl = $cfg.SecurityDescriptorSddl
    $hasNonAdminAccess = $false
    $nonAdminPrincipals = @()
    if ($sddl) {
        try {
            $parsed = ConvertFrom-SddlString -Sddl $sddl -ErrorAction SilentlyContinue
            foreach ($ace in $parsed.DiscretionaryAcl) {
                if ($ace -match '^(?<principal>[^:]+):\s*(?<rights>.+)$') {
                    $principal = $Matches.principal.Trim()
                    if ($principal -match 'Administrators|SYSTEM|NT SERVICE|TrustedInstaller|CREATOR OWNER') { continue }
                    if ($principal -match 'Remote Management Users|Users|Everyone|Authenticated Users|Domain Users') {
                        $hasNonAdminAccess = $true
                        $nonAdminPrincipals += $ace
                    }
                }
            }
        } catch {}
    }

    $severity = if ($runAs -and $hasNonAdminAccess) { 'Critical' }
                elseif ($hasNonAdminAccess) { 'High' }
                elseif ($runAs) { 'Medium' }
                else { 'Low' }

    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PSRM-001' `
        -Category 'RemoteAccess' `
        -Title ("Custom PSSessionConfiguration '{0}' (RunAs={1}, NonAdminAccess={2})" -f $cfg.Name, ($runAs -ne $null), $hasNonAdminAccess) `
        -Severity $severity `
        -Exploitability 'High' `
        -AttackPath 'Non-admin-accessible PS remoting endpoint running as elevated RunAsUser context - instant privilege escalation via Enter-PSSession -ConfigurationName' `
        -MITRE @('T1021.006','T1078') `
        -Evidence @{
            Name           = $cfg.Name
            RunAsUser      = $runAs
            NonAdminAccess = $hasNonAdminAccess
            NonAdminACEs   = $nonAdminPrincipals
            SDDL           = $sddl
        } `
        -Remediation 'Review each custom config for business justification. If JEA: confirm role capability restrictions prevent arbitrary code execution. Tighten SDDL to only necessary principals.' `
        -OperatorNotes 'JEA abuse: misconfigured role capability allows command inclusion via wildcards or ValidateScript holes. Enter-PSSession -ConfigurationName <n>, then run allowed commands to stage payload. If RunAsUser is a privileged account and SDDL lets you in, direct PE to that account context.' `
        -References @(
            'https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview',
            'https://posts.specterops.io/offensive-jea-abuse-a37158c73664'
        )
    ))
}

$defaultSDDL = $null
try { $defaultSDDL = (Get-PSSessionConfiguration -Name Microsoft.PowerShell -ErrorAction SilentlyContinue).SecurityDescriptorSddl } catch {}

if ($defaultSDDL) {
    $parsed = ConvertFrom-SddlString -Sddl $defaultSDDL -ErrorAction SilentlyContinue
    $unexpectedAccess = @()
    foreach ($ace in $parsed.DiscretionaryAcl) {
        if ($ace -match '^(?<principal>[^:]+):') {
            $principal = $Matches.principal.Trim()
            if ($principal -match 'Administrators|Remote Management Users|SYSTEM|BUILTIN|NT SERVICE') { continue }
            $unexpectedAccess += $principal
        }
    }

    if ($unexpectedAccess.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-PSRM-002' `
            -Category 'RemoteAccess' `
            -Title ('Default PowerShell endpoint grants access to non-standard principals: ' + ($unexpectedAccess -join ', ')) `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Broader-than-default WinRM access surface - lateral movement into this host with a non-admin domain credential' `
            -MITRE 'T1021.006' `
            -Evidence @{ Principals = $unexpectedAccess } `
            -Remediation "Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI, tighten to Administrators and Remote Management Users only." `
            -OperatorNotes 'Enter-PSSession via any granted principal lands inside the host with that principal context. Common accidental mis-grant: Domain Users added during testing and never removed.' `
            -References @()
        ))
    }
}
