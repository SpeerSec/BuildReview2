function New-Finding {
<#
.SYNOPSIS
    Constructs a BuildReview2 finding with a uniform schema.

.DESCRIPTION
    Every rule in BuildReview2 emits a finding through this function so the
    schema stays consistent across collectors, analysers, and exporters.
    Keep this function tolerant: if a collector has incomplete evidence,
    still emit the finding and let the reporter surface the gap.

.PARAMETER CheckID
    Stable identifier, e.g. BR-KRB-001. Used for suppressions and deltas
    between runs.

.PARAMETER Severity
    Impact if the condition is exploited. Business-risk framing.
    Values: Critical, High, Medium, Low, Info.

.PARAMETER Exploitability
    How readily an operator can weaponise this on the current host given
    its role, memberships, and preconditions. Orthogonal to severity.
    Values: High, Medium, Low, Theoretical, NotOnThisHost.

.EXAMPLE
    New-Finding -CheckID 'BR-LSA-001' -Category 'LSA' `
        -Title 'WDigest plaintext credential caching enabled' `
        -Severity 'High' -Exploitability 'High' `
        -AttackPath 'WDigest clear-text credential extraction from LSASS' `
        -MITRE 'T1003.001' `
        -Evidence @{ UseLogonCredential = 1; Path = 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest' } `
        -Remediation 'Set UseLogonCredential to 0 and reboot.' `
        -OperatorNotes 'Dump LSASS with nanodump or a BOF after triggering an interactive logon; WDigest will cache plaintext for that session only after the reg flip.' `
        -References @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/credentials-protection-and-management')
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $CheckID,
        [Parameter(Mandatory)] [string]   $Category,
        [Parameter(Mandatory)] [string]   $Title,
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]   $Severity,
        [Parameter(Mandatory)]
        [ValidateSet('High','Medium','Low','Theoretical','NotOnThisHost')]
        [string]   $Exploitability,
        [Parameter(Mandatory)] [string]   $AttackPath,
        [string[]] $MITRE          = @(),
        [hashtable]$Evidence       = @{},
        [string]   $Remediation    = '',
        [string]   $OperatorNotes  = '',
        [string[]] $References     = @()
    )

    [PSCustomObject]@{
        CheckID        = $CheckID
        Category       = $Category
        Title          = $Title
        Severity       = $Severity
        Exploitability = $Exploitability
        AttackPath     = $AttackPath
        MITRE          = $MITRE
        Evidence       = $Evidence
        Remediation    = $Remediation
        OperatorNotes  = $OperatorNotes
        References     = $References
        Host           = $env:COMPUTERNAME
        Collected      = (Get-Date).ToUniversalTime()
    }
}

function Get-RegistryValueSafe {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        if (-not (Test-Path $Path)) { return $null }
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Test-IsElevated {
<#
.SYNOPSIS
    Returns $true if the current process is running as Administrator.
#>
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [System.Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-HostRole {
<#
.SYNOPSIS
    Classifies the host as Workstation, MemberServer, DC, or Standalone.

.DESCRIPTION
    Many rules only fire on a specific role.
#>
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs) { return 'Unknown' }

    # DomainRole values per Win32_ComputerSystem:
    # 0 Standalone Workstation, 1 Member Workstation, 2 Standalone Server,
    # 3 Member Server, 4 Backup DC, 5 Primary DC
    switch ($cs.DomainRole) {
        0 { 'Standalone' }
        1 { 'Workstation' }
        2 { 'Standalone' }
        3 { 'MemberServer' }
        4 { 'DomainController' }
        5 { 'DomainController' }
        default { 'Unknown' }
    }
}
