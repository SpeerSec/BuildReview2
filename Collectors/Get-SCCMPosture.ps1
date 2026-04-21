#requires -Version 5.1


$ctx = $global:BR2.Context

# Existence gate
$ccmExec   = Get-Service -Name 'CcmExec'        -ErrorAction SilentlyContinue
$smsExec   = Get-Service -Name 'SMS_EXECUTIVE'  -ErrorAction SilentlyContinue
$smsSvcHost = Get-Service -Name 'SMS_SITE_COMPONENT_MANAGER' -ErrorAction SilentlyContinue
$ccmSetupFolder = "$env:windir\ccmsetup"
$ccmFolder      = "$env:windir\CCM"

$isSccmClient = ($ccmExec -ne $null) -or (Test-Path $ccmFolder)
$isSccmSite   = ($smsExec -ne $null) -or ($smsSvcHost -ne $null)

$BR2.Raw.SCCMPresence = @{
    IsClient    = $isSccmClient
    IsSiteServer = $isSccmSite
    CcmExecState = if ($ccmExec) { $ccmExec.Status } else { 'NotInstalled' }
    SmsExecState = if ($smsExec) { $smsExec.Status } else { 'NotInstalled' }
}

# Hard exit if neither role - no false positive SCCM findings on clean hosts
if (-not $isSccmClient -and -not $isSccmSite) {
    return
}

# Client: site code and MP identification
if ($isSccmClient) {
    $mpCandidates = @()
    $siteCode = $null

    try {
        # CCM_Authority has site info on modern clients
        $authority = Get-CimInstance -Namespace 'root\ccm' -ClassName 'CCM_Authority' -ErrorAction SilentlyContinue
        if ($authority) {
            $siteCode = ($authority | Where-Object { $_.Name -match 'SMS:(.+)' } | Select-Object -First 1).Name -replace 'SMS:',''
        }

        # Assigned Management Points
        $smClient = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction SilentlyContinue
        $mps = Get-CimInstance -Namespace 'root\ccm\LocationServices' -ClassName 'SMS_MPInformation' -ErrorAction SilentlyContinue
        if ($mps) { $mpCandidates = @($mps.MP | Sort-Object -Unique) }
    } catch {}

    $BR2.Raw.SCCMClient = @{
        SiteCode        = $siteCode
        ManagementPoints = $mpCandidates
    }
}

# ---- CRED-1: Network Access Account extraction from WMI ------------------

# NAA credentials are blob-encrypted in WMI but decryptable by anyone who
# can read root\ccm\policy\machine\actualconfig namespace (usually local
# admins, though some historical installs leaked to Authenticated Users).
if ($isSccmClient) {
    $naaPresent = $false
    $naaSettings = $null
    try {
        $naaSettings = Get-CimInstance -Namespace 'root\ccm\policy\machine\actualconfig' `
                                        -ClassName 'CCM_NetworkAccessAccount' `
                                        -ErrorAction SilentlyContinue
        if ($naaSettings) { $naaPresent = ($naaSettings.Count -gt 0) -or ($naaSettings -ne $null) }
    } catch {
        # Fall back to registry location that caches NAA blobs
        try {
            $polPath = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reserved1'
            if (Test-Path $polPath) { $naaPresent = $true }
        } catch {}
    }

    $BR2.Raw.SCCM_NAA = @{
        Present = $naaPresent
    }

    if ($naaPresent) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SCCM-001' `
            -Category 'SCCM' `
            -Title 'SCCM Network Access Account credentials present in WMI policy store' `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'CRED-1: Decrypt NAA blob from root\ccm\policy\machine\actualconfig - yields valid domain credential used by every client in the site' `
            -MITRE @('T1552.007','T1552.001') `
            -Evidence @{
                Namespace = 'root\ccm\policy\machine\actualconfig'
                Class     = 'CCM_NetworkAccessAccount'
            } `
            -Remediation 'Configure "Enhanced HTTP" and PKI certificates so MP content access does not require NAA. Microsoft has deprecated NAA in favour of Enhanced HTTP (aka trusted-root-bootstrap). Remove all NAAs from the site if possible; if kept, ensure the account has minimum read-only rights on content.' `
            -OperatorNotes 'SharpSCCM local get naa (google Chris Thompson, SpecterOps) which reads the DPAPI-protected blob and decrypts using the local SYSTEM master key. Works as any local admin. Yields plaintext DOMAIN\username and password. NAAs are frequently granted far beyond "read content shares" so check for reuse as a service account, privileged membership, or SCCM admin rights. This is the single most common privesc yield on SCCM-managed environments.' `
            -References @(
                'https://github.com/Mayyhem/SharpSCCM',
                'https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9',
                'https://github.com/subat0mik/Misconfiguration-Manager'
            )
        ))
    }
}

# ---- EXEC-1: Client push installation account (reverse credential hunt) --

# Check if client push accounts are stored locally - less common on client,
# more likely on site servers but occasionally visible.
if ($isSccmSite) {
    # Look for SMS Admin Console config files / credential stores
    $siteConfigPaths = @(
        "$env:ProgramFiles\Microsoft Configuration Manager\inboxes",
        "$env:ProgramFiles\Microsoft Configuration Manager\AdminConsole",
        "${env:ProgramFiles(x86)}\Microsoft Endpoint Manager\AdminConsole"
    )
    foreach ($p in $siteConfigPaths) {
        if (Test-Path $p) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-SCCM-005' `
                -Category 'SCCM' `
                -Title 'Host is an SCCM site server - run full Misconfiguration Manager attack chain assessment' `
                -Severity 'Critical' `
                -Exploitability 'High' `
                -AttackPath 'Site server compromise = full estate compromise. TAKEOVER-1 through TAKEOVER-5 chain available from any admin on this host.' `
                -MITRE 'T1210' `
                -Evidence @{
                    ConfigPath = $p
                    Role       = 'SiteServer'
                } `
                -Remediation 'Apply the tiered-admin model: SCCM site administrators must be tier-0 accounts. Hardening per Misconfiguration Manager DEFEND-1 through DEFEND-9.' `
                -OperatorNotes 'SharpSCCM, MalSCCM, and SCCMHunter (you can use my updated version @speersec for ADWS route) cover the in-domain reconnaissance. Key extracts from a site server: SiteDB connection string (often SYSTEM/NTAuth default), all client NAAs, discovery data for every domain-joined machine. If site DB SQL server is separate, DACL on the SCCM service accounts often includes dbo on the site DB so use for query of MECM_Admins role.' `
                -References @(
                    'https://github.com/subat0mik/Misconfiguration-Manager',
                    'https://github.com/Mayyhem/SharpSCCM',
                    'https://posts.specterops.io/tagged/sccm'
                )
            ))
            break
        }
    }
}

# ---- RECON-3: AdminService REST API (on SMS Provider host) ---------------

# The AdminService runs on hosts with the SMS Provider role. Expose on
# port 443/tcp at https://<host>/AdminService/v1.0/. Any domain user
# with "Read" role in SCCM can query hosts, collections, software.
if ($isSccmSite) {
    $adminSvcPort = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
    if ($adminSvcPort) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-SCCM-004' `
            -Category 'SCCM' `
            -Title 'SCCM AdminService endpoint listening on port 443' `
            -Severity 'Medium' `
            -Exploitability 'High' `
            -AttackPath 'RECON-3: Query AdminService with any SCCM-privileged domain credential to enumerate hosts, collections, software deployments, and discovery data' `
            -MITRE 'T1082' `
            -Evidence @{
                Port = 443
                Path = '/AdminService/v1.0/'
            } `
            -Remediation 'Restrict AdminService access to SCCM management network. Confirm SCCM RBAC (Role-Based Access Control) is correctly scoped - "Read-only Analyst" role should not include discovery data browse.' `
            -OperatorNotes 'SCCMHunter admin / SharpSCCM get collections can hit this. With a deploy-capable role, use exec to target a collection for immediate code execution on all members. Useful in-memory without touching WMI on individual clients.' `
            -References @(
                'https://github.com/garrettfoster13/sccmhunter',
                'https://learn.microsoft.com/en-us/mem/configmgr/develop/adminservice/overview'
            )
        ))
    }
}

# MP relay potential (HTTP with NTLM)
if ($isSccmSite) {
    # Heuristic - MP uses IIS; check IIS state
    $iisSvc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    if ($iisSvc -and $iisSvc.Status -eq 'Running') {
        # Check for Extended Protection on SCCM virtual dirs
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $ccmDirs = Get-WebVirtualDirectory -Name 'CCM*' -ErrorAction SilentlyContinue
            if ($ccmDirs) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-SCCM-002' `
                    -Category 'SCCM' `
                    -Title 'Management Point IIS virtual directories present - relay surface (TAKEOVER-1)' `
                    -Severity 'High' `
                    -Exploitability 'Medium' `
                    -AttackPath 'TAKEOVER-1: Coerce site server machine account auth; relay to MP/SQL for site database takeover' `
                    -MITRE 'T1557' `
                    -Evidence @{
                        Service      = 'W3SVC'
                        CCMVirtualDirs = @($ccmDirs.Path)
                    } `
                    -Remediation 'Enable Extended Protection for Authentication on all CCM virtual directories. Require HTTPS. Enable SMB signing on site database server.' `
                    -OperatorNotes 'Coerce site server to auth to your listener (PetitPotam to the site server machine account), relay to MP or site DB. If site DB falls, full hierarchy compromise. The TAKEOVER-1 chain in Misconfiguration Manager has the exact ntlmrelayx recipe.' `
                    -References @('https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md')
                ))
            }
        } catch {}
    }
}

# Distribution Point: PXE creds + content folder ACLs
$dpContentPath = "$env:SystemDrive\SMSPKG"
$dpVariable = "$env:SystemDrive\SMSPKGC$"
if ((Test-Path $dpContentPath) -or (Test-Path $dpVariable)) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-SCCM-003' `
        -Category 'SCCM' `
        -Title 'Host is an SCCM Distribution Point - review PXE credentials and content share ACLs' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'CRED-2: PXE task sequence media credentials recoverable from pxeboot variable file; content share SMB exposure' `
        -MITRE 'T1552.001' `
        -Evidence @{
            ContentShare = $dpContentPath
            Role         = 'DistributionPoint'
        } `
        -Remediation 'Enable HTTPS for DP content. Review PXE-enabled boot media for embedded credentials. Rotate any media password or task sequence variables that leaked.' `
        -OperatorNotes 'PXE task sequences often carry media variables (TS_ variables) that include credentials. PXEThief performs the decryption. Even without PXE, unprotected DP shares allow reading every app/package available for deployment which sometimes includes line-of-business credentials.' `
        -References @(
            'https://github.com/MWR-CyberSec/PXEThief',
            'https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md'
        )
    ))
}
