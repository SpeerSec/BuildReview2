#requires -Version 5.1


$ctx = $global:BR2.Context

# ---- Server-side: is this a WSUS server? ------------------------------

$wsusSvc = Get-Service -Name 'WsusService' -ErrorAction SilentlyContinue
$wsusDbPath = "$env:ProgramFiles\Update Services\Database"
$isWsusServer = ($wsusSvc -ne $null) -or (Test-Path $wsusDbPath)

$BR2.Raw.WSUS = @{
    IsServer = $isWsusServer
}

if ($isWsusServer) {
    # Determine WSUS listener port and scheme
    $wsusConfigPath = 'HKLM:\SOFTWARE\Microsoft\Update Services\Server\Setup'
    $portNumber    = Get-RegistryValueSafe -Path $wsusConfigPath -Name 'PortNumber'
    $usingSSL      = Get-RegistryValueSafe -Path $wsusConfigPath -Name 'UsingSSL'
    $sslPortNumber = Get-RegistryValueSafe -Path $wsusConfigPath -Name 'ServerPortNumber'

    $BR2.Raw.WSUS.PortNumber     = $portNumber
    $BR2.Raw.WSUS.UsingSSL       = $usingSSL
    $BR2.Raw.WSUS.SSLPortNumber  = $sslPortNumber

    # CVE-2025-59287: WSUS deserialisation RCE, out-of-band KB5070884
    # Strategy: check for KB5070884 or subsequent cumulative. Approximate because cumulative supersedence logic is hard.
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID
    $wsusKB = $hotfixes -contains 'KB5070884'

    if (-not $wsusKB) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WSUS-002' `
            -Category 'Patching' `
            -Title 'Host is a WSUS server possibly missing CVE-2025-59287 fix (KB5070884)' `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'Unauthenticated deserialisation on port 8530/8531 - RCE as SYSTEM. Pivot from WSUS to every client via poisoned updates.' `
            -MITRE @('T1210','T1195.002') `
            -Evidence @{
                WsusKB5070884Present = $false
                Port                 = $portNumber
                SSLPort              = $sslPortNumber
            } `
            -Remediation 'Install KB5070884 (October 2025 out-of-band) or any subsequent cumulative that supersedes it. Also: WSUS should never be Internet-exposed. Verify.' `
            -OperatorNotes 'Unauthenticated external RCE. Public PoC landed within days of disclosure. Note: KB match is approximate, cumulative updates may cover so verify via Settings > Windows Update history.' `
            -References @(
                'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59287',
                'https://support.microsoft.com/en-us/topic/kb5070884'
            )
        ))
    }

    # HTTPS required?
    if ($usingSSL -ne 1) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WSUS-001' `
            -Category 'WSUSPosture' `
            -Title 'WSUS server not configured for SSL (HTTP only)' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'WSUSpect: MITM on the WSUS->client connection, inject signed-by-Microsoft-but-operator-chosen updates (e.g. PsExec) for SYSTEM execution on target clients' `
            -MITRE 'T1557' `
            -Evidence @{
                UsingSSL   = $usingSSL
                PortNumber = $portNumber
            } `
            -Remediation 'Enable WSUS SSL: certificate on IIS WSUSAdministration site, set HTTPS-only, then re-point all clients with updated WUServer GPO. Microsoft has a step-by-step guide.' `
            -OperatorNotes 'Potential to use WSUSpect. From a position in the HTTP path between client and WSUS, intercept update XML, substitute your own signed binary (any MS-signed exe works - psexec.exe common). Client runs the update as SYSTEM. Adjacent-subnet attack from any compromised machine on the WSUS path.' `
            -References @(
                'https://www.contextis.com/en/blog/wsuspect-compromising-windows-enterprise-via-windows-update',
                'https://github.com/pimps/wsuxploit'
            )
        ))
    }
}

# ---- Client-side: WUServer policy ------------------------------------

$wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wuServer = Get-RegistryValueSafe -Path $wuPath -Name 'WUServer'
$wuStatusServer = Get-RegistryValueSafe -Path $wuPath -Name 'WUStatusServer'

$BR2.Raw.WSUSClient = @{
    WUServer       = $wuServer
    WUStatusServer = $wuStatusServer
}

if ($wuServer -and $wuServer -match '^http://') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-WSUS-003' `
        -Category 'WSUSPosture' `
        -Title "WUServer policy points to an HTTP (not HTTPS) WSUS: $wuServer" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'WSUSpect MITM - as described in BR-WSUS-001; client-side view means THIS host is at risk regardless of WSUS server config' `
        -MITRE 'T1557' `
        -Evidence @{ WUServer = $wuServer } `
        -Remediation 'Re-point WUServer to HTTPS URL via GPO. Requires HTTPS-enabled WSUS (BR-WSUS-001 fix).' `
        -OperatorNotes 'If you control a host on this subnet, ARP or DHCP spoof to position in-path. If admin on this host: just change WUServer to own WSUS impersonator and wait. WSUXploit / pywsus simulate a WSUS and serve Microsoft-signed binaries with command-line args that result in code execution.' `
        -References @('https://github.com/pimps/wsuxploit')
    ))
}
