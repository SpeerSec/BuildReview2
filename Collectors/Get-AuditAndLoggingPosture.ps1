#requires -Version 5.1


$ctx = $global:BR2.Context

# Advanced audit policy subcategories
# auditpol /get /category:* returns subcategory-level audit config
$auditPol = @{}
try {
    $raw = & auditpol.exe /get /category:* 2>$null
    foreach ($line in $raw) {
        if ($line -match '^\s+(.+?)\s{2,}(No Auditing|Success|Failure|Success and Failure)\s*$') {
            $subcat = $Matches[1].Trim()
            $state  = $Matches[2].Trim()
            $auditPol[$subcat] = $state
        }
    }
} catch {}

$BR2.Raw.AuditPolicy = $auditPol

# Critical audit subcategories that MUST be enabled for red-team detection
$criticalAudits = @{
    'Logon'                         = 'Success and Failure'
    'Logoff'                        = 'Success'
    'Special Logon'                 = 'Success'
    'Process Creation'              = 'Success'
    'Kerberos Authentication Service'  = 'Success and Failure'
    'Kerberos Service Ticket Operations' = 'Success and Failure'
    'Credential Validation'         = 'Success and Failure'
    'Sensitive Privilege Use'       = 'Success and Failure'
    'Security Group Management'     = 'Success'
    'User Account Management'       = 'Success and Failure'
    'Computer Account Management'   = 'Success'
    'Directory Service Changes'     = 'Success'
    'Directory Service Access'      = 'Success'
    'Handle Manipulation'           = 'Success'
    'Removable Storage'             = 'Success and Failure'
}

$missingCritical = @()
foreach ($k in $criticalAudits.Keys) {
    $actual = $auditPol[$k]
    if (-not $actual -or $actual -eq 'No Auditing') {
        $missingCritical += [PSCustomObject]@{
            Subcategory = $k
            Expected    = $criticalAudits[$k]
            Actual      = $actual
        }
    }
}

if ($missingCritical.Count -gt 0) {
    $sev = if ($missingCritical.Count -ge 5) { 'High' } else { 'Medium' }
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-001' `
        -Category 'EventLogging' `
        -Title "$($missingCritical.Count) critical audit subcategories not configured" `
        -Severity $sev `
        -Exploitability 'High' `
        -AttackPath 'Operator activity (logon, process creation, privilege use) not written to Security event log - silent tradecraft against local IR' `
        -MITRE 'T1562.002' `
        -Evidence @{ Missing = $missingCritical } `
        -Remediation 'Apply the Microsoft Audit Baseline or the Malware Archaeology Windows Logging Cheat Sheet. auditpol.exe /set /subcategory:"<name>" /success:enable /failure:enable.' `
        -OperatorNotes 'When these are off, runas /user, impersonation, token duplication, and process creation leave no Security log trace. Advance reconnaissance before loud activity. Critical precursor check before running tooling on a host.' `
        -References @(
            'https://www.malwarearchaeology.com/cheat-sheets',
            'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations'
        )
    ))
}

# ---- Process Creation command-line capture ------------------------------

# Event 4688 carries command-line only if this registry value is set.
# Without it, 4688 shows only image name - defenders miss arguments.
$procCmdLine = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'

$BR2.Raw.ProcessCreationCmdLine = $procCmdLine

if ($procCmdLine -ne 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-002' `
        -Category 'EventLogging' `
        -Title 'Process Creation command-line capture disabled (no cmdline in 4688 events)' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'Process arguments not logged - LOLBIN abuse patterns (rundll32 / regsvr32 with specific args, PowerShell encoded commands) invisible in 4688' `
        -MITRE 'T1562.002' `
        -Evidence @{ ProcessCreationIncludeCmdLine_Enabled = $procCmdLine } `
        -Remediation 'Set ProcessCreationIncludeCmdLine_Enabled=1 via GPO: Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events.' `
        -OperatorNotes 'Without this flag: encoded-powershell, rundll32 with malicious export, regsvr32 /u /n /i... - all show as benign image names in Security event 4688. With it: full command line visible.' `
        -References @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing')
    ))
}

# Event log size and retention mode
# If a critical event log is small and overwrite-oldest, high-volume activity
# wraps the log before forwarder pulls it.
$criticalLogs = @(
    @{ Name = 'Security'; MinMB = 1024 }
    @{ Name = 'Microsoft-Windows-PowerShell/Operational'; MinMB = 256 }
    @{ Name = 'Microsoft-Windows-Windows Defender/Operational'; MinMB = 128 }
    @{ Name = 'Microsoft-Windows-Sysmon/Operational'; MinMB = 512 }
    @{ Name = 'Microsoft-Windows-AppLocker/EXE and DLL'; MinMB = 128 }
    @{ Name = 'Microsoft-Windows-CodeIntegrity/Operational'; MinMB = 128 }
)

$logIssues = @()
foreach ($log in $criticalLogs) {
    try {
        $cfg = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
        $sizeMB = [math]::Round($cfg.MaximumSizeInBytes / 1MB, 0)
        if ($sizeMB -lt $log.MinMB) {
            $logIssues += [PSCustomObject]@{
                Log           = $log.Name
                CurrentSizeMB = $sizeMB
                RecommendedMB = $log.MinMB
                LogMode       = "$($cfg.LogMode)"
                RecordCount   = $cfg.RecordCount
            }
        }
    } catch {
        # Log doesn't exist on this host (e.g. Sysmon not installed) - skip, not a finding
    }
}

if ($logIssues.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-003' `
        -Category 'EventLogging' `
        -Title "$($logIssues.Count) critical event log(s) below recommended retention size" `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'High-volume adversary activity wraps the log faster than the forwarder polls - evidence destroyed in place.' `
        -MITRE 'T1070.001' `
        -Evidence @{ Logs = $logIssues } `
        -Remediation "Increase log size. PowerShell: wevtutil sl '<logname>' /ms:<bytes>. Example: wevtutil sl Security /ms:1073741824 for 1GB Security log. Critical: ensure Windows Event Forwarding (or SIEM agent) is pulling faster than log wrap interval." `
        -OperatorNotes 'Generate high log volume to force rotation. Log clearing itself (wevtutil cl) fires event 1102 which is normally well-monitored. Legitimate-looking activity at high volume (cmdlet spam via PSRemoting, mass share enum) wraps the log without alerting.' `
        -References @()
    ))
}

# Sysmon presence + config quality
$sysmonSvc = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
$BR2.Raw.Sysmon = @{
    Present = [bool]$sysmonSvc
    ServiceName = if ($sysmonSvc) { $sysmonSvc.Name } else { $null }
    Status = if ($sysmonSvc) { "$($sysmonSvc.Status)" } else { 'NotInstalled' }
}

if (-not $sysmonSvc) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-004' `
        -Category 'EventLogging' `
        -Title 'Sysmon is not installed' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'No process-tree / DNS / file-create / registry / named-pipe telemetry beyond basic Windows audit - malicious behaviour may be invisibile.' `
        -MITRE 'T1562.006' `
        -Evidence @{ SysmonInstalled = $false } `
        -Remediation 'Deploy Sysmon with a vetted config (e.g. SwiftOnSecurity or Olaf Hartong modular). Install via sysmon.exe -accepteula -i config.xml. Verify Microsoft-Windows-Sysmon/Operational log fills with events within minutes.' `
        -OperatorNotes 'Without Sysmon, process-tree correlation for complex adversary chains is difficult for the defender. Makes (injection, spawned shells, WMI activity, network connections) largely uncorrelated.' `
        -References @(
            'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon',
            'https://github.com/SwiftOnSecurity/sysmon-config',
            'https://github.com/olafhartong/sysmon-modular'
        )
    ))
} elseif ($sysmonSvc.Status -ne 'Running') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-005' `
        -Category 'EventLogging' `
        -Title "Sysmon service ($($sysmonSvc.Name)) not in Running state: $($sysmonSvc.Status)" `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Sysmon installed but not running - binaries exist on host but no telemetry generated' `
        -MITRE 'T1562.006' `
        -Evidence @{ ServiceName = $sysmonSvc.Name; Status = "$($sysmonSvc.Status)" } `
        -Remediation "sc.exe start $($sysmonSvc.Name). Investigate service failure - Sysmon rarely crashes without adversary action." `
        -OperatorNotes 'Adversary has either stopped Sysmon (cleanup) or renamed / driver unloaded it. Report to blue team.' `
        -References @()
    ))
}

# Windows Event Forwarding (WEF) subscriptions
# If no subscriptions are configured, logs stay local and IR is forensics-on-dead-host.
$wecSvc = Get-Service -Name 'Wecsvc' -ErrorAction SilentlyContinue
if ($wecSvc) {
    $BR2.Raw.WEC = @{
        ServiceState = "$($wecSvc.Status)"
        StartType    = "$($wecSvc.StartType)"
    }

    if ($wecSvc.Status -eq 'Running') {
        # Enumerate subscriptions
        try {
            $subs = & wecutil.exe es 2>$null
            $subCount = @($subs | Where-Object { $_ -and $_.Trim() -ne '' }).Count
            $BR2.Raw.WEC.SubscriptionCount = $subCount
        } catch {}
    }
}

# Collector-side log forwarding flag
$wefSubscriptionMgr = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -Name '1'

$BR2.Raw.WEFClient = @{
    SubscriptionManagerConfigured = [bool]$wefSubscriptionMgr
    Target                        = $wefSubscriptionMgr
}

if (-not $wefSubscriptionMgr -and -not $wecSvc) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUDIT-006' `
        -Category 'EventLogging' `
        -Title 'No Windows Event Forwarding (WEF) configuration detected (collector nor source)' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'Event logs remain local only - local tampering / log wrap destroys evidence before forwarding' `
        -MITRE 'T1070.001' `
        -Evidence @{
            SubscriptionManager = $wefSubscriptionMgr
            WECService          = [bool]$wecSvc
        } `
        -Remediation 'Configure the Windows Event Forwarding SubscriptionManager policy to target an event collector. Minimum target URL format: Server=http://<wec>:5985/wsman/SubscriptionManager/WEC. Confirm subscription pulls on the collector via wecutil er.' `
        -OperatorNotes 'If this fires, activity stays on-host. log_clear / wevtutil cl Security still leaves event 1102 BUT also destroys pre-cleanup forensics. SIEM agent (Splunk UF, Winlogbeat, LogRhythm) may still forward - check running services for agent presence before concluding "no forwarding".' `
        -References @(
            'https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription',
            'https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection'
        )
    ))
}

# ---- Third-party SIEM / agent presence (informational) -----------------

$siemAgents = @(
    @{ Name = 'SplunkForwarder'; Product = 'Splunk UF' }
    @{ Name = 'winlogbeat';      Product = 'Elastic Winlogbeat' }
    @{ Name = 'scomagent';       Product = 'SCOM Agent' }
    @{ Name = 'NXLogSvc';        Product = 'NXLog' }
    @{ Name = 'SysInternalsELK'; Product = 'Elastic ELK bridge' }
    @{ Name = 'lrlogmgr';        Product = 'LogRhythm' }
)
$detectedAgents = @()
foreach ($agent in $siemAgents) {
    $svc = Get-Service -Name $agent.Name -ErrorAction SilentlyContinue
    if ($svc) { $detectedAgents += "$($agent.Product) ($($svc.Status))" }
}
if ($detectedAgents.Count -gt 0) {
    $BR2.Raw.SIEMAgents = $detectedAgents
}
