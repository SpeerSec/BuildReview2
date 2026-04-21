#requires -Version 5.1


$ctx = $global:BR2.Context

# ---- System-wide Exploit Protection via Get-ProcessMitigation ---------

try {
    $sys = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    $BR2.Raw.ExploitProtection = @{
        ASLR       = "$($sys.ASLR.ForceRelocateImages)"
        DEP        = "$($sys.DEP.Enable)"
        SEHOP      = "$($sys.SEHOP.Enable)"
        CFG        = "$($sys.CFG.Enable)"
        Heap       = "$($sys.Heap.TerminateOnError)"
    }

    if ("$($sys.ASLR.ForceRelocateImages)" -ne 'ON') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-MIT-001' `
            -Category 'ExploitMitigation' `
            -Title 'Mandatory ASLR (ForceRelocateImages) not enforced system-wide' `
            -Severity 'Medium' `
            -Exploitability 'Low' `
            -AttackPath 'Binaries built without /DYNAMICBASE load at predictable addresses - aids ROP chain construction' `
            -MITRE 'T1203' `
            -Evidence @{ ForceRelocateImages = "$($sys.ASLR.ForceRelocateImages)" } `
            -Remediation 'Set-ProcessMitigation -System -Enable ForceRelocateImages. Test legacy apps for compatibility - some old 32-bit code breaks.' `
            -OperatorNotes 'Affects classic memory-corruption exploit methods. Modern operator techniques rarely ROP-based, so direct relevance is limited. Still worth having for defence-in-depth against browser / Office exploit chains.' `
            -References @()
        ))
    }

    if ("$($sys.SEHOP.Enable)" -ne 'ON') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-MIT-002' `
            -Category 'ExploitMitigation' `
            -Title 'SEHOP (Structured Exception Handler Overwrite Protection) not enabled system-wide' `
            -Severity 'Low' `
            -Exploitability 'Low' `
            -AttackPath 'Classic SEH chain overwrite exploit technique available against non-opted-in binaries' `
            -MITRE 'T1203' `
            -Evidence @{ SEHOP = "$($sys.SEHOP.Enable)" } `
            -Remediation 'Set-ProcessMitigation -System -Enable SEHOP. Default-on since Windows 10 / Server 2016 but verify.' `
            -OperatorNotes 'x86-specific mitigation. Largely obsolete on x64 Windows. Recorded for completeness.' `
            -References @()
        ))
    }
} catch {}

# Full Attack Surface Reduction rule matrix
# 19 known ASR rule IDs as of early 2026. For each: flag if action != 1 (Block).
$asrRules = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office apps from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless meeting prevalence/age/trust'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript from launching downloaded content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office from injecting into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec and WMI'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes running from USB'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode (preview)'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied/impersonated system tools (preview)'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
}

$mpPref = Get-MpPreference -ErrorAction SilentlyContinue
if ($mpPref -and $mpPref.AttackSurfaceReductionRules_Ids) {
    $enforced = 0
    $disabled = @()
    foreach ($rule in $asrRules.Keys) {
        $idx = [Array]::IndexOf($mpPref.AttackSurfaceReductionRules_Ids.ToLower(), $rule)
        $action = if ($idx -ge 0) { $mpPref.AttackSurfaceReductionRules_Actions[$idx] } else { 0 }
        if ($action -eq 1) { $enforced++ }
        else { $disabled += [PSCustomObject]@{ Rule = $asrRules[$rule]; Action = $action; Id = $rule } }
    }
    $BR2.Raw.ASRFullMatrix = @{
        Enforced = $enforced
        Disabled = $disabled
    }

    # Flag key high-impact rules if not enforced
    $highValueRules = @(
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'    # LSASS credential stealing block
        'd1e49aac-8f56-4280-b9ba-993a6d77406c'    # PSExec/WMI process create
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'    # WMI subscription persistence
        '56a863a9-875e-4185-98a7-b882c64b5ce5'    # BYOVD vulnerable drivers
    )
    foreach ($r in $highValueRules) {
        $idx = [Array]::IndexOf($mpPref.AttackSurfaceReductionRules_Ids.ToLower(), $r)
        $action = if ($idx -ge 0) { $mpPref.AttackSurfaceReductionRules_Actions[$idx] } else { 0 }
        if ($action -ne 1) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID "BR-ASR-$($r.Substring(0,8))" `
                -Category 'ExploitMitigation' `
                -Title ("High-impact ASR rule not enforced: '{0}' (action={1})" -f $asrRules[$r], $action) `
                -Severity 'High' `
                -Exploitability 'High' `
                -AttackPath 'Specific adversary behaviour class not blocked at the OS layer' `
                -MITRE 'T1562.001' `
                -Evidence @{
                    RuleId = $r
                    Rule   = $asrRules[$r]
                    Action = $action
                } `
                -Remediation 'Enable via Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled. Audit mode first (action=2) before Block (action=1) to assess false positives.' `
                -OperatorNotes (switch ($r) {
                    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' { 'This rule is pretty effective against standard LSASS dumping. With it off, mimikatz sekurlsa::logonpasswords, nanodump, ProcDump all work. With it on: need in-memory hash lookup variants, SeDebugPrivilege-via-process-handle techniques, or SYSTEM-context EDR-compatible dumping.' }
                    'd1e49aac-8f56-4280-b9ba-993a6d77406c' { 'Blocks PsExec / WMI process creation. Can pivot to WinRM, scheduled tasks, or DCOM/WMI non-process-create activation. Impacket wmiexec breaks; atexec still works for tasks.' }
                    'e6db77e5-3df2-4cf1-b95a-636979351e5b' { 'Blocks WMI event subscription but check that the corresponding registry / AD monitoring catches alternative persistence.' }
                    '56a863a9-875e-4185-98a7-b882c64b5ce5' { 'Blocks Bring-Your-Own-Vulnerable-Driver chain. Check VulnerableDriverBlocklistEnable simultaneously.' }
                    default { '' }
                }) `
                -References @(
                    'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference'
                )
            ))
        }
    }
}

# Outbound SMB / NTLM
$smbClient = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
$restrictOutboundNtlm = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic'

$BR2.Raw.OutboundSMB = @{
    RestrictSendingNTLMTraffic = $restrictOutboundNtlm
}

if (-not $restrictOutboundNtlm -or $restrictOutboundNtlm -eq 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NTLM-001' `
        -Category 'NetworkPosture' `
        -Title 'Outbound NTLM not restricted (RestrictSendingNTLMTraffic unset or 0)' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Coerced outbound NTLM to attacker host for hash capture / relay' `
        -MITRE @('T1187','T1557.001') `
        -Evidence @{ RestrictSendingNTLMTraffic = $restrictOutboundNtlm } `
        -Remediation 'Set RestrictSendingNTLMTraffic=1 (Audit) then 2 (Deny except for servers in exception list). Test before enforcing.' `
        -OperatorNotes 'Set to 2 = outbound NTLM blocked except to allowed servers via ClientAllowedNTLMServers list. Forces Kerberos.' `
        -References @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers')
    ))
}

# WPAD disabled
# WPAD auto-detect enabled + responder on LAN = NTLM capture / HTTP MITM
$wpadEnabled = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride'
$wpadService = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
$BR2.Raw.WPAD = @{
    WpadOverride = $wpadEnabled
    ServiceState = if ($wpadService) { "$($wpadService.Status)" } else { 'NotInstalled' }
}

if ($wpadService -and $wpadService.Status -eq 'Running') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-WPAD-001' `
        -Category 'NetworkPosture' `
        -Title 'WPAD auto-discovery service (WinHTTP Web Proxy Auto-Discovery) is running' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'Responder / mitm6 WPAD spoofing - inject malicious PAC file for NTLM auth capture or HTTPS MITM' `
        -MITRE @('T1557.002','T1557.001') `
        -Evidence @{ ServiceState = 'Running' } `
        -Remediation 'Disable via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off WPAD. Or disable Auto-Detect Settings in Internet Options.' `
        -OperatorNotes 'Responder -w option serves a WPAD PAC file. Chrome and some modern apps ignore WPAD, but Windows Update / some enterprise tooling still consults it. Low-probability today but zero-effort coerce.' `
        -References @('https://github.com/lgandx/Responder')
    ))
}

# AutoPlay / AutoRun
$autoRun = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
# 0xFF (255) = all drives disabled

$BR2.Raw.AutoRun = @{ NoDriveTypeAutoRun = $autoRun }

if (-not $autoRun -or $autoRun -lt 255) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-AUTORUN-001' `
        -Category 'NetworkPosture' `
        -Title 'AutoRun / AutoPlay not fully disabled (NoDriveTypeAutoRun < 255)' `
        -Severity 'Low' `
        -Exploitability 'Medium' `
        -AttackPath 'USB / removable media autoplay triggers attacker payload on insertion' `
        -MITRE 'T1091' `
        -Evidence @{ NoDriveTypeAutoRun = $autoRun } `
        -Remediation 'Set NoDriveTypeAutoRun=0xFF (255) via Group Policy to disable on all drive types.' `
        -OperatorNotes 'Mostly relevant for physical-access scenarios: plant USB at target site, AutoRun.inf triggers LNK-style exploit on insert. Modern Windows restricts this heavily but still honoured for some legacy drive types.' `
        -References @()
    ))
}

# ---- Machine account password auto-rotation ---------------------------

# DisablePasswordChange = 1 disables automatic 30-day machine password rotation.
# If set, machine NT hash remains valid indefinitely = persistent pass-the-ticket / silver ticket surface.

$mpChange = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange'
$mpAge    = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge'

$BR2.Raw.MachinePasswordRotation = @{
    DisablePasswordChange = $mpChange
    MaximumPasswordAge    = $mpAge
}

if ($mpChange -eq 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-MACHPW-001' `
        -Category 'DCHardening' `
        -Title 'Machine account password auto-rotation disabled (DisablePasswordChange=1)' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'Machine NT hash extracted from LSA secrets remains valid indefinitely - persistent silver ticket forgery target' `
        -MITRE 'T1550.003' `
        -Evidence @{ DisablePasswordChange = $mpChange } `
        -Remediation 'Set DisablePasswordChange=0. Default behaviour rotates machine account password every 30 days.' `
        -OperatorNotes 'Once machine account NT hash obtained (SYSTEM on this host + lsadump::secrets), silver tickets for this computer account remain forgeable until the password rotates. With rotation disabled, indefinite persistence via silver ticket.' `
        -References @(
            'https://adsecurity.org/?p=556',
            'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-disable-machine-account-password-changes'
        )
    ))
}

if ($mpAge -and $mpAge -gt 30) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-MACHPW-002' `
        -Category 'DCHardening' `
        -Title "Machine account password age set to $mpAge days (>30 default)" `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Extended machine password rotation window prolongs silver ticket viability' `
        -MITRE 'T1550.003' `
        -Evidence @{ MaximumPasswordAge = $mpAge } `
        -Remediation 'Set MaximumPasswordAge to 30 (default) or lower.' `
        -OperatorNotes 'Secondary finding to DisablePasswordChange. Softer control but same principle that long rotation window = long silver ticket viability.' `
        -References @()
    ))
}

# ---- Print Spooler enabled on non-print-server ------------------------

$spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq 'Running' -and $spooler.StartType -ne 'Disabled') {
    # On DCs, spooler is particularly risky (PrintNightmare / SpoolSample coercion)
    $sev = if ($ctx.IsDC) { 'High' } elseif ($ctx.IsServer) { 'Medium' } else { 'Low' }

    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-SPOOL-001' `
        -Category 'NetworkPosture' `
        -Title "Print Spooler service running (role: $($ctx.HostRole))" `
        -Severity $sev `
        -Exploitability 'High' `
        -AttackPath 'Spooler enables PrinterBug / SpoolSample coercion for NTLM relay, and is attack surface for PrintNightmare-class exploits' `
        -MITRE @('T1187','T1557.001') `
        -Evidence @{
            Status    = "$($spooler.Status)"
            StartType = "$($spooler.StartType)"
            HostRole  = $ctx.HostRole
        } `
        -Remediation 'On DCs: disable Spooler unless critical. On member servers: disable if no print function. Workstations: typically required for printing - accept risk.' `
        -OperatorNotes 'SpoolSample / Coercer / printerbug.py trigger DC outbound NTLM via RpcRemoteFindFirstPrinterChangeNotificationEx. With unconstrained delegation + relay, becomes domain compromise. Disable on DCs as priority.' `
        -References @(
            'https://github.com/leechristensen/SpoolSample',
            'https://github.com/p0dalirius/Coercer'
        )
    ))
}

# ---- Registry hives with non-default ACLs -----------------------------

# Check SAM / SECURITY hive keys for non-standard access
if ($ctx.Elevated) {
    $sensitiveHives = @(
        'HKLM:\SAM\SAM',
        'HKLM:\SECURITY'
    )
    foreach ($h in $sensitiveHives) {
        try {
            $acl = Get-Acl -LiteralPath $h -ErrorAction Stop
            $risky = @()
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.RegistryRights -notmatch 'Read|FullControl|QueryValues|EnumerateSubKeys') { continue }
                $id = "$($ace.IdentityReference)"
                if ($id -match 'Administrators|SYSTEM|BUILTIN|RESTRICTED|NT SERVICE') { continue }
                $risky += $id
            }
            if ($risky.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID "BR-HIVE-$(($h -replace '[:\\]','_'))" `
                    -Category 'Credentials' `
                    -Title "Sensitive registry hive $h has non-default read ACE(s)" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Read SAM / SECURITY without admin - recover local NT hashes, LSA secrets' `
                    -MITRE 'T1003.002' `
                    -Evidence @{
                        Hive       = $h
                        ExtraReaders = @($risky | Sort-Object -Unique)
                    } `
                    -Remediation 'Reset ACL to defaults. Almost never a legitimate reason for custom ACLs on SAM/SECURITY.' `
                    -OperatorNotes 'HiveNightmare / SeriousSAM territory if this fires. With read access, reg save + secretsdump yields local creds without requiring admin. Pair with VSS check in BitLocker collector.' `
                    -References @()
                ))
            }
        } catch {}
    }
}
