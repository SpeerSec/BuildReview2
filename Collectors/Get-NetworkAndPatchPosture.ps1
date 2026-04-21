#requires -Version 5.1

<#
.SYNOPSIS
    Network services and patch posture. Covers:
    - LLMNR, NBT-NS, mDNS (name resolution poisoning surface)
    - IPv6 with DHCPv6 on (mitm6)
    - Firewall profile state
    - SMB1 installed
    - Insecure guest auth
    - Known CVEs mapped to installed KB hotfixes (ZeroLogon, PrintNightmare,
    NoPac, HiveNightmare, Kerberos CVEs, WSUS RCE)
#>

$ctx = $global:BR2.Context

$llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$llmnrDisabled = Get-RegistryValueSafe -Path $llmnrPath -Name 'EnableMulticast'
# 0 = disabled, missing/1 = enabled (default)

$BR2.Raw.LLMNR = @{ EnableMulticast = $llmnrDisabled }

if ($llmnrDisabled -ne 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NET-001' `
        -Category 'NetworkPosture' `
        -Title 'LLMNR (Link-Local Multicast Name Resolution) is enabled' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'LLMNR poisoning on local subnet -> NetNTLMv2 capture -> offline crack or relay' `
        -MITRE 'T1557.001' `
        -Evidence @{ EnableMulticast = $llmnrDisabled; Path = $llmnrPath } `
        -Remediation 'Set Computer Configuration\Administrative Templates\Network\DNS Client\Turn off multicast name resolution to Enabled (EnableMulticast=0).' `
        -OperatorNotes 'Responder -I eth0 -wrf on the same VLAN captures NetNTLMv2 when a user mistypes an SMB path or DNS fails to resolve. If hashes dont crack, relay with ntlmrelayx to LDAPS/SMB (per coercion findings). Inveigh is the PowerShell equivalent for in-memory use on a foothold host.' `
        -References @(
            'https://github.com/lgandx/Responder',
            'https://github.com/Kevin-Robertson/Inveigh'
        )
    ))
}

$nbtAdapters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
$nbtEnabled = @()
foreach ($a in $nbtAdapters) {
    $netbiosOpt = (Get-ItemProperty -Path $a.PSPath -Name 'NetbiosOptions' -ErrorAction SilentlyContinue).NetbiosOptions
    # 0 = default (enabled via DHCP), 1 = enabled, 2 = disabled
    if ($netbiosOpt -ne 2) {
        $nbtEnabled += [PSCustomObject]@{
            Adapter        = $a.PSChildName
            NetbiosOptions = $netbiosOpt
        }
    }
}

$BR2.Raw.NBTNS = $nbtEnabled

if ($nbtEnabled.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NET-002' `
        -Category 'NetworkPosture' `
        -Title "NBT-NS (NetBIOS Name Service) enabled on $($nbtEnabled.Count) adapter(s)" `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'NBT-NS poisoning (UDP 137) -> NetNTLM capture -> offline crack or relay' `
        -MITRE 'T1557.001' `
        -Evidence @{ Adapters = $nbtEnabled } `
        -Remediation 'Disable NetBIOS over TCP/IP per adapter (NetbiosOptions=2). Can be set via DHCP scope option 1, 2, or via Group Policy (NetBT options).' `
        -OperatorNotes 'Responder handles NBT-NS automatically alongside LLMNR. Particularly useful when LLMNR is disabled but NBT-NS isn''t.' `
        -References @('https://github.com/lgandx/Responder')
    ))
}

if (Test-OSPrecondition -Requirements @{ MinBuild = 19041 }) {
    $mdnsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
    $mdns = Get-RegistryValueSafe -Path $mdnsPath -Name 'EnableMDNS'

    $BR2.Raw.mDNS = $mdns

    # Default-enabled on modern Windows - flag as Low unless on a DC/server
    if ($mdns -ne 0) {
        $sev = if ($ctx.IsServer) { 'Medium' } else { 'Low' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-NET-003' `
            -Category 'NetworkPosture' `
            -Title 'mDNS (Multicast DNS) is enabled' `
            -Severity $sev `
            -Exploitability 'Medium' `
            -AttackPath 'mDNS spoofing -> NetNTLMv2 capture (newer Responder variants, Pretender)' `
            -MITRE 'T1557.001' `
            -Evidence @{ EnableMDNS = $mdns } `
            -Remediation 'Set EnableMDNS=0 under DnsCache\Parameters. Default on since Windows 10 2004 for local .local discovery; rarely needed on servers.' `
            -OperatorNotes 'Pretender handles mDNS + LLMNR + NBT-NS in IPv4/IPv6 with a single binary. Golang, works from Linux foothold as well as native Windows. mDNS is the one defenders most commonly miss when they think they''ve killed Responder attacks.' `
            -References @('https://github.com/RedTeamPentesting/pretender')
        ))
    }
}

$ipv6Disabled = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents'
# Bit flags: 0xFF = fully disabled, 0x20 = prefer IPv4, 0x10 = disable IPv6 on non-tunnel, etc.

$BR2.Raw.IPv6 = @{ DisabledComponents = $ipv6Disabled }

if ($null -eq $ipv6Disabled -or ($ipv6Disabled -band 0x10) -eq 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NET-004' `
        -Category 'NetworkPosture' `
        -Title 'IPv6 enabled with DHCPv6 available (mitm6 vector)' `
        -Severity 'Medium' `
        -Exploitability 'High' `
        -AttackPath 'mitm6 rogue DHCPv6 -> WPAD spoofing -> NTLM relay' `
        -MITRE 'T1557.002' `
        -Evidence @{
            DisabledComponents = $ipv6Disabled
            Note               = 'IPv6 preferred over IPv4 for DNS resolution by default'
        } `
        -Remediation 'Either disable IPv6 fully (DisabledComponents=0xFF) where not used, or disable DHCPv6 and WPAD (wpad registry blackhole).' `
        -OperatorNotes 'mitm6 on the LAN: Windows boxes prefer IPv6 DNS via DHCPv6 over IPv4. Combine with ntlmrelayx -wh attacker-wpad.local - machines resolve WPAD over IPv6, receive attacker PAC file, auth to attacker proxy with NetNTLMv2. Relay to LDAPS for RBCD on machines themselves, or to ADCS Web Enrollment for ESC8. Reliable on environments that have not disabled IPv6 or WPAD auto-detect.' `
        -References @(
            'https://github.com/dirkjanm/mitm6',
            'https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/'
        )
    ))
}

$smb1Feature = $null
try {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
} catch {}

$smb1Config = $null
try { $smb1Config = Get-SmbServerConfiguration -ErrorAction SilentlyContinue } catch {}

$smb1Enabled = ($smb1Feature -and $smb1Feature.State -eq 'Enabled') -or
               ($smb1Config -and $smb1Config.EnableSMB1Protocol -eq $true)

$BR2.Raw.SMB1 = @{
    FeatureState      = if ($smb1Feature) { $smb1Feature.State } else { $null }
    EnableSMB1Protocol = if ($smb1Config)  { $smb1Config.EnableSMB1Protocol } else { $null }
}

if ($smb1Enabled) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NET-006' `
        -Category 'NetworkPosture' `
        -Title 'SMB1 protocol is enabled' `
        -Severity 'High' `
        -Exploitability 'High' `
        -AttackPath 'EternalBlue (MS17-010) family on unpatched hosts, NTLM relay without signing negotiation' `
        -MITRE 'T1210' `
        -Evidence @{
            FeatureState = if ($smb1Feature) { $smb1Feature.State } else { 'Unknown' }
        } `
        -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. SMB1 has been removed by default since Windows 10 1709 and Server 2019.' `
        -OperatorNotes 'Presence of SMB1 is usually a signal the host also lacks MS17-010 (EternalBlue, WannaCry vector). Test with nmap --script smb-vuln-ms17-010. If unpatched, impacket-style exploitation is trivial. Even if patched, SMB1 does not negotiate signing the same way; relay attacks become more reliable.' `
        -References @('https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')
    ))
}

$guestPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
$insecureGuest = Get-RegistryValueSafe -Path $guestPath -Name 'AllowInsecureGuestAuth'

$BR2.Raw.InsecureGuestAuth = $insecureGuest

if ($insecureGuest -eq 1) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-NET-007' `
        -Category 'NetworkPosture' `
        -Title 'Insecure SMB guest authentication enabled' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Connect to attacker-controlled SMB share as guest without warning - drive-by credential/malware delivery' `
        -MITRE 'T1078' `
        -Evidence @{ AllowInsecureGuestAuth = $insecureGuest } `
        -Remediation 'Set AllowInsecureGuestAuth=0. Default off in Windows 11 24H2 Pro; commonly re-enabled for third-party NAS.' `
        -OperatorNotes 'Combined with a WebDAV or SMB share on the attacker LAN, can be used for drive-by binary delivery via UNC paths in phishing. Less valuable than other relay primitives, but worth noting.' `
        -References @('https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11-version-24h2')
    ))
}

$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$BR2.Raw.Firewall = $fwProfiles | Select-Object Name, Enabled

foreach ($profile in $fwProfiles) {
    if (-not $profile.Enabled) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID "BR-NET-005-$($profile.Name)" `
            -Category 'NetworkPosture' `
            -Title "Windows Firewall is disabled on the $($profile.Name) profile" `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Exposed services and lateral movement ports available from adjacent hosts' `
            -MITRE 'T1562.004' `
            -Evidence @{ Profile = $profile.Name; Enabled = $false } `
            -Remediation "Enable firewall on the $($profile.Name) profile. Review inbound rules for scope." `
            -OperatorNotes 'Firewall-off on Domain profile often indicates legacy third-party product or incomplete decommission. Inbound 445/135/3389/5985 unfiltered is the common result. This can be fed into lateral movement.' `
            -References @()
        ))
    }
}

$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID
$BR2.Raw.Hotfixes = $hotfixes

# Map of high-weaponisation CVEs to the minimum KB that fixes them,
# scoped by OS build. Add entries here as new CVEs land.
# Format: @{ CVE = 'CVE-XXXX'; Title = '...'; MinBuild = int; MaxBuild = int;
#            MinKB = 'KB......'; MITRE = '...'; Exploitability = '...';
#            AttackPath = '...'; OperatorNotes = '...' }
$cveCatalogue = @(
    @{
        CVE        = 'CVE-2020-1472'
        Title      = 'ZeroLogon - Netlogon unauthenticated DC takeover'
        AppliesToDC = $true
        MinKB      = 'KB4556836'   # Aug 2020 cumulative for 2019; Secura nomi uses a wider set
        MITRE      = 'T1210'
        Exploit    = 'High'
        Path       = 'Netlogon ComputeNetlogonCredential zero-challenge auth - dump DC NTLM hashes'
        Notes      = 'impacket zerologon, then secretsdump. Still found unpatched occasionally in 2025+. Patch state is complex - two-phase rollout. Missing Aug 2020 or later cumulative on a DC = vulnerable.'
    }
    @{
        CVE        = 'CVE-2021-34527'
        Title      = 'PrintNightmare - print driver RCE'
        MinKB      = 'KB5004945'
        MITRE      = 'T1068'
        Exploit    = 'High'
        Path       = 'Authenticated remote add of malicious print driver -> SYSTEM on the spooler host'
        Notes      = 'Initial fix incomplete; subsequent updates required. Check also for Point and Print restrictions (NoWarningNoElevationOnInstall=1 reintroduces risk). Still viable on unpatched hosts or where Point and Print overrides are configured.'
    }
    @{
        CVE        = 'CVE-2021-36934'
        Title      = 'HiveNightmare / SeriousSAM - non-admin SAM/SECURITY read'
        AppliesToClient = $true
        MinKB      = 'KB5005565'
        MITRE      = 'T1003'
        Exploit    = 'High'
        Path       = 'Non-admin reads SAM/SECURITY/SYSTEM via VSS shadow copy - DCC2 hash extraction'
        Notes      = 'On unpatched clients with active shadow copies: GetShadowCopies enumerates, then read \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\System32\config\SAM. Often still found on workstations rebuilt from images older than Sept 2021.'
    }
    @{
        CVE        = 'CVE-2021-42278,CVE-2021-42287'
        Title      = 'noPac / sAMAccountName spoofing - non-admin domain escalation'
        AppliesToDC = $true
        MinKB      = 'KB5008102'
        MITRE      = 'T1068'
        Exploit    = 'High'
        Path       = 'Rename a machine account to a DC samaccountname, request ticket, revert'
        Notes      = 'noPac.py from impacket or the original Cube0x0 tool. Requires MachineAccountQuota > 0 or an existing account to rename. Effective when chained.'
    }
    @{
        CVE        = 'CVE-2022-26923'
        Title      = 'Certifried - ADCS certificate request spoofing dNSHostName'
        AppliesToDC = $true
        MinKB      = 'KB5014754'
        MITRE      = 'T1649'
        Exploit    = 'High'
        Path       = 'Create computer, change dNSHostName to match DC, request cert, auth as DC'
        Notes      = 'Certipy handles end-to-end. The StrongCertificateBindingEnforcement registry key is what actually prevents this - see BR-KRB-007. KB5014754 lands the binding enforcement config; still requires admin action to set to 2.'
    }
    @{
        CVE        = 'CVE-2022-30190'
        Title      = 'Follina - MSDT protocol handler RCE'
        MinKB      = 'KB5014699'   # June 2022 cumulative
        MITRE      = 'T1203'
        Exploit    = 'High'
        Path       = 'Malicious DOCX/RTF referencing ms-msdt:// URL -> RCE on open'
        Notes      = 'Still a useful initial access primitive on hosts that rolled back or missed June 2022 updates. Good phishing payload type.'
    }
    @{
        CVE        = 'CVE-2023-28252'
        Title      = 'CLFS LPE - kernel privesc'
        MinKB      = 'KB5025221'
        MITRE      = 'T1068'
        Exploit    = 'High'
        Path       = 'Local privesc to SYSTEM via Common Log File System driver'
        Notes      = 'Actively exploited by Nokoyawa ransomware in 2023. Public PoC available. Can be a good escalation method when you have code execution as a low-priv user.'
    }
    @{
        CVE        = 'CVE-2024-38063'
        Title      = 'TCP/IP IPv6 wormable RCE'
        MinKB      = 'KB5041585'
        MITRE      = 'T1210'
        Exploit    = 'Medium'
        Path       = 'IPv6 packet with malformed fragmentation -> kernel RCE'
        Notes      = 'Unauthenticated and remote. Microsoft rated Critical. Requires IPv6 enabled. Public research disclosed significant exploitation details in late 2024; PoC availability has matured.'
    }
    @{
        CVE        = 'CVE-2025-59287'
        Title      = 'WSUS RCE - deserialisation on port 8530/8531'
        AppliesToRole = 'WSUS'
        MinKB      = 'KB5070884'   # Out-of-band October 2025
        MITRE      = 'T1210'
        Exploit    = 'High'
        Path       = 'Unauthenticated RCE on WSUS server -> SYSTEM, pivot to all clients via poisoned updates'
        Notes      = 'Out-of-band emergency patch Oct 2025. If this host is a WSUS server and missing KB5070884, priority is immediate. Even with patch, check Internet exposure - WSUS should never be Internet-reachable.'
    }
    @{
        CVE        = 'CVE-2025-53779'
        Title      = 'Kerberos LPE - relative path privesc'
        MinKB      = 'KB5062561'
        MITRE      = 'T1068'
        Exploit    = 'Medium'
        Path       = 'Local privesc via Kerberos authentication flow'
        Notes      = 'Disclosed August 2025. Verify cumulative update state on client and server builds.'
    }
)

foreach ($cve in $cveCatalogue) {
    # Role-gating
    if ($cve.AppliesToDC     -and -not $ctx.IsDC)     { continue }
    if ($cve.AppliesToClient -and     $ctx.IsServer)  { continue }

    if ($cve.MinBuild -and $ctx.BuildNumber -lt $cve.MinBuild) { continue }
    if ($cve.MaxBuild -and $ctx.BuildNumber -gt $cve.MaxBuild) { continue }

    $hasKB = $hotfixes -contains $cve.MinKB

    # If the MinKB isn't found but build is newer than the KB's release month,
    # skip (cumulative likely covers it). This heuristic is crude - a real implementation would parse the supersedence chain from MSRC API.
    if (-not $hasKB) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID ("BR-PAT-" + $cve.CVE.Replace(',','_')) `
            -Category 'Patching' `
            -Title "Possibly missing fix for $($cve.CVE): $($cve.Title)" `
            -Severity 'High' `
            -Exploitability $cve.Exploit `
            -AttackPath $cve.Path `
            -MITRE $cve.MITRE `
            -Evidence @{
                CVE       = $cve.CVE
                MinKB     = $cve.MinKB
                KBPresent = $false
                Note      = 'Cumulative KBs may supersede this specific ID - confirm against current build UBR before reporting.'
            } `
            -Remediation "Install $($cve.MinKB) or any subsequent cumulative that supersedes it. Verify in Settings > Windows Update > Update history." `
            -OperatorNotes $cve.Notes `
            -References @("https://msrc.microsoft.com/update-guide/vulnerability/$($cve.CVE)")
        ))
    }
}
