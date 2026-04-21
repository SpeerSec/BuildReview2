# BuildReview2 - Usage Guide

**Version:** 2.1.0  
**Author:** @Speersec  
**Scope:** Single Windows host, local execution only

---

## Overview

BuildReview2 is a passive Windows host build review tool. It reads
configuration state, registry values, service settings, and file ACLs
and maps what it finds to known attack paths. It does not exploit
anything, extract credentials, or modify any system state (see the
Passive Behaviour section below).

Run it on a host to get a prioritised list of misconfigurations sorted
by exploitability and severity, exported as HTML, Markdown,
JSON, or CSV.

---

## Requirements

- Windows 10 / Windows Server 2016 or later
- PowerShell 5.1 or later (built into all supported Windows versions)
- No additional modules required for basic operation
- The `ActiveDirectory` module improves coverage on domain-joined hosts
  but is not mandatory - collectors that need it fail gracefully

**Elevation:** The tool runs as a standard user but several checks
require admin. Running elevated produces substantially more findings.
Checks that need elevation and don't have it are logged in the
`$BR2.Skipped` collection and noted in the report.

---

## Installation

Extract the zip and run from the extracted folder. No installation step
is required - the module loads on demand.

```powershell
Expand-Archive -Path .\BuildReview2.zip -DestinationPath .\
```

The extracted structure should look like this:

```
BuildReview2\
  BuildReview2.psd1       # Module manifest
  BuildReview2.psm1       # Root module
  Engine\
    Get-HostContext.ps1
    Invoke-BuildReview.ps1
    New-Finding.ps1
  Collectors\             # 30 collector scripts
    Get-*.ps1
  Reporting\
    Export-HtmlReport.ps1
    Export-MarkdownReport.ps1
  Docs\
    CheckCatalogue-v2.md
    USAGE.md              # This file
  README.md
```

---

## Running a Review

### Step 1 - Import the module

```powershell
Import-Module .\BuildReview2\BuildReview2.psd1
```

If you receive an execution policy error:

```powershell
# Temporarily allow the import for this session only
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
Import-Module .\BuildReview2\BuildReview2.psd1
```

### Step 2 - Run the review

The minimum required parameter is `-OutputPath`, which is where reports
are written. The module creates the folder if it does not already exist.

```powershell
# Standard run - produces HTML and Markdown
Invoke-BuildReview -OutputPath C:\Results

# Elevated session (open PowerShell as Administrator first)
# The same command - the tool detects elevation automatically
Invoke-BuildReview -OutputPath C:\Results
```

When the tool starts it prints a pre-flight summary:

```
=== BuildReview2 pre-flight ===
Host          : DESKTOP-ABC123
OS            : Windows 11 Pro (build 22631.4169, edition Professional)
Role          : Client
Domain        : corp.example.local
Entra         : Joined (tenant: example.onmicrosoft.com) [Hybrid]
Virtualised   : True (VMware)
Hardware sec  : TPM 2.0, SecureBoot True, VBS True, HVCI False
Elevated      : True
EOL status    : Supported
Confidence    : 95%
```

Collectors then run in sequence. Depending on the host this typically
takes between 30 seconds and 3 minutes (but may take longer, have faith it hasn't stalled). Slow collectors are usually
those that enumerate large numbers of services or ACLs.

### Step 3 - Review output

Output files are named `BR2-<hostname>-<timestamp>.<ext>` in the folder
you specified.

Open the `.html` file in any browser for a filterable, interactive
report. Open the `.md` file in any Markdown viewer, including Obsidian.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | **Required** | Folder to write reports into. Created if absent. |
| `-Formats` | String[] | `Html, Markdown` | One or more of: `Html`, `Markdown`, `Json`, `Csv` |
| `-MinSeverity` | String | `Info` | Filter findings below this level. Options: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `-IncludeCategories` | String[] | All | Limit output to specific categories (see list below) |
| `-SkipPreflightBanner` | Switch | Off | Suppress the pre-flight output block |

### Output format examples

```powershell
# HTML only
Invoke-BuildReview -OutputPath C:\Results -Formats Html

# All four formats
Invoke-BuildReview -OutputPath C:\Results -Formats Html, Markdown, Json, Csv

# High and Critical findings only, HTML report
Invoke-BuildReview -OutputPath C:\Results -MinSeverity High

# Only credential and persistence categories
Invoke-BuildReview -OutputPath C:\Results -IncludeCategories Credentials, Persistence

# Suppress the banner (useful in scripts)
Invoke-BuildReview -OutputPath C:\Results -SkipPreflightBanner
```

### Category names for -IncludeCategories

```
ADCS                ApplicationSecurity   BootIntegrity
Credentials         DCHardening           Entra
EventLogging        ExecutionControl      ExploitMitigation
GroupPolicy         Kerberos              LAPS
Lifecycle           LocalAccounts         NetworkPosture
Patching            Persistence           RemoteAccess
SCCM                ServicePermissions    UAC
WSUSPosture
```

---

## Capturing output in a variable

`Invoke-BuildReview` returns the sorted, filtered findings as a
PowerShell object collection in addition to writing files. You can
assign this to a variable for further processing:

```powershell
$findings = Invoke-BuildReview -OutputPath C:\Results

# Count by severity
$findings | Group-Object Severity | Select-Object Name, Count

# Show all Critical findings
$findings | Where-Object Severity -eq 'Critical' | Select-Object CheckID, Title

# Export to a quick table on screen
$findings | Select-Object Severity, Exploitability, CheckID, Title | Format-Table -AutoSize
```

The global `$BR2` object is also available after a run:

```powershell
# All findings
$BR2.Findings

# Host context (OS, role, capabilities)
$BR2.Context

# Collectors that were skipped and why
$BR2.Skipped

# Raw data collected (registry values, service lists, etc.)
$BR2.Raw
```

---

## Running specific collectors manually

Each collector is a standard `.ps1` script that writes to `$BR2.Findings`.
You can source individual collectors after setting up the engine
state, which is useful when iterating on a specific check area:

```powershell
# Set up engine state first
Import-Module .\BuildReview2\BuildReview2.psd1

$global:BR2 = [PSCustomObject]@{
    StartTime = Get-Date
    Context   = Get-HostContext
    Raw       = @{}
    Findings  = [System.Collections.Generic.List[object]]::new()
    Skipped   = [System.Collections.Generic.List[object]]::new()
}

# Run a single collector
. .\BuildReview2\Collectors\Get-LSACredentialHygiene.ps1

# Inspect results
$BR2.Findings | Format-List
```

---

## Current collectors and what they check

Each collector silently returns early if the feature it targets is not
present on the host. An SCCM collector on a host without SCCM produces
no output and no findings.

| Collector | Existence gate | Checks |
|---|---|---|
| Get-ADCSHostPosture | CertSvc service | ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC8 (web enrolment), ESC16 (DisableExtensionList), software CSP key protection |
| Get-ApplicationSecurityState | Product-specific (Office/SQL/IIS) | Office macro settings per app, Trusted Location writability, SQL service account domain identity, SQL Browser, IIS Basic auth without HTTPS, IIS LocalSystem app pool, web.config credential patterns |
| Get-AuditAndLoggingPosture | Universal | 15 critical audit subcategories, 4688 command-line capture, event log size vs recommendation, Sysmon presence, WEF subscription config, SIEM agent detection |
| Get-BitLockerAndBoot | manage-bde.exe or Get-BitLockerVolume cmdlet | BitLocker per-volume state, TPM-only vs TPM+PIN, suspended protection, Secure Boot state, Kernel DMA Protection, TPM version |
| Get-CachedSessionData | Per-path existence | Wi-Fi PSKs via netsh, VPN profiles, saved .rdp credential blobs, PSReadLine history credential patterns, git-credentials, Teams cookies, VSCode settings secrets |
| Get-CertificateStoreHygiene | Cert:\ provider (universal) | Self-signed roots with <2yr validity, known-bad CA patterns (Superfish/eDellRoot), TrustedPublisher self-signed certs, code-signing keys exportable in LocalMachine\My |
| Get-CoercionAndRelayPosture | Universal, DC-specific sub-checks gated | SMB signing (client/server), LDAP signing, LDAP channel binding, Spooler service, WebClient state, EFS/DFSR/WMI RPC coerce surface, NTLMv1 |
| Get-CredentialLocations | Per-product existence | Chrome/Edge/Firefox login data and cookie stores, unattend.xml and sysprep artefacts, PuTTY saved sessions, SSH keys, WSL distro home dirs, cloud CLI credential files (Azure/AWS/gcloud/kubectl/Docker/GitHub) |
| Get-DCHardeningAndDNS | IsDC | DnsAdmins DLL load privesc, DsrmAdminLogonBehavior, NTDS.dit ACL, LDAP signing, LDAP channel binding |
| Get-DefenderExclusions | WinDefend service | Active mode detection vs third-party AV, real-time protection state, Tamper Protection, path/process/extension exclusions, Controlled Folder Access, Network Protection, MAPS/cloud reporting |
| Get-EntraHybridState | IsAzureADJoined or IsHybridJoined | Device certificate TPM protection, PRT presence and extraction surface, TokenBroker cache, Windows Hello for Business keys, Intune IME script credential patterns |
| Get-ExecutionControlState | Universal | PSv2 engine availability, Script Block Logging, WDAC and AppLocker enforcement state, Defender Tamper Protection, ASR rule count, Vulnerable Driver Blocklist |
| Get-GPOAppliedState | IsDomainJoined and SYSVOL reachable | GPP cpassword blobs in SYSVOL (all six file types), gpresult-parsed startup script UNC writability |
| Get-KerberosHygiene | Universal, AD sub-checks gated | RC4 encryption types, RC4 default disablement phase (KB5021131), MachineAccountQuota, StrongCertificateBindingEnforcement (KB5014754), CertificateMappingMethods |
| Get-LAPSState | IsDomainJoined and not IsDC | Legacy LAPS vs Windows LAPS (built-in) detection, encryption state, rotation age, BackupDirectory=Disabled |
| Get-LSACredentialHygiene | Universal | WDigest, LSA PPL (RunAsPPL), Credential Guard, cached logon count, autologon credentials, Credential Manager vault, LocalAccountTokenFilterPolicy, NTLM auditing |
| Get-MiscPersistenceAndDLL | Universal | Active Setup StubPath with scripting interpreters, HKCU UserInitMprLogonScript, non-System32 screensaver, BITS jobs, Explorer shell extension DLL writability, writable PATH entries, writable Tasks folder |
| Get-NetworkAndPatchPosture | Universal | LLMNR, NBT-NS, mDNS (Pretender surface), mitm6 (DHCPv6), SMBv1, firewall profile state, missing patches for 10 weaponised CVEs |
| Get-OSHardeningMitigations | Universal | System-wide Exploit Protection (ASLR/SEHOP/DEP), 19 ASR rules (full matrix with per-rule findings for high-value subset), outbound NTLM restriction, WPAD service, AutoRun, machine password rotation, Spooler (DC-weighted), SAM/SECURITY hive ACLs |
| Get-PSRemotingEndpoints | WinRM service | Non-default PSSessionConfiguration names, RunAsCredential-enabled configs, SDDL granting non-admin connect access, default endpoint SDDL |
| Get-PowerShellPostureExtended | Universal | Module Logging, Transcription (plus transcript path writability), CLM enforcement state and current session language mode, AMSI provider DLL writability, PS7 side-by-side logging config |
| Get-RegistryAutorunsAndPersistence | Universal | IFEO Debugger and SilentProcessExit entries, accessibility binary writability, Winlogon Userinit/Shell/Taskman, AppInit_DLLs, AppCertDlls, LSA Notification/Authentication/Security packages, netsh helper DLLs, BootExecute, COM TreatAs, Office test key, all-users Startup folder ACL, Print Monitor DLLs, W32Time providers, PowerShell profile files |
| Get-RemoteAccessServices | Per-service | WinRM HTTP/HTTPS state and auth config, Remote Registry service state, OpenSSH password authentication, WebClient/WebDAV state, CredSSP wildcard delegation, CVE-2018-0886 encryption oracle, RestrictAnonymous/RestrictAnonymousSAM, EveryoneIncludesAnonymous, SMB null session pipes |
| Get-SCCMPosture | CcmExec or SMS_EXECUTIVE service | NAA credential blob presence (CRED-1), site server detection, AdminService endpoint, MP IIS relay surface, DP content and PXE credentials |
| Get-ScheduledTasksAndPersistence | Universal | Stored-password tasks (LSA secret), writable task binary targets, task XML embedded credential patterns, WMI event subscription bindings, HKCU COM CLSID overrides |
| Get-ServicePermissions | Universal | Unquoted service paths with writable intermediate directories, writable service binaries, weak service DACLs via sc sdshow, service registry key write ACL, AlwaysInstallElevated (both hives), AppPath writable targets, writable loaded driver binaries |
| Get-TokenPrivsAndDelegation | Universal | Current process token privileges (all 35 named), unconstrained delegation computer objects (domain-joined), RBCD write access, AD DACL write rights on own computer object |
| Get-UACRDPLocalAccounts | Universal; RDP gated on TermService | UAC EnableLUA / ConsentPromptBehaviorAdmin / FilterAdministratorToken, RDP NLA, shadow without consent, local Administrators membership, legacy operator groups (Backup/Server/Account/Print Operators), Guest account state, PasswordNeverExpires accounts |
| Get-WSUSPosture | WsusService or WUServer policy | Server-side: SSL state, CVE-2025-59287 patch (KB5070884). Client-side: WUServer policy over HTTP |
| Get-Win11AndServer2025Posture | Build >= 22621 | Smart App Control state, Personal Data Encryption, Hardware Stack Protection (CET), BYOVD ASR rule, Pluton TPM detection, Config Lock |

---

## Output formats

### HTML

A single self-contained file with no external dependencies. Open in any
browser. Includes:

- Host context panel (OS, role, Entra state, hardware security)
- Finding count by severity
- Filter controls for severity, category, and free-text search
- Collapsible finding cards with attack path, remediation, operator
  notes, evidence, and references

### Markdown

A `.md` file that renders in any Markdown viewer. Drop it into an
Obsidian vault for extra features: the YAML frontmatter is read as
note properties for Dataview queries, severity blocks render as
colour-coded callouts, and MITRE technique IDs are wiki-links that
build a technique tree as you accumulate reviews.

### JSON

Full structured output including host context, all finding fields,
skipped collectors with reasons, and the full `$BR2.Raw` data
dictionary. Useful for ingesting into a SIEM, ticketing system, or
custom reporting pipeline.

### CSV

Flat export of CheckID, Category, Title, Severity, Exploitability,
AttackPath, MITRE, and Remediation. Suitable for importing into Excel
or a vulnerability tracker.

---

## Passive behaviour

BuildReview2 reads configuration state only. It does not:

- Attempt to exploit any vulnerability it finds
- Dump LSASS or extract credentials from memory
- Make network connections to external hosts
- Modify any registry value, service, or file (with two minor exceptions
  noted below)
- Trigger authentication coercion
- Perform any Kerberos AS-REQ or TGS-REQ
- Open or parse browser credential databases

**Minor exceptions:**

1. `Get-ApplicationSecurityState` creates a randomly-named `.tmp` file
   inside each Office Trusted Location directory to test whether the
   current user can write there, then immediately deletes it. This is a
   standard touch-test used to verify ACLs where `Get-Acl` alone may
   not reflect effective access. The file is never written to and is
   always deleted in the same code block.

2. `Get-GPOAppliedState` runs `gpresult.exe /x` to produce an XML of
   applied Group Policy into `$env:TEMP`, reads it, then deletes it.
   This is a standard Windows admin tool producing a read-only snapshot.

Both are read-in-effect operations that leave no persistent artefact.

---

## Troubleshooting

**"Access is denied" on multiple checks**

The tool is running without elevation. Right-click PowerShell and
choose "Run as Administrator", then re-import and re-run.

**Collectors listed in $BR2.Skipped**

Normal behaviour when a feature is not present (e.g. SCCM not
installed, host is not domain-joined, SYSVOL not reachable). Review the
`Reason` field on each skipped entry for context.

```powershell
$BR2.Skipped | Format-List
```

**"The term 'Get-BitLockerVolume' is not recognised"**

BitLocker feature is not installed on this host. The collector gates
on this and skips itself. No action needed.

**Import-Module fails with "cannot be loaded because running scripts is
disabled"**

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
Import-Module .\BuildReview2\BuildReview2.psd1
```

**HTML report is blank in Internet Explorer**

IE is not supported and is end-of-life. WHY are you still using it?! Use Edge, Chrome, or Firefox.

**Very slow on a host with hundreds of services**

Normal. The service permissions collector evaluates ACLs for every
installed service. On a large application server this can take several
minutes. The tool will complete.

---

## Finding schema

Every finding has the same fields regardless of which collector
produced it:

| Field | Description |
|---|---|
| `CheckID` | Stable identifier e.g. `BR-LSA-001`. Consistent across runs for delta tracking. |
| `Category` | Logical grouping e.g. `Credentials`, `Persistence`, `Kerberos` |
| `Title` | One-line description of the specific condition found |
| `Severity` | Impact if exploited: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `Exploitability` | How readily weaponisable on this specific host: `High`, `Medium`, `Low`, `Theoretical`, `NotOnThisHost` |
| `AttackPath` | Plain-English description of the attack chain this enables |
| `MITRE` | One or more ATT&CK technique IDs |
| `Evidence` | Hashtable of the specific values that triggered the finding |
| `Remediation` | Recommended fix |
| `OperatorNotes` | Red-team context: tools, commands, and tradecraft relevant to this finding |
| `References` | URLs to supporting research, CVE advisories, or Microsoft documentation |
| `Host` | Hostname at collection time |
| `Collected` | UTC timestamp |

Severity and Exploitability are intentionally separate. A finding can
be `Critical` severity (severe impact if exploited) but `Theoretical`
exploitability (requires conditions not present on this host). The sort
order in reports weighs Exploitability first so the most immediately
actionable findings surface at the top.
