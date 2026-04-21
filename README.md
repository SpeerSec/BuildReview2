# BuildReview2 - Attack-Path-Driven Windows Host Review

A rewrite of my `BuildReview-Windows` that pivots from compliance-style checks to
attack-path-driven findings. Each check is framed around what an operator can
*do* with the misconfiguration, mapped to MITRE ATT&CK, rated separately for
severity and exploitability, and exported in HTML, JSON, or Markdown.

## Why this rewrite

The original tool gave a pass/fail per registry setting. For a red team build
review that's the wrong unit of analysis as what matters is whether the host
(plus its place in the domain) yields a path to lateral movement, credential
theft, or escalation. This rewrite keeps the collection approach (PowerShell,
runs locally, minimal deps) and replaces the reporting shape.

## Architecture

```
BuildReview2/
  Engine/
    Invoke-BuildReview.ps1      # Entry point - Import this
    New-Finding.ps1             # Uniform finding constructor
    Test-Precondition.ps1       # Shared preconditions (elevated, domain-joined, role=DC, etc.)
  Collectors/                   # Grab raw state
    Get-LSACredentialHygiene.ps1
    Get-CoercionAndRelayPosture.ps1
    Get-KerberosHygiene.ps1
    Get-ADCSClientPosture.ps1
    Get-ExecutionControlState.ps1
    Get-DelegationState.ps1
    Get-LAPSState.ps1
    Get-NetworkServicesPosture.ps1
    Get-PatchPosture.ps1
    Get-LocalAccountAndGroupState.ps1
    Get-ServicePermissions.ps1
    Get-GPOAppliedState.ps1
    Get-RDPPosture.ps1
    Get-BitLockerState.ps1
    Get-AutologonAndStoredCreds.ps1
  Rules/                        # Rule metadata and logic (one rule = one finding type)
    *.psd1                      # Machine-readable rule definitions
  Reporting/
    Export-HtmlReport.ps1
    Export-JsonReport.ps1
    Export-MarkdownReport.ps1
    Export-CsvReport.ps1
  Docs/
    CheckCatalogue.md           # This file's catalogue lives here too
    USAGE.md                    # How to run this thing
```

## Finding schema

Every rule emits `[PSCustomObject]` with these fields:

| Field             | Type     | Notes                                                         |
|-------------------|----------|---------------------------------------------------------------|
| `CheckID`         | string   | Stable ID, e.g. `BR-KRB-001`                                  |
| `Category`        | string   | `Kerberos`, `ADCS`, `Coercion`, `LSA`, etc.                   |
| `Title`           | string   | Human-readable one-liner                                      |
| `Severity`        | string   | `Critical` \| `High` \| `Medium` \| `Low` \| `Info`           |
| `Exploitability`  | string   | `High` \| `Medium` \| `Low` \| `Theoretical` \| `NotOnThisHost` |
| `AttackPath`      | string   | Short explanation, e.g. "Kerberoasting of RC4-only SPN"         |
| `MITRE`           | string[] | One or more technique IDs                                     |
| `Evidence`        | hashtable| Whatever proves the finding (reg values, file paths, output)  |
| `Remediation`     | string   | Blue team action                                              |
| `OperatorNotes`   | string   | Red team notes: tooling, preconditions, OPSEC cost            |
| `References`      | string[] | URLs - research blogs, CVEs, Microsoft docs                   |
| `Host`            | string   | `$env:COMPUTERNAME`                                           |
| `Collected`       | datetime | Collection timestamp                                          |

The `OperatorNotes` field is the practical one as it's where you capture "what
do I actually run to leverage this?" and sometimes, "how loud is it?". That's the
information missing from my old CIS-style output.

## Severity vs exploitability

These are seperate. Examples:

| Condition                                            | Severity  | Exploitability     |
|------------------------------------------------------|-----------|---------------------|
| WDigest `UseLogonCredential=1` on Server 2019        | High      | High                |
| RC4 enabled cluster-wide but no kerberoastable SPNs  | High      | Low on this host    |
| WebClient service running + host not domain-joined   | Medium    | NotOnThisHost       |
| PrintNightmare patch missing on non-DC workstation   | High      | Medium              |
| KrbRelayUp preconditions present on a DC             | Critical  | High                |

The report sorts by `Exploitability desc, Severity desc` by default, so the
things you can use first.

## Check catalogue (what to add)

Grouped by attack path. Each entry is a rule to implement. In my dated and existing
`BuildReview-Windows`, the checks are mostly re-used as collectors; the value add
is the rules layered on top.

### Credential access - LSA, DPAPI, caches

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-LSA-001   | `UseLogonCredential` enables WDigest plaintext caching                  | T1003.001     |
| BR-LSA-002   | LSA not running as PPL (`RunAsPPL=0` or missing)                        | T1003.001     |
| BR-LSA-003   | Credential Guard not enabled on supported OS (`LsaCfgFlags`)            | T1003.001     |
| BR-LSA-004   | `TokenLeakDetectDelaySecs` unset (allows MSV1_0 cred retention)         | T1003.001     |
| BR-LSA-005   | `CachedLogonsCount` > 4 (offline cached domain logon hashes)            | T1003.005     |
| BR-LSA-006   | `DisableDomainCreds=0` (credential theft from vault)                    | T1555.004     |
| BR-LSA-007   | `LimitBlankPasswordUse=0` on workstation                                | T1078.003     |
| BR-LSA-008   | Plaintext autologon creds in `Winlogon\DefaultPassword`                 | T1552.002     |
| BR-LSA-009   | Unattend/Sysprep files with creds on disk                               | T1552.001     |
| BR-LSA-010   | Saved creds in `cmdkey` / vault readable by current user                | T1555.004     |
| BR-LSA-011   | DPAPI master keys present + user browsed to cred-storing apps (hint)    | T1555.003     |
| BR-LSA-012   | RDP saved creds (`TERMSRV/*` entries in vault)                          | T1555.004     |

### Kerberos hygiene

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-KRB-001   | RC4 in `SupportedEncryptionTypes` or `DefaultDomainSupportedEncTypes`   | T1558.003     |
| BR-KRB-002   | Account SPNs present locally without AES keys (Kerberoast-friendly)     | T1558.003     |
| BR-KRB-003   | `RC4DefaultDisablementPhase` unset on 2026+ DCs                         | T1558.003     |
| BR-KRB-004   | AS-REP roastable local users (`DONT_REQ_PREAUTH`)                       | T1558.004     |
| BR-KRB-005   | `msDS-MachineAccountQuota` writable by this machine's context (>0)      | T1136.002     |
| BR-KRB-006   | Kerberos armouring (FAST) not enforced                                  | T1558.003     |
| BR-KRB-007   | `StrongCertificateBindingEnforcement` < 2 (KB5014754 rollback)          | T1649         |
| BR-KRB-008   | `CertificateMappingMethods` permits weak mappings (0x4 or 0x8)          | T1649         |

### ADCS - client-side visibility

Full CA-side checks belong to Certipy. Host-side, we can surface:

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-CA-001    | Enterprise CA templates cached, includes client-auth template           | T1649         |
| BR-CA-002    | User has enrol rights on client-auth template (context-dependent)       | T1649         |
| BR-CA-003    | Host role is Enterprise CA - run full Certipy suite locally             | T1649         |
| BR-CA-004    | `EnrollmentAgentRights` present locally (ESC3 prep)                     | T1649         |
| BR-CA-005    | CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag (ESC6)                       | T1649         |
| BR-CA-006    | CA lists `szOID_NTDS_CA_SECURITY_EXT` in DisableExtensionList (ESC16)   | T1649         |

### NTLM relay posture

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-REL-001   | SMB signing `RequireSecuritySignature=0` on workstation/server          | T1557.001     |
| BR-REL-002   | SMB signing enforced on DC but not member servers                       | T1557.001     |
| BR-REL-003   | LDAP signing `LDAPServerIntegrity` < 2 on DC                            | T1557         |
| BR-REL-004   | LDAP channel binding `LdapEnforceChannelBinding` < 2 on DC              | T1557         |
| BR-REL-005   | IIS / HTTPS Extended Protection for Authentication not set              | T1557         |
| BR-REL-006   | SPN-less HTTP endpoint (e.g. AD CS Web Enrollment) + no EPA             | T1557         |
| BR-REL-007   | NTLMv1 accepted (`LmCompatibilityLevel` < 3)                            | T1557.001     |

### Coercion primitives

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-COE-001   | WebClient service running (enables HTTP-based relay)                    | T1187         |
| BR-COE-002   | Print Spooler running on DC (PrinterBug)                                | T1187         |
| BR-COE-003   | MS-EFSR / MS-DFSNM reachable (PetitPotam, DFSCoerce, Coercer matrix)    | T1187         |
| BR-COE-004   | MS-RPRN / MS-PAR accessible (PrinterBug, NightmareScheduler)            | T1187         |
| BR-COE-005   | Host is DC and `ClientPrintTNL` policy not set                          | T1187         |
| BR-COE-006   | RpcFilter rules absent for coercion RPC interfaces                      | T1187         |

### Delegation abuse

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-DEL-001   | Host has `TRUSTED_FOR_DELEGATION` (unconstrained delegation)            | T1550         |
| BR-DEL-002   | Host has `msDS-AllowedToActOnBehalfOfOtherIdentity` entries (RBCD)      | T1550         |
| BR-DEL-003   | Host has `msDS-AllowedToDelegateTo` with `protocolTransition` (KCD any) | T1550         |
| BR-DEL-004   | Sensitive accounts not in Protected Users                               | T1550         |
| BR-DEL-005   | Tier-0 account logged on interactively (derived from recent logons)     | T1078         |

### Execution control & EDR evasion surface

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-EXE-001   | PowerShell v2 engine installed (AMSI-less scripting)                    | T1562.001     |
| BR-EXE-002   | No AppLocker policy / no WDAC policy in enforce mode                    | T1562.001     |
| BR-EXE-003   | ASR rules disabled or in audit-only mode                                | T1562.001     |
| BR-EXE-004   | Tamper Protection off (Defender)                                        | T1562.001     |
| BR-EXE-005   | Script Block logging disabled                                           | T1562.002     |
| BR-EXE-006   | PPL not enforced for Defender MsMpEng                                   | T1562.001     |
| BR-EXE-007   | Vulnerable drivers present (Microsoft vuln-driver blocklist not on)     | T1068         |
| BR-EXE-008   | Credential Guard VBS off on capable hardware                            | T1003         |
| BR-EXE-009   | LSA protection (RunAsPPL) not UEFI-locked                               | T1003.001     |
| BR-EXE-010   | Sysmon absent or running with empty config                              | T1562.006     |

### Local privilege & lateral movement enablers

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-LAT-001   | Local admin password reuse detectable (no LAPS, same install image)     | T1078.003     |
| BR-LAT-002   | Windows LAPS not configured (new, AD-integrated) vs legacy LAPS         | T1078.003     |
| BR-LAT-003   | `LocalAccountTokenFilterPolicy=1` (remote local-admin pass-the-hash)    | T1550.002     |
| BR-LAT-004   | `FilterAdministratorToken=0` enabling RID-500 remote admin              | T1078.003     |
| BR-LAT-005   | Non-default local admins (other than RID-500)                           | T1136.001     |
| BR-LAT-006   | Backup Operators / Server Operators / Account Operators members         | T1078.002     |
| BR-LAT-007   | Service binary path write-able by non-admin (SeAssignPrimaryToken)      | T1574.010     |
| BR-LAT-008   | Unquoted service paths with writable intermediate directory             | T1574.009     |
| BR-LAT-009   | Services running as domain users with reused passwords                  | T1078.002     |
| BR-LAT-010   | Scheduled tasks with stored creds readable                              | T1053.005     |
| BR-LAT-011   | DLL search order hijack opportunities (user-writable in service PATH)   | T1574.001     |
| BR-LAT-012   | SeManageVolumePrivilege held by non-admin (elevation via shadow copy)   | T1134.001     |
| BR-LAT-013   | SeImpersonate / SeAssignPrimaryTokenPrivilege on service account        | T1134.001     |

### Network posture

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-NET-001   | LLMNR enabled (`EnableMulticast=0` missing)                             | T1557.001     |
| BR-NET-002   | NBT-NS enabled on any NIC                                               | T1557.001     |
| BR-NET-003   | mDNS responding (`EnableMDNS=1`)                                        | T1557.001     |
| BR-NET-004   | IPv6 enabled with DHCPv6 (mitm6 vector)                                 | T1557.002     |
| BR-NET-005   | Firewall profile off on domain network                                  | T1562.004     |
| BR-NET-006   | SMB1 still installed (protocol-level and for RCE surface)               | T1210         |
| BR-NET-007   | Insecure guest auth enabled (`AllowInsecureGuestAuth=1`)                | T1078         |

### RDP posture

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-RDP-001   | NLA not enforced (`UserAuthentication=0`)                               | T1021.001     |
| BR-RDP-002   | RDP Restricted Admin mode `DisableRestrictedAdmin=0` (hash-pass risk)   | T1550.002     |
| BR-RDP-003   | Shadow session without consent (`fAllowToGetHelp=1`, `Shadow=2`)        | T1021.001     |
| BR-RDP-004   | TLS 1.0/1.1 still enabled on RDP                                        | T1021.001     |
| BR-RDP-005   | RDP exposed beyond management VLAN (derived from firewall)              | T1021.001     |

### BitLocker / boot integrity

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-BIT-001   | BitLocker TPM-only (no PIN) - sniffable from bus on some laptops        | T1548         |
| BR-BIT-002   | BitLocker off on fixed drives                                           | T1552         |
| BR-BIT-003   | Secure Boot disabled                                                    | T1542.003     |
| BR-BIT-004   | No UEFI lock on LSA PPL                                                 | T1003.001     |

### Patch posture (attack-path framed)

Rather than listing every missing KB, we highlight KBs that unlock specific
attack paths.

| ID           | Check                                                                   | MITRE         |
|--------------|-------------------------------------------------------------------------|---------------|
| BR-PAT-001   | PrintNightmare family patches (CVE-2021-34527 and follow-ups)           | T1068         |
| BR-PAT-002   | PetitPotam / EFSRPC hardening (KB5005413, May 2022 rollup)              | T1187         |
| BR-PAT-003   | CVE-2022-26923 (Certifried) StrongCertificateBindingEnforcement rollout | T1649         |
| BR-PAT-004   | WSUS RCE CVE-2025-59287 (out-of-band Oct 2025)                          | T1210         |
| BR-PAT-005   | CVE-2026-20833 Kerberos RC4 hardening (Jan 2026 rollout)                | T1558.003     |
| BR-PAT-006   | Follina CVE-2022-30190 (MSDT)                                           | T1203         |
| BR-PAT-007   | Driver blocklist version behind latest MSRC list                        | T1068         |

## Getting started (also check the USAGE.md file in the DOCS directory)

```powershell
Import-Module .\BuildReview2.psd1
Invoke-BuildReview -OutputPath C:\Results -Formats Html,Json,Markdown
```

`Invoke-BuildReview` walks `Collectors/`, then applies `Rules/`, then writes
out in the requested formats. Default is HTML + Markdown.

## Extending (because this still needs heavy expanding)

Adding a check:

1. If the data isn't already captured, add collection logic to the relevant
   file in `Collectors/`. Output a `$global:BR2.Raw.<Area>` entry.
2. Create `Rules/BR-<CAT>-<NNN>.psd1` with metadata.
3. Add the rule logic inside the collector (or a separate analyser) that
   reads `$global:BR2.Raw.<Area>` and calls `New-Finding` when the condition
   is met.

## Notes on OPSEC and use

This is an authorised build review tool. It runs locally on the target host,
reads state, and will write temp files to disk. That's loud by design - registry reads, WMI
queries, and ADWS lookups are all visible to EDR in the usual ways.

If you want to run it during an active engagement (as opposed to an
authorised build review), you can try and use the collectors as
standalone. Feed them into your C2 via `execute-assembly`, `powerpick`, or a
`BOF`.