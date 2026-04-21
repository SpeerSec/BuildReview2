# BuildReview2 Extended Check Catalogue (v2)

Current checks and catalogue.

---

## Host context gating (Engine/Get-HostContext.ps1)

Every check below can declare preconditions via `Test-OSPrecondition`.
Common gating shapes:

```powershell
# Windows 11 22H2+ only
@{ MinBuild = 22621; Server = $false }

# Server 2016+ DC only
@{ MinBuild = 14393; DC = $true }

# Enterprise/Education/Server SKUs
@{ Edition = @('Enterprise','Education','Server') }

# Hybrid-joined hosts only (Entra + AD)
@{ DomainJoined = $true; EntraJoined = $true }

# Host capability
@{ RequiresCapability = 'PPLWithSigner' }
```

---

## SCCM / MECM attack paths (big gap in v1)

Modern internal engagements often have SCCM as the highest-value pivot
surface. Misconfiguration Manager project has catalogued these under
CRED-, ELEVATE-, EXEC-, RECON-, TAKEOVER- codes.

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-SCCM-001  | SCCM client installed + NAA (Network Access Account) creds retrievable from WMI   | T1552.007     |
| BR-SCCM-002  | Host is an SCCM Management Point with NTLM auth not hardened (relay target)       | T1557         |
| BR-SCCM-003  | Host is an SCCM Distribution Point with unauthenticated PXE / media creds         | T1552.001     |
| BR-SCCM-004  | AdminService REST API reachable (SMS Provider role enumeration)                   | T1082         |
| BR-SCCM-005  | SCCM client push account configured (CRED-2)                                      | T1078.002     |
| BR-SCCM-006  | Site database reachable with SYSTEM on MP (TAKEOVER-1)                            | T1210         |
| BR-SCCM-007  | Local admin on SMS Provider host (ELEVATE-3)                                      | T1068         |

Collector approach: check `root\CCM\Policy\Machine\ActualConfig`,
`root\ccm\ClientSDK`, running services (CcmExec, SMS_EXECUTIVE), and
SQL listener exposure on 1433.

---

## Entra ID / hybrid join specific

Only meaningful when `Context.IsAzureADJoined = true`.

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-AAD-001   | PRT (Primary Refresh Token) extractable via roadtoken from this user context      | T1528         |
| BR-AAD-002   | Device registered but not compliant (bypassed CA policies)                        | T1078.004     |
| BR-AAD-003   | WHfB (Windows Hello for Business) keys present in registry for persistence        | T1098.004     |
| BR-AAD-004   | TokenBroker cached tokens for other Entra apps                                    | T1528         |
| BR-AAD-005   | dsregcmd shows KeySignTest failure (device cert misconfigured)                    | T1552         |
| BR-AAD-006   | Intune MDM enrolment state and certificate presence                               | -             |
| BR-AAD-007   | Seamless SSO enabled (AZUREADSSOACC machine account reachable)                    | T1558         |

Collector approach: `dsregcmd /status` parse, `%LOCALAPPDATA%\Microsoft\TokenBroker`
enumeration, HKCU WHfB keys, Intune management extension state.

---

## gMSA / dMSA / service accounts

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-GMSA-001  | gMSA password readable by current context (PrincipalsAllowedToRetrieve)           | T1552         |
| BR-GMSA-002  | gMSA with stale ManagedPasswordInterval (potential cracking window)               | T1558         |
| BR-DMSA-001  | dMSA (Server 2025) migration state - target authenticating as migrated user       | T1098         |
| BR-SVC-001   | Service account in Domain Admins / equivalent (tier crossover)                    | T1078.002     |
| BR-SVC-002   | MSA still using legacy RC4 key material                                           | T1558.003     |

---

## Defender exclusions and bypass surface

v1 mentioned these; v2 expands. All require admin to read HKLM exclusions,
but they're the highest-impact finding on many engagements.

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-DEF-001   | Path exclusions (HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths)       | T1562.001     |
| BR-DEF-002   | Process exclusions                                                                | T1562.001     |
| BR-DEF-003   | Extension exclusions                                                              | T1562.001     |
| BR-DEF-004   | Controlled Folder Access disabled                                                 | T1562.001     |
| BR-DEF-005   | Cloud-delivered protection disabled                                               | T1562.001     |
| BR-DEF-006   | Sample submission disabled                                                        | T1562.001     |
| BR-DEF-007   | Network Protection in audit only                                                  | T1562.001     |
| BR-DEF-008   | MAPS membership = 0 (no cloud lookup)                                             | T1562.001     |
| BR-DEF-009   | ThreatIDDefaultAction overrides (custom allows for specific threat IDs)           | T1562.001     |
| BR-DEF-010   | DisableAntiSpyware legacy flag set                                                | T1562.001     |

---

## PowerShell / AMSI / CLM

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-PS-001    | PowerShell v2 engine installed (covered in v1 as BR-EXE-001)                      | T1562.001     |
| BR-PS-002    | Script Block Logging disabled (covered in v1 as BR-EXE-005)                       | T1562.002     |
| BR-PS-003    | Module Logging disabled                                                           | T1562.002     |
| BR-PS-004    | Transcription disabled                                                            | T1562.002     |
| BR-PS-005    | Constrained Language Mode not enforced via WDAC/AppLocker                         | T1059.001     |
| BR-PS-006    | AMSI provider DLL registry entries writable by non-admin (DLL hijack)             | T1562.001     |
| BR-PS-007    | PowerShell 7+ installed alongside 5.1 (different AMSI/logging scope)              | T1059.001     |
| BR-PS-008    | JEA (Just Enough Administration) endpoints exposed without constrained config     | T1059.001     |

---

## Scheduled tasks (lateral movement + persistence)

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-TSK-001   | Task XML in C:\Windows\System32\Tasks world-readable with creds in Actions        | T1053.005     |
| BR-TSK-002   | Task binary path writable by non-admin (DLL/EXE hijack)                           | T1574.010     |
| BR-TSK-003   | Task author is non-existent / removed user                                        | T1053.005     |
| BR-TSK-004   | Task trigger via obscure event (persistence indicator)                            | T1546.003     |
| BR-TSK-005   | Task runs as SYSTEM but writable by authenticated users                           | T1053.005     |

---

## COM / WMI / Named pipes

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-COM-001   | Writable HKCR\CLSID\{...}\InprocServer32 (COM hijack opportunity)                 | T1546.015     |
| BR-COM-002   | User-writable HKCU\Software\Classes COM overrides                                 | T1546.015     |
| BR-WMI-001   | WMI namespace DACL modified (persistence via event subscription)                  | T1546.003     |
| BR-WMI-002   | Existing __EventFilter / __EventConsumer (WMI persistence indicator)              | T1546.003     |
| BR-PIPE-001  | Writable named pipes created by services (impersonation on connect)               | T1134.002     |

---

## DNS / DnsAdmin / DHCP

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-DNS-001   | Host is DC + DnsAdmins membership permits non-Domain-Admins (DLL load on DNS svc) | T1574.001     |
| BR-DNS-002   | DNS server allows unauthenticated zone updates                                    | T1557         |
| BR-DNS-003   | DHCP admins can write DNS records (ADIDNS poisoning)                              | T1557         |

---

## BitLocker / boot / TPM

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-BIT-001   | BitLocker TPM-only (no PIN) - TPM bus sniffing attack surface                     | T1548         |
| BR-BIT-002   | BitLocker off on fixed drives                                                     | T1552         |
| BR-BIT-003   | BitLocker suspended (common during updates, catches leftover state)               | T1552         |
| BR-BIT-004   | Secure Boot disabled on capable hardware                                          | T1542.003     |
| BR-BIT-005   | DMA protection off (Thunderbolt / PCIe attack surface)                            | T1542         |
| BR-BIT-006   | TPM 1.2 only on a capable-of-2.0 platform                                         | -             |
| BR-BIT-007   | BitLocker recovery key backup to AD not configured                                | -             |

---

## RDP specific

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-RDP-001   | NLA not enforced (UserAuthentication=0)                                           | T1021.001     |
| BR-RDP-002   | RestrictedAdmin disabled allows credential landing (hash exposure)                | T1550.002     |
| BR-RDP-003   | Remote Credential Guard not available or not enforced                             | T1550.002     |
| BR-RDP-004   | TLS 1.0/1.1 still enabled on RDP                                                  | T1021.001     |
| BR-RDP-005   | RDP over non-management VLAN (inferred from firewall rule scope)                  | T1021.001     |
| BR-RDP-006   | RDP session shadowing without consent (Shadow=2)                                  | T1021.001     |
| BR-RDP-007   | Local security policy "Deny access this computer from network" missing for local  | T1078.003     |

---

## UAC and interactive logon

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-UAC-001   | EnableLUA=0 (UAC off)                                                             | T1548.002     |
| BR-UAC-002   | ConsentPromptBehaviorAdmin=0 (auto-elevate, no prompt)                            | T1548.002     |
| BR-UAC-003   | FilterAdministratorToken=0 (RID-500 remote admin bypass)                          | T1078.003     |
| BR-UAC-004   | PromptOnSecureDesktop=0 (auto-elevation without secure desktop)                   | T1548.002     |
| BR-UAC-005   | InactivityTimeoutSecs unset or > 900                                              | T1078         |

---

## Services and service permissions

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-SVC-010   | Unquoted service binary path with writable intermediate directory                 | T1574.009     |
| BR-SVC-011   | Service binary writable by non-admin                                              | T1574.010     |
| BR-SVC-012   | Service parent directory DLL-search-order writable                                | T1574.001     |
| BR-SVC-013   | Service DACL allows non-admin SERVICE_CHANGE_CONFIG / SERVICE_START               | T1543.003     |
| BR-SVC-014   | Service registry key (ImagePath) writable by non-admin                            | T1543.003     |
| BR-SVC-015   | AlwaysInstallElevated=1 in HKLM AND HKCU (MSI escalation)                         | T1548.002     |

---

## Local accounts and groups

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-LOC-001   | Multiple local administrators beyond RID-500                                      | T1136.001     |
| BR-LOC-002   | Members of Backup Operators / Server Operators / Account Operators                | T1078.002     |
| BR-LOC-003   | Members of Hyper-V Administrators (GI from guest to host)                         | T1078.002     |
| BR-LOC-004   | Members of Print Operators (driver load = kernel code)                            | T1078.002     |
| BR-LOC-005   | RID-500 Administrator password age >365 days (with LAPS absent)                   | T1078.003     |
| BR-LOC-006   | Local accounts with PasswordNeverExpires                                          | T1078.003     |
| BR-LOC-007   | Guest account enabled or renamed+enabled                                          | T1078         |

---

## LAPS posture

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-LAPS-001  | Neither Legacy LAPS nor Windows LAPS (built-in) configured                        | T1078.003     |
| BR-LAPS-002  | Legacy LAPS in use on OS that supports Windows LAPS (Win11/Server 2019+ Apr 2023) | -             |
| BR-LAPS-003  | LAPS password read permission granted to broad group (AllExtendedRights)          | T1098         |
| BR-LAPS-004  | LAPS password history not enabled (Windows LAPS feature)                          | -             |
| BR-LAPS-005  | LAPS password never rotated (ms-Mcs-AdmPwdExpirationTime stale)                   | -             |

---

## ADCS host-side

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-CA-001    | Host is Enterprise CA - run Certipy find locally (v1)                             | T1649         |
| BR-CA-007    | Cached enterprise templates available - enumerate enrollee context rights         | T1649         |
| BR-CA-008    | CA registry EditFlags contains EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)              | T1649         |
| BR-CA-009    | DisableExtensionList contains szOID_NTDS_CA_SECURITY_EXT (ESC16)                  | T1649         |
| BR-CA-010    | IIS CES/CEP endpoint without EPA (ESC8 relay surface)                             | T1557         |
| BR-CA-011    | Certificate store Personal contains client-auth cert for elevated principal       | T1649         |

---

## VSS / shadow copies / hive reads

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-VSS-001   | Shadow copy accessible to non-admins (HiveNightmare chain)                        | T1003         |
| BR-VSS-002   | VSS service runs with SeBackupPrivilege available to operators group              | T1003         |

---

## Sysmon / telemetry

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-TEL-001   | Sysmon not installed                                                              | T1562.006     |
| BR-TEL-002   | Sysmon installed but running with default/empty config                            | T1562.006     |
| BR-TEL-003   | Sysmon driver altitude changed (potential EDR evasion indicator)                  | T1562.002     |
| BR-TEL-004   | Event log forwarding (WEF) not configured                                         | T1562.006     |
| BR-TEL-005   | PowerShell transcripts not centralised                                            | T1562.002     |
| BR-TEL-006   | ETW ThreatIntelligence provider disabled                                          | T1562.006     |
| BR-TEL-007   | AMSI providers registered (check for third-party; absence = bypass window)        | -             |

---

## Smart App Control / Personal Data Encryption (Windows 11 22H2+)

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-WIN11-001 | Smart App Control in Off mode (was never enrolled at install)                     | T1562.001     |
| BR-WIN11-002 | Personal Data Encryption not enabled on Enterprise Win11 22H2+                    | -             |
| BR-WIN11-003 | Hardware-enforced Stack Protection not enabled                                    | -             |

---

## Hyper-V / VBS / Secured-core

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-HV-001    | VBS available but disabled                                                        | -             |
| BR-HV-002    | HVCI (Memory Integrity) available but disabled                                    | -             |
| BR-HV-003    | Secured-core PC capable but not configured                                        | -             |
| BR-HV-004    | Hyper-V Admins membership non-default (Guest escape)                              | T1611         |
| BR-HV-005    | nested virt disabled on capable host (capability only)                            | -             |

---

## Firefox / Chrome / Edge browser state (engagement persistence)

Only runs on workstations.

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-BRW-001   | Chrome Login Data file readable by current user                                   | T1555.003     |
| BR-BRW-002   | Edge cookies store for enterprise SSO session                                     | T1539         |
| BR-BRW-003   | DPAPI blob for Chrome keystore retrievable                                        | T1555.003     |
| BR-BRW-004   | Edge WebView2 hijack opportunity (user-data-dir redirect)                         | T1176         |

Refs: SharpChrome, SharpDPAPI, cookie extractors (Chlonium, Donut-Loader variants).

---

## WSUS / configuration

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-WSUS-001  | Host is WSUS server + HTTP (not HTTPS) listener (WSUSpect MITM)                   | T1557         |
| BR-WSUS-002  | Host is WSUS server missing CVE-2025-59287 patch (KB5070884)                      | T1210         |
| BR-WSUS-003  | WUServer policy points to HTTP URL (client-side WSUSpect)                         | T1557         |

---

## Misc / catch-alls

| ID           | Check                                                                             | MITRE         |
|--------------|-----------------------------------------------------------------------------------|---------------|
| BR-MISC-001  | Unattend.xml / sysprep.inf with credentials in Panther, System32, Provisioning    | T1552.001     |
| BR-MISC-002  | Group Policy cached passwords in SYSVOL (Groups.xml cpassword)                    | T1552.006     |
| BR-MISC-003  | PuTTY saved session keys readable                                                 | T1552.004     |
| BR-MISC-004  | SSH agent sockets / stored keys readable                                          | T1552.004     |
| BR-MISC-005  | WSL distros installed with credentials in Linux home                              | T1552         |
| BR-MISC-006  | Docker daemon exposed on TCP                                                      | T1611         |
| BR-MISC-007  | Azure CLI / AWS CLI / gcloud credentials on disk                                  | T1552.001     |
| BR-MISC-008  | Chocolatey / scoop / winget install from user-writable source                    | T1195.002     |

---

## LIMITATIONS

- **No true WDAC policy parser.** Detecting "is WDAC enforcing?" is easy,
  analysing the policy for weak rules (allow-by-hash for old binaries,
  supplemental policy bypasses, allowed publishers that sign operator
  tooling) is a separate effort. 
- **No live PKINIT / certificate chain validation** on ADCS findings -
  spot the misconfig, not whether exploitation works end-to-end right now.
- **Entra checks are local-host only.** Tenant-level findings (CA policies,
  app registrations with risky permissions, token lifetimes) need to run
  against Microsoft Graph and should be a separate tool.
- **No BloodHound-style pathfinding.** Rules are per-host; they don't
  understand "this credential would grant access to that host via that
  service." That's BloodHound / BloodHound CE / ADalanche territory.
- **No Sysmon or EDR identification.** Can detect presence, don't
  know what the deployed config covers.
- **No CVE supersedence logic.** The patch collector uses a naive
  "does this KB number appear in Get-HotFix" check. A cumulative might
  supersede the MinKB without that specific ID showing. Parse MSRC CVRF
  feeds for a real fix.
