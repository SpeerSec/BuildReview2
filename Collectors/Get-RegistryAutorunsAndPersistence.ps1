#requires -Version 5.1

$ctx = $global:BR2.Context

# Helper: check if a registry string value's target file exists and is non-default writable
function Test-DllPathWritable {
    param([string]$DllPath)
    if (-not $DllPath) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($DllPath).Trim('"')
    # Not absolute? PATH-searched DLL - hijackable differently (phantom DLL)
    if ($expanded -notmatch '[:\\]') { return "NotAbsolute:$expanded" }
    if (-not (Test-Path -LiteralPath $expanded)) { return "Missing:$expanded" }
    try {
        $acl = Get-Acl -LiteralPath $expanded -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|CreateFiles|AppendData') { continue }
            $id = "$($ace.IdentityReference)"
            if ($id -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
            if ($id -match 'Users$|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                return "Writable:$expanded (by $id)"
            }
        }
    } catch {}
    return $null
}

# Any subkey under HKLM\...\Image File Execution Options\<exe> with a Debugger REG_SZ value redirects that exe launch to the debugger binary as SYSTEM when the exe is launched elevated. Classic privesc and persistence mechanism (also used by the "sticky keys" attack family).

$ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeoRoot) {
    $ifeoEntries = Get-ChildItem -Path $ifeoRoot -ErrorAction SilentlyContinue
    $ifeoSuspicious = @()
    foreach ($entry in $ifeoEntries) {
        try {
            $props = Get-ItemProperty -Path $entry.PSPath -ErrorAction Stop
            $debugger = $props.Debugger
            $gflag    = $props.GlobalFlag
            if ($debugger -and $debugger -ne '') {
                $ifeoSuspicious += [PSCustomObject]@{
                    TargetExe = $entry.PSChildName
                    Debugger  = $debugger
                    Type      = 'Debugger'
                }
            }
            # Silent Process Exit monitor (SilentProcessExit persistence)
            if ($props.MonitorProcess) {
                $ifeoSuspicious += [PSCustomObject]@{
                    TargetExe = $entry.PSChildName
                    Debugger  = $props.MonitorProcess
                    Type      = 'SilentProcessExit'
                }
            }
        } catch {}
    }

    $BR2.Raw.IFEO = @{ Count = $ifeoSuspicious.Count; Entries = $ifeoSuspicious }

    # Accessibility backdoor targets - if any of these specific binaries have
    # Debugger or a writable binary, it's the classic logon-screen privesc
    $accessibilityTargets = @('sethc.exe','utilman.exe','osk.exe','narrator.exe','displayswitch.exe','magnify.exe','atbroker.exe')

    foreach ($item in $ifeoSuspicious) {
        $isAccess = $accessibilityTargets -contains $item.TargetExe.ToLower()
        $sev = if ($isAccess) { 'Critical' } else { 'High' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-IFEO-001' `
            -Category 'Persistence' `
            -Title ("IFEO {0} set on '{1}' pointing to '{2}'" -f $item.Type, $item.TargetExe, $item.Debugger) `
            -Severity $sev `
            -Exploitability 'High' `
            -AttackPath 'IFEO redirects process start to attacker-controlled binary running as parent context (often SYSTEM if launched from logon screen)' `
            -MITRE @('T1546.012','T1574.012') `
            -Evidence @{
                TargetExe = $item.TargetExe
                Debugger  = $item.Debugger
                Type      = $item.Type
                Accessibility = $isAccess
            } `
            -Remediation "Delete the IFEO entry: reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($item.TargetExe)' /f. Investigate how it was created." `
            -OperatorNotes (if ($isAccess) { 'Common sticky-keys backdoor. Pressing Shift 5x (sethc) or Windows+U (utilman) at the logon screen launches the debugger as SYSTEM. Persists across reboots. Inspect for adversary-left backdoors.' } else { 'IFEO Debugger also used for defensive debugging of specific apps so review context before assuming malice. MonitorProcess (SilentProcessExit) is rarely legitimate and a stronger persistence indicator.' }) `
            -References @(
                'https://attack.mitre.org/techniques/T1546/012/',
                'https://pentestlab.blog/2020/01/13/persistence-accessibility-features/'
            )
        ))
    }

    # Also check the accessibility binaries themselves for writability
    foreach ($t in $accessibilityTargets) {
        $target = Join-Path "$env:SystemRoot\System32" $t
        if (Test-Path $target) {
            $writeResult = Test-DllPathWritable -DllPath $target
            if ($writeResult -and $writeResult -match 'Writable:') {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-IFEO-002' `
                    -Category 'Persistence' `
                    -Title "Accessibility binary $t is writable by non-admin" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Replace accessibility binary; invoke from logon screen for SYSTEM code exec without needing any running session' `
                    -MITRE 'T1546.008' `
                    -Evidence @{ Binary = $target; Detail = $writeResult } `
                    -Remediation 'Reset ACL to default: icacls $target /reset. Should be SYSTEM/TrustedInstaller FullControl only.' `
                    -OperatorNotes 'Drop cmd.exe copy over utilman.exe, trigger via Ease of Access on logon screen. Predates the IFEO technique so more reliable.' `
                    -References @('https://pentestlab.blog/2020/01/13/persistence-accessibility-features/')
                ))
            }
        }
    }
}

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $winlogon) {
    $wlProps = Get-ItemProperty -Path $winlogon -ErrorAction SilentlyContinue

    # Userinit should be C:\Windows\system32\userinit.exe,
    # Shell should be explorer.exe
    # Both being set to something else indicates persistence
    $userinit = $wlProps.Userinit
    $shell    = $wlProps.Shell
    $taskman  = $wlProps.Taskman   # REG_SZ - if set, alternate task manager; rarely legitimate

    if ($userinit -and $userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINLOGON-001' `
            -Category 'Persistence' `
            -Title 'Winlogon Userinit value is non-default' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Userinit runs as logged-on user at every interactive logon - persistence vector' `
            -MITRE 'T1547.004' `
            -Evidence @{ Userinit = $userinit } `
            -Remediation "Restore Userinit to 'C:\\Windows\\system32\\userinit.exe,' (note trailing comma)." `
            -OperatorNotes 'Appending ",C:\\path\\payload.exe" (note comma separator) adds your binary to the logon chain without replacing userinit. Stealthier than Run keys.' `
            -References @('https://attack.mitre.org/techniques/T1547/004/')
        ))
    }

    if ($shell -and $shell -ne 'explorer.exe') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINLOGON-002' `
            -Category 'Persistence' `
            -Title "Winlogon Shell value is non-default: $shell" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Shell value runs in place of explorer.exe - full logon-time replacement' `
            -MITRE 'T1547.004' `
            -Evidence @{ Shell = $shell } `
            -Remediation "Restore Shell to 'explorer.exe'." `
            -OperatorNotes 'Used when you want every interactive logon to trigger a payload. Less stealthy than Userinit append because the shell change may break user experience unless proxied.' `
            -References @()
        ))
    }

    if ($taskman) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WINLOGON-003' `
            -Category 'Persistence' `
            -Title "Winlogon Taskman value is set: $taskman" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Ctrl+Shift+Esc launches the configured Taskman instead of taskmgr.exe - covert on-demand trigger' `
            -MITRE 'T1547.004' `
            -Evidence @{ Taskman = $taskman } `
            -Remediation 'Delete the Taskman value unless documented legitimate reason.' `
            -OperatorNotes 'Very rarely legitimate. Useful when you want a trigger that only fires on deliberate admin action.' `
            -References @()
        ))
    }
}

# AppInit_DLLs: DLLs loaded into every GUI user-mode process via user32.dll.
# Requires RequireSignedAppInit_DLLs=0 or signed DLL to be effective on modern Windows.
# Default on Win7+ with Secure Boot: effectively disabled via DisableSignatureValidation.

$appInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$appInitDlls = Get-RegistryValueSafe -Path $appInitPath -Name 'AppInit_DLLs'
$appInitLoaded = Get-RegistryValueSafe -Path $appInitPath -Name 'LoadAppInit_DLLs'
$appInitSigned = Get-RegistryValueSafe -Path $appInitPath -Name 'RequireSignedAppInit_DLLs'

$BR2.Raw.AppInit = @{
    AppInit_DLLs            = $appInitDlls
    LoadAppInit_DLLs        = $appInitLoaded
    RequireSignedAppInit_DLLs = $appInitSigned
}

if ($appInitDlls -and $appInitDlls.Trim() -ne '') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-APPINIT-001' `
        -Category 'Persistence' `
        -Title "AppInit_DLLs is populated: $appInitDlls" `
        -Severity 'High' `
        -Exploitability 'Medium' `
        -AttackPath 'DLLs listed here load into every GUI process via user32.dll - system-wide injection' `
        -MITRE 'T1546.010' `
        -Evidence @{
            AppInit_DLLs              = $appInitDlls
            LoadAppInit_DLLs          = $appInitLoaded
            RequireSignedAppInit_DLLs = $appInitSigned
        } `
        -Remediation 'Clear AppInit_DLLs and set RequireSignedAppInit_DLLs=1, LoadAppInit_DLLs=0.' `
        -OperatorNotes 'On Windows 8+ with Secure Boot enabled, AppInit_DLLs loading is disabled regardless of settings so effectiveness limited. Still a strong signal of persistence on older hosts or misconfigured ones.' `
        -References @('https://attack.mitre.org/techniques/T1546/010/')
    ))
}

# AppCertDlls - loaded into every process that calls CreateProcess family
$appCertPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
if (Test-Path $appCertPath) {
    $appCertProps = Get-ItemProperty -Path $appCertPath -ErrorAction SilentlyContinue
    $appCertEntries = @()
    foreach ($p in $appCertProps.PSObject.Properties) {
        if ($p.Name -match 'PS(Path|ParentPath|ChildName|Provider|Drive)') { continue }
        $appCertEntries += [PSCustomObject]@{ Name = $p.Name; Value = $p.Value }
    }

    if ($appCertEntries.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-APPCERT-001' `
            -Category 'Persistence' `
            -Title "AppCertDlls registered: $($appCertEntries.Count) entry" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Any listed DLL loads into every process that calls CreateProcess - broad injection surface' `
            -MITRE 'T1546.009' `
            -Evidence @{ Entries = $appCertEntries } `
            -Remediation 'Clear AppCertDlls unless DLL is legitimate (rare - some antivirus use it; most do not need to).' `
            -OperatorNotes 'Less restricted than AppInit_DLLs on modern Windows but Secure Boot DOES NOT disable it. Check DLL signature and publisher, third-party monitoring tools occasionally use this path legitimately.' `
            -References @('https://attack.mitre.org/techniques/T1546/009/')
        ))
    }
}

# Three LSA-adjacent registry values that load DLLs into LSASS:
#   Notification Packages - password filter DLLs (captures password changes in PLAINTEXT)
#   Authentication Packages - custom auth providers (MSV1_0, Kerberos)
#   Security Packages - SSPs (Mimikatz memssp, classic credential capture)
# Any non-default DLL here is either enterprise auth (rare) or persistence.

$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$notifyPackages  = (Get-ItemProperty -Path $lsaKey -Name 'Notification Packages' -ErrorAction SilentlyContinue).'Notification Packages'
$authPackages    = (Get-ItemProperty -Path $lsaKey -Name 'Authentication Packages' -ErrorAction SilentlyContinue).'Authentication Packages'
$securityPkgs    = (Get-ItemProperty -Path $lsaKey -Name 'Security Packages' -ErrorAction SilentlyContinue).'Security Packages'

# Known-default values (anything else = finding)
$defaultNotify = @('scecli','rassfm')
$defaultAuth   = @('msv1_0')
$defaultSec    = @('kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap')

$BR2.Raw.LSAPackages = @{
    NotificationPackages = $notifyPackages
    AuthenticationPackages = $authPackages
    SecurityPackages = $securityPkgs
}

$extraNotify = @($notifyPackages | Where-Object { $_ -and ($defaultNotify -notcontains $_.ToLower()) })
$extraAuth   = @($authPackages   | Where-Object { $_ -and ($defaultAuth   -notcontains $_.ToLower()) })
$extraSec    = @($securityPkgs   | Where-Object { $_ -and ($defaultSec    -notcontains $_.ToLower()) })

if ($extraNotify.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-020' `
        -Category 'Persistence' `
        -Title "Non-default LSA Notification Packages registered: $($extraNotify -join ',')" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Password filter DLL receives plaintext password on every change / set operation - persistent credential capture' `
        -MITRE 'T1556.002' `
        -Evidence @{ Entries = $extraNotify } `
        -Remediation "Remove unknown entries. Default is 'scecli,rassfm'. Investigate provenance of any additional DLL." `
        -OperatorNotes 'Drop a password filter DLL, register here, reboot: every subsequent password change is logged in plaintext. Used to harvest credentials from domain controllers. If this fires on a DC, the entire domain is compromised.' `
        -References @(
            'https://attack.mitre.org/techniques/T1556/002/',
            'https://github.com/3gstudent/PasswordFilter'
        )
    ))
}

if ($extraSec.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-021' `
        -Category 'Persistence' `
        -Title "Non-default LSA Security Packages registered: $($extraSec -join ',')" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Custom SSP (Security Support Provider) loaded into LSASS - credential capture on every authentication' `
        -MITRE 'T1547.005' `
        -Evidence @{ Entries = $extraSec } `
        -Remediation 'Remove unknown entries. Investigate provenance.' `
        -OperatorNotes 'Mimikatz misc::memssp registers an SSP in-memory only (no reg change). Registry entry = persistent variant. Known DLL: mimilib.dll from mimikatz.' `
        -References @(
            'https://attack.mitre.org/techniques/T1547/005/',
            'https://adsecurity.org/?p=1760'
        )
    ))
}

if ($extraAuth.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-LSA-022' `
        -Category 'Persistence' `
        -Title "Non-default LSA Authentication Packages: $($extraAuth -join ',')" `
        -Severity 'Critical' `
        -Exploitability 'High' `
        -AttackPath 'Custom authentication package in LSA - intercept auth flows' `
        -MITRE 'T1556' `
        -Evidence @{ Entries = $extraAuth } `
        -Remediation 'Remove unknown entries. Default is msv1_0. Investigate.' `
        -OperatorNotes 'Less common than Security Packages. Investigate DLL for unsigned or strange location = adversary persistence.' `
        -References @()
    ))
}

# netsh.exe loads helper DLLs listed in HKLM\SOFTWARE\Microsoft\Netsh.
# Any DLL there is injected into netsh when it runs. Running netsh is
# common (scripts, helpers) so this is a low-touch persistence vector.

$netshPath = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $netshPath) {
    $netshProps = Get-ItemProperty -Path $netshPath -ErrorAction SilentlyContinue
    # Built-in Netsh helpers - anything else is suspicious
    $defaultNetsh = @('dhcpclient','dhcpcmonitor','dhcpmon','dot3cfg','fwcfg','hnetmon','ifmon','mprapi',
                      'nettrace','p2p','p2pnetsh','p2pnetshell','peerdist','rasmontr','rpcnsh','wcnnetsh',
                      'wfapi','wlancfg','wshelper')
    $customNetsh = @()
    foreach ($p in $netshProps.PSObject.Properties) {
        if ($p.Name -match 'PS(Path|ParentPath|ChildName|Provider|Drive)') { continue }
        if ($defaultNetsh -contains $p.Name.ToLower()) { continue }
        $customNetsh += [PSCustomObject]@{ Name = $p.Name; DLL = $p.Value }
    }

    if ($customNetsh.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-NETSH-001' `
            -Category 'Persistence' `
            -Title "Non-default netsh helper DLL registered: $($customNetsh.Count) entry" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'netsh.exe loads registered helper DLLs whenever invoked - code execution with netsh invocation context' `
            -MITRE 'T1546.007' `
            -Evidence @{ Entries = $customNetsh } `
            -Remediation 'Remove non-default entries. Investigate DLL signatures and paths.' `
            -OperatorNotes 'After planting the DLL and reg entry, invoke with: netsh.exe <helper_name> to trigger on demand, or wait for scripts/monitors to run netsh routinely.' `
            -References @(
                'https://attack.mitre.org/techniques/T1546/007/',
                'https://pentestlab.blog/2020/01/21/persistence-netsh-helper-dll/'
            )
        ))
    }
}

# HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute
# Default: "autocheck autochk *". Additions run before Windows starts.

$bootExec = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'BootExecute' -ErrorAction SilentlyContinue).BootExecute
$BR2.Raw.BootExecute = $bootExec

if ($bootExec) {
    $boot = @($bootExec | Where-Object { $_ -and $_ -notmatch '^(autocheck autochk \*|\s*)$' })
    if ($boot.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BOOT-001' `
            -Category 'Persistence' `
            -Title "Non-default BootExecute entries present: $($boot -join '; ')" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'Native binaries run by smss.exe before Windows fully boots - extremely early persistence' `
            -MITRE 'T1037' `
            -Evidence @{ Entries = $boot } `
            -Remediation "Reset to 'autocheck autochk *'. Only native subsystem binaries should ever appear here." `
            -OperatorNotes 'Rarely legitimate outside of autochk. Requires Native subsystem binary and not arbitrary exe. Real-world malware uses it to gate payload decryption on boot-time environment.' `
            -References @()
        ))
    }
}

# A TreatAs value under HKLM\SOFTWARE\Classes\CLSID\{guid}\TreatAs redirects
# the CLSID to a different CLSID. Allows replacing a well-known COM object
# with an attacker-chosen one.

$classesCLSID = 'HKLM:\SOFTWARE\Classes\CLSID'
if (Test-Path $classesCLSID) {
    # Only look for rare-but-present TreatAs entries, limit to 500 for perf
    $clsidKeys = Get-ChildItem -Path $classesCLSID -ErrorAction SilentlyContinue | Select-Object -First 2000
    $treatAsFindings = @()
    foreach ($k in $clsidKeys) {
        $treatAsPath = Join-Path $k.PSPath 'TreatAs'
        if (Test-Path $treatAsPath) {
            $redirect = (Get-ItemProperty -Path $treatAsPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            if ($redirect) {
                $treatAsFindings += [PSCustomObject]@{
                    OriginalCLSID = $k.PSChildName
                    TargetCLSID   = $redirect
                }
            }
        }
    }
    if ($treatAsFindings.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-COM-010' `
            -Category 'Persistence' `
            -Title "$($treatAsFindings.Count) COM CLSID TreatAs redirect entries present" `
            -Severity 'Medium' `
            -Exploitability 'Low' `
            -AttackPath 'TreatAs redirect allows substituting the implementation of a well-known CLSID with attacker-controlled InprocServer32' `
            -MITRE 'T1546.015' `
            -Evidence @{
                RedirectCount = $treatAsFindings.Count
                Sample        = $treatAsFindings | Select-Object -First 5
            } `
            -Remediation 'Review redirect targets. Legitimate uses exist (COM version shims) but redirects pointing to unsigned DLLs are suspicious.' `
            -OperatorNotes 'Less common than direct InprocServer32 hijack. Quiet persistence because the CLSID consumer is unaware the implementation was swapped so looks normal to the calling code.' `
            -References @()
        ))
    }
}

# If the key HKCU\Software\Microsoft\Office test\Special\Perf exists and
# (default) points to a DLL, every Office app loads the DLL on startup.
# Low-touch user-context persistence.

$officeTest = 'HKCU:\Software\Microsoft\Office test\Special\Perf'
if (Test-Path $officeTest) {
    $dll = (Get-ItemProperty -Path $officeTest -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
    if ($dll) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-OFFICE-001' `
            -Category 'Persistence' `
            -Title 'Office "test" persistence key populated - DLL loads into every Office app' `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Office Test registry key: every Office app load pulls the configured DLL as the user' `
            -MITRE 'T1137.002' `
            -Evidence @{
                RegistryPath = $officeTest
                DllTarget    = $dll
            } `
            -Remediation "Delete HKCU\Software\Microsoft\Office test\Special\Perf unless documented reason. Default absent." `
            -OperatorNotes 'Per-user persistence, no elevation required. Key is documented in several Office persistence toolkits. Survives Office updates.' `
            -References @(
                'https://attack.mitre.org/techniques/T1137/002/',
                'https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence'
            )
        ))
    }
}

$startupFolders = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",     # All Users
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"           # Current User (no abuse = no finding)
)

foreach ($f in $startupFolders) {
    if (-not (Test-Path $f)) { continue }

    # All-Users startup folder writable by non-admin = any user persists as every user
    if ($f -match 'ProgramData') {
        try {
            $acl = Get-Acl -LiteralPath $f
            $risky = @()
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|CreateFiles|AppendData') { continue }
                $idRef = "$($ace.IdentityReference)"
                if ($idRef -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
                if ($idRef -match 'Users$|Everyone|Authenticated Users|INTERACTIVE|Domain Users') {
                    $risky += $idRef
                }
            }
            if ($risky.Count -gt 0) {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-STARTUP-001' `
                    -Category 'Persistence' `
                    -Title "All-Users Startup folder is writable by non-admin: $f" `
                    -Severity 'Critical' `
                    -Exploitability 'High' `
                    -AttackPath 'Drop LNK / EXE / SCR in all-users Startup - runs as every user on logon' `
                    -MITRE 'T1547.001' `
                    -Evidence @{
                        Folder     = $f
                        WritableBy = $risky
                    } `
                    -Remediation 'Reset ACLs - ProgramData startup should be SYSTEM/Administrators write only.' `
                    -OperatorNotes 'This is bad. Drop an LNK pointing at your payload. Every user who logs in triggers. No UAC involved.' `
                    -References @()
                ))
            }
        } catch {}
    }

    # List existing contents briefly - anything there is autorun
    $contents = Get-ChildItem -Path $f -File -ErrorAction SilentlyContinue
    if ($contents.Count -gt 0) {
        $BR2.Raw."StartupContents_$(Split-Path $f -Leaf)" = @($contents.Name)
    }
}

# Print monitors are DLLs that load into spoolsv.exe (SYSTEM). Register
# via HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver.
# Historic privesc / persistence vector; related to but not same as PrintNightmare.

$monitorsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
if (Test-Path $monitorsKey) {
    $monitors = Get-ChildItem -Path $monitorsKey -ErrorAction SilentlyContinue
    # Known default monitors vary by OS; any with a non-system Driver path is suspicious
    $customMonitors = @()
    foreach ($m in $monitors) {
        $drv = Get-RegistryValueSafe -Path $m.PSPath -Name 'Driver'
        if ($drv -and $drv -notmatch '^(localspl|tcpmon|usbmon|inetmon|appmon|wsdmon)\.dll$') {
            $customMonitors += [PSCustomObject]@{ Monitor = $m.PSChildName; Driver = $drv }
        }
    }
    if ($customMonitors.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-PRINT-001' `
            -Category 'Persistence' `
            -Title "Non-default Print Monitor DLL registered: $($customMonitors.Count) entry" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Print monitor DLL loads into spoolsv.exe as SYSTEM - persistent local SYSTEM code exec' `
            -MITRE @('T1547.010','T1068') `
            -Evidence @{ Monitors = $customMonitors } `
            -Remediation 'Review Driver DLL path. Non-standard entries warrant investigation (vendor print products can legitimately register - verify signatures).' `
            -OperatorNotes 'Legacy persistence technique also used for privesc: SeLoadDriverPrivilege not required, adding a Monitor registry entry with a non-default Driver triggers DLL load into spoolsv. Blocked on recent Windows only if the Point and Print restrictions are enforced (PrintNightmare mitigation path).' `
            -References @(
                'https://attack.mitre.org/techniques/T1547/010/',
                'https://pentestlab.blog/2019/10/28/persistence-port-monitors/'
            )
        ))
    }
}

# W32Time loads DLLs registered as time providers. Persistence vector.

$timeProviders = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
if (Test-Path $timeProviders) {
    $tps = Get-ChildItem -Path $timeProviders -ErrorAction SilentlyContinue
    $defaultTPs = @('NtpClient','NtpServer','VMICTimeProvider')   # Hyper-V adds VMIC
    $customTPs = @()
    foreach ($tp in $tps) {
        if ($defaultTPs -contains $tp.PSChildName) { continue }
        $dll = Get-RegistryValueSafe -Path $tp.PSPath -Name 'DllName'
        $customTPs += [PSCustomObject]@{ Name = $tp.PSChildName; DLL = $dll }
    }

    if ($customTPs.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-TIME-001' `
            -Category 'Persistence' `
            -Title "Non-default Windows Time provider DLL registered: $($customTPs.Count) entry" `
            -Severity 'High' `
            -Exploitability 'Medium' `
            -AttackPath 'W32Time loads time provider DLLs into svchost as LocalService or NetworkService - persistence + limited code exec' `
            -MITRE 'T1547.003' `
            -Evidence @{ Entries = $customTPs } `
            -Remediation 'Remove non-default time providers. Default set varies by OS - check against VM vendor additions (VMICTimeProvider for Hyper-V).' `
            -OperatorNotes 'Lesser-known persistence technique. Runs under the svchost service account or LocalService typically, so impact depends on service identity. Useful when needing persistence without touching Run keys or scheduled tasks.' `
            -References @('https://attack.mitre.org/techniques/T1547/003/')
        ))
    }
}

# If a PowerShell profile file exists and is non-default, every PS session run as that identity executes it. Local admin machine-wide profile or SYSTEM-context tasks that launch PowerShell = elevation persistence.

$profileCandidates = @(
    "$PSHOME\profile.ps1",                                               # all users, all hosts
    "$PSHOME\Microsoft.PowerShell_profile.ps1",                          # all users, PS host
    "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",         # current user, all hosts
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
)
$profilePresent = @()
foreach ($p in $profileCandidates) {
    if (Test-Path $p) {
        $size = (Get-Item $p).Length
        $profilePresent += [PSCustomObject]@{ Path = $p; Size = $size }
    }
}
if ($profilePresent.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-PS-010' `
        -Category 'Persistence' `
        -Title "PowerShell profile file(s) present: $($profilePresent.Count) location" `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'Profile scripts run on every PowerShell session start - persistence per identity / scope' `
        -MITRE 'T1546.013' `
        -Evidence @{ Profiles = $profilePresent } `
        -Remediation 'Review profile contents. Blank profile files (0 bytes) are benign. Non-trivial content should be verified against expected config management.' `
        -OperatorNotes 'Machine-wide profile ($PSHOME\profile.ps1) is rare and writable only as admin but persists for SYSTEM tasks that launch PS. User profile file writable by that user which is easy user persistence. Check file size and contents.' `
        -References @('https://attack.mitre.org/techniques/T1546/013/')
    ))
}
