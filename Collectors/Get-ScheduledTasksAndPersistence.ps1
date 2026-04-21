#requires -Version 5.1

$ctx = $global:BR2.Context

# Scheduled Task scanning
$tasksRoot = "$env:windir\System32\Tasks"
if (-not (Test-Path $tasksRoot)) { return }

$allTasks = @()
try {
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
} catch {
    # Fall back to XML parsing if cmdlet not available / restricted
    $allTasks = @()
}

$BR2.Raw.ScheduledTasks = @{
    Count = $allTasks.Count
}

# Tasks with stored creds (Password flag set) -----------------------------

foreach ($t in $allTasks) {
    try {
        $logon = $t.Principal.LogonType
        $userId = $t.Principal.UserId
        if (-not $userId) { continue }

        # LogonType Password = stored password in LSA; accessible by SYSTEM
        # via lsadump::secrets / mimikatz. Only interesting if the principal
        # is a privileged domain account.
        if ($logon -eq 'Password') {
            $sev = 'Medium'
            # Escalate if the principal name hints at privileged account
            if ($userId -match 'admin|svc_|_svc|service|backup|sa-') { $sev = 'High' }

            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-TSK-010' `
                -Category 'ScheduledTasks' `
                -Title ("Task '{0}' runs as {1} with stored password (LSA secret)" -f $t.TaskName, $userId) `
                -Severity $sev `
                -Exploitability 'High' `
                -AttackPath 'lsadump::secrets from SYSTEM recovers the plaintext credential of the task principal' `
                -MITRE @('T1053.005','T1003.004') `
                -Evidence @{
                    TaskName   = $t.TaskName
                    TaskPath   = $t.TaskPath
                    LogonType  = $logon
                    UserId     = $userId
                    Enabled    = $t.State
                } `
                -Remediation 'Switch the task to a Group Managed Service Account (gMSA) where possible. gMSA passwords are retrieved just-in-time from AD and not stored in LSA secrets on individual hosts.' `
                -OperatorNotes 'As SYSTEM: mimikatz lsadump::secrets reveals SCM service account passwords (_SC_) and scheduled task stored passwords. The stored principal may be a service account with widespread access so always check domain group membership of recovered accounts.' `
                -References @(
                    'https://attack.mitre.org/techniques/T1003/004/',
                    'https://learn.microsoft.com/en-us/windows/security/threat-protection/credential-guard/credential-guard-protection-limits'
                )
            ))
        }
    } catch {}
}

# Tasks with writable executable targets ----------------------------------

foreach ($t in $allTasks) {
    foreach ($action in $t.Actions) {
        if ($action.Execute) {
            # Resolve the executable path. Can be just "notepad.exe" via PATH
            $exe = [Environment]::ExpandEnvironmentVariables($action.Execute)
            if ($exe -notmatch '[:\\]') {
                # Short name - look up via PATH
                $where = (Get-Command $exe -ErrorAction SilentlyContinue).Path
                if ($where) { $exe = $where } else { continue }
            }
            # Strip quotes
            $exe = $exe.Trim('"')
            if (-not (Test-Path -LiteralPath $exe)) { continue }

            # Reuse helper from service-perms collector if present,
            # else inline simple check
            $writers = $null
            try {
                $acl = Get-Acl -LiteralPath $exe
                $risky = @()
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    if ($ace.FileSystemRights -notmatch 'Write|Modify|FullControl|CreateFiles|AppendData') { continue }
                    $idRef = "$($ace.IdentityReference)"
                    if ($idRef -match 'Administrators|SYSTEM|TrustedInstaller|CREATOR OWNER|NT SERVICE') { continue }
                    if ($idRef -match 'Everyone|Authenticated Users|Users$|INTERACTIVE|Domain Users') {
                        $risky += $idRef
                    }
                }
                if ($risky.Count -gt 0) { $writers = ($risky | Sort-Object -Unique) }
            } catch {}

            if ($writers) {
                $runsAs = try { $t.Principal.UserId } catch { 'Unknown' }
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-TSK-002' `
                    -Category 'ScheduledTasks' `
                    -Title ("Scheduled task '{0}' executes non-admin-writable binary" -f $t.TaskName) `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'Overwrite task binary; wait for trigger or force via Start-ScheduledTask - binary runs as task principal' `
                    -MITRE 'T1053.005' `
                    -Evidence @{
                        TaskName   = $t.TaskName
                        Binary     = $exe
                        WritableBy = $writers
                        RunsAs     = $runsAs
                    } `
                    -Remediation 'Fix ACLs on the binary. Task targets should be protected by SYSTEM/Admins write only.' `
                    -OperatorNotes 'Drop payload over the binary. If the task is SYSTEM or an interactive user with elevated rights, privesc is immediate. If the task runs on logon/at-time-X, persistence without modifying task definition which is stealthier than task creation.' `
                    -References @('https://attack.mitre.org/techniques/T1053/005/')
                ))
            }
        }
    }
}

# XML files readable by anyone - look for in-line credentials/hints --------

if ($ctx.Elevated) {
    # Walk the Tasks folder directly
    $xmlFiles = Get-ChildItem -Path $tasksRoot -Recurse -File -ErrorAction SilentlyContinue
    foreach ($xml in $xmlFiles) {
        try {
            $content = Get-Content -Path $xml.FullName -Raw -ErrorAction Stop
            # Tasks rarely contain plaintext passwords but sometimes
            # arguments contain connection strings or tokens.
            if ($content -match 'password\s*=|pwd\s*=|-p\s+[''"]?[^"''\s]+|token\s*=|apikey|api_key|secret\s*=') {
                $BR2.Findings.Add( (New-Finding `
                    -CheckID 'BR-TSK-020' `
                    -Category 'ScheduledTasks' `
                    -Title ("Task XML '{0}' contains potential embedded secret (password/token/key pattern)" -f $xml.Name) `
                    -Severity 'High' `
                    -Exploitability 'High' `
                    -AttackPath 'Credentials / API tokens embedded in task action arguments, readable from on-disk XML' `
                    -MITRE 'T1552.001' `
                    -Evidence @{
                        XmlPath  = $xml.FullName
                        Matched  = 'password|pwd|token|apikey|secret regex pattern'
                    } `
                    -Remediation 'Remove plaintext credentials from task arguments. Use credential stores, Windows Credential Manager, or AD-integrated auth.' `
                    -OperatorNotes 'Authors occasionally put SQL connection strings, PowerShell -Credential bypass arguments, or webhook tokens directly in the command line. Grep for them.' `
                    -References @()
                ))
            }
        } catch {}
    }
}

# WMI event subscription persistence
# root\subscription classes __EventFilter, __EventConsumer,
# __FilterToConsumerBinding are the classic WMI persistence trio.
# Any entry here is either intentional (vendor monitoring) or malicious.

try {
    $filters = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue
    $consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue

    $BR2.Raw.WMIPersistence = @{
        FilterCount   = @($filters).Count
        ConsumerCount = @($consumers).Count
        BindingCount  = @($bindings).Count
    }

    # Filter out known-legitimate vendor subscriptions
    $vendorPatterns = 'SCM Event Log Consumer|BVTConsumer|BVTFilter'  # Microsoft default

    $suspect = @($bindings | Where-Object { $_.Filter -notmatch $vendorPatterns -and $_.Consumer -notmatch $vendorPatterns })

    if ($suspect.Count -gt 0) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-WMI-002' `
            -Category 'Persistence' `
            -Title "$($suspect.Count) WMI event subscription binding(s) present (persistence mechanism)" `
            -Severity 'High' `
            -Exploitability 'Low' `
            -AttackPath 'Existing WMI event subscription may be adversary persistence or legitimate vendor monitoring - review required' `
            -MITRE 'T1546.003' `
            -Evidence @{
                Bindings = @($suspect | Select-Object -First 10 Filter, Consumer)
            } `
            -Remediation 'Review each subscription for legitimacy. Known-good vendor subscriptions (SCCM, some EDR, backup) are expected; others warrant investigation.' `
            -OperatorNotes 'This is a Defensive finding, but useful during ops if you plan to add WMI persistence. Existing bindings make additions blend in. Review consumer commands for hints of prior actor presence (always worth flagging even if outside scope).' `
            -References @(
                'https://attack.mitre.org/techniques/T1546/003/',
                'https://github.com/mattifestation/WMI_Forensics'
            )
        ))
    }
} catch {}

# COM object hijack surface
# Writable HKCR\CLSID\{...}\InprocServer32 defaults - COM hijack
# Limited by design - HKCR is HKLM\SOFTWARE\Classes merged with HKCU.
# Non-admin writes to HKCU\Software\Classes\CLSID override HKCR lookups
# for that user. Check known-abused CLSIDs.

$abusedClsids = @(
    '{0006F03A-0000-0000-C000-000000000046}',  # Outlook.Application
    '{00020812-0000-0000-C000-000000000046}',  # Excel.Application
    '{00024500-0000-0000-C000-000000000046}',
    '{F8842F8E-DAFE-4B37-9D38-4E0714A61F1C}',  # Common COM hijack target
    '{42aedc87-2188-41fd-b9a3-0c966feabec1}',  # WORK FOLDERS COM
    '{CEBB6BBE-17A4-4B4E-8F8A-E2E8AF47B6FC}'   # Shelllinkobject
)

$hcuClassesRoot = 'HKCU:\Software\Classes\CLSID'
$hijackableHere = @()
foreach ($clsid in $abusedClsids) {
    $userPath = "$hcuClassesRoot\$clsid\InprocServer32"
    if (Test-Path $userPath) {
        $userTarget = (Get-ItemProperty -Path $userPath -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
        if ($userTarget) {
            $hijackableHere += [PSCustomObject]@{
                Clsid   = $clsid
                Target  = $userTarget
            }
        }
    }
}

if ($hijackableHere.Count -gt 0) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-COM-002' `
        -Category 'Persistence' `
        -Title "HKCU COM CLSID overrides exist for $($hijackableHere.Count) commonly-abused CLSID(s)" `
        -Severity 'High' `
        -Exploitability 'Medium' `
        -AttackPath 'HKCU COM hijack persistence - when the current user launches a COM-consuming process, attacker DLL loads' `
        -MITRE 'T1546.015' `
        -Evidence @{ Overrides = $hijackableHere } `
        -Remediation 'Remove unexpected HKCU\Software\Classes\CLSID entries. Windows normally installs per-machine into HKLM; HKCU overrides are rare outside of elevated-install apps.' `
        -OperatorNotes 'Existing overrides could be attacker persistence or legitimate (e.g. some dev tools register per-user COM). Verify the target DLL path and signature. This is a known-good persistence technique: write own DLL, drop it, add HKCU\Software\Classes\CLSID\<clsid>\InprocServer32 pointing to it. Next time the user opens Outlook / Excel / File Explorer, payload loads.' `
        -References @(
            'https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/',
            'https://attack.mitre.org/techniques/T1546/015/'
        )
    ))
}
