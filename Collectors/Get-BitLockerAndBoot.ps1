#requires -Version 5.1


$ctx = $global:BR2.Context

# BitLocker existence
$bitLockerCmd = Get-Command 'Get-BitLockerVolume' -ErrorAction SilentlyContinue
$manageBde    = Test-Path "$env:SystemRoot\System32\manage-bde.exe"

if (-not $bitLockerCmd -and -not $manageBde) {
    # BitLocker feature not installed (some Server Core builds)
    if ($ctx.IsClient) {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BIT-100' `
            -Category 'BootIntegrity' `
            -Title 'BitLocker feature not installed on a client host' `
            -Severity 'Medium' `
            -Exploitability 'Medium' `
            -AttackPath 'Offline disk access (single-board reader, USB enclosure) yields full filesystem; ntds.dit / SAM / DPAPI blobs extractable' `
            -MITRE 'T1552' `
            -Evidence @{ BitLockerFeaturePresent = $false } `
            -Remediation 'Install BitLocker feature and enable on the OS drive with TPM+PIN protector where possible.' `
            -OperatorNotes 'Pair with unattended access (laptop theft scenario): boot from USB, mount NTFS, copy HKLM\SYSTEM + SAM + SECURITY, DPAPI master key blobs, ntds.dit if available.' `
            -References @()
        ))
    }
    return
}

# BitLocker volume state
$volumes = @()
try {
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
} catch {
    # Elevation may be required for full info - record and continue
}

$BR2.Raw.BitLocker = @{
    VolumeCount = $volumes.Count
    Volumes     = @()
}

foreach ($vol in $volumes) {
    $volInfo = @{
        MountPoint       = $vol.MountPoint
        ProtectionStatus = "$($vol.ProtectionStatus)"
        VolumeStatus     = "$($vol.VolumeStatus)"
        EncryptionMethod = "$($vol.EncryptionMethod)"
        KeyProtectors    = @($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
        VolumeType       = "$($vol.VolumeType)"
    }
    $BR2.Raw.BitLocker.Volumes += $volInfo

    # Flag: protection off on OS/fixed volumes
    if ($vol.VolumeType -in 'OperatingSystem','Data' -and $vol.ProtectionStatus -eq 'Off') {
        $sev = if ($vol.VolumeType -eq 'OperatingSystem') { 'High' } else { 'Medium' }
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BIT-002' `
            -Category 'BootIntegrity' `
            -Title "BitLocker protection is off on $($vol.VolumeType) volume $($vol.MountPoint)" `
            -Severity $sev `
            -Exploitability 'Medium' `
            -AttackPath 'Unprotected volume readable offline - extract OS secrets or data from a stolen/lost disk' `
            -MITRE 'T1552' `
            -Evidence $volInfo `
            -Remediation "Enable-BitLocker -MountPoint $($vol.MountPoint) with a TPM-based protector. Back up recovery key to AD / Entra." `
            -OperatorNotes 'Offline attack model: if this host is portable and can be physically acquired, entire volume is readable by booting from alternative media. ntds.dit on DCs, SAM + SYSTEM on workstations.' `
            -References @()
        ))
    }

    # Flag: OS volume with TPM-only (no PIN) protector
    if ($vol.VolumeType -eq 'OperatingSystem' -and $vol.ProtectionStatus -eq 'On') {
        $protectors = @($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
        if ($protectors -contains 'Tpm' -and $protectors -notcontains 'TpmPin' -and $protectors -notcontains 'TpmPinStartupKey') {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-BIT-001' `
                -Category 'BootIntegrity' `
                -Title "BitLocker OS volume uses TPM-only protector (no PIN) on $($vol.MountPoint)" `
                -Severity 'Medium' `
                -Exploitability 'Medium' `
                -AttackPath 'TPM bus sniffing - LPC/SPI attack extracts VMK during boot on vulnerable hardware; DMA attack via Thunderbolt on pre-Kernel-DMA hosts' `
                -MITRE 'T1548' `
                -Evidence $volInfo `
                -Remediation "Switch to TPM+PIN protector: manage-bde -protectors -add $($vol.MountPoint) -tpmandpin. Enable Kernel DMA Protection (requires VBS + hardware support)." `
                -OperatorNotes 'TPM-only unlocks automatically before login, so TPM bus sniffing is feasible (fTPM on ASUS / certain Lenovo / Surface models documented). Stacksmashing and hardware research from 2021-2024 show the attack on discrete TPMs too. Once the Volume Master Key is captured, disk is decryptable offline.' `
                -References @(
                    'https://pulsesecurity.co.nz/articles/TPM-sniffing',
                    'https://dolosgroup.io/blog/2021/7/9/from-stolen-laptop-to-inside-the-company-network'
                )
            ))
        }
    }

    # Flag: suspended protection (common during OS updates, sometimes forgotten)
    if ($vol.ProtectionStatus -eq 'Off' -and $vol.VolumeStatus -ne 'FullyDecrypted') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-BIT-003' `
            -Category 'BootIntegrity' `
            -Title "BitLocker suspended on $($vol.MountPoint) (encryption intact but protectors inactive)" `
            -Severity 'High' `
            -Exploitability 'High' `
            -AttackPath 'Suspended BitLocker means clear VMK on disk - offline attack gives key without TPM or recovery key' `
            -MITRE 'T1552' `
            -Evidence $volInfo `
            -Remediation "Resume-BitLocker -MountPoint $($vol.MountPoint) immediately. Suspensions should be time-bounded and automatic." `
            -OperatorNotes 'Usually an artefact of a half-finished Windows Update / firmware update. If you pick this up on a live host, the VMK is recoverable from the partition metadata. High finding on lost/stolen hardware.' `
            -References @()
        ))
    }
}

# Secure Boot
if ($ctx.SecureBootEnabled -eq $false) {
    # Only flag if hardware is capable - firmware interface present
    try {
        $sbPolicy = Get-SecureBootPolicy -ErrorAction SilentlyContinue
        if ($sbPolicy) {
            $BR2.Findings.Add( (New-Finding `
                -CheckID 'BR-BIT-004' `
                -Category 'BootIntegrity' `
                -Title 'Secure Boot is disabled on a Secure-Boot-capable platform' `
                -Severity 'High' `
                -Exploitability 'Medium' `
                -AttackPath 'Bootkit / unsigned bootloader can persist below the OS - survives reinstalls' `
                -MITRE 'T1542.003' `
                -Evidence @{ SecureBootEnabled = $false } `
                -Remediation 'Enable Secure Boot in UEFI. Requires Windows 8+ / Server 2012+ bootloader chain. Key for defence against BlackLotus and similar bootkits.' `
                -OperatorNotes 'BlackLotus (2023) bypasses Secure Boot via CVE-2022-21894 baton drop; Microsoft mitigations via KB5025885 are partial. Presence of Secure Boot raises the bar but is not sufficient alone.' `
                -References @(
                    'https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/',
                    'https://support.microsoft.com/en-us/topic/kb5025885'
                )
            ))
        }
    } catch {}
}

# DMA protection (Thunderbolt / PCIe)
# Kernel DMA Protection requires VT-d/AMD-Vi + VBS + policy enabled.
# On client laptops with Thunderbolt, DMA attacks (PCILeech, Inception)
# extract memory directly.
$dmaEnabled = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses' -Name '*'

# Simpler check: see if MDAG/Kernel-DMA-Protection key exists
$kdmaState = $null
try {
    $kdmaState = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue).SecurityServicesRunning
    # 4 = Kernel DMA Protection (running)
} catch {}

$BR2.Raw.KernelDMAProtection = @{
    SecurityServicesRunning = $kdmaState
}

if ($ctx.IsClient -and $kdmaState -and -not ($kdmaState -contains 4)) {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-BIT-005' `
        -Category 'BootIntegrity' `
        -Title 'Kernel DMA Protection not running on a client device' `
        -Severity 'Medium' `
        -Exploitability 'Medium' `
        -AttackPath 'DMA (Direct Memory Access) attack via Thunderbolt / PCIe; read VMK / TGTs / credentials from physical memory' `
        -MITRE 'T1542' `
        -Evidence @{ SecurityServicesRunning = $kdmaState } `
        -Remediation 'Enable Kernel DMA Protection via UEFI + VBS + Windows 10 1803+ settings. Hardware must support it (Intel VT-d or AMD equivalent).' `
        -OperatorNotes 'PCILeech with a FPGA adapter, or Inception with Firewire/Thunderbolt, read arbitrary memory from a running Windows host. BitLocker VMK, cached Kerberos TGTs, session keys all extractable. High finding on lost/stolen laptop scenarios.' `
        -References @('https://github.com/ufrisk/pcileech')
    ))
}

# TPM 2.0 availability
if ($ctx.TPMVersion -and $ctx.TPMVersion -notmatch '2\.') {
    $BR2.Findings.Add( (New-Finding `
        -CheckID 'BR-BIT-006' `
        -Category 'BootIntegrity' `
        -Title "TPM version is $($ctx.TPMVersion) - less than 2.0" `
        -Severity 'Low' `
        -Exploitability 'Low' `
        -AttackPath 'TPM 1.2 has weaker crypto and smaller PCR banks; known bus-sniffing research easier against 1.2 chips' `
        -MITRE '-' `
        -Evidence @{ TPMVersion = $ctx.TPMVersion } `
        -Remediation 'Upgrade hardware or enable fTPM (firmware TPM) 2.0 if available in UEFI. Windows 11 requires TPM 2.0.' `
        -OperatorNotes 'Low exploit value in isolation - relevant for BitLocker threat model on older hardware.' `
        -References @()
    ))
}
