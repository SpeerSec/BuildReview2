#requires -Version 5.1

function Get-HostContext {
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS          -ErrorAction SilentlyContinue

    # ---- OS version, build, UBR ------------------------------------------
    $currentVer = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $productName = Get-RegistryValueSafe -Path $currentVer -Name 'ProductName'
    $displayVer  = Get-RegistryValueSafe -Path $currentVer -Name 'DisplayVersion'   # 22H2, 23H2, 24H2
    $releaseId   = Get-RegistryValueSafe -Path $currentVer -Name 'ReleaseId'        # legacy 1909, 2004, 20H2
    $editionId   = Get-RegistryValueSafe -Path $currentVer -Name 'EditionID'        # Enterprise, ServerDatacenter
    $installType = Get-RegistryValueSafe -Path $currentVer -Name 'InstallationType' # 'Server Core' if Core
    $ubr         = Get-RegistryValueSafe -Path $currentVer -Name 'UBR'              # Update Build Revision
    $buildNum    = [int]$os.BuildNumber

    # Windows 11 has ProductName = 'Windows 10 ...' on earlier registries;
    # build number is the reliable discriminator (22000+ = Windows 11)
    $isWin11  = ($buildNum -ge 22000 -and $buildNum -lt 26100) -and ($os.ProductType -eq 1)
    $isWin10  = ($buildNum -ge 10240 -and $buildNum -lt 22000) -and ($os.ProductType -eq 1)
    $isServer = ($os.ProductType -ne 1)

    # Map build -> friendly server version. Microsoft's build numbers:
    #   14393 -> Server 2016
    #   17763 -> Server 2019
    #   20348 -> Server 2022
    #   25398 -> Server 23H2 (Azure Stack HCI / semi-annual)
    #   26100 -> Server 2025
    $serverVersion = switch ($buildNum) {
        7601  { 'Server 2008 R2' }
        9200  { 'Server 2012' }
        9600  { 'Server 2012 R2' }
        14393 { 'Server 2016' }
        17763 { 'Server 2019' }
        20348 { 'Server 2022' }
        25398 { 'Server 23H2' }
        26100 { 'Server 2025' }
        default { if ($isServer) { "Server (build $buildNum)" } else { $null } }
    }

    $clientVersion = switch ($buildNum) {
        7601   { 'Windows 7 SP1' }
        9200   { 'Windows 8' }
        9600   { 'Windows 8.1' }
        10240  { 'Windows 10 1507' }
        14393  { 'Windows 10 1607' }
        15063  { 'Windows 10 1703' }
        16299  { 'Windows 10 1709' }
        17134  { 'Windows 10 1803' }
        17763  { 'Windows 10 1809 / LTSC 2019' }
        18362  { 'Windows 10 1903' }
        18363  { 'Windows 10 1909' }
        19041  { 'Windows 10 2004' }
        19042  { 'Windows 10 20H2' }
        19043  { 'Windows 10 21H1' }
        19044  { 'Windows 10 21H2 / LTSC 2021' }
        19045  { 'Windows 10 22H2' }
        22000  { 'Windows 11 21H2' }
        22621  { 'Windows 11 22H2' }
        22631  { 'Windows 11 23H2' }
        26100  { 'Windows 11 24H2' }
        default { if ($isWin10 -or $isWin11) { "Windows (build $buildNum)" } else { $null } }
    }

    # ---- Domain / Entra state --------------------------------------------
    $isDomainJoined = [bool]$cs.PartOfDomain
    $isWorkgroup    = -not $isDomainJoined

    # Entra / Azure AD / Hybrid join state via dsregcmd /status output.
    # dsregcmd exists from Windows 10 1607+.
    $aadJoined    = $false
    $hybridJoined = $false
    $entraTenant  = $null
    try {
        $dsreg = & dsregcmd.exe /status 2>$null
        if ($dsreg) {
            $aadJoined    = [bool]($dsreg | Select-String -Pattern 'AzureAdJoined\s*:\s*YES'   -SimpleMatch:$false)
            $domainJoinedD = [bool]($dsreg | Select-String -Pattern 'DomainJoined\s*:\s*YES'   -SimpleMatch:$false)
            # Hybrid = both AzureAdJoined and DomainJoined
            $hybridJoined = ($aadJoined -and $domainJoinedD)
            $tenantLine = $dsreg | Select-String -Pattern 'TenantName\s*:\s*(.+)' | Select-Object -First 1
            if ($tenantLine) {
                $entraTenant = $tenantLine.Matches[0].Groups[1].Value.Trim()
            }
        }
    } catch {}

    # ---- Domain role and DC specifics ------------------------------------
    $domainRole = $cs.DomainRole
    $isDC = ($domainRole -eq 4 -or $domainRole -eq 5)

    $hostRole = switch ($domainRole) {
        0 { 'Standalone' }
        1 { 'Workstation' }
        2 { 'Standalone' }
        3 { 'MemberServer' }
        4 { 'DomainController' }
        5 { 'DomainController' }
        default { 'Unknown' }
    }

    $isServerCore = ($installType -eq 'Server Core')

    # ---- Virtualisation --------------------------------------------------
    $isVirtual = $false
    $hypervisor = 'Physical'
    if ($cs) {
        $manufacturer = "$($cs.Manufacturer)"
        $model        = "$($cs.Model)"
        switch -Regex ("$manufacturer $model") {
            'Microsoft Corporation.*Virtual Machine' { $isVirtual = $true; $hypervisor = 'Hyper-V' }
            'VMware'                                  { $isVirtual = $true; $hypervisor = 'VMware' }
            'QEMU|KVM'                                { $isVirtual = $true; $hypervisor = 'QEMU/KVM' }
            'Xen'                                     { $isVirtual = $true; $hypervisor = 'Xen' }
            'Parallels'                               { $isVirtual = $true; $hypervisor = 'Parallels' }
            'innotek|VirtualBox'                      { $isVirtual = $true; $hypervisor = 'VirtualBox' }
        }
    }

    # ---- Hardware security capability ------------------------------------
    $tpmPresent = $false
    $tpmVersion = $null
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            $tpmPresent = [bool]$tpm.IsEnabled_InitialValue
            $tpmVersion = "$($tpm.SpecVersion)".Split(',')[0].Trim()
        }
    } catch {}

    $secureBootEnabled = $null
    try { $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue } catch {}

    # VBS / HVCI state via Win32_DeviceGuard (needs admin for full data)
    $vbsEnabled  = $null
    $hvciEnabled = $null
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                              -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            # VirtualizationBasedSecurityStatus: 0 off, 1 enabled-not-running, 2 running
            $vbsEnabled  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
            $hvciEnabled = ($dg.SecurityServicesRunning -contains 2)   # 2 = HVCI
        }
    } catch {}

    # ---- EOL status (approximate, note to self: update as dates shift) -----------------
    # Key dates from Microsoft lifecycle:
    #   Server 2008 R2  - Extended EOL 14 Jan 2020 (ESU ended 10 Jan 2023 for non-Azure)
    #   Server 2012     - Extended EOL 10 Oct 2023 (ESU extends limitedly)
    #   Server 2012 R2  - Extended EOL 10 Oct 2023 (ESU extends limitedly)
    #   Windows 7       - EOL 14 Jan 2020
    #   Windows 8.1     - EOL 10 Jan 2023
    #   Windows 10 22H2 - EOL 14 Oct 2025 (ESU 2025-2028)
    #   Server 2016     - Mainstream ended, Extended through 12 Jan 2027
    #   Server 2019     - Mainstream ended, Extended through 9 Jan 2029
    #   Windows 11 21H2 - EOL Oct 2024 (Ent/Edu: Oct 2025)
    $eolStatus = 'Supported'
    $eolNote   = $null
    $today = Get-Date
    switch ($buildNum) {
        7601  { $eolStatus = 'EOL'; $eolNote = 'Windows 7 / Server 2008 R2 extended support ended 14 Jan 2020 (ESU 10 Jan 2023).' }
        9200  { $eolStatus = 'EOL'; $eolNote = 'Windows 8 / Server 2012 extended support ended 10 Oct 2023.' }
        9600  { $eolStatus = 'EOL'; $eolNote = 'Windows 8.1 / Server 2012 R2 extended support ended 10 Oct 2023.' }
        10240 { $eolStatus = 'EOL'; $eolNote = 'Windows 10 1507 EOL 2017.' }
        19045 { if ($today -gt (Get-Date '2025-10-14')) { $eolStatus = 'ExtendedSupport'; $eolNote = 'Windows 10 22H2 reached end of consumer support 14 Oct 2025; ESU available.' } }
        22000 { if ($today -gt (Get-Date '2025-10-08')) { $eolStatus = 'EOL'; $eolNote = 'Windows 11 21H2 (non-Enterprise) EOL Oct 2023; Enterprise Oct 2024.' } }
    }

    # ---- Capability flags ------------------------------------------------
    # These are the things checks actually care about. Computed once here;
    # rules just test Context.SupportsX.
    $supports = [PSCustomObject]@{
        # Credential Guard: Enterprise/Education/Server SKUs on Win10 1511+
        CredentialGuard      = ( ($editionId -match 'Enterprise|Education') -or $isServer ) `
                                  -and ($buildNum -ge 10586)
        # LSA RunAsPPL: Win 8.1 / Server 2012 R2 and above
        RunAsPPL             = ($buildNum -ge 9600)
        # RunAsPPL=2 (PPLWithSigner): Win11 22H2+ / Server 2025
        PPLWithSigner        = ( ($isWin11 -and $buildNum -ge 22621) -or ($buildNum -ge 26100) )
        # UEFI-locked RunAsPPL: Win11 22H2+
        UEFILockedLSA        = ($isWin11 -and $buildNum -ge 22621)
        # Windows LAPS built-in (not legacy): Win11 21H2+ and Server 2019+ after Apr 2023 update
        WindowsLAPS_Builtin  = ( ($isWin11) -or ($isServer -and $buildNum -ge 17763) )
        # Smart App Control: Win11 22H2+, clean install only (not detected here)
        SmartAppControl      = ($isWin11 -and $buildNum -ge 22621)
        # Personal Data Encryption: Win11 22H2+ Enterprise/Education
        PDE                  = ($isWin11 -and $buildNum -ge 22621 -and ($editionId -match 'Enterprise|Education'))
        # SMB over QUIC listener: Server 2022 Azure Ed / Server 2025 / Win11 24H2
        SMBoverQUIC_Listener = ($isServer -and $buildNum -ge 20348)
        # Default-required SMB signing: Win11 24H2 / Server 2025
        DefaultSMBSigning    = ( ($isWin11 -and $buildNum -ge 26100) -or ($isServer -and $buildNum -ge 26100) )
        # dMSA (delegated Managed Service Accounts): Server 2025 DC
        dMSA                 = ($isDC -and $buildNum -ge 26100)
        # Credential Guard default-on: Win11 22H2 Enterprise, supported hardware
        CredGuardDefaultOn   = ($isWin11 -and $buildNum -ge 22621 -and ($editionId -match 'Enterprise|Education'))
        # VBS capability (hardware)
        VBSCapable           = ($tpmPresent -and $secureBootEnabled -eq $true)
        # Kerberos RC4DefaultDisablementPhase registry: Jan 2026 cumulative update
        KerberosRC4Phase     = ($isDC -and $buildNum -ge 14393)
        # StrongCertificateBindingEnforcement registry: KB5014754, May 2022 cumulative
        StrongCertBinding    = ($isDC -and $buildNum -ge 14393)
        # Sysmon can run on anything modern; placeholder for future Sysmon version gate
        Sysmon               = $true
    }

    # ---- Confidence --------------------------------------------------------
    # Fields that needed admin and didn't get it degrade confidence
    $confidence = 100
    if (-not (Test-IsElevated)) {
        $confidence -= 20
        # VBS/HVCI detection is less reliable without admin
        if ($null -eq $vbsEnabled)  { $confidence -= 5 }
        if ($null -eq $hvciEnabled) { $confidence -= 5 }
    }
    if ($null -eq $tpmPresent -or $null -eq $secureBootEnabled) { $confidence -= 10 }

    [PSCustomObject]@{
        # Identity
        ComputerName       = $env:COMPUTERNAME
        DomainName         = $cs.Domain
        IsDomainJoined     = $isDomainJoined
        IsWorkgroup        = $isWorkgroup
        IsAzureADJoined    = $aadJoined
        IsHybridJoined     = $hybridJoined
        EntraTenant        = $entraTenant

        # OS
        ProductName        = $productName
        FriendlyVersion    = if ($isServer) { $serverVersion } else { $clientVersion }
        BuildNumber        = $buildNum
        UBR                = $ubr
        DisplayVersion     = $displayVer
        ReleaseId          = $releaseId
        Edition            = $editionId
        InstallationType   = $installType
        IsServer           = $isServer
        IsClient           = -not $isServer
        IsServerCore       = $isServerCore
        IsWin10            = $isWin10
        IsWin11            = $isWin11
        IsDC               = $isDC
        HostRole           = $hostRole

        # Lifecycle
        EOLStatus          = $eolStatus
        EOLNote            = $eolNote

        # Virtualisation
        IsVirtual          = $isVirtual
        Hypervisor         = $hypervisor

        # Hardware security
        TPMPresent         = $tpmPresent
        TPMVersion         = $tpmVersion
        SecureBootEnabled  = $secureBootEnabled
        VBSEnabled         = $vbsEnabled
        HVCIEnabled        = $hvciEnabled

        # Architecture
        Architecture       = $env:PROCESSOR_ARCHITECTURE

        # Derived capability flags
        Supports           = $supports

        # Meta
        Elevated           = Test-IsElevated
        Confidence         = $confidence
        Collected          = Get-Date
    }
}


function Test-OSPrecondition {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Requirements
    )

    $ctx = $global:BR2.Context
    if (-not $ctx) { return $true }  # Fail open if context isn't loaded

    if ($Requirements.ContainsKey('MinBuild') -and $ctx.BuildNumber -lt $Requirements.MinBuild) { return $false }
    if ($Requirements.ContainsKey('MaxBuild') -and $ctx.BuildNumber -gt $Requirements.MaxBuild) { return $false }

    if ($Requirements.ContainsKey('Server') -and $ctx.IsServer -ne $Requirements.Server) { return $false }
    if ($Requirements.ContainsKey('DC')     -and $ctx.IsDC     -ne $Requirements.DC)     { return $false }
    if ($Requirements.ContainsKey('DomainJoined') -and $ctx.IsDomainJoined  -ne $Requirements.DomainJoined)  { return $false }
    if ($Requirements.ContainsKey('EntraJoined')  -and $ctx.IsAzureADJoined -ne $Requirements.EntraJoined)   { return $false }

    if ($Requirements.ContainsKey('Edition')) {
        $match = $false
        foreach ($e in $Requirements.Edition) {
            if ($ctx.Edition -match $e) { $match = $true; break }
        }
        if (-not $match) { return $false }
    }

    if ($Requirements.ContainsKey('Architecture')) {
        if ($Requirements.Architecture -notcontains $ctx.Architecture) { return $false }
    }

    if ($Requirements.ContainsKey('RequiresCapability')) {
        $cap = $Requirements.RequiresCapability
        if (-not $ctx.Supports.$cap) { return $false }
    }

    if ($Requirements.ContainsKey('RequiresElevation') -and $Requirements.RequiresElevation -and -not $ctx.Elevated) {
        return $false
    }

    if ($Requirements.ContainsKey('NotEOL') -and $Requirements.NotEOL -and $ctx.EOLStatus -eq 'EOL') {
        return $false
    }

    return $true
}
