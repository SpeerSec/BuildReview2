function Invoke-BuildReview {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet('Html','Json','Markdown','Csv')]
        [string[]]$Formats = @('Html','Markdown'),
        [string[]]$IncludeCategories,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$MinSeverity = 'Info',
        [switch]$SkipPreflightBanner
    )

    $global:BR2 = [PSCustomObject]@{
        StartTime = Get-Date
        Context   = $null
        Raw       = @{}
        Findings  = [System.Collections.Generic.List[object]]::new()
        Skipped   = [System.Collections.Generic.List[object]]::new()
    }

    Write-Progress -Id 1 -Activity 'BuildReview2 by @speersec' -Status 'Gathering host context (percentage bar may be buggy...sorry)' -PercentComplete 0
    $BR2.Context = Get-HostContext

    if (-not $SkipPreflightBanner) {
        $c = $BR2.Context
        Write-Host ""
        Write-Host "=== BuildReview2 Computer Info Checks ===" -ForegroundColor Cyan
        Write-Host "Host          : $($c.ComputerName)"
        Write-Host "OS            : $($c.FriendlyVersion)  (build $($c.BuildNumber).$($c.UBR), edition $($c.Edition))"
        Write-Host "Role          : $($c.HostRole)$(if ($c.IsServerCore) { ' (Server Core)' })"
        Write-Host "Domain        : $(if ($c.IsDomainJoined) { $c.DomainName } else { 'Workgroup' })"
        if ($c.IsAzureADJoined) { Write-Host "Entra         : Joined (tenant: $($c.EntraTenant))$(if ($c.IsHybridJoined) { ' [Hybrid]' })" }
        Write-Host "Virtualised   : $($c.IsVirtual) ($($c.Hypervisor))"
        Write-Host "Hardware sec  : TPM $(if ($c.TPMPresent) { $c.TPMVersion } else { 'absent' }), SecureBoot $($c.SecureBootEnabled), VBS $($c.VBSEnabled), HVCI $($c.HVCIEnabled)"
        Write-Host "Elevated      : $($c.Elevated)"
        $eolColour = switch ($c.EOLStatus) { 'EOL' { 'Red' } 'ExtendedSupport' { 'Yellow' } default { 'Green' } }
        Write-Host "EOL status    : $($c.EOLStatus)$(if ($c.EOLNote) { " - $($c.EOLNote)" })" -ForegroundColor $eolColour
        Write-Host "Confidence    : $($c.Confidence)%"
        Write-Host ""
    }

    if ($BR2.Context.EOLStatus -eq 'EOL') {
        $BR2.Findings.Add( (New-Finding `
            -CheckID 'BR-META-001' `
            -Category 'Lifecycle' `
            -Title "Host is running an end-of-life OS: $($BR2.Context.FriendlyVersion)" `
            -Severity 'Critical' `
            -Exploitability 'High' `
            -AttackPath 'Unpatched kernel primitives, legacy protocol acceptance, widening attack surface with every disclosed vuln' `
            -MITRE 'T1210' `
            -Evidence @{
                FriendlyVersion = $BR2.Context.FriendlyVersion
                BuildNumber     = $BR2.Context.BuildNumber
                Note            = $BR2.Context.EOLNote
            } `
            -Remediation 'This host is past vendor extended support. Individual hardening findings below are secondary - priority is migration or ESU purchase.' `
            -OperatorNotes 'EOL Windows broadens the operator toolkit considerably: SMB1 often available, NTLMv1 often accepted, no ASR, no AMSI on Win7/2008R2, no LSA PPL on 2012 and below, and any privesc primitive published in the last 3 years may be unpatched.' `
            -References @('https://learn.microsoft.com/en-us/lifecycle/products/')
        ))
    }

    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }

    $collectorDir = Join-Path $PSScriptRoot '..\Collectors'
    $collectors = @(Get-ChildItem -Path $collectorDir -Filter *.ps1 -ErrorAction SilentlyContinue | Sort-Object Name)

    $total = $collectors.Count
    $idx = 0
    foreach ($c in $collectors) {
        $idx++
        $pct = if ($total -gt 0) { [int][Math]::Min(100, [Math]::Max(1, ($idx / $total) * 100)) } else { 50 }
        $display = $c.BaseName -replace '^Get-',''
        Write-Progress -Id 1 -Activity 'BuildReview2' `
            -Status "[$idx/$total] $display" `
            -CurrentOperation "Findings so far: $($BR2.Findings.Count)" `
            -PercentComplete $pct

        try { . $c.FullName }
        catch {
            $BR2.Skipped.Add([PSCustomObject]@{
                Collector = $c.BaseName
                Reason    = "Collector failed: $($_.Exception.Message)"
            })
        }
    }

    Write-Progress -Id 1 -Activity 'BuildReview2' -Status 'Sorting and exporting' -PercentComplete 100

    $severityOrder = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1; 'Info' = 0 }
    $minLevel = $severityOrder[$MinSeverity]
    $filtered = $BR2.Findings | Where-Object {
        $severityOrder[$_.Severity] -ge $minLevel -and
        ( -not $IncludeCategories -or $IncludeCategories -contains $_.Category )
    }

    $exploitOrder = @{ 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Theoretical' = 1; 'NotOnThisHost' = 0 }
    $sorted = $filtered | Sort-Object `
        @{ Expression = { $exploitOrder[$_.Exploitability] }; Descending = $true },
        @{ Expression = { $severityOrder[$_.Severity]     }; Descending = $true }

    $stamp    = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $hostName = $BR2.Context.ComputerName
    foreach ($f in $Formats) {
        switch ($f) {
            'Json' {
                $path = Join-Path $OutputPath "BR2-$hostName-$stamp.json"
                @{
                    Context  = $BR2.Context
                    Findings = $sorted
                    Skipped  = $BR2.Skipped
                    Raw      = $BR2.Raw
                } | ConvertTo-Json -Depth 10 | Out-File -FilePath $path -Encoding UTF8
                Write-Host "Wrote $path"
            }
            'Csv' {
                $path = Join-Path $OutputPath "BR2-$hostName-$stamp.csv"
                $sorted | Select-Object CheckID, Category, Title, Severity, Exploitability, AttackPath,
                    @{n='MITRE';e={ $_.MITRE -join ',' }}, Remediation |
                    Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
                Write-Host "Wrote $path"
            }
            'Markdown' {
                $path = Join-Path $OutputPath "BR2-$hostName-$stamp.md"
                Export-MarkdownReport -Findings $sorted -Context $BR2.Context -Path $path
                Write-Host "Wrote $path"
            }
            'Html' {
                $path = Join-Path $OutputPath "BR2-$hostName-$stamp.html"
                Export-HtmlReport -Findings $sorted -Context $BR2.Context -Path $path
                Write-Host "Wrote $path"
            }
        }
    }

    Write-Progress -Id 1 -Activity 'BuildReview2' -Completed

    $elapsed = (Get-Date) - $BR2.StartTime
    Write-Host ""
    Write-Host ("Review complete: {0} findings in {1:mm}:{1:ss}" -f $sorted.Count, $elapsed) -ForegroundColor Green

    return $sorted
}
