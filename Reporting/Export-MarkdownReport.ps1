function Export-MarkdownReport {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Findings,
        [Parameter(Mandatory)] [object]   $Context,
        [Parameter(Mandatory)] [string]   $Path
    )

    $hostName  = $Context.ComputerName
    $collected = (Get-Date).ToString('dd-MM-yyyy HH:mm')

    $sevCounts = @{}
    foreach ($s in 'Critical','High','Medium','Low','Info') {
        $sevCounts[$s] = @($Findings | Where-Object { $_.Severity -eq $s }).Count
    }
    $categories = @($Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object)

    $sb = [System.Text.StringBuilder]::new()

    # YAML frontmatter (Obsidian Dataview / any YAML-aware tool)
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('tags:')
    [void]$sb.AppendLine('  - buildreview')
    [void]$sb.AppendLine('  - engagement')
    [void]$sb.AppendLine("host: $hostName")
    [void]$sb.AppendLine("collected: $collected")
    [void]$sb.AppendLine("total_findings: $($Findings.Count)")
    [void]$sb.AppendLine("critical: $($sevCounts['Critical'])")
    [void]$sb.AppendLine("high: $($sevCounts['High'])")
    [void]$sb.AppendLine("medium: $($sevCounts['Medium'])")
    [void]$sb.AppendLine("low: $($sevCounts['Low'])")
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine()

    [void]$sb.AppendLine("# BuildReview2 report for $hostName")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Host context')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("- **OS:** $($Context.FriendlyVersion) (build $($Context.BuildNumber).$($Context.UBR), $($Context.Edition))")
    [void]$sb.AppendLine("- **Role:** $($Context.HostRole)$(if ($Context.IsServerCore) { ' (Server Core)' })")
    [void]$sb.AppendLine("- **Domain:** $(if ($Context.IsDomainJoined) { $Context.DomainName } else { 'Workgroup' })")
    if ($Context.IsAzureADJoined) {
        [void]$sb.AppendLine("- **Entra:** Joined ($($Context.EntraTenant))$(if ($Context.IsHybridJoined) { ' [Hybrid]' })")
    }
    [void]$sb.AppendLine("- **Virtualised:** $($Context.IsVirtual) ($($Context.Hypervisor))")
    [void]$sb.AppendLine("- **Hardware security:** TPM $(if ($Context.TPMPresent) { $Context.TPMVersion } else { 'absent' }), SecureBoot $($Context.SecureBootEnabled), VBS $($Context.VBSEnabled), HVCI $($Context.HVCIEnabled)")
    [void]$sb.AppendLine("- **EOL status:** $($Context.EOLStatus)$(if ($Context.EOLNote) { " - $($Context.EOLNote)" })")
    [void]$sb.AppendLine("- **Elevated:** $($Context.Elevated)")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('> [!info] Run summary')
    [void]$sb.AppendLine("> Collected: $collected")
    [void]$sb.AppendLine("> Host: ``$hostName``")
    [void]$sb.AppendLine("> Findings: **$($Findings.Count)** total - Critical **$($sevCounts['Critical'])**, High **$($sevCounts['High'])**, Medium **$($sevCounts['Medium'])**, Low **$($sevCounts['Low'])**")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Top attack paths on this host')
    [void]$sb.AppendLine()
    $topPaths = $Findings |
        Where-Object { $_.Exploitability -in 'High','Medium' } |
        Select-Object -First 10
    if ($topPaths.Count -eq 0) {
        [void]$sb.AppendLine('_No High- or Medium-exploitability findings._')
    } else {
        foreach ($f in $topPaths) {
            $sevBadge = "``$($f.Severity.ToUpper())``"
            [void]$sb.AppendLine("- $sevBadge **$($f.CheckID)** - $($f.Title) _(exploitability: $($f.Exploitability))_")
        }
    }
    [void]$sb.AppendLine()

    foreach ($cat in $categories) {
        [void]$sb.AppendLine("## $cat")
        [void]$sb.AppendLine()

        $catFindings = $Findings | Where-Object { $_.Category -eq $cat }
        foreach ($f in $catFindings) {
            $calloutType = switch ($f.Severity) {
                'Critical' { 'danger'  }
                'High'     { 'danger'  }
                'Medium'   { 'warning' }
                'Low'      { 'note'    }
                default    { 'info'    }
            }

            [void]$sb.AppendLine("> [!$calloutType]- $($f.CheckID): $($f.Title)")
            [void]$sb.AppendLine('> ')
            [void]$sb.AppendLine("> **Severity:** $($f.Severity) | **Exploitability:** $($f.Exploitability)")
            [void]$sb.AppendLine('> ')
            [void]$sb.AppendLine("> **Attack path:** $($f.AttackPath)")

            if ($f.MITRE -and $f.MITRE.Count -gt 0) {
                $mitreLinks = ($f.MITRE | ForEach-Object { "[[$_]]" }) -join ', '
                [void]$sb.AppendLine('> ')
                [void]$sb.AppendLine("> **MITRE ATT&CK:** $mitreLinks")
            }

            if ($f.Evidence -and $f.Evidence.Keys.Count -gt 0) {
                [void]$sb.AppendLine('> ')
                [void]$sb.AppendLine('> **Evidence:**')
                foreach ($k in $f.Evidence.Keys) {
                    $v = $f.Evidence[$k]
                    if ($v -is [array]) {
                        $vStr = '[' + (($v | ForEach-Object { "``$_``" }) -join ', ') + ']'
                    } elseif ($v -is [hashtable]) {
                        $vStr = ($v | ConvertTo-Json -Compress)
                    } else {
                        $vStr = "``$v``"
                    }
                    [void]$sb.AppendLine("> - $k`: $vStr")
                }
            }

            if ($f.OperatorNotes) {
                [void]$sb.AppendLine('> ')
                [void]$sb.AppendLine('> **Operator notes:**')
                foreach ($line in ($f.OperatorNotes -split "`n")) {
                    [void]$sb.AppendLine("> $line")
                }
            }

            if ($f.Remediation) {
                [void]$sb.AppendLine('> ')
                [void]$sb.AppendLine("> **Remediation:** $($f.Remediation)")
            }

            if ($f.References -and $f.References.Count -gt 0) {
                [void]$sb.AppendLine('> ')
                [void]$sb.AppendLine('> **References:**')
                foreach ($r in $f.References) {
                    [void]$sb.AppendLine("> - $r")
                }
            }

            [void]$sb.AppendLine()
        }
    }

    [void]$sb.AppendLine('## Appendix: raw findings (JSON)')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('```json')
    [void]$sb.AppendLine(($Findings | ConvertTo-Json -Depth 6))
    [void]$sb.AppendLine('```')

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
}
