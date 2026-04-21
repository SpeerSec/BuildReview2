function Export-HtmlReport {

    param(
        [Parameter(Mandatory)] $Findings,
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string]$Path
    )

    $severityColour = @{
        'Critical' = '#b00020'
        'High'     = '#d97706'
        'Medium'   = '#c7a500'
        'Low'      = '#4a8f3a'
        'Info'     = '#4399e4'
    }

    $severityCounts = @{
        Critical = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
        Medium   = @($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
        Low      = @($Findings | Where-Object { $_.Severity -eq 'Low'      }).Count
        Info     = @($Findings | Where-Object { $_.Severity -eq 'Info'     }).Count
    }

    $ctxHtml = @"
<div class='ctx'>
<h2>Host context</h2>
<table>
<tr><td>Computer</td><td>$($Context.ComputerName)</td></tr>
<tr><td>OS</td><td>$($Context.FriendlyVersion) (build $($Context.BuildNumber).$($Context.UBR), $($Context.Edition))</td></tr>
<tr><td>Role</td><td>$($Context.HostRole)$(if ($Context.IsServerCore) { ' (Server Core)' })</td></tr>
<tr><td>Domain</td><td>$(if ($Context.IsDomainJoined) { $Context.DomainName } else { 'Workgroup' })</td></tr>
<tr><td>Entra</td><td>$(if ($Context.IsAzureADJoined) { "Joined ($($Context.EntraTenant))$(if ($Context.IsHybridJoined) { ' [Hybrid]' })" } else { 'Not joined' })</td></tr>
<tr><td>Virtualised</td><td>$($Context.IsVirtual) ($($Context.Hypervisor))</td></tr>
<tr><td>Hardware security</td><td>TPM $(if ($Context.TPMPresent) { $Context.TPMVersion } else { 'absent' }), SecureBoot $($Context.SecureBootEnabled), VBS $($Context.VBSEnabled), HVCI $($Context.HVCIEnabled)</td></tr>
<tr><td>EOL</td><td>$($Context.EOLStatus)$(if ($Context.EOLNote) { " - $($Context.EOLNote)" })</td></tr>
<tr><td>Elevation</td><td>$($Context.Elevated)</td></tr>
<tr><td>Confidence</td><td>$($Context.Confidence)%</td></tr>
</table>
</div>
"@

    $summary = @"
<div class='summary'>
<h2>Findings summary</h2>
<ul class='sevcount'>
<li class='sev-critical'>Critical: $($severityCounts.Critical)</li>
<li class='sev-high'>High: $($severityCounts.High)</li>
<li class='sev-medium'>Medium: $($severityCounts.Medium)</li>
<li class='sev-low'>Low: $($severityCounts.Low)</li>
<li class='sev-info'>Info: $($severityCounts.Info)</li>
</ul>
</div>
"@

    $findingsHtml = foreach ($f in $Findings) {
        $sevClass = "sev-$($f.Severity.ToLower())"
        $evJson = try { ($f.Evidence | ConvertTo-Json -Depth 6 -Compress) } catch { '{}' }
        $mitre = if ($f.MITRE) { ($f.MITRE -join ', ') } else { '' }
        $refs  = if ($f.References) { ($f.References | ForEach-Object { "<a href='$_' target='_blank' rel='noopener'>$_</a>" }) -join '<br>' } else { '' }

        @"
<details class='finding $sevClass' data-category='$($f.Category)' data-severity='$($f.Severity)' data-exploit='$($f.Exploitability)'>
<summary><span class='sev-pill $sevClass'>$($f.Severity)</span> <span class='expl-pill'>$($f.Exploitability)</span> <strong>$($f.Title)</strong> <span class='cid'>$($f.CheckID)</span></summary>
<div class='body'>
<p><strong>Category:</strong> $($f.Category)</p>
<p><strong>Attack path:</strong> $($f.AttackPath)</p>
<p><strong>MITRE:</strong> $mitre</p>
<p><strong>Remediation:</strong> $($f.Remediation)</p>
<p><strong>Operator notes:</strong> $($f.OperatorNotes)</p>
<details class='evidence'><summary>Evidence</summary><pre>$([System.Web.HttpUtility]::HtmlEncode($evJson))</pre></details>
<p class='refs'>$refs</p>
</div>
</details>
"@
    }

    $findingsHtmlBlob = $findingsHtml -join "`n"

    # Build distinct categories for filter
    $categories = @($Findings.Category | Sort-Object -Unique)
    $categoryOptions = ($categories | ForEach-Object { "<option value='$_'>$_</option>" }) -join ''

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>BuildReview2 - $($Context.ComputerName)</title>
<style>
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 1.5rem; color: #1a1a1a; background: #fafafa; }
h1 { margin: 0 0 0.2rem; font-size: 1.4rem; }
h2 { margin-top: 1.4rem; font-size: 1.1rem; border-bottom: 1px solid #ddd; padding-bottom: 0.2rem; }
.ctx table { border-collapse: collapse; }
.ctx td { padding: 2px 10px; vertical-align: top; font-size: 0.9rem; }
.ctx td:first-child { color: #666; }
.summary ul.sevcount { list-style: none; padding: 0; display: flex; gap: 1rem; flex-wrap: wrap; }
.summary li { padding: 0.3rem 0.8rem; border-radius: 4px; color: white; font-weight: 600; }
.sev-critical { background: #b00020; }
.sev-high     { background: #d97706; }
.sev-medium   { background: #c7a500; }
.sev-low      { background: #4a8f3a; }
.sev-info     { background: #4399e4; }
.filters { margin: 1rem 0; display: flex; gap: 1rem; flex-wrap: wrap; }
.filters select, .filters input { padding: 0.3rem 0.5rem; border: 1px solid #bbb; border-radius: 3px; }
.finding { background: white; border: 1px solid #ddd; border-left-width: 5px; border-radius: 4px; margin: 0.4rem 0; padding: 0.4rem 0.7rem; }
.finding.sev-critical { border-left-color: #b00020; }
.finding.sev-high     { border-left-color: #d97706; }
.finding.sev-medium   { border-left-color: #c7a500; }
.finding.sev-low      { border-left-color: #4a8f3a; }
.finding.sev-info     { border-left-color: #4399e4; }
.finding summary { cursor: pointer; padding: 0.3rem 0; }
.finding .body { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #eee; font-size: 0.95rem; }
.finding .body p { margin: 0.3rem 0; }
.sev-pill, .expl-pill { padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.75rem; color: white; display: inline-block; margin-right: 0.3rem; }
.expl-pill { background: #334; }
.cid { color: #777; font-family: monospace; font-size: 0.8rem; margin-left: 0.4rem; }
pre { background: #f4f4f4; padding: 0.6rem; border-radius: 3px; overflow: auto; font-size: 0.8rem; max-height: 18rem; }
.refs a { color: #0058a8; font-size: 0.8rem; }
footer { margin-top: 2rem; color: #888; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>BuildReview2 Report for $($Context.ComputerName)</h1>
<p>$($Context.FriendlyVersion) - $($Context.HostRole) - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
$ctxHtml
$summary
<div class='filters'>
<label>Severity: <select id='f-sev'>
<option value=''>All</option>
<option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option>
</select></label>
<label>Category: <select id='f-cat'>
<option value=''>All</option>
$categoryOptions
</select></label>
<label>Search: <input id='f-search' type='search' placeholder='title / check ID' style='width:20rem'></label>
</div>
<div id='findings'>
$findingsHtmlBlob
</div>
<footer>Generated by BuildReview2 developed by @speersec. Findings reviewed by host-aware preconditions - see check IDs for source.</footer>
<script>
(function(){
    const f = document.querySelectorAll('.finding');
    const sevSel = document.getElementById('f-sev');
    const catSel = document.getElementById('f-cat');
    const search = document.getElementById('f-search');
    function apply() {
        const s = sevSel.value, c = catSel.value, q = (search.value || '').toLowerCase();
        f.forEach(n => {
            const okSev = !s || n.dataset.severity === s;
            const okCat = !c || n.dataset.category === c;
            const okQry = !q || n.textContent.toLowerCase().includes(q);
            n.style.display = (okSev && okCat && okQry) ? '' : 'none';
        });
    }
    sevSel.addEventListener('change', apply);
    catSel.addEventListener('change', apply);
    search.addEventListener('input',   apply);
})();
</script>
</body>
</html>
"@

    # Add System.Web assembly for HtmlEncode if needed
    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

    $html | Out-File -FilePath $Path -Encoding UTF8
}
