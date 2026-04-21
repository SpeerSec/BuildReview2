#requires -Version 5.1


$scriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent

# Engine -> Reporting -> Runner. Collectors load at Invoke-BuildReview time.
. (Join-Path $scriptRoot 'Engine\New-Finding.ps1')
. (Join-Path $scriptRoot 'Engine\Get-HostContext.ps1')

. (Join-Path $scriptRoot 'Reporting\Export-MarkdownReport.ps1')
. (Join-Path $scriptRoot 'Reporting\Export-HtmlReport.ps1')

. (Join-Path $scriptRoot 'Engine\Invoke-BuildReview.ps1')

Export-ModuleMember -Function `
    'Invoke-BuildReview',
    'Get-HostContext',
    'Test-OSPrecondition',
    'New-Finding',
    'Get-RegistryValueSafe',
    'Test-IsElevated',
    'Export-MarkdownReport',
    'Export-HtmlReport'
