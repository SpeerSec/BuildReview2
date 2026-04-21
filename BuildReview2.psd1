@{
    RootModule         = 'BuildReview2.psm1'
    ModuleVersion      = '2.1.0'
    GUID               = 'b2e4e3d0-3f21-4e8a-9c5f-0a7d8c4a6b3e'
    Author             = '@Speersec'
    Description        = 'Attack-path-driven Windows host build review with OS-aware precondition gating. Single-host scope;'
    PowerShellVersion  = '5.1'

    ScriptsToProcess   = @(
        'Engine/New-Finding.ps1'
        'Engine/Get-HostContext.ps1'
        'Reporting/Export-MarkdownReport.ps1'
        'Reporting/Export-HtmlReport.ps1'
        'Engine/Invoke-BuildReview.ps1'
    )

    FunctionsToExport  = @(
        'Invoke-BuildReview'
        'Get-HostContext'
        'Test-OSPrecondition'
        'New-Finding'
        'Get-RegistryValueSafe'
        'Test-IsElevated'
        'Export-MarkdownReport'
        'Export-HtmlReport'
    )

    PrivateData = @{
        PSData = @{
            ProjectUri = 'https://github.com/SpeerSec'
        }
    }
}
