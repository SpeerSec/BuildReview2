@{
    RootModule         = 'BuildReview2.psm1'
    ModuleVersion      = '2.1.1'
    GUID               = [guid]::NewGuid().ToString()
    Author             = '@Speersec'
    Description        = 'Attack-path-driven Windows host build review with OS-aware precondition gating. Single-host scope; feature-existence checks gate every collector to avoid false positives.'
    PowerShellVersion  = '5.1'
 
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
