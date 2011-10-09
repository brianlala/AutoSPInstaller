# ===================================================================================
# CUSTOM FUNCTIONS - Put your new or overriding functions here
# ===================================================================================

#Region Get Version
# ===================================================================================
# FUNC: Get Version
# DESC: Gets the version of the installation
# ===================================================================================
Function GetVersion()
{
    ## Detect installer/product version
    #$0 = $myInvocation.MyCommand.Definition
    #$dp0 = [System.IO.Path]::GetDirectoryName($0)
    #$bits = Get-Item $dp0 | Split-Path -Parent
    [string]$bits = Get-Location
    Write-Host (Get-Command "$bits\SharePoint\setup.exe" -ErrorAction SilentlyContinue).FileVersionInfo.ProductVersion
}
#EndRegion