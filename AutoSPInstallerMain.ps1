param 
(
    [string]$InputFile = $(throw '- Need parameter input file (e.g. "c:\SP2010\AutoSPInstaller\AutoSPInstallerInput.xml")'),
    [string]$targetServer = "",
    [string]$RemoteAuthPassword = ""
)

# Globally update all instances of "localhost" in the input file to actual local server name
[xml]$xmlinput = (Get-Content $InputFile) -replace ("localhost", $env:COMPUTERNAME)

# ===================================================================================
#
# AutoSPInstaller - See # MAIN for what to run
#
# ===================================================================================

#Region Setup Paths & Environment

$Host.UI.RawUI.WindowTitle = " -- AutoSPInstaller -- $env:COMPUTERNAME --"
$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)
$bits = Get-Item $env:dp0 | Split-Path -Parent
# Check if SharePoint binaries are in the \SharePoint subfolder as per new folder structure
If (Test-Path -Path "$bits\SharePoint\setup.exe")
{
    $env:SPbits = $bits+"\SharePoint"
}
Elseif (Test-Path -Path "$bits\setup.exe") # Use old path convention
{
    $env:SPbits = $bits
}
Else
{
    Throw " - Cannot locate SharePoint binaries; please check that the files are in the \SharePoint subfolder as per new folder structure."
}
$env:spVer,$null = (Get-Item -Path "$env:SPbits\setup.exe").VersionInfo.ProductVersion -split "\."
If (!$env:spVer) {Throw " - Cannot determine version of SharePoint setup binaries."}
# Create a hash table with major version to product year mappings
$spYear = @{"14" = "2010"; "15" = "2013"}
$PSConfig = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\BIN\psconfig.exe"
$PSConfigUI = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\BIN\psconfigui.exe"

$script:DBPrefix = $xmlinput.Configuration.Farm.Database.DBPrefix
If (($DBPrefix -ne "") -and ($DBPrefix -ne $null)) {$script:DBPrefix += "_"}
If ($DBPrefix -like "*localhost*") {$script:DBPrefix = $DBPrefix -replace "localhost","$env:COMPUTERNAME"}

#EndRegion

#Region External Functions
. "$env:dp0\AutoSPInstallerFunctions.ps1"
. "$env:dp0\AutoSPInstallerFunctionsCustom.ps1"
#EndRegion

#Region Remote Install
Function Install-Remote
{
    If ($xmlinput.Configuration.Install.RemoteInstall -eq $true)
    {
        StartTracing
        If (!$env:RemoteStartDate) {$env:RemoteStartDate = Get-Date}
        Write-Host -ForegroundColor Green "-----------------------------------"
        Write-Host -ForegroundColor Green "| Automated SP($spYear.$env:spVer) Remote Installs |"
        Write-Host -ForegroundColor Green "| Started on: $env:RemoteStartDate |"
        Write-Host -ForegroundColor Green "-----------------------------------"
        Enable-CredSSP $RemoteFarmServers
        ForEach ($server in $RemoteFarmServers)
        {
            If ($xmlinput.Configuration.Install.ParallelInstall -eq $true) # Launch each farm server install simultaneously
            {
                ##$serverJob = 
                ##Start-Job -Name "$server" -Credential $Credential -FilePath $MyInvocation.ScriptName -ArgumentList "$InputFile -targetServer $server"
                ##$Credential = New-Object System.Management.Automation.PsCredential $Credential.UserName,$Credential.Password
                Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "Invoke-Command -ScriptBlock {
                                                                                . `"$env:dp0\AutoSPInstallerFunctions.ps1`"; `
                                                                                StartTracing -Server $server; `
                                                                                Test-ServerConnection -Server $server; `
                                                                                Enable-RemoteSession -Server $server -Password $(ConvertFrom-SecureString $($Credential.Password)); `
                                                                                Install-NetFramework -Server $server -Password $(ConvertFrom-SecureString $($Credential.Password)); `
                                                                                Install-WindowsIdentityFoundation -Server $server -Password $(ConvertFrom-SecureString $($Credential.Password)); `
                                                                                Start-RemoteInstaller -Server $server -Password $(ConvertFrom-SecureString $($Credential.Password)) -InputFile $InputFile; `
                                                                                Pause `"exit`"; `
                                                                                Stop-Transcript}" -Verb Runas
                Start-Sleep 10
                #Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "$($MyInvocation.ScriptName) $InputFile -targetServer $server" -Verb Runas
                ##[array]$serverJobs += $serverJob 
            }
            Else # Launch each farm server install in sequence, one-at-a-time, or run these steps on the current $targetServer
            {
                WriteLine
                Write-Host -ForegroundColor Green " - Server: $server"
                Test-ServerConnection -Server $server
                Enable-RemoteSession -Server $server
                Install-NetFramework -Server $server         
                Install-WindowsIdentityFoundation -Server $server
                Start-RemoteInstaller -Server $server -InputFile $InputFile
            }
        }
        $env:EndDate = Get-Date
        Write-Host -ForegroundColor Green "-----------------------------------"
        Write-Host -ForegroundColor Green "| Automated SP$($spYear.$env:spVer) remote installs |"
        Write-Host -ForegroundColor Green "| Started on: $env:RemoteStartDate |"
        Write-Host -ForegroundColor Green "| Completed:  $env:EndDate |"
        Write-Host -ForegroundColor Green "-----------------------------------"
        If ($isTracing) {Stop-Transcript; $script:isTracing = $false}
    }
    Else
    {
        Write-Host -ForegroundColor Yellow " - There are other servers specified as farm members in:"
        Write-Host -ForegroundColor Yellow " - $InputFile"
        Write-Host -ForegroundColor Yellow " - but <RemoteInstall> is not set to `"true`" - nothing else to do."
    }
}
#EndRegion

#Region Prepare For Install
Function PrepForInstall
{
    $SPInstalled = (Get-SharePointInstall)
    ValidateCredentials $xmlinput
    ValidatePassphrase $xmlinput
    CheckConfig
    CheckSQLAccess
}
#EndRegion

#Region Install SharePoint binaries
Function Run-Install
{
    Write-Host -ForegroundColor White " - Install based on:" `n" - "$InputFile `n" - Environment: "$($xmlinput.Configuration.getAttribute("Environment")) `n" - Version: "$($xmlinput.Configuration.getAttribute("Version"))
    DisableLoopbackCheck $xmlinput
    RemoveIEEnhancedSecurity $xmlinput
    DisableServices $xmlinput
    DisableCRLCheck $xmlinput
    InstallPrerequisites $xmlinput
    ConfigureIISLogging $xmlinput
    InstallSharePoint $xmlinput
    InstallOfficeWebApps $xmlinput
    InstallLanguagePacks $xmlinput
    FixTaxonomyPickerBug
}
#EndRegion

#Region Setup Farm
Function Setup-Farm
{
    [System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput
    [security.securestring]$SecPhrase = GetSecureFarmPassphrase $xmlinput
    ConfigureFarmAdmin $xmlinput
    Load-SharePoint-Powershell
    CreateOrJoinFarm $xmlinput ([security.securestring]$SecPhrase) ([System.Management.Automation.PsCredential]$farmCredential)
    CheckFarmTopology $xmlinput
    ConfigureFarm $xmlinput
    ConfigureDiagnosticLogging $xmlinput
    ConfigureOfficeWebApps $xmlinput
    ConfigureLanguagePacks $xmlinput
    AddManagedAccounts $xmlinput
    CreateWebApplications $xmlinput
}
#EndRegion

#Region Setup Services
Function Setup-Services
{
    StartSandboxedCodeService $xmlinput
    CreateStateServiceApp $xmlinput
    CreateMetadataServiceApp $xmlinput
    StartClaimsToWindowsTokenService $xmlinput
    CreateUserProfileServiceApplication $xmlinput
    CreateSPUsageApp $xmlinput
    ConfigureUsageLogging $xmlinput
    CreateWebAnalyticsApp $xmlinput
    CreateSecureStoreServiceApp $xmlinput
    ConfigureFoundationSearch $xmlinput
    ConfigureTracing $xmlinput
    # This is still buggy
    ConfigureDistributedCacheService $xmlinput
    CreateEnterpriseSearchServiceApp $xmlinput
    CreateBusinessDataConnectivityServiceApp $xmlinput
    CreateExcelServiceApp $xmlinput
    CreateAccessServiceApp $xmlinput
    CreateVisioServiceApp $xmlinput
    CreatePerformancePointServiceApp $xmlinput
    CreateWordAutomationServiceApp $xmlinput
    CreateExcelOWAServiceApp $xmlinput
    CreatePowerPointServiceApp $xmlinput
    CreateWordViewingServiceApp $xmlinput
    InstallSMTP $xmlinput
    ConfigureOutgoingEmail $xmlinput
    Configure-PDFSearchAndIcon $xmlinput
    InstallForeFront $xmlinput
}
#EndRegion

#Region Finalize Install (perform any cleanup operations)
# Run last
Function Finalize-Install 
{
    # Perform these steps only if the local server is a SharePoint farm server
    If ($FarmServers -like "$env:COMPUTERNAME*")
    {
        # Remove Farm Account from local Administrators group to avoid big scary warnings in Central Admin
        # But only if the script actually put it there, and we want to leave it there 
        # (e.g. to work around the issue with native SharePoint backups deprovisioning UPS per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=275)
        $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
        If (!($RunningAsFarmAcct) -and ($xmlinput.Configuration.Farm.Account.getAttribute("AddToLocalAdminsDuringSetup") -eq $true) -and ($xmlinput.Configuration.Farm.Account.LeaveInLocalAdmins -eq $false))
        {
            $builtinAdminGroup = Get-AdministratorsGroup
            Write-Host -ForegroundColor White " - Removing $FarmAcct from local group `"$builtinAdminGroup`"..."
            $FarmAcctDomain,$FarmAcctUser = $FarmAcct -Split "\\"
            try
            {
                ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$FarmAcctDomain/$FarmAcctUser")
                If (-not $?) {throw}
            }
            catch {Write-Host -ForegroundColor White " - $FarmAcct already removed from `"$builtinAdminGroup.`""}
            # Restart SPTimerV4 so it can now run under non-local Admin privileges and avoid Health Analyzer warning
            Write-Host -ForegroundColor White " - Restarting SharePoint Timer Service..."
            Restart-Service SPTimerV4
        }
        Else
        {
            Write-Host -ForegroundColor White " - Not changing local Admin membership of $FarmAcct."    
        }
        
        Write-Host -ForegroundColor White " - Adding Network Service to local WSS_WPG group (fixes event log warnings)..."
        Try
        {
            ([ADSI]"WinNT://$env:COMPUTERNAME/WSS_WPG,group").Add("WinNT://NETWORK SERVICE")
            If (-not $?) {Throw}
        }
        Catch {Write-Host -ForegroundColor White " - Network Service is already a member."}
        Run-HealthAnalyzerJobs
    }
    
    Write-Host -ForegroundColor White " - Completed!`a"
    $Host.UI.RawUI.WindowTitle = " -- Completed -- $env:COMPUTERNAME --"
    $env:EndDate = Get-Date
}
#EndRegion

#Region MAIN - Check for input file and start the install

If (!([string]::IsNullOrEmpty($targetServer))) {$FarmServers = $targetServer}
Else {$FarmServers = Get-FarmServers $xmlinput}
$RemoteFarmServers = $FarmServers | Where-Object {$_ -notlike "$env:COMPUTERNAME"}
$password = $RemoteAuthPassword
If ($xmlinput.Configuration.Install.RemoteInstall -eq $true -and !([string]::IsNullOrEmpty($RemoteFarmServers)))
{
    If (Confirm-LocalSession)
    {
        While ($credentialVerified -ne $true)
        {
            If ($password) # In case this is an automatic re-launch of the local script, re-use the password from the remote auth credential
            {
                Write-Host -ForegroundColor White " - Re-using previous credentials..."
                $Credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString -String $password -AsPlainText -Force -ErrorAction SilentlyContinue)
            }
            If (!$Credential) # Otherwise prompt for the remote auth credential
            {
                Write-Host -ForegroundColor White " - Prompting for remote credentials..."
                $Credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")
            }
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $null,$user = $Credential.Username -split "\\"
            If (($user -ne $null) -and ($Credential.Password -ne $null)) {$password = ConvertTo-PlainText $Credential.Password}
            Else {Write-Error " - Credentials are required for remote authentication."; Pause "exit"; Throw}
            Write-Host -ForegroundColor White " - Checking credentials: `"$($Credential.Username)`"..." -NoNewline
            $dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$user,$password)
            If ($dom.Path -ne $null)
            {
                Write-Host -BackgroundColor Blue -ForegroundColor Black "Verified."
                $credentialVerified = $true
            }
            Else
            {
                Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid - please try again."
                $password = $null
                $Credential = $null
            }
        }
    }
}

If (Confirm-LocalSession) {StartTracing} # Only start tracing if this is a local session
If (!$env:StartDate) {$env:StartDate = Get-Date}
Write-Host -ForegroundColor White "-----------------------------------"
Write-Host -ForegroundColor White "| Automated SP$($spYear.$env:spVer) install script |"
Write-Host -ForegroundColor White "| Started on: $env:StartDate |"
Write-Host -ForegroundColor White "-----------------------------------"

# In case we are running this installer from a non-SharePoint farm server, only do these steps for farm member servers
If ($FarmServers -like "$env:COMPUTERNAME*")
{
    Try
    {
        If (Confirm-LocalSession) 
        {
            $SPInstalled = Get-SharePointInstall
            Write-Host -ForegroundColor White " - SharePoint $($spYear.$env:spVer) binaries are"($SPInstalled -replace "True","already" -replace "False","not yet") "installed."
        }
        PrepForInstall
        Run-Install
        Write-Host -ForegroundColor White " - SharePoint $($spYear.$env:spVer) binary file installation done!"
        
        If (($xmlinput.Configuration.Install.PauseAfterInstall -eq $true) -or ($xmlinput.Configuration.Install.ParallelInstall -eq $true))
        {
            Pause "proceed with farm configuration"
        }
        Setup-Farm
        Setup-Services
        Finalize-Install
        # We only want to Install-Remote if we aren't already *in* a remote session, and if there are actually remote servers to install!
        If ((Confirm-LocalSession) -and !([string]::IsNullOrEmpty($RemoteFarmServers))) {Install-Remote}
    }
    Catch 
    {
        WriteLine
        Write-Host -ForegroundColor Yellow " - Script aborted!" 
        If ($_.FullyQualifiedErrorId -ne $null -and $_.FullyQualifiedErrorId.StartsWith(" - ")) 
        {
            # Error messages starting with " - " are thrown directly from this script
            Write-Host -ForegroundColor Red $_.FullyQualifiedErrorId
            If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue).RestartRequired -eq "1")
            {
                Write-Host -ForegroundColor White " - Setting RunOnce registry entry for AutoSPInstaller..."
                ##$RunOnceCommandLine,$null = $($MyInvocation.Line) -split " "
                # Create the RunOnce key in case it doesn't yet exist (as I discovered on on Win2012)
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name RunOnce -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name AutoSPInstaller -Value "`"$env:dp0\AutoSPInstallerLaunch.bat`" `"$InputFile`"" -Force | Out-Null
                Write-Host -ForegroundColor White " - The AutoSPInstaller script will resume after the server is restarted."
                $restartPrompt = Read-Host -Prompt " - Do you want to restart immediately? (y/n)"
                If ($restartPrompt -eq "y")
                {
                    Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "Write-Host `" - Restarting - `"; Start-Sleep 5; Restart-Computer"
                    $restarting = $true
                }
                Else {Write-Host -ForegroundColor Yellow " - Please restart your computer to continue AutoSPInstaller."}
            }
            if (!$restarting) {Pause "exit"}
        }
        # Lately, loading the snapin throws an error: "System.TypeInitializationException: The type initializer for 'Microsoft.SharePoint.Utilities.SPUtility' threw an exception. ---> System.IO.FileNotFoundException:"...
        ElseIf ($_.Exception.Message -like "*Microsoft.SharePoint.Utilities.SPUtility*")
        {
            Write-Host -ForegroundColor Yellow " - A known (annoying) issue occurred loading the SharePoint Powershell snapin."
            Write-Host -ForegroundColor Yellow " - We need to re-launch the script to clear this condition."
            $ScriptCommandLine = $($MyInvocation.Line)
            If (Confirm-LocalSession) 
            {
                Write-Host -ForegroundColor White " - Re-Launching:"
                Write-Host -ForegroundColor White " - $ScriptCommandLine"
                Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -ArgumentList "$ScriptCommandLine -RemoteAuthPassword $password" -Verb RunAs
                Start-Sleep 10
            }
        }
        Else
        {
            #Other error messages are exceptions. Can't find a way to make this Red
            $_ | Format-List -Force
        }
        $env:EndDate = Get-Date
        Write-Host -ForegroundColor White "-----------------------------------"
        Write-Host -ForegroundColor White "| Automated SP$($spYear.$env:spVer) install script |"
        Write-Host -ForegroundColor White "| Started on: $env:StartDate |"
        Write-Host -ForegroundColor White "| Aborted:    $env:EndDate |"
        Write-Host -ForegroundColor White "-----------------------------------"
        $Aborted = $true
        If (!$ScriptCommandLine) {Pause "exit"}
    }
    Finally 
    {
        # Only do this stuff if this was a local session and it succeeded, and if there are no remote servers to install;
        # Otherwise these sites may not be available or 'complete' yet
        If ((Confirm-LocalSession) -and !$Aborted -and [string]::IsNullOrEmpty($RemoteFarmServers))
        {
            # Launch Central Admin
            If (ShouldIProvision($xmlinput.Configuration.Farm.CentralAdmin) -eq $true)
            {
                $CentralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.CentralAdminPort
                Write-Host -ForegroundColor White " - Launching Central Admin..."
                Start-Process $PSConfigUI -ArgumentList "-cmd showcentraladmin"
            }
            # Launch any site collections we created, but only if this is a local (non-remote) session and this is a farm server
            If ($FarmServers -like "$env:COMPUTERNAME*")
            {
                ForEach ($webApp in $xmlinput.Configuration.WebApplications.WebApplication)
                {
                    ForEach ($SiteCollection in $webApp.SiteCollections.SiteCollection)
                    {
                        $SiteURL = $SiteCollection.siteURL
                        If ($SiteURL -ne $null)
                        {
                            Start-Sleep 30 # Wait for the previous site to load before trying to load this site
                            Write-Host -ForegroundColor White " - Launching $SiteURL..."
                            Start-Process "$SiteURL" -WindowStyle Minimized
                        }
                    }
                }
            }
        }
    }
}
# If the local server isn't a SharePoint farm server, just attempt remote installs
Else ##If (!($FarmServers -like "$env:COMPUTERNAME*"))
{
    Install-Remote
    Finalize-Install
}
If ((Confirm-LocalSession) -and !$Aborted) # Only do this stuff if this was a local session and it succeeded
{
    $StartDate = $env:StartDate
    Write-Host -ForegroundColor White "-----------------------------------"
    Write-Host -ForegroundColor White "| Automated SP$($spYear.$env:spVer) install script |"
    Write-Host -ForegroundColor White "| Started on: $StartDate |"
    Write-Host -ForegroundColor White "| Completed:  $env:EndDate |"
    Write-Host -ForegroundColor White "-----------------------------------"
    If ($isTracing) {Stop-Transcript; $script:isTracing = $false}
    Pause "exit"
    Invoke-Item $LogFile
}
#EndRegion

# ===================================================================================
# LOAD ASSEMBLIES
# ===================================================================================
#[void][System.Reflection.Assembly]::Load("Microsoft.SharePoint, Version=14.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c") 
