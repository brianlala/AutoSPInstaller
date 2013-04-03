param 
(
    [string]$inputFile = $(throw '- Need parameter input file (e.g. "\\SPSERVER01\C$\SP\AutoSPInstaller\AutoSPInstallerInput.xml")'),
    [string]$targetServer = "",
    [string]$remoteAuthPassword = "",
    [switch]$unattended
)

# Globally update all instances of "localhost" in the input file to actual local server name
[xml]$xmlinput = (Get-Content $inputFile) -replace ("localhost", $env:COMPUTERNAME)

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
# Check if SharePoint binaries are in the \SP20xx\SharePoint subfolder as per new folder structure
# Look for SP2013
If ($xmlinput.Configuration.Install.SPVersion -eq "2013")
{
    if (Test-Path -Path "$bits\2013\SharePoint\setup.exe")
    {
        $env:SPbits = $bits+"\2013\SharePoint"
    }
    else {Write-Host -ForegroundColor Yellow " - SP2013 was specified in $($inputfile.replace($bits,'')),`n - but $bits\2013\SharePoint\setup.exe was not found. Looking for SP2010..."}
}
# If 2013 bits aren't found, look for SP2010 bits or use the value specified in $xmlinput
ElseIf ((Test-Path -Path "$bits\2010\SharePoint\setup.exe") -or ($xmlinput.Configuration.Install.SPVersion -eq "2010"))
{
    $env:SPbits = $bits+"\2010\SharePoint"
}
Elseif (Test-Path -Path "$bits\SharePoint\setup.exe") # Use old path convention
{
    $env:SPbits = $bits+"\SharePoint"
}
Else
{
    Throw " - Cannot locate SharePoint binaries; please check that the files are in the \SharePoint subfolder as per new folder structure."
}
$env:spVer,$null = (Get-Item -Path "$env:SPbits\setup.exe").VersionInfo.ProductVersion -split "\."
If (!$env:spVer) {Throw " - Cannot determine version of SharePoint setup binaries."}
# Create a hash table with major version to product year mappings
$spYears = @{"14" = "2010"; "15" = "2013"}
$spYear = $spYears.$env:spVer
$PSConfig = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\BIN\psconfig.exe"
$PSConfigUI = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\BIN\psconfigui.exe"

$script:DBPrefix = $xmlinput.Configuration.Farm.Database.DBPrefix
If (($dbPrefix -ne "") -and ($dbPrefix -ne $null)) {$script:DBPrefix += "_"}
If ($dbPrefix -like "*localhost*") {$script:DBPrefix = $dbPrefix -replace "localhost","$env:COMPUTERNAME"}


if ($xmlinput.Configuration.Install.RemoteInstall.Enable -eq $true)
{
    if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue).CancelRemoteInstall -eq "1")
    {
        Write-Host -ForegroundColor White " - Disabling RemoteInstall, since we are resuming after a restart..."
        $enableRemoteInstall = $false
    }
    else
    {
        $enableRemoteInstall = $true
    }
}
else
{
    $enableRemoteInstall = $false
}

Write-Host -ForegroundColor White " - Setting power management plan to `"High Performance`"..."
Start-Process -FilePath "$env:SystemRoot\system32\powercfg.exe" -ArgumentList "/s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -NoNewWindow
#EndRegion

#Region External Functions
. "$env:dp0\AutoSPInstallerFunctions.ps1"
. "$env:dp0\AutoSPInstallerFunctionsCustom.ps1"
#EndRegion

#Region Remote Install
Function Install-Remote
{
    If ($enableRemoteInstall)
    {
        StartTracing
        If (!$env:RemoteStartDate) {$env:RemoteStartDate = Get-Date}
        Write-Host -ForegroundColor Green "-----------------------------------"
        Write-Host -ForegroundColor Green "| Automated SP$spYear Remote Installs |"
        Write-Host -ForegroundColor Green "| Started on: $env:RemoteStartDate |"
        Write-Host -ForegroundColor Green "-----------------------------------"
        Enable-CredSSP $remoteFarmServers
        ForEach ($server in $remoteFarmServers)
        {
            If ($xmlinput.Configuration.Install.RemoteInstall.ParallelInstall -eq $true) # Launch each farm server install simultaneously
            {
                ##$serverJob = 
                ##Start-Job -Name "$server" -Credential $credential -FilePath $MyInvocation.ScriptName -ArgumentList "$inputFile -targetServer $server"
                ##$credential = New-Object System.Management.Automation.PsCredential $credential.UserName,$credential.Password
                Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-ExecutionPolicy Bypass Invoke-Command -ScriptBlock {
                                                                                . `"$env:dp0\AutoSPInstallerFunctions.ps1`"; `
                                                                                StartTracing -Server $server; `
                                                                                Test-ServerConnection -Server $server; `
                                                                                Enable-RemoteSession -Server $server -Password $(ConvertFrom-SecureString $($credential.Password)); `
                                                                                Install-NetFramework -Server $server -Password $(ConvertFrom-SecureString $($credential.Password)); `
                                                                                Install-WindowsIdentityFoundation -Server $server -Password $(ConvertFrom-SecureString $($credential.Password)); `
                                                                                Start-RemoteInstaller -Server $server -Password $(ConvertFrom-SecureString $($credential.Password)) -InputFile $inputFile; `
                                                                                Pause `"exit`"; `
                                                                                Stop-Transcript}" -Verb Runas
                Start-Sleep 10
            }
            Else # Launch each farm server install in sequence, one-at-a-time, or run these steps on the current $targetServer
            {
                WriteLine
                Write-Host -ForegroundColor Green " - Server: $server"
                Test-ServerConnection -Server $server
                Enable-RemoteSession -Server $server
                Install-NetFramework -Server $server         
                Install-WindowsIdentityFoundation -Server $server
                Start-RemoteInstaller -Server $server -InputFile $inputFile
            }
        }
        $env:EndDate = Get-Date
        Write-Host -ForegroundColor Green "-----------------------------------"
        Write-Host -ForegroundColor Green "| Automated SP$spYear remote installs |"
        Write-Host -ForegroundColor Green "| Started on: $env:RemoteStartDate |"
        Write-Host -ForegroundColor Green "| Completed:  $env:EndDate |"
        Write-Host -ForegroundColor Green "-----------------------------------"
        If ($isTracing) {Stop-Transcript; $script:isTracing = $false}
    }
    Else
    {
        Write-Host -ForegroundColor Yellow " - There are other servers specified as farm members in:"
        Write-Host -ForegroundColor Yellow " - $inputFile"
        Write-Host -ForegroundColor Yellow " - but <RemoteInstall> is not set to `"true`" - nothing else to do."
    }
}
#EndRegion

#Region Prepare For Install
Function PrepForInstall
{
    CheckInput
    $spInstalled = (Get-SharePointInstall)
    ValidateCredentials $xmlinput
    ValidatePassphrase $xmlinput
    CheckConfigFiles $xmlinput
    CheckSQLAccess
}
#EndRegion

#Region Install SharePoint binaries
Function Run-Install
{
    Write-Host -ForegroundColor White " - Install based on: `n  - $inputFile `n  - Environment: $($xmlinput.Configuration.getAttribute(`"Environment`")) `n  - Version: $($xmlinput.Configuration.getAttribute(`"Version`"))"
    DisableLoopbackCheck $xmlinput
    RemoveIEEnhancedSecurity $xmlinput
    AddSourcePathToLocalIntranetZone
    DisableServices $xmlinput
    DisableCRLCheck $xmlinput
    InstallPrerequisites $xmlinput
    ConfigureIISLogging $xmlinput
    InstallSharePoint $xmlinput
    InstallOfficeWebApps2010 $xmlinput
    InstallLanguagePacks $xmlinput
    FixTaxonomyPickerBug
}
#EndRegion

#Region Setup Farm
Function Setup-Farm
{
    [System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput
    [security.securestring]$secPhrase = GetSecureFarmPassphrase $xmlinput
    ConfigureFarmAdmin $xmlinput
    Load-SharePoint-Powershell
    CreateOrJoinFarm $xmlinput ([security.securestring]$secPhrase) ([System.Management.Automation.PsCredential]$farmCredential)
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
    CreateEnterpriseSearchServiceApp $xmlinput
    CreateBusinessDataConnectivityServiceApp $xmlinput
    CreateExcelServiceApp $xmlinput
    CreateAccess2010ServiceApp $xmlinput
    CreateVisioServiceApp $xmlinput
    CreatePerformancePointServiceApp $xmlinput
    CreateWordAutomationServiceApp $xmlinput
    if ($env:spVer -eq "14") # These are for SP2010 / Office Web Apps 2010 only
    {
        CreateExcelOWAServiceApp $xmlinput
        CreatePowerPointOWAServiceApp $xmlinput
        CreateWordViewingOWAServiceApp $xmlinput
    }
    if ($env:spVer -eq "15") # These are for SP2013 only
	{
		CreateAppManagementServiceApp $xmlinput
		CreateSubscriptionSettingsServiceApp $xmlinput
        CreateWorkManagementServiceApp $xmlinput
        CreateMachineTranslationServiceApp $xmlinput
        CreateAccessServicesApp $xmlinput
        CreatePowerPointConversionServiceApp $xmlinput
	    ConfigureDistributedCacheService $xmlinput
    }
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
    If (MatchComputerName $farmServers $env:COMPUTERNAME)
    {
        # Remove Farm Account from local Administrators group to avoid big scary warnings in Central Admin
        # But only if the script actually put it there, and we want to leave it there 
        # (e.g. to work around the issue with native SharePoint backups deprovisioning UPS per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=275)
        $farmAcct = $xmlinput.Configuration.Farm.Account.Username
        If (!($runningAsFarmAcct) -and ($xmlinput.Configuration.Farm.Account.getAttribute("AddToLocalAdminsDuringSetup") -eq $true) -and ($xmlinput.Configuration.Farm.Account.LeaveInLocalAdmins -eq $false))
        {
            $builtinAdminGroup = Get-AdministratorsGroup
            Write-Host -ForegroundColor White " - Removing $farmAcct from local group `"$builtinAdminGroup`"..."
            $farmAcctDomain,$farmAcctUser = $farmAcct -Split "\\"
            try
            {
                ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$farmAcctDomain/$farmAcctUser")
                If (-not $?) {throw}
            }
            catch {Write-Host -ForegroundColor White " - $farmAcct already removed from `"$builtinAdminGroup.`""}
            # Restart SPTimerV4 so it can now run under non-local Admin privileges and avoid Health Analyzer warning
            Write-Host -ForegroundColor White " - Restarting SharePoint Timer Service..."
            Restart-Service SPTimerV4
        }
        Else
        {
            Write-Host -ForegroundColor White " - Not changing local Admin membership of $farmAcct."    
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

If (!([string]::IsNullOrEmpty($targetServer))) {$farmServers = $targetServer}
Else {$farmServers = Get-FarmServers $xmlinput}
$remoteFarmServers = $farmServers | Where-Object {-not (MatchComputerName $_ $env:COMPUTERNAME)}
$password = $remoteAuthPassword
If ([string]::IsNullOrEmpty($password)) {$password = $xmlinput.Configuration.Install.AutoAdminLogon.Password}
If (($enableRemoteInstall -and !([string]::IsNullOrEmpty($remoteFarmServers))) -or ($xmlinput.Configuration.Install.AutoAdminLogon.Enable -eq $true))
{
    If (Confirm-LocalSession)
    {
        While ($credentialVerified -ne $true)
        {
            If ($password) # In case this is an automatic re-launch of the local script, re-use the password from the remote auth credential
            {
                Write-Host -ForegroundColor White " - Using pre-provided credentials..."
                $credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString -String $password -AsPlainText -Force -ErrorAction SilentlyContinue)
            }
            If (!$credential) # Otherwise prompt for the remote auth or AutoAdminLogon credential
            {
                Write-Host -ForegroundColor White " - Prompting for remote/autologon credentials..."
                $credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote/Automatic Install", "Enter Credentials for Remote/Automatic Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")
            }
            $currentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            $null,$user = $credential.Username -split "\\"
            If (($user -ne $null) -and ($credential.Password -ne $null)) {$password = ConvertTo-PlainText $credential.Password}
            Else 
            {
                If ($enableRemoteInstall -and !([string]::IsNullOrEmpty($remoteFarmServers))) {Write-Error " - Credentials are required for remote authentication."; Pause "exit"; Throw}
                Else {Write-Host -ForegroundColor Yellow " - No password supplied; skipping AutoAdminLogon."; break}
            }
            Write-Host -ForegroundColor White " - Checking credentials: `"$($credential.Username)`"..." -NoNewline
            $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain,$user,$password)
            If ($dom.Path -ne $null)
            {
                Write-Host -ForegroundColor Black -BackgroundColor Green "Verified."
                $credentialVerified = $true
            }
            Else
            {
                Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid - please try again."
                $password = $null
                $credential = $null
            }
        }
    }
}

If (Confirm-LocalSession) {StartTracing} # Only start tracing if this is a local session
If (!$env:StartDate) {$env:StartDate = Get-Date}
Write-Host -ForegroundColor White "-----------------------------------"
Write-Host -ForegroundColor White "| Automated SP$spYear install script |"
Write-Host -ForegroundColor White "| Started on: $env:StartDate |"
Write-Host -ForegroundColor White "-----------------------------------"

# In case we are running this installer from a non-SharePoint farm server, only do these steps for farm member servers
If (MatchComputerName $farmServers $env:COMPUTERNAME)
{
    Try
    {
        If (Confirm-LocalSession) 
        {
            $spInstalled = Get-SharePointInstall
            Write-Host -ForegroundColor White " - SharePoint $spYear binaries are"($spInstalled -replace "True","already" -replace "False","not yet") "installed."
        }
        PrepForInstall
        Run-Install
        Write-Host -ForegroundColor White " - SharePoint $spYear binary file installation done!"
        
        If (($xmlinput.Configuration.Install.PauseAfterInstall -eq $true) -or ($xmlinput.Configuration.Install.RemoteInstall.ParallelInstall -eq $true))
        {
            Pause "proceed with farm configuration"
        }
        Setup-Farm
        Setup-Services
        Finalize-Install
        # We only want to Install-Remote if we aren't already *in* a remote session, and if there are actually remote servers to install!
        If ((Confirm-LocalSession) -and !([string]::IsNullOrEmpty($remoteFarmServers))) {Install-Remote}
    }
    Catch 
    {
        WriteLine
        Write-Host -ForegroundColor Yellow " - Script halted!" 
        If ($_.FullyQualifiedErrorId -ne $null -and $_.FullyQualifiedErrorId.StartsWith(" - ")) 
        {
            # Error messages starting with " - " are thrown directly from this script
            Write-Host -ForegroundColor Red $_.FullyQualifiedErrorId
            If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue).RestartRequired -eq "1")
            {
                Write-Host -ForegroundColor White " - Setting RunOnce registry entry for AutoSPInstaller..."
                # Create the RunOnce key in case it doesn't yet exist (as I discovered on on Win2012)
                New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name RunOnce -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name AutoSPInstaller -Value "`"$env:dp0\AutoSPInstallerLaunch.bat`" `"$inputFile`"" -Force | Out-Null
                If ($xmlinput.Configuration.Install.AutoAdminLogon.Enable -eq $true)
                {
                    If ([string]::IsNullOrEmpty($password)) 
                    {
                        $password = $xmlinput.Configuration.Install.AutoAdminLogon.Password
                        If ([string]::IsNullOrEmpty($password))
                        {
                            $password = Read-Host -Prompt " - Please enter the password for $env:USERDOMAIN\$env:USERNAME to enable auto-login"
                        }
                    }
                    If (!([string]::IsNullOrEmpty($password)))
                    {
                        Write-Host -ForegroundColor White " - Setting AutoAdminLogon in the registry for $env:USERDOMAIN\$env:USERNAME..."
                        # Set the AutoAdminLogon values. Adapted from a patch uploaded by Codeplex user Sheppounet (http://www.codeplex.com/site/users/view/Sheppounet)
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoAdminLogon" -Value 1 -PropertyType "String" -Force | Out-Null
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultDomainName" -Value $env:USERDOMAIN -PropertyType "String" -Force | Out-Null
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultUserName" -Value $env:USERNAME -PropertyType "String" -Force | Out-Null
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "DefaultPassword" -Value $password -PropertyType "String" -Force | Out-Null
                        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon" -Name "AutoLogonCount" -Value 1 -PropertyType "Dword" -Force | Out-Null
                        $restartPrompt = "y"
                        # Disable UAC so the script can run unobstructed. We will re-enable it as a security precaution when the script re-runs and only disable it again if we get to this point
                        Set-UserAccountControl 0
                    }
                    Else {Write-Host -ForegroundColor Yellow " - No password supplied; skipping AutoAdminLogon."}
                }
                Else {Write-Host -ForegroundColor White " - AutoAdminLogon is not enabled in $inputFile; set it to `"true`" to enable it."}
                Write-Host -ForegroundColor White " - The AutoSPInstaller script will resume after the server reboots and $env:USERDOMAIN\$env:USERNAME logs in."
                if ((Confirm-LocalSession) -and ([string]::IsNullOrEmpty($restartPrompt))) {$restartPrompt = Read-Host -Prompt " - Do you want to restart immediately? (y/n)"}
                If ($restartPrompt -eq "y")
                {
                    if (!(Confirm-LocalSession))
                    {
                        Write-Host " - Restarting - "
                        Start-Sleep 5
                        Restart-Computer -ErrorAction SilentlyContinue
                        if (!$?)
                        {
                            Write-Warning "Restart failed; there may be (an) other user(s) logged in!"
                            $forceRestart = Read-Host -Prompt " - Do you want to force a restart? (y/n)"
                            if ($forceRestart -eq "y") {Restart-Computer -Force}
                        }
                    }
                    # If this is a non-remote session, launch Restart-Computer from another PS window/process
                    else {Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "Write-Host ' - Restarting - '; Start-Sleep 5; Restart-Computer -ErrorAction SilentlyContinue; if (!`$?) {Write-Warning 'Restart failed; there may be (an) other user(s) logged in!'; `$forceRestart = Read-Host -Prompt ' - Do you want to force a restart? (y/n)'; if (`$forceRestart -eq 'y') {Restart-Computer -Force}}"}
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
            $scriptCommandLine = $($MyInvocation.Line)
            If (Confirm-LocalSession) 
            {
                Write-Host -ForegroundColor White " - Re-Launching:"
                Write-Host -ForegroundColor White " - $scriptCommandLine"
                Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass $scriptCommandLine -RemoteAuthPassword $password" -Verb RunAs
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
        Write-Host -ForegroundColor White "| Automated SP$spYear install script |"
        Write-Host -ForegroundColor White "| Started on: $env:StartDate |"
        Write-Host -ForegroundColor White "| Aborted:    $env:EndDate |"
        Write-Host -ForegroundColor White "-----------------------------------"
        $aborted = $true
        If (!$scriptCommandLine -and (!(Confirm-LocalSession))) {Pause "exit"}
    }
    Finally 
    {
        # Only do this stuff if this was a local session and it succeeded, and if we aren't attempting a remote install;
        # Otherwise these sites may not be available or 'complete' yet
        If ((Confirm-LocalSession) -and !$aborted -and !($enableRemoteInstall))
        {
            # Launch Central Admin
            If (ShouldIProvision($xmlinput.Configuration.Farm.CentralAdmin) -eq $true)
            {
                $centralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.CentralAdminPort
                Write-Host -ForegroundColor White " - Launching Central Admin..."
                Start-Process $PSConfigUI -ArgumentList "-cmd showcentraladmin"
            }
            # Launch any site collections we created, but only if this is a local (non-remote) session and this is a farm server
            If (MatchComputerName $farmServers $env:COMPUTERNAME)
            {
                ForEach ($webApp in $xmlinput.Configuration.WebApplications.WebApplication)
                {
                    ForEach ($siteCollection in $webApp.SiteCollections.SiteCollection)
                    {
                        $siteURL = $siteCollection.siteURL
                        If ($siteURL -ne $null)
                        {
                            Start-Sleep 30 # Wait for the previous site to load before trying to load this site
                            Write-Host -ForegroundColor White " - Launching $siteURL..."
                            Start-Process "$siteURL" -WindowStyle Minimized
                        }
                    }
                }
            }
        }
    }
}
# If the local server isn't a SharePoint farm server, just attempt remote installs
Else ##If (!($farmServers -like "$env:COMPUTERNAME*"))
{
    Install-Remote
    Finalize-Install
}
If (!$aborted)
{
	If (Confirm-LocalSession) # Only do this stuff if this was a local session and it succeeded
	{
		$startDate = $env:StartDate
	    Write-Host -ForegroundColor White "-----------------------------------"
	    Write-Host -ForegroundColor White "| Automated SP$spYear install script |"
	    Write-Host -ForegroundColor White "| Started on: $startDate |"
	    Write-Host -ForegroundColor White "| Completed:  $env:EndDate |"
	    Write-Host -ForegroundColor White "-----------------------------------"
	    If ($isTracing) {Stop-Transcript; $script:isTracing = $false}
	    Pause "exit"
	    If (-not $unattended) { Invoke-Item $logFile }
	}
	# Remove any lingering LogTime values in the registry
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "LogTime" -ErrorAction SilentlyContinue
}

#EndRegion

# ===================================================================================
# LOAD ASSEMBLIES
# ===================================================================================
#[void][System.Reflection.Assembly]::Load("Microsoft.SharePoint, Version=14.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c") 
