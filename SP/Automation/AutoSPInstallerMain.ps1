param
(
    [string]$inputFile = $(throw '- Need parameter input file (e.g. "\\SPSERVER01\C$\SP\AutoSPInstaller\AutoSPInstallerInput.xml")'),
    [string]$targetServer = "",
    [string]$remoteAuthPassword = "",
    [switch]$unattended
)

# Globally update all instances of "localhost" in the input file to actual local server name
[xml]$xmlInput = (Get-Content $inputFile -ErrorAction Inquire) -replace ("localhost", $env:COMPUTERNAME) # "-ErrorAction Inquire" should show something meaningful now instead of just quickly skipping over a bad or malformed XML

# ===================================================================================
#
# AutoSPInstaller - See # MAIN for what to run
#
# ===================================================================================

#region Setup Paths & Environment

$Host.UI.RawUI.WindowTitle = " -- AutoSPInstaller -- $env:COMPUTERNAME --"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host
$0 = $myInvocation.MyCommand.Definition
$env:dp0 = [System.IO.Path]::GetDirectoryName($0)
$env:bits = Get-Item $env:dp0 | Split-Path -Parent

#region Source External Functions
Write-Host -ForegroundColor White " - Importing AutoSPInstaller PowerShell Module..."
Import-Module -Name "$env:dp0\AutoSPInstallerModule.psm1" -Force
#endregion

# Create hash table with product year to major version mappings
$spVersions = @{"2010" = "14"; "2013" = "15"; "2016" = "16"; "2019" = "16"} # SharePoint 2019 still uses major build 16
$spYear = $xmlInput.Configuration.Install.SPVersion
if ([string]::IsNullOrEmpty($spYear))
{
    throw "SharePoint version (year) was not specified in `"$inputFile`""
}

if ($xmlInput.Configuration.Install.SKU -eq "Foundation") {$product = "Foundation"}
else {$product = "SharePoint"}

# Check if SharePoint binaries are in the \SP20xx\$product subfolder as per new folder structure
# Look for SP2013+
If ($spYear -ge 2013)
{
    if (Test-Path -Path "$env:bits\$($spYear)\$product\setup.exe" -ErrorAction SilentlyContinue)
    {
        $env:SPbits = $env:bits+"\$($spYear)\$product"
    }
    else {Write-Host -ForegroundColor Yellow " - SP$($spYear) was specified in $($inputfile.replace($env:bits,'')),`n - but $env:bits\$($spYear)\$product\setup.exe was not found. Looking for SP2010..."}
}
# If 2013+ bits aren't found, look for SP2010 bits and ensure they match the value specified in $xmlInput
ElseIf ((Test-Path -Path "$env:bits\2010\$product\setup.exe" -ErrorAction SilentlyContinue) -and ($spYear -eq "2010"))
{
    $env:SPbits = $env:bits+"\2010\$product"
}
Elseif (Test-Path -Path "$env:bits\$product\setup.exe" -ErrorAction SilentlyContinue) # Use old path convention
{
    $env:SPbits = $env:bits+"\$product"
}
if ([string]::IsNullOrEmpty($env:SPbits))
{
    # Changed this to a warning in case we just want to create/configure a farm and are sure that SharePoint is pre-installed
    Write-Warning "Cannot locate SharePoint binaries; please check that the files are in the \$product subfolder as per new folder structure."
    Pause "proceed if you know that SharePoint is already installed, or Ctrl-C to exit" "y"
    # If no setup binaries are present, this might be OK if SharePoint is already installed and we've specified the version in the XML
    $spInstalled = $true
    # Check to see that we've at least specified the desired version in the XML
    if ($spVersions.Keys -contains $spyear)
    {
        # Grab the version from the hashtable
        $spVer = $spVersions.$spYear
    }
    else {Throw " - Cannot determine version of SharePoint setup binaries, and no Version was specified in `"$(Split-Path -Path $inputFile -Leaf)`"."}
}
else
{
    $setupVersion = (Get-Item -Path "$env:SPbits\setup.exe").VersionInfo.ProductVersion
    $spVer,$null,$spBuild,$null = $setupVersion -split "\."
}
$PSConfigUI = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\BIN\psconfigui.exe"

$script:DBPrefix = $xmlInput.Configuration.Farm.Database.DBPrefix
If (($dbPrefix -ne "") -and ($dbPrefix -ne $null)) {$script:DBPrefix += "_"}
If ($dbPrefix -like "*localhost*") {$script:DBPrefix = $dbPrefix -replace "localhost","$env:COMPUTERNAME"}

if ($xmlInput.Configuration.Install.RemoteInstall.Enable -eq $true)
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
#endregion

#region Remote Install
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
            If ($xmlInput.Configuration.Install.RemoteInstall.ParallelInstall -eq $true) # Launch each farm server install simultaneously
            {
                Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-ExecutionPolicy Bypass Invoke-Command -ScriptBlock {
                                                                                Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; `
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
        Write-Host -ForegroundColor White " - There are other servers specified as farm members in:"
        Write-Host -ForegroundColor White " - $inputFile"
        Write-Host -ForegroundColor White " - but <RemoteInstall> is not set to `"true`" - nothing else to do."
    }
}
#endregion

#region Prepare For Install
Function PrepForInstall
{
    CheckXMLVersion $xmlInput
    CheckInput $inputFile
    Write-Host -ForegroundColor White " - Install based on: `n  - $inputFile `n  - Environment: $($xmlInput.Configuration.getAttribute(`"Environment`")) `n  - Version: $($xmlInput.Configuration.getAttribute(`"Version`"))"
    ValidateCredentials $xmlInput
    ValidatePassphrase $xmlInput
    CheckConfigFiles $xmlInput
    # Pass SQL username and password to the CheckSQLAccess function if we are using SQL auth
    if ($xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true")
    {
        CheckSQLAccess -xmlinput $xmlInput -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
    }
    # Otherwise just assume Windows integrated authentication and skip passing SQL login info
    else
    {
        CheckSQLAccess -xmlinput $xmlInput
    }
}
#endregion

#region Install SharePoint binaries
Function Start-Install
{
    DisableLoopbackCheck $xmlInput
    RemoveIEEnhancedSecurity $xmlInput
    UnblockFiles -path "$env:bits\$spYear"
    DisableServices $xmlInput
    DisableCRLCheck $xmlInput
    InstallPrerequisites $xmlInput
    ConfigureIISLogging $xmlInput
    InstallSharePoint $xmlInput
    # Try to apply a recent CU for the AppFabric Caching Service if we're installing at least SP2013
    if ($spVer -ge 15) {Install-AppFabricCU $xmlInput}
    InstallOfficeWebApps2010 $xmlInput
    InstallProjectServer $xmlInput
    InstallLanguagePacks $xmlInput
    InstallUpdates $xmlInput
    FixTaxonomyPickerBug $xmlInput
    Set-ShortcutRunAsAdmin -shortcutFile "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft SharePoint $spYear Products\SharePoint $spYear Management Shell.lnk"
}
#endregion

#region Setup Farm
Function Set-FarmConfig ([xml]$xmlInput)
{
    [System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlInput
    [security.securestring]$secPhrase = GetSecureFarmPassphrase $xmlInput
    ConfigureFarmAdmin $xmlInput
    Add-SharePointPSSnapin
    CreateOrJoinFarm $xmlInput ([security.securestring]$secPhrase) ([System.Management.Automation.PsCredential]$farmCredential)
    CheckFarmTopology $xmlInput
    ConfigureFarm $xmlInput
    ConfigureDiagnosticLogging $xmlInput
    ConfigureOfficeWebApps $xmlInput
    $languagePackInstalled = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS\").GetValue("LanguagePackInstalled")
    ConfigureLanguagePacks $xmlInput
    AddManagedAccounts $xmlInput
    if (($spYear -eq 2016) -and ($languagePackInstalled -eq 1))
    {
        Write-Host -ForegroundColor Yellow " - We need to re-launch the script to work around a known issue with SP2016 when language packs are installed."
        $scriptCommandLine = $($MyInvocation.Line)
        If (Confirm-LocalSession)
        {
            $scriptCommandLine = "$env:dp0\AutoSPInstallerLaunch.bat $inputFile"
            Write-Host -ForegroundColor White " - Re-Launching:"
            Write-Host -ForegroundColor White " - $scriptCommandLine"
            Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass $scriptCommandLine -RemoteAuthPassword $password" -Verb RunAs
            $script:aborted = $true
            Start-Sleep 10
            exit
        }
    }
    CreateWebApplications $xmlInput
}
#endregion

#region Setup Services
Function Set-ServiceConfig  ([xml]$xmlInput)
{
    ConfigureSandboxedCodeService $xmlInput
    CreateStateServiceApp $xmlInput
    CreateMetadataServiceApp $xmlInput
    ConfigureClaimsToWindowsTokenService $xmlInput
    CreateUserProfileServiceApplication $xmlInput
    CreateSPUsageApp $xmlInput
    ConfigureUsageLogging $xmlInput
    CreateWebAnalyticsApp $xmlInput
    CreateSecureStoreServiceApp $xmlInput
    ConfigureFoundationSearch $xmlInput
    ConfigureTracing $xmlInput
    CreateEnterpriseSearchServiceApp $xmlInput
    CreateBusinessDataConnectivityServiceApp $xmlInput
    CreateExcelServiceApp $xmlInput
    CreateAccess2010ServiceApp $xmlInput
    CreateVisioServiceApp $xmlInput
    CreatePerformancePointServiceApp $xmlInput
    CreateWordAutomationServiceApp $xmlInput
    CreateProjectServerServiceApp $xmlInput
    ConfigureWorkflowTimerService $xmlInput
    if ($spYear -eq 2010) # These are for SP2010 / Office Web Apps 2010 only
    {
        CreateExcelOWAServiceApp $xmlInput
        CreatePowerPointOWAServiceApp $xmlInput
        CreateWordViewingOWAServiceApp $xmlInput
    }
    if ($spVer -ge 15) # These are for SP2013+ only
    {
        CreateAppManagementServiceApp $xmlInput
        CreateSubscriptionSettingsServiceApp $xmlInput
        CreateWorkManagementServiceApp $xmlInput
        CreateMachineTranslationServiceApp $xmlInput
        CreateAccessServicesApp $xmlInput
        CreatePowerPointConversionServiceApp $xmlInput
        ConfigureDistributedCacheService $xmlInput
    }
    if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spVer -eq 14))
    {
        Write-Host -ForegroundColor White " - Installing SMTP Windows feature in a separate PowerShell window..."
        Start-Process -FilePath "$PSHOME\powershell.exe" -Verb Runas -ArgumentList "-Command `"Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; InstallSMTP (Get-Content $inputFile); Start-Sleep 5`"" -Wait
    }
    else {InstallSMTP $xmlInput}
    ConfigureOutgoingEmail $xmlInput
    ConfigureIncomingEmail $xmlInput
    Set-PDFSearchAndIcon $xmlInput
    ConfigureFoundationWebApplicationService $xmlInput
    InstallForeFront $xmlInput
}
#endregion

#region Finalize Install (perform any cleanup operations)
# Run last
Function Complete-Install ([xml]$xmlInput)
{
    # Perform these steps only if the local server is a SharePoint farm server
    If (MatchComputerName $farmServers $env:COMPUTERNAME)
    {
        # Remove Farm Account from local Administrators group to avoid big scary warnings in Central Admin
        # But only if the script actually put it there, and we want to leave it there
        # (e.g. to work around the issue with native SharePoint backups deprovisioning UPS per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=275)
        $farmAcct = $xmlInput.Configuration.Farm.Account.Username
        If (!($runningAsFarmAcct) -and ($xmlInput.Configuration.Farm.Account.AddToLocalAdminsDuringSetup -eq $true) -and ($xmlInput.Configuration.Farm.Account.LeaveInLocalAdmins -eq $false))
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
        Invoke-HealthAnalyzerJobs
    }

    Write-Host -ForegroundColor White " - Completed!`a"
    $Host.UI.RawUI.WindowTitle = " -- Completed -- $env:COMPUTERNAME --"
    $env:EndDate = Get-Date
}
#endregion

#region MAIN - Check for input file and start the install

If (!([string]::IsNullOrEmpty($targetServer))) {$farmServers = $targetServer}
Else {$farmServers = Get-FarmServers $xmlInput}
$remoteFarmServers = $farmServers | Where-Object {-not (MatchComputerName $_ $env:COMPUTERNAME)}
$password = $remoteAuthPassword
If ([string]::IsNullOrEmpty($password)) {$password = $xmlInput.Configuration.Install.AutoAdminLogon.Password}
If (($enableRemoteInstall -and !([string]::IsNullOrEmpty($remoteFarmServers))) -or ($xmlInput.Configuration.Install.AutoAdminLogon.Enable -eq $true))
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
        Start-Install
        Write-Host -ForegroundColor White " - SharePoint $spYear binary file installation done!"

        #region Re-Launch Script under PowerShell v2
        # Check for SharePoint 2010 on Windows Server 2012, and re-launch script under PowerShell version 2 if it's not already
        # Required for compatibility
        if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($host.Version.Major -gt 2) -and ($spVer -eq 14))
        {
            Write-Host -ForegroundColor Yellow " - A version of PowerShell greater than 2.0 was detected."
            Write-Host -ForegroundColor Yellow " - We need to re-launch the script to enable PowerShell version 2 for SharePoint $spYear."
            $scriptCommandLine = $($MyInvocation.Line)
            If (Confirm-LocalSession)
            {
                Write-Host -ForegroundColor White " - Re-Launching:"
                Write-Host -ForegroundColor White " - $scriptCommandLine"
                Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -ArgumentList "-Version 2 -NoExit -ExecutionPolicy Bypass $scriptCommandLine" -Verb RunAs
                $aborted = $true
                If ($isTracing) {Stop-Transcript; $script:isTracing = $false}
                Start-Sleep 10
                Write-Host -ForegroundColor White " - You can now safely close this window."
            }
            exit
        }
        #endregion

        If (($xmlInput.Configuration.Install.PauseAfterInstall -eq $true) -or ($xmlInput.Configuration.Install.RemoteInstall.ParallelInstall -eq $true))
        {
            Pause "proceed with farm configuration" "y"
        }
        Set-FarmConfig -xmlinput $xmlInput
        Set-ServiceConfig -xmlinput $xmlInput
        Complete-Install -xmlinput $xmlInput
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
                If ($xmlInput.Configuration.Install.AutoAdminLogon.Enable -eq $true)
                {
                    If ([string]::IsNullOrEmpty($password))
                    {
                        $password = $xmlInput.Configuration.Install.AutoAdminLogon.Password
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
            Write-Host -ForegroundColor Yellow " - A known (annoying) issue occurred loading the SharePoint PowerShell snapin."
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
            If (ShouldIProvision($xmlInput.Configuration.Farm.CentralAdmin) -eq $true)
            {
                Write-Host -ForegroundColor White " - Launching Central Admin..."
                Start-Process $PSConfigUI -ArgumentList "-cmd showcentraladmin"
            }
            # Launch any site collections we created, but only if this is a local (non-remote) session and this is a farm server and the Foundation Web Application Service is not disabled
            If ((MatchComputerName $farmServers $env:COMPUTERNAME) -and (ShouldIProvision $xmlInput.Configuration.Farm.Services.FoundationWebApplication))
            {
                ForEach ($webApp in $xmlInput.Configuration.WebApplications.WebApplication)
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
    Complete-Install
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
        If ((-not $unattended) -and (-not (Get-WmiObject Win32_OperatingSystem).Version -eq "6.1.7601")) {Invoke-Item $logFile} # We don't want to automatically open the log Win 2008 with SP2013, due to a nasty bug causing BSODs! See https://autospinstaller.codeplex.com/workitem/19491 for more info.
    }
    # Remove any lingering LogTime values in the registry
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "LogTime" -ErrorAction SilentlyContinue
}

#endregion

# ===================================================================================
# LOAD ASSEMBLIES
# ===================================================================================
#[void][System.Reflection.Assembly]::Load("Microsoft.SharePoint, Version=14.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c")
