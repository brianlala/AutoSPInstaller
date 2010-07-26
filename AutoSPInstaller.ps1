############################################################################ 
## AutoSPInstaller 1.4
## http://autospinstaller.codeplex.com
## Partially based on Create-SPFarm by Jos.Verlinde from http://poshcode.org/1485
## And on http://sharepoint.microsoft.com/blogs/zach/Lists/Posts/Post.aspx?ID=50
## Major additions, edits and tweaks by Brian Lalancette
############################################################################

#Region Get XML config file parameters & set install path
## This needs to be the first section of the script!
## Get XML configuration file parameters
param 
(
    [string]$InputFile = $(throw '- Need parameter input file (e.g. "c:\SP2010\Scripted\SetInputs.xml")')
)
## Start logging
$LogTime = Get-Date -Format yyyy-MM-dd_h-mm
$LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$LogTime.rtf"
Start-Transcript -Path $LogFile -Force
## Go through each Farm configuration parameter in the input xml file
Write-Host -ForegroundColor White "- Reading Input File $InputFile..."
$xmlinput = [xml] (get-content $InputFile)
$item = $xmlinput.SP2010Config.Farm
## Read the Farm parameters
$id                       					= $item.getAttribute("id")
$FarmName                 					= $item.FarmName
$DBServer                 					= $item.DBServer
## Fix up localhost with proper computer name
If ($DBServer -like "*localhost*") {$DBServer = $DBServer -replace "localhost","$env:COMPUTERNAME"}
If (($DBServer -eq "") -or ($DBServer -eq $null)) {Write-Host -ForegroundColor White " - DB server not specified, so assuming local server SQL instance."; $DBServer = $env:COMPUTERNAME}
$DBPrefix                 					= $item.DBPrefix
If ($DBPrefix -like "*localhost*") {$DBPrefix = $DBPrefix -replace "localhost","$env:COMPUTERNAME"}
If (($DBPrefix -ne "") -and ($DBPrefix -ne $null)) {$DBPrefix = $DBPrefix+"_"} ## If the prefix isn't blank, append an underscore as separator. You can replace with a different character (as long as it's valid in a DB name).
$ConfigFile                                 = $item.ConfigFile
If (($ConfigFile -eq "") -or ($ConfigFile -eq $null)) {$ConfigFile = "config.xml"} ## Set the default name of the config file for SP2010 binary installation, in case we haven't specified one
$DisableUnneededServices  					= $item.DisableUnneededServices
$OfflineInstall								= $item.OfflineInstall
$CreateCentralAdmin							= $item.CreateCentralAdmin
$CreateMetadataServiceApp 					= $item.CreateMetadataServiceApp
$CreateUserProfileApp     					= $item.CreateUserProfileApp     
$CreatePowerPivot 		  					= $item.CreatePowerPivot
$CreateWSSUsageApp        					= $item.CreateWSSUsageApp
$CreateWebAnalytics       					= $item.CreateWebAnalytics
$CreateStateServiceApp    					= $item.CreateStateServiceApp
$StartSearchQueryAndSiteSettingsService    	= $item.StartSearchQueryAndSiteSettingsService
$CreateSecureStoreServiceApp    			= $item.CreateSecureStoreServiceApp
$CentralAdminContentDB    					= $item.CentralAdminContentDB
$CentralAdminContentDB    					= $DBPrefix+$CentralAdminContentDB
$ConfigDB                 					= $DBPrefix+$item.ConfigDB
$FarmPassPhrase           					= $item.FarmPassPhrase
$FarmAcct                 					= $item.FarmAcct
If (($item.FarmAcctPWD -ne "") -and ($item.FarmAcctPWD -ne $null)) {$FarmAcctPWD = (ConvertTo-SecureString $item.FarmAcctPWD -AsPlainText -force)}
$FarmAcctEmail            					= $item.FarmAcctEmail
$ManagedAccountsToAdd     					= ($item.AppPoolAcct)
$AppPoolAcct              					= $item.AppPoolAcct
If (($item.AppPoolAcctPWD -ne "") -and ($item.AppPoolAcctPWD -ne $null)) {$AppPoolAcctPWD = (ConvertTo-SecureString $item.AppPoolAcctPWD -AsPlainText -force)}
$CentralAdminPort         					= $item.CentralAdminPort
$MetaDataDB               					= $DBPrefix+$item.MetaDataDB
$UserProfileServiceName   					= $item.UserProfileServiceName
$ProfileDB                					= $DBPrefix+$item.ProfileDB
$SyncDB                   					= $DBPrefix+$item.SyncDB
$SocialDB                 					= $DBPrefix+$item.SocialDB
$PortalName           						= $item.PortalName
$PortalURL		  		 				 	= $item.PortalURL
## Fix up localhost with proper computer name, and detect SSL
If ($PortalURL -like "*localhost*") {$PortalURL = $PortalURL -replace "localhost","$env:COMPUTERNAME"}
If ($PortalURL -like "https://*") {$PortalHostHeader = $PortalURL -replace "https://",""; $PortalUseSSL = $true}
Else {$PortalHostHeader   = $PortalURL -replace "http://",""; $PortalUseSSL = $false}
$PortalPort               					= $item.PortalPort
$PortalTemplate       					    = $item.PortalTemplate
$PortalLCID                                 = $item.PortalLCID
If (!($item.PortalLCID) -or ($item.PortalLCID -eq "")) {$PortalLCID = "1033"} #Default to English-US if missing or not set in SetInputs.xml
$PortalDB            				     	= $DBPrefix+$item.PortalDB
$PortalAppPool            					= $item.PortalAppPool
$PortalAppPoolAcct         					= $item.PortalAppPoolAcct
If (($item.PortalAppPoolAcctPWD -ne "") -and ($item.PortalAppPoolAcctPWD -ne $null)) {$PortalAppPoolAcctPWD = (ConvertTo-SecureString $item.PortalAppPoolAcctPWD -AsPlainText -force)}
$PortalUseClaims                            = $item.PortalUseClaims
$MySiteName		  		  					= $item.MySiteName
$MySiteDB                 					= $DBPrefix+$item.MySiteDB
$MySiteAppPool            					= $item.MySiteAppPool
$MySiteAppPoolAcct         					= $item.MySiteAppPoolAcct
If (($item.MySiteAppPoolAcctPWD -ne "") -and ($item.MySiteAppPoolAcctPWD -ne $null)) {$MySiteAppPoolAcctPWD = (ConvertTo-SecureString $item.MySiteAppPoolAcctPWD -AsPlainText -force)}
$MySiteRelativeURL        					= $item.MySiteRelativeURL
$MySiteURL       	  	  					= $item.MySiteURL
## Fix up localhost with proper computer name, and detect SSL
If ($MySiteURL -like "*localhost*") {$MySiteURL = $MySiteURL -replace "localhost","$env:COMPUTERNAME"}
If ($MySiteURL -like "https://*") {$MySiteHostHeader = $MySiteURL -replace "https://",""; $MySiteUseSSL = $true}
Else {$MySiteHostHeader   = $MySiteURL -replace "http://",""; $MySiteUseSSL = $false}
$MySitePort		          					= $item.MySitePort
$MySiteTemplate           					= $item.MySiteTemplate
$MySiteLCID                                 = $item.MySiteLCID
If (!($item.MySiteLCID) -or ($item.MySiteLCID -eq "")) {$MySiteLCID = "1033"} #Default to English-US if missing or not set in SetInputs.xml
$PersonalSiteRelativePath 					= $item.PersonalSiteRelativePath
$WSSUsageApplication      					= $item.WSSUsageApplication
$WSSUsageDB               					= $DBPrefix+$item.WSSUsageDB
$WebAnalyticsService      					= $item.WebAnalyticsService
$WebAnalyticsReportingDB  					= $DBPrefix+$item.WebAnalyticsReportingDB
$WebAnalyticsStagingDB    					= $DBPrefix+$item.WebAnalyticsStagingDB
$StateServiceDB           					= $DBPrefix+$item.StateServiceDB
$SecureStoreDB		  	  					= $DBPrefix+$item.SecureStoreDB

$stsadm = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\BIN\stsadm.exe"

$0 = $myInvocation.MyCommand.Definition
$dp0 = [System.IO.Path]::GetDirectoryName($0)
$bits = Get-Item $dp0 | Split-Path -Parent

Function ConvertTo-PlainText( [security.securestring]$secure )
## Used (for example) to get the Farm Account password into plain text as input to provision the User Profile Sync Service
## From http://www.vistax64.com/powershell/159190-read-host-assecurestring-problem.html
{
	$marshal = [Runtime.InteropServices.Marshal]
	$marshal::PtrToStringAuto( $marshal::SecureStringToBSTR($secure) )
}

#EndRegion

#Region Start Banner
$StartDate = Get-Date
Write-Host -ForegroundColor White "-----------------------------------"
Write-Host -ForegroundColor White "| Automated SP2010 install script |"
Write-Host -ForegroundColor White "| Started on: $StartDate |"
Write-Host -ForegroundColor White "-----------------------------------"
#EndRegion

#Region Pre-Checks
Function Pause
{
	#From http://www.microsoft.com/technet/scriptcenter/resources/pstips/jan08/pstip0118.mspx
	Write-Host "Press any key to exit..."
	$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
## Detect installer/product version
$SPVersion = (Get-Command "$bits\setup.exe" -ErrorAction SilentlyContinue).FileVersionInfo.ProductVersion
If ($SPVersion -like "14.0.4514*") 
{
	Write-Host -ForegroundColor White "- SharePoint 2010 Beta 2 `($SPVersion`) installer detected."
	$SPBeta = $true
}
ElseIf ($SPVersion -like "14.0.4730*") 
{
	Write-Host -ForegroundColor White "- SharePoint 2010 Release Candidate `($SPVersion`) installer detected."
	$SPBeta = $false
}
ElseIf ($SPVersion -like "14.0.4755*")
{
	Write-Host -ForegroundColor White "- SharePoint 2010 RTM `($SPVersion`) installer detected."
	$SPBeta = $false
}
ElseIf ($SPVersion -eq $null)
{
	Write-Warning "No version information returned, or `"$bits\setup.exe`" could not be found."
	Write-Warning "Please check the path of the SharePoint 2010 installer files."
	Pause
	break
}
Else
{
	Write-Host -ForegroundColor White "- SharePoint 2010 installer build $SPVersion detected."
	$SPBeta = $false
}
## Check if we are running under Farm Account credentials
If ($env:USERDOMAIN+"\"+$env:USERNAME -ne $FarmAcct)
{
	Write-Host -ForegroundColor Red "- This script should be executed using the `"$FarmAcct`" credentials."
	Write-Host -ForegroundColor Red "- (Otherwise, database objects will have inconsistent owners)"
	Write-Host -ForegroundColor Red "- Exiting..."
	Pause
	break
}

## Set aliases for cmdlets which were renamed from Beta2 to RC
If ($SPBeta)
{
	Write-Host -ForegroundColor White " - Setting cmdlet Alias(es) for SharePoint 2010 Beta..."
	New-Alias -Name New-SPServiceApplicationPool -Value New-SPIisWebServiceApplicationPool -Scope Script
	New-Alias -Name Get-SPServiceApplicationPool -Value Get-SPIisWebServiceApplicationPool -Scope Script
}

Function CheckSQLAccess
{
	Write-Host -ForegroundColor White "- Checking access to SQL server (or instance) `"$DBServer`"..."
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlConnection.ConnectionString = "Server=$DBServer;Database=master;Integrated Security=True"
	$SqlCmd.CommandText = "SELECT HAS_DBACCESS('master')"
	$SqlCmd.Connection = $SqlConnection
	$SqlCmd.CommandTimeout = 10
	Try
	{
		$SqlCmd.Connection.Open()
		$SqlCmd.ExecuteReader() | Out-Null
	}
	Catch
	{
		Write-Error $_
		Write-Warning " - Connection failed to SQL server or instance `"$DBServer`"!"
		Write-Warning " - Check the server (or instance) name, or verify rights for $FarmAcct."
		$SqlCmd.Connection.Close()
		Pause
		break
	}	
	Write-Host -ForegroundColor White " - $FarmAcct appears to have access."
	$SqlCmd.Connection.Close()
}
CheckSQLAccess

#EndRegion

#Region Query OS Type
$QueryOS = Gwmi Win32_OperatingSystem
$QueryOS = $QueryOS.Version 
If ($QueryOS.contains("6.1")) {$OS = "Win2008R2"}
ElseIf ($QueryOS.contains("6.0")) {$OS = "Win2008"}
Write-Host -ForegroundColor White "- Running on $OS."
#EndRegion

#Region Disable Unneeded Services
Function DisableServices
{
## Disable unneeded services in Windows 2008
## Brian Lalancette, 2009
Write-Host -ForegroundColor White "- Disabling Loopback Check on $OS..."
## Disable the Loopback Check on stand alone demo servers.  
## This setting usually kicks out a 401 error when you try to navigate to sites that resolve to a loopback address e.g.  127.0.0.1 

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$LsaPathValue = Get-ItemProperty -path $LsaPath
If (-not ($LsaPathValue.DisableLoopbackCheck -eq "1"))
{
    New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -value "1" -PropertyType dword -Force | Out-Null
}
$ServicesToSetManual = "Spooler","AudioSrv","TabletInputService"
$ServicesToDisable = "WerSvc"
Write-Host -ForegroundColor White "- Disabling (or setting manual) some unneeded services..."
ForEach ($SvcName in $ServicesToSetManual)
{
$Svc = get-wmiobject win32_service | where-object {$_.Name -eq $SvcName} 
$SvcStartMode = $Svc.StartMode
$SvcState = $Svc.State
 If (($SvcState -eq "Running") -and ($SvcStartMode -eq "Auto"))
  {
  Stop-Service -Name $SvcName
  Set-Service -name $SvcName -startupType Manual
  Write-Host -ForegroundColor White " - Service $SvcName is now set to Manual start"
  }
 Else 
  {
  Write-Host -ForegroundColor White " - $SvcName is already stopped and set Manual, no action required."
  }
}

ForEach ($SvcName in $ServicesToDisable) 
{
$Svc = get-wmiobject win32_service | where-object {$_.Name -eq $SvcName} 
$SvcStartMode = $Svc.StartMode
$SvcState = $Svc.State
 If (($SvcState -eq "Running") -and (($SvcStartMode -eq "Auto") -or ($SvcStartMode -eq "Manual")))
  {
  Stop-Service -Name $SvcName
  Set-Service -name $SvcName -startupType Disabled
  Write-Host -ForegroundColor White " - Service $SvcName is now stopped and disabled."
  }
 Else 
  {
  Write-Host -ForegroundColor White " - $SvcName is already stopped and disabled, no action required."
  }
}
Write-Host -ForegroundColor White "- Finished disabling services."
}
If ($DisableUnneededServices -eq "1") {DisableServices}
#EndRegion

#Region Process Input Parameters and Credentials
If (!($FarmPassPhrase) -or $FarmPassPhrase -eq "")
{
	Write-Warning "- Farm passphrase not found in $InputFile."
	$FarmPassPhrase = Read-Host -Prompt " - Please enter the farm passphrase now" -AsSecureString
	If (!($FarmPassPhrase) -or $FarmPassPhrase -eq "") {Write-Warning " - Farm passphrase is required!" ; Pause; break}
	Else {$SecPhrase = "$FarmPassPhrase"} ## Quotes around $FarmPassPhrase in case it has spaces or special characters
}
Else
{
	$SecPhrase = ConvertTo-SecureString "$FarmPassPhrase" –AsPlaintext –Force
}
#$FarmPassPhrase = $null
## get Farm Account
If ($FarmAcct -eq $null -or $FarmAcctPWD -eq $null) 
{
    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue "- Prompting for Farm Account:"
	$cred_farm = $host.ui.PromptForCredential("Farm Setup", "Enter Farm Account Credentials:", "$FarmAcct", "NetBiosUserName" )
} 
else
{
    $cred_farm = New-Object System.Management.Automation.PsCredential $FarmAcct,$FarmAcctPWD
}

<## Add Farm Account to local Administrators group (not needed if we are already running as $FarmAcct)
Write-Host -ForegroundColor White " - Adding $FarmAcct to the local Administrators group..."
$FarmAcctDomain,$FarmAcctUser = $FarmAcct -Split "\\"
try
{
	([ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group").Add("WinNT://$FarmAcctDomain/$FarmAcctUser")
	If (-not $?) {throw}
}
catch {Write-Host -ForegroundColor White "- $FarmAcct is already an Administrator, continuing."}#>

## get General App Pool Account
If ($AppPoolAcct -eq $null -or $AppPoolAcctPWD -eq $null) 
{
    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue "- Prompting for App Pool Account:"
	$cred_AppPoolAcct = $host.ui.PromptForCredential("Farm Setup", "Enter App Pool Account Credentials:", "$AppPoolAcct", "NetBiosUserName" )
} 
else
{
    $cred_AppPoolAcct = New-Object System.Management.Automation.PsCredential $AppPoolAcct,$AppPoolAcctPWD
}
## get Portal App Pool Account
If ($PortalAppPoolAcct -eq $null -or $PortalAppPoolAcctPWD -eq $null) 
{
    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue "- Prompting for Portal App Pool Account:"
	$cred_PortalAppPoolAcct = $host.ui.PromptForCredential("Farm Setup", "Enter Portal App Pool Account Credentials:", "$PortalAppPoolAcct", "NetBiosUserName" )
} 
else
{
    $cred_PortalAppPoolAcct = New-Object System.Management.Automation.PsCredential $PortalAppPoolAcct,$PortalAppPoolAcctPWD
}
## get My Sites App Pool Account
If ($MySiteAppPoolAcct -eq $null -or $MySiteAppPoolAcctPWD -eq $null) 
{
    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue "- Prompting for My Sites App Pool Account:"
	$cred_MySiteAppPoolAcct = $host.ui.PromptForCredential("Farm Setup", "Enter My Sites App Pool Account Credentials:", "$MySiteAppPoolAcct", "NetBiosUserName" )
} 
else
{
    $cred_MySiteAppPoolAcct = New-Object System.Management.Automation.PsCredential $MySiteAppPoolAcct,$MySiteAppPoolAcctPWD
}
#Endregion

#Region Install Prerequisites
If  (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\BIN\stsadm.exe") #Crude way of checking if SP2010 is already installed
{
	Write-Host -ForegroundColor White "- SP2010 prerequisites appear be already installed - skipping installation."
}
Else
{
	#Write-Progress -Activity "Installing Prerequisite Software" -Status "Please Wait..."
	Write-Host -ForegroundColor White "- Installing Prerequisite Software:"
	#Write-Progress -Activity "Installing Prerequisite Software" -Status "Please Wait..." -CurrentOperation "SharePoint 2010 Prerequisite Installation Wizard..."
	Write-Host -ForegroundColor White " - Running Prerequisite Installer..."

	Try 
	{
		If ($OfflineInstall	-eq "1") ## Install all prerequisites from local folder
		{
			Start-Process "$bits\PrerequisiteInstaller.exe" -Wait -ArgumentList "/unattended `
																				/SQLNCli:`"$bits\PrerequisiteInstallerFiles\sqlncli.msi`" `
																				/ChartControl:`"$bits\PrerequisiteInstallerFiles\MSChart.exe`" `
																				/NETFX35SP1:`"$bits\PrerequisiteInstallerFiles\dotnetfx35.exe`" `
																				/PowerShell:`"$bits\PrerequisiteInstallerFiles\Windows6.0-KB968930-x64.msu`" `
																				/KB976394:`"$bits\PrerequisiteInstallerFiles\Windows6.0-KB976394-x64.msu`" `
																				/KB976462:`"$bits\PrerequisiteInstallerFiles\Windows6.1-KB976462-v2-x64.msu`" `
																				/IDFX:`"$bits\PrerequisiteInstallerFiles\Windows6.0-KB974405-x64.msu`" `
																				/IDFXR2:`"$bits\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu`" `
																				/Sync:`"$bits\PrerequisiteInstallerFiles\Synchronization.msi`" `
																				/FilterPack:`"$bits\PrerequisiteInstallerFiles\FilterPack\FilterPack.msi`" `
																				/ADOMD:`"$bits\PrerequisiteInstallerFiles\SQLSERVER2008_ASADOMD10.msi`" `
																				/ReportingServices:`"$bits\PrerequisiteInstallerFiles\rsSharePoint.msi`" `
																				/Speech:`"$bits\PrerequisiteInstallerFiles\SpeechPlatformRuntime.msi`" `
																				/SpeechLPK:`"$bits\PrerequisiteInstallerFiles\MSSpeech_SR_en-US_TELE.msi`""																		
			If (-not $?) {throw}
		}
		Else ## Regular prerequisite install - download required files
		{
			Start-Process "$bits\PrerequisiteInstaller.exe" -Wait -ArgumentList "/unattended" -WindowStyle Minimized
			If (-not $?) {throw}
		}
	}
	Catch 
	{
		Write-Host -ForegroundColor Red "- Error: $LastExitCode"
		If ($LastExitCode -eq "1") {throw "- Another instance of this application is already running"}
		ElseIf ($LastExitCode -eq "2") {throw "- Invalid command line parameter(s)"}
		ElseIf ($LastExitCode -eq "1001") {throw "- A pending restart blocks installation"}
		ElseIf ($LastExitCode -eq "3010") {throw "- A restart is needed"}
		Else {throw "- An unknown error occurred installing prerequisites"}
	}
	## Parsing most recent PreRequisiteInstaller log for errors or restart requirements, since $LastExitCode doesn't seem to work...
	$PreReqLog = get-childitem $env:TEMP | ? {$_.Name -like "PrerequisiteInstaller.*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
	If ($PreReqLog -eq $null) 
	{
		Write-Warning " - Could not find PrerequisiteInstaller log file"
	}
	Else 
	{
		## Get error(s) from log
		$PreReqLastError = $PreReqLog | select-string -SimpleMatch -Pattern "Error" -Encoding Unicode | ? {$_.Line  -notlike "*Startup task*"}
		If ($PreReqLastError)
		{
			Write-Warning $PreReqLastError.Line
			$PreReqLastReturncode = $PreReqLog | select-string -SimpleMatch -Pattern "Last return code" -Encoding Unicode | Select-Object -Last 1
			If ($PreReqLastReturnCode) {Write-Warning $PreReqLastReturncode.Line}
			Write-Host -ForegroundColor White " - Review the log file and try to correct any error conditions."
			Pause
			Invoke-Item $env:TEMP\$PreReqLog
			break
		}
		## Look for restart requirement in log
		$PreReqRestartNeeded = $PreReqLog | select-string -SimpleMatch -Pattern "0XBC2=3010" -Encoding Unicode
		If ($PreReqRestartNeeded)
		{
			Write-Warning " - One or more of the prerequisites requires a restart."
			Write-Host -ForegroundColor White " - Run the script again after restarting to continue."
			Pause
			break
		}
	}

	Function Install-WCFHotfix
	{
		If ($OS -eq "Win2008") {$WCFHotfix = "Windows6.0-KB971831-x64.msu"}
		ElseIf ($OS -eq "Win2008R2") {$WCFHotfix = "Windows6.1-KB976462-v2-x64.msu"}
		Write-Progress -Activity "Installing Prerequisite Software" -Status "Please Wait..." -CurrentOperation "$WCFHotfix for $OS"
		Write-Host -ForegroundColor White " - WCF hotfix for $OS..."
		try 
		{
			Start-Process "$bits\PrerequisiteInstallerFiles\$WCFHotfix" -ArgumentList "/quiet /promptrestart" -Wait
			If (-not $?) {throw}
		}
		catch 
		{
			If ($LastExitCode -eq "87") {Write-Host -ForegroundColor White " - $WCFHotfix already installed"}
			ElseIf (($LastExitCode -eq "1641") -or ($LastExitCode -eq "1001") -or ($LastExitCode -eq "3010"))
			{
				Write-Host -ForegroundColor Yellow " - You should restart your server NOW for the hotfix to take effect."
				Write-Host -ForegroundColor Yellow " - You can re-run the script again once you've rebooted."
				Pause
				break
			}
			ElseIf ($LastExitCode -eq "5") {throw " - Local Administrator permissions are required to proceed!"}
			ElseIf ($LastExitCode -eq "-2145124329") {throw " - $WCFHotfix not applicable to your system (is .NET framework installed?)"}
			ElseIf (($LastExitCode -ne "2359302") -and ($LastExitCode -ne "87"))
			{
				Write-Host -ForegroundColor Red "- Error: $LastExitCode"
				throw "- An unknown error ($LastExitCode) occurred installing the $OS hotfix"
			}
		}
	}
	If ($SPBeta) {Install-WCFHotfix}
	
	Write-Progress -Activity "Installing Prerequisite Software" -Status "Done." -Completed
	Write-Host -ForegroundColor White "- All Prerequisite Software installed successfully."
}
#EndRegion

#Region Install SharePoint
Function InstallSharePoint
{
If  (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\BIN\stsadm.exe") #Crude way of checking if SP2010 is already installed
{
	Write-Host -ForegroundColor White "- SP2010 binaries appear be already installed - skipping installation."
}
Else
{
	## Install SharePoint Binaries
	If (Test-Path "$bits\setup.exe")
	{
  		Write-Progress -Activity "Installing SharePoint (Unattended)" -Status "Installing SharePoint binaries..."
		Write-Host -ForegroundColor White "- Installing SharePoint binaries..."
  		try
		{
			Start-Process "$bits\setup.exe" -ArgumentList "/config `"$dp0\$ConfigFile`"" -WindowStyle Minimized -Wait
			If (-not $?) {throw}
		}
		catch 
		{
			Write-Warning "- Error $LastExitCode occurred running $bits\setup.exe"
			break
		}
		
		## Parsing most recent SharePoint Server Setup log for errors or restart requirements, since $LastExitCode doesn't seem to work...
		$SetupLog = get-childitem $env:TEMP | ? {$_.Name -like "SharePoint Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
		If ($SetupLog -eq $null) 
		{
			Write-Warning " - Could not find SharePoint Server Setup log file!"
			Pause
			break
		}
		Else 
		{
			## Get error(s) from log
			$SetupLastError = $SetupLog | select-string -SimpleMatch -Pattern "Error:" | Select-Object -Last 1 #| ? {$_.Line  -notlike "*Startup task*"}
			If ($SetupLastError)
			{
				Write-Warning $SetupLastError.Line
				#$SetupLastReturncode = $SetupLog | select-string -SimpleMatch -Pattern "Last return code" | Select-Object -Last 1
				#If ($SetupLastReturnCode) {Write-Warning $SetupLastReturncode.Line}
				Write-Host -ForegroundColor White " - Review the log file and try to correct any error conditions."
				Pause
				Invoke-Item $env:TEMP\$SetupLog
				break
			}
			## Look for restart requirement in log
			$SetupRestartNotNeeded = $SetupLog | select-string -SimpleMatch -Pattern "System reboot is not pending."
			If (!($SetupRestartNotNeeded))
			{
				Write-Host -ForegroundColor White " - SharePoint setup requires a restart."
				Write-Host -ForegroundColor White " - Run the script again after restarting to continue."
				Pause
				break
			}
		}
		Write-Host -ForegroundColor Blue "- Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
		While ((Get-Process |?{$_.ProcessName -like "psconfigui*"}) -eq $null)
		{
			Write-Host -ForegroundColor Blue "." -NoNewline
			sleep 1
		}
		Write-Host -ForegroundColor Blue "Done."
  		Write-Host -ForegroundColor White "- Exiting Products and Technologies Wizard - using Powershell instead!"
		Stop-Process -Name psconfigui
	}
	Else
	{
	  	Write-Host -ForegroundColor Red "- Install path $bits Not found!!"
	  	Pause
		break
	}
}
}
InstallSharepoint
#EndRegion

#Region Install Language Packs
## Detects any language packs in $bits\LanguagePacks folder and installs them.
Write-Progress -Activity "Installing SharePoint (Unattended)" -Status "Installing Language Packs..."
## Look for Server language packs
$ServerLanguagePacks = (Get-ChildItem "$bits\LanguagePacks" -Name -Include ServerLanguagePack*.exe -ErrorAction SilentlyContinue)
If ($ServerLanguagePacks)
{
	Write-Host -ForegroundColor White "- Installing SharePoint (Server) Language Packs:"
	## Get installed languages from registry (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office Server\14.0\InstalledLanguages)
    $InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
	ForEach ($LanguagePack in $ServerLanguagePacks)
	{
        ## Slightly convoluted check to see if language pack is already installed, based on name of language pack file.
        ## This only works if you've renamed your language pack(s) to follow the convention "ServerLanguagePack_XX-XX.exe" where <XX-XX> is a culture such as <en-us>.
		$Language = $InstalledOfficeServerLanguages | ? {$_ -eq (($LanguagePack -replace "ServerLanguagePack_","") -replace ".exe","")}
        If (!$Language)
        {
	        Write-Host -ForegroundColor Blue " - Installing $LanguagePack..." -NoNewline
	        Start-Process -FilePath "$bits\LanguagePacks\$LanguagePack" -ArgumentList "/quiet /norestart"
	        While (Get-Process -Name ($LanguagePack -replace ".exe", "") -ErrorAction SilentlyContinue)
	        {
	        	Write-Host -ForegroundColor Blue "." -NoNewline
	        	sleep 5
	        }
   		    Write-Host -BackgroundColor Blue -ForegroundColor Black "Done."
        }
        Else
        {
            Write-Host -ForegroundColor White " - Language $Language already appears to be installed, skipping."
        }
	}
	Write-Host -ForegroundColor White " - Language Pack installation complete."
}
Else {Write-Host -ForegroundColor White " - No language packs found in $bits\LanguagePacks, skipping."}

## Detect installed languages
## Courtesy of Anders Rask (@andersrask)!
#$InstalledFoundationLanguages = (Get-Item "HKLM:\Software\Microsoft\Shared Tools\Web Server Extensions\14.0\InstalledLanguages" ).GetValueNames()
#$InstalledFoundationLanguages = [system.globalization.cultureinfo]$InstalledFoundationLanguages
#Write-Host -ForegroundColor White " - Currently installed LCIDs:" $InstalledFoundationLanguages | Select-Object -ExpandProperty DisplayName
$InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
Write-Host -ForegroundColor White " - Currently installed languages:" 
ForEach ($Language in $InstalledOfficeServerLanguages)
{
	Write-Host "  -" ([System.Globalization.CultureInfo]::GetCultureInfo($Language).DisplayName)
}
#EndRegion

#Region Create/Join Farm
Write-Progress -Activity "Installing SharePoint (Unattended)" -Status "Creating (or Joining) Farm..."
Write-Host -ForegroundColor White "- Creating & configuring (or joining) farm:"
Write-Host -ForegroundColor White " - Enabling SP PowerShell cmdlets..."
If ((Get-PsSnapin |?{$_.Name -eq "Microsoft.SharePoint.PowerShell"})-eq $null)
	{
    	$PSSnapin = Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
	}

Start-SPAssignment -Global | Out-Null

## Look for an existing farm and join the farm if not already joined, or create a new farm
try
{
	Write-Host -ForegroundColor White " - Checking farm membership for $env:COMPUTERNAME in `"$ConfigDB`"..."
	$SPFarm = Get-SPFarm | Where-Object {$_.Name -eq $ConfigDB} -ErrorAction SilentlyContinue
}
catch {""}
If ($SPFarm -eq $null)
{
	try
	{
		Write-Host -ForegroundColor White " - Attempting to join farm on `"$ConfigDB`"..."
		$ConnectFarm = Connect-SPConfigurationDatabase -DatabaseName "$ConfigDB" -Passphrase $SecPhrase -DatabaseServer "$DBServer" -ErrorAction SilentlyContinue
		If (-not $?)
		{
			Write-Host -ForegroundColor White " - No existing farm found.`n - Creating config database `"$ConfigDB`"..."
			## Waiting a few seconds seems to help with the Connect-SPConfigurationDatabase barging in on the New-SPConfigurationDatabase command; not sure why...
			sleep 5
			New-SPConfigurationDatabase –DatabaseName "$ConfigDB" –DatabaseServer "$DBServer" –AdministrationContentDatabaseName "$CentralAdminContentDB" –Passphrase $SecPhrase –FarmCredentials $Cred_Farm
			If (-not $?) {throw}
			Else {$FarmMessage = "- Done creating configuration database for farm."}
		}
		Else {$FarmMessage = "- Done joining farm."}
	Write-Host -ForegroundColor White " - Creating Version registry value (required workaround for apparent bug in command shell-based installs)"
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\' -Name Version -Value '14.0.0.4762' -ErrorAction SilentlyContinue | Out-Null
	}
	catch 
	{
		Write-Output $_
		Pause
		break
	}
}
Else {$FarmMessage = "- $env:COMPUTERNAME is already joined to farm on `"$ConfigDB`"."}
Write-Host -ForegroundColor White $FarmMessage
#EndRegion

#Region Create Central Admin
Function CreateCentralAdmin
{
	Write-Host -ForegroundColor White "- Creating and configuring Central Administration..."
	try
	{
		## Install Help Files
		Write-Host -ForegroundColor White " - Installing Help Collection..."
		Install-SPHelpCollection -All
		## Secure resources
		Write-Host -ForegroundColor White " - Securing Resources..."
		Initialize-SPResourceSecurity
		## Install Services
		Write-Host -ForegroundColor White " - Installing Services..."
		Install-SPService
		## Install (all) features
		Write-Host -ForegroundColor White " - Installing Features..."
		$Features = Install-SPFeature –AllExistingFeatures -Force
		## Create Central Admin
		Write-Host -ForegroundColor White " - Creating Central Admin site..."
		$NewCentralAdmin = New-SPCentralAdministration -Port $CentralAdminPort -WindowsAuthProvider "NTLM" -ErrorVariable err
		If (-not $?) {throw}
		Write-Host -ForegroundColor Blue " - Waiting for Central Admin site to provision..." -NoNewline
		sleep 5
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Done!"
		Write-Host -ForegroundColor White " - Installing Application Content..."
		Install-SPApplicationContent
	}
	catch	
	{
	    If ($err -like "*update conflict*")
		{
			Write-Warning " - A concurrency error occured, trying again."
			CreateCentralAdmin
		}
		Else 
		{
			Write-Output $_
			Pause
			break
		}
	}
	Write-Host -ForegroundColor White "- Done creating Central Administration."
}
If ($CreateCentralAdmin -eq "1") {CreateCentralAdmin}
Write-Progress -Activity "Installing SharePoint (Unattended)" -Status "Done." -Completed

#EndRegion

#Region Register Managed Accounts
## Add Managed Account for General App Pool Account
$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $AppPoolAcct}
If ($ManagedAccountGen -eq $NULL) 
{ 
	Write-Host -ForegroundColor White "- Registering managed account" $AppPoolAcct
	New-SPManagedAccount -Credential $cred_AppPoolAcct | Out-Null 
}
Else {Write-Host -ForegroundColor White "- Managed account $AppPoolAcct already exists, continuing."}

## Add Managed Account for Portal App Pool Account
$ManagedAccountPortal = Get-SPManagedAccount | Where-Object {$_.UserName -eq $PortalAppPoolAcct}
If ($ManagedAccountPortal -eq $NULL) 
{ 
	Write-Host -ForegroundColor White "- Registering managed account" $PortalAppPoolAcct
	New-SPManagedAccount -Credential $cred_PortalAppPoolAcct | Out-Null 
}
Else {Write-Host -ForegroundColor White "- Managed account $PortalAppPoolAcct already exists, continuing."}
## Add Managed Account for My Sites App Pool Account
$ManagedAccountMySite = Get-SPManagedAccount | Where-Object {$_.UserName -eq $MySiteAppPoolAcct}
If ($ManagedAccountMySite -eq $NULL) 
{ 
	Write-Host -ForegroundColor White "- Registering managed account" $MySiteAppPoolAcct
	New-SPManagedAccount -Credential $cred_MySiteAppPoolAcct | Out-Null 
}
Else {Write-Host -ForegroundColor White "- Managed account $MySiteAppPoolAcct already exists, continuing."}
#EndRegion

#Region Start Microsoft SharePoint Foundation Sandboxed Code Service
$SandboxedCodeService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"} 
If ($SandboxedCodeService.Status -eq "Disabled") 
{
	try
	{
		Write-Host -ForegroundColor White "- Starting Microsoft SharePoint Foundation Sandboxed Code Service..."
		$SandboxedCodeService | Start-SPServiceInstance | Out-Null
		If (-not $?) {throw "- Failed to start Sandboxed Code Service"}
	}
	catch {"- An error occurred starting the Microsoft SharePoint Foundation Sandboxed Code Service"}
	#Wait
			Write-Host -ForegroundColor Blue " - Waiting for Sandboxed Code service to start" -NoNewline
			While ($SandboxedCodeService.Status -ne "Online") 
			{
				Write-Host -ForegroundColor Blue "." -NoNewline
				sleep 1
				$SandboxedCodeService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
			}
			Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!"
}
#EndRegion

#Region Create Metadata Service Application
Function CreateMetadataServiceApp
{
	try
	{
      	## Managed Account
      	$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $AppPoolAcct}
      	If ($ManagedAccountGen -eq $NULL) { throw "- Managed Account $AppPoolAcct not found" }      
	    ## App Pool
		Write-Host -ForegroundColor White "- Getting Hosted Services Application Pool, creating if necessary..."
    	$ApplicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
    	if($ApplicationPool -eq $null)
	  	{ 
            $ApplicationPool = New-SPServiceApplicationPool "SharePoint Hosted Services" -account $ManagedAccountGen
            if (-not $?) { throw "Failed to create an application pool" }
      	}
 	    ## Create a Metadata Service Application
      	If((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}) -eq $null)
	  	{      
			Write-Host -ForegroundColor White " - Creating Managed Metadata Service:"
            ## Get the service instance
            $MetadataServiceInstance = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
            if (-not $?) { throw "- Failed to find Metadata service instance" }

            ## Start Service instance
            if($MetadataserviceInstance.Status -eq "Disabled")
			{ 
                  Write-Host -ForegroundColor White " - Starting Metadata Service Instance..."
                  $MetadataServiceInstance | Start-SPServiceInstance | Out-Null
                  if (-not $?) { throw "- Failed to start Metadata service instance" }
            } 

            ## Wait
			Write-Host -ForegroundColor Blue " - Waiting for Metadata service to start" -NoNewline
			While ($MetadataServiceInstance.Status -ne "Online") 
			{
				Write-Host -ForegroundColor Blue "." -NoNewline
				sleep 1
				$MetadataServiceInstance = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
			}
			Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!"

			## Create Service App
   			Write-Host -ForegroundColor White " - Creating Metadata Service Application..."
            $MetaDataServiceApp  = New-SPMetadataServiceApplication -Name "Metadata Service Application" -ApplicationPool $ApplicationPool -DatabaseName $MetaDataDB -AdministratorAccount $FarmAcct -FullAccessAccount $FarmAcct
            if (-not $?) { throw "- Failed to create Metadata Service Application" }

            ## create proxy
			Write-Host -ForegroundColor White " - Creating Metadata Service Application Proxy..."
            $MetaDataServiceAppProxy  = New-SPMetadataServiceApplicationProxy -Name "Metadata Service Application Proxy" -ServiceApplication $MetaDataServiceApp -DefaultProxyGroup
            if (-not $?) { throw "- Failed to create Metadata Service Application Proxy" }
            
			Write-Host -ForegroundColor White " - Granting rights to Metadata Service Application..."
			## Get ID of "Managed Metadata Service"
			$MetadataServiceAppToSecure = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
			$MetadataServiceAppIDToSecure = $MetadataServiceAppToSecure.Id
			## Create a variable that contains the list of administrators for the service application 
			$MetadataServiceAppSecurity = Get-SPServiceApplicationSecurity $MetadataServiceAppIDToSecure
			## Create a variable that contains the claims principal for app pool and farm user accounts
			$PortalAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $PortalAppPoolAcct -IdentityType WindowsSamAccountName
			## Give permissions to the claims principal you just created
			Grant-SPObjectSecurity $MetadataServiceAppSecurity -Principal $PortalAppPoolAcctPrincipal -Rights "Full Access to Term Store"
			## Apply the changes to the Metadata Service application
			Set-SPServiceApplicationSecurity $MetadataServiceAppIDToSecure -objectSecurity $MetadataServiceAppSecurity
            
			Write-Host -ForegroundColor White "- Done creating Managed Metadata Service."
      	}
	  	Else {Write-Host -ForegroundColor White "- Managed Metadata Service already exists."}
	}
	catch
	{
		Write-Output $_ 
	}
}
If ($CreateMetadataServiceApp -eq "1") {CreateMetadataServiceApp}
#EndRegion

#Region Assign Certificate
Function AssignCert
{
	## Load IIS WebAdministration Snapin/Module
	## Inspired by http://stackoverflow.com/questions/1924217/powershell-load-webadministration-in-ps1-script-on-both-iis-7-and-iis-7-5
	Try
	{
		If ($OS -eq "Win2008")
		{
			If (!(Get-PSSnapin WebAdministration -ErrorAction SilentlyContinue))
			{	 
  				If (!(Test-Path $env:ProgramFiles\IIS\PowerShellSnapin\IIsConsole.psc1)) 
				{
					Start-Process -Wait -NoNewWindow -FilePath msiexec.exe -ArgumentList "/i `"$bits\PrerequisiteInstallerFiles\iis7psprov_x64.msi`" /passive /promptrestart"
				}
				Add-PSSnapin WebAdministration
			}
		}
		Else ## Win2008R2
		{ 
  			Import-Module WebAdministration
		}
	}
	Catch
	{
		Write-Host -ForegroundColor White " - Could not load IIS Administration module."
	}
	Write-Host -ForegroundColor White " - Assigning certificate to site `"https://$SSLHostHeader`:$SSLPort`""
	Write-Host -ForegroundColor White " - Looking for existing `"$SSLHostHeader`" certificate to use..."
	$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
	If (!$Cert)
	{
		Write-Host -ForegroundColor White " - None found."
		If (Test-Path "$dp0\makecert.exe")
		{
			Write-Host -ForegroundColor White " - Creating new self-signed certificate..."
			Start-Process -NoNewWindow -Wait -FilePath "$dp0\makecert.exe" -ArgumentList "-r -pe -n `"CN=$SSLHostHeader`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
			$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
			$CertSubject = $Cert.Subject
		}
		Else 
		{
			Write-Host -ForegroundColor White " - `"$dp0\makecert.exe`" not found."
			Write-Host -ForegroundColor White " - Looking for any machine-named certificates we can use..."
			## Select the first certificate with the most recent valid date
			$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "*$env:COMPUTERNAME"} | Sort-Object NotBefore -Desc | Select-Object -First 1
			If (!$Cert)
			{
				Write-Host -ForegroundColor White " - None found, skipping certificate creation."
			}
			Else {$CertSubject = $Cert.Subject}
		}
	}
	Else
	{
		$CertSubject = $Cert.Subject
		Write-Host -ForegroundColor White " - Certificate `"$CertSubject`" found."
	}
	If ($Cert)
	{
		## Export our certificate to a file, then import it to the Trusted Root Certification Authorites store so we don't get nasty browser warnings
		## This will actually only work if the Subject and the host part of the URL are the same
		## Borrowed from https://www.orcsweb.com/blog/james/powershell-ing-on-windows-server-how-to-import-certificates-using-powershell/
		Write-Host -ForegroundColor White " - Exporting `"$CertSubject`" to `"$SSLHostHeader.cer`"..."
		$Cert.Export("Cert") | Set-Content "$env:TEMP\$SSLHostHeader.cer" -Encoding byte
		$Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		Write-Host -ForegroundColor White " - Importing `"$SSLHostHeader.cer`" to Local Machine\Root..."
		$Pfx.Import("$env:TEMP\$SSLHostHeader.cer")
		$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
		$Store.Open("MaxAllowed")
		$Store.Add($Pfx)
		$Store.Close()
		Write-Host -ForegroundColor White " - Assigning certificate `"$CertSubject`" to SSL-enabled site..."
		#Set-Location IIS:\SslBindings -ErrorAction Inquire
		$Cert | New-Item IIS:\SslBindings\0.0.0.0!$SSLPort -ErrorAction Inquire | Out-Null
		Write-Host -ForegroundColor White "- Certificate has been assigned to site `"https://$SSLHostHeader`:$SSLPort`""
	}
	Else {Write-Host -ForegroundColor White " - No certificates were found, and none could be created."}
	$Cert = $null
}
#EndRegion

#Region Create Content Web Apps
$GetSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $PortalName}
If ($GetSPWebApplication -eq $Null)
{
    Write-Host -ForegroundColor White "- Creating Web App `"$PortalName`"..."
	If ($PortalUseClaims -eq "1")
	{
		## Configure new web app to use Claims-based authentication
		$PortalAuthProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication
		New-SPWebApplication -Name $PortalName -ApplicationPoolAccount $PortalAppPoolAcct -ApplicationPool $PortalAppPool -DatabaseName $PortalDB -HostHeader $PortalHostHeader -Url $PortalURL -Port $PortalPort -SecureSocketsLayer:$PortalUseSSL -AuthenticationProvider $PortalAuthProvider | Out-Null
	}
	Else
	{
		## Create the web app using Classic mode authentication
		New-SPWebApplication -Name $PortalName -ApplicationPoolAccount $PortalAppPoolAcct -ApplicationPool $PortalAppPool -DatabaseName $PortalDB -HostHeader $PortalHostHeader -Url $PortalURL -Port $PortalPort -SecureSocketsLayer:$PortalUseSSL | Out-Null
	}
	Write-Host -ForegroundColor White "- Creating Site Collection `"$PortalURL`"..."
	## Verify that the Language we're trying to create the site in is currently installed on the server
    $PortalCulture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($PortalLCID)))
	$PortalCultureDisplayName = $PortalCulture.DisplayName
	If (!($InstalledOfficeServerLanguages | Where-Object {$_ -eq $PortalCulture.Name}))
	{
	    Write-Warning " - You must install the `"$PortalCulture ($PortalCultureDisplayName)`" Language Pack before you can create a site using LCID $PortalLCID"
	}
	Else
	{
		New-SPSite -Url $PortalURL -OwnerAlias $FarmAcct -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $PortalDB -Description $PortalName -Name $PortalName -Template $PortalTemplate -Language $PortalLCID | Out-Null
		If ($PortalUseSSL)
	    {
		    $SSLHostHeader = $PortalHostHeader
		    $SSLPort = $PortalPort
		    AssignCert
	    }
	    Write-Host -ForegroundColor White "- Launching $PortalURL..."
	    Start-Process "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe" "$PortalUrl" -WindowStyle Minimized
    }
}
Else
{
	Write-Host -ForegroundColor White "- Web app $PortalName already exists, continuing..."
}
#EndRegion

#Region Create User Profile Service Application
Function CreateUserProfileServiceApplication
{
## Based on http://sharepoint.microsoft.com/blogs/zach/Lists/Posts/Post.aspx?ID=50
	try
	{
      	Write-Host -ForegroundColor White "- Provisioning $UserProfileServiceName..."
	  	## Managed Account
      	$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $AppPoolAcct}
      	If ($ManagedAccountGen -eq $NULL) { throw " - Managed Account $AppPoolAcct not found" }      
      	## App Pool
	  	Write-Host -ForegroundColor White " - Getting Hosted Services Application Pool, creating if necessary..."
      	$ApplicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
      	If ($ApplicationPool -eq $null)
	  	{ 
            $ApplicationPool = New-SPServiceApplicationPool "SharePoint Hosted Services" -account $ManagedAccountGen 
            If (-not $?) { throw " - Failed to create the application pool" }
      	}

      	## Create a Profile Service Application
      	If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileApplication"}) -eq $null)
	  	{      
            ## get the service instance
            $ProfileServiceInstance = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
            If (-not $?) { throw " - Failed to find User Profile Service instance" }

            ## Start Service instance
			Write-Host -ForegroundColor White " - Starting User Profile Service instance..."
            If (($ProfileServiceInstance.Status -eq "Disabled") -or ($ProfileServiceInstance.Status -ne "Online"))
			{  
                $ProfileServiceInstance | Start-SPServiceInstance | Out-Null
                If (-not $?) { throw " - Failed to start User Profile Service instance" }

                ## Wait
   				Write-Host -ForegroundColor Blue " - Waiting for User Profile Service to start" -NoNewline
			    While ($ProfileServiceInstance.Status -ne "Online") 
			    {
					Write-Host -ForegroundColor Blue "." -NoNewline
					sleep 1
				    $ProfileServiceInstance = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
			    }
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!"
            }

			## Create MySites Web Application
			$GetSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $MySiteName}
			If ($GetSPWebApplication -eq $Null)
			{
			    Write-Host -ForegroundColor White " - Creating Web App `"$MySiteName`"..."
				New-SPWebApplication -Name $MySiteName -ApplicationPoolAccount $MySiteAppPoolAcct -ApplicationPool $MySiteAppPool -DatabaseName $MySiteDB -HostHeader $MySiteHostHeader -Url $MySiteURL -Port $MySitePort -SecureSocketsLayer:$MySiteUseSSL | Out-Null
			}
			Else
			{
				Write-Host -ForegroundColor White " - Web app `"$MySiteName`" already exists, continuing..."
			}
			
            ## Create MySites Site Collection
			If ((Get-SPContentDatabase | Where-Object {$_.Name -eq $MySiteDB})-eq $null)
			{
				Write-Host -ForegroundColor White " - Creating My Sites content DB..."
				$NewMySitesDB = New-SPContentDatabase -Name $MySiteDB -WebApplication "$MySiteURL`:$MySitePort"
				If (-not $?) { throw " - Failed to create My Sites content DB" }
			}
			If ((Get-SPSite | Where-Object {$_.Url -eq "$MySiteURL`:$MySitePort"})-eq $null)
			{
				Write-Host -ForegroundColor White " - Creating My Sites site collection $MySiteURL`:$MySitePort..."
				## Verify that the Language we're trying to create the site in is currently installed on the server
                $MySiteCulture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($MySiteLCID)))
		        $MySiteCultureDisplayName = $MySiteCulture.DisplayName
				If (!($InstalledOfficeServerLanguages | Where-Object {$_ -eq $MySiteCulture.Name}))
				{
		            Write-Warning " - You must install the `"$MySiteCulture ($MySiteCultureDisplayName)`" Language Pack before you can create a site using LCID $MySiteLCID"
                    Pause
                    break
	            }
	            Else
	            {
    				$NewMySitesCollection = New-SPSite -Url "$MySiteURL`:$MySitePort" -OwnerAlias $FarmAcct -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $MySiteDB -Description $MySiteName -Name $MySiteName -Template $MySiteTemplate -Language $MySiteLCID | Out-Null
				    If (-not $?) {throw " - Failed to create My Sites site collection"}
                    ## Assign SSL certificate, if required
			        If ($MySiteUseSSL)
			        {
				    	$SSLHostHeader = $MySiteHostHeader
				    	$SSLPort = $MySitePort
				    	AssignCert
			        }
                }
			}
			## Create Service App
			Write-Host -ForegroundColor White " - Creating $UserProfileServiceName..."
#           $ProfileServiceApp  = New-SPProfileServiceApplication -Name "$UserProfileServiceName" -ApplicationPool $ApplicationPool -ProfileDBName $ProfileDB -ProfileSyncDBName $SyncDB -SocialDBName $SocialDB -SyncInstanceMachine $env:COMPUTERNAME -MySiteHostLocation "$MySiteURL`:$MySitePort"
           	$ProfileServiceApp  = New-SPProfileServiceApplication -Name "$UserProfileServiceName" -ApplicationPool $ApplicationPool -ProfileDBName $ProfileDB -ProfileSyncDBName $SyncDB -SocialDBName $SocialDB -MySiteHostLocation "$MySiteURL`:$MySitePort"
           	If (-not $?) { throw " - Failed to create $UserProfileServiceName" }

            ## Create Proxy
			Write-Host -ForegroundColor White " - Creating $UserProfileServiceName Proxy..."
            $ProfileServiceAppProxy  = New-SPProfileServiceApplicationProxy -Name "$UserProfileServiceName Proxy" -ServiceApplication $ProfileServiceApp -DefaultProxyGroup
            If (-not $?) { throw " - Failed to create $UserProfileServiceName Proxy" }
			
			## Get ID of $UserProfileServiceName
			Write-Host -ForegroundColor White " - Get ID of $UserProfileServiceName..."
			$ProfileServiceAppToSecure = Get-SPServiceApplication |?{$_.TypeName -eq $UserProfileServiceName}
			$ProfileServiceAppIDToSecure = $ProfileServiceAppToSecure.Id

			Write-Host -ForegroundColor White " - Granting rights to $UserProfileServiceName..."
			## Create a variable that contains the guid for the User Profile service for which you want to delegate Full Control
			$serviceapp = Get-SPServiceApplication $ProfileServiceAppIDToSecure

			## Create a variable that contains the list of administrators for the service application 
			$ProfileServiceAppSecurity = Get-SPServiceApplicationSecurity $serviceapp -Admin

			## Create a variable that contains the claims principal for app pool and farm user accounts
			$MySiteAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $MySiteAppPoolAcct -IdentityType WindowsSamAccountName
			$FarmAcctPrincipal =  New-SPClaimsPrincipal -Identity $FarmAcct -IdentityType WindowsSamAccountName

			## Give Full Control permissions to the claims principal you just created, and the Farm Account
			Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $MySiteAppPoolAcctPrincipal -Rights "Full Control"
			Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $FarmAcctPrincipal -Rights "Full Control"

			## Apply the changes to the User Profile service application
			Set-SPServiceApplicationSecurity $serviceapp -objectSecurity $ProfileServiceAppSecurity -Admin
			
			## Launch My Site host
			Write-Host -ForegroundColor White " - Launching $MySiteURL`:$MySitePort..."
			Start-Process "$MySiteURL`:$MySitePort" -WindowStyle Minimized
			
			Write-Host -ForegroundColor White "- Done creating $UserProfileServiceName."
      	}
		## Start User Profile Synchronization Service
		## Get User Profile Service
		$ProfileServiceApp = Get-SPServiceApplication |?{$_.TypeName -eq $UserProfileServiceName}
		If ($ProfileServiceApp)
		{
			## Get User Profile Synchronization Service
			Write-Host -ForegroundColor White "- Checking User Profile Synchronization Service..." -NoNewline
			$ProfileSyncService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}
			If ($ProfileSyncService.Status -ne "Online")
			{
				## Inspired by http://technet.microsoft.com/en-us/library/ee721049.aspx
				If (!($FarmAcct)) {$FarmAcct = (Get-SPFarm).DefaultServiceAccount}
				If (!($FarmAcctPWD)) 
				{
					Write-Host -ForegroundColor White "`n"
					$FarmAcctPWD = Read-Host -Prompt " - Please (re-)enter the Farm Account Password" -AsSecureString
				}
				#$FarmAcctPlainPWD = $item.FarmAcctPWD
				Write-Host -ForegroundColor White "`n"
				Write-Host -ForegroundColor White " - Starting User Profile Synchronization Service..." -NoNewline
				$ProfileServiceApp.SetSynchronizationMachine($env:COMPUTERNAME, $ProfileSyncService.Id, $FarmAcct, (ConvertTo-PlainText $FarmAcctPWD))
				#If ($ProfileSyncService.Status -eq "Provisioning") {Write-Host -ForegroundColor Blue " - Waiting for User Profile Service Synchronization Service to start provisioning..." -NoNewline}
				#ElseIf 
				If (($ProfileSyncService.Status -ne "Provisioning") -and ($ProfileSyncService.Status -ne "Online")) {Write-Host -ForegroundColor Blue " - Waiting for User Profile Synchronization Service to be started..." -NoNewline}
				Else ## Monitor User Profile Sync service status
				{
				While ($ProfileSyncService.Status -ne "Online")
				{
					While ($ProfileSyncService.Status -ne "Provisioning")
					{
						Write-Host -ForegroundColor Blue ".`a" -NoNewline
						Sleep 1
						$ProfileSyncService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}
					}
					If ($ProfileSyncService.Status -eq "Provisioning")
					{
						Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!`a`a"
            			Write-Host -ForegroundColor Blue " - Provisioning User Profile Sync Service, please wait (up to 15 minutes)..." -NoNewline
					}
					While($ProfileSyncService.Status -eq "Provisioning" -and $ProfileSyncService.Status -ne "Disabled")
					{
						Write-Host -ForegroundColor Blue ".`a" -NoNewline
						sleep 1
						$ProfileSyncService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}
					}
					If ($ProfileSyncService.Status -ne "Online")
					{
						Write-Host -ForegroundColor Red ".`a`a`a`a`a`a`a`a" 
						Write-Host -BackgroundColor Red -ForegroundColor Black "- User Profile Synchronization Service could not be started!"
						break
					}
					Else
					{
						Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!`a`a"
						## Need to restart IIS before we can do anything with the User Profile Sync Service
						Write-Host -ForegroundColor White " - Restarting IIS..."
						Start-Process -FilePath iisreset.exe -ArgumentList "-noforce" -Wait -NoNewWindow
					}
				}
				}
			}
			Else {Write-Host -ForegroundColor White "Already started."}
		}
		Else 
		{
			Write-Host "`n"
			Write-Host -ForegroundColor Red "- Could not get User Profile Service"
		}
	}
	catch
    {
        Write-Output $_ 
    }
}
If ($CreateUserProfileApp -eq "1") {CreateUserProfileServiceApplication}
#EndRegion

#Region Create State Service Application
Function CreateStateServiceApp
{
	try
	{
		$GetSPStateServiceApplication = Get-SPStateServiceApplication
		If ($GetSPStateServiceApplication -eq $Null)
		{
			Write-Host -ForegroundColor White "- Creating State Service Application..."
			New-SPStateServiceDatabase -Name $StateServiceDB | Out-Null
			New-SPStateServiceApplication -Name "State Service Application" -Database $StateServiceDB | Out-Null
			Get-SPStateServiceDatabase | Initialize-SPStateServiceDatabase | Out-Null
			Write-Host -ForegroundColor White " - Creating State Service Application Proxy..."
			Get-SPStateServiceApplication | New-SPStateServiceApplicationProxy -Name "State Service Application Proxy" -DefaultProxyGroup | Out-Null
			Write-Host -ForegroundColor White "- Done creating State Service Application."
		}
		Else {Write-Host -ForegroundColor White "- State Service Application exists, continuing..."}
	}
catch
	{
		Write-Output $_
	}
}
If ($CreateStateServiceApp -eq "1") {CreateStateServiceApp}
#EndRegion

#Region Create WSS Usage Application
Function CreateWSSUsageApp
{
	try
	{
		$GetSPUsageApplication = Get-SPUsageApplication
		If ($GetSPUsageApplication -eq $Null)
		{
			Write-Host -ForegroundColor White "- Creating WSS Usage Application..."
			New-SPUsageApplication -Name $WSSUsageApplication -DatabaseServer $DBServer -DatabaseName $WSSUsageDB | Out-Null
			Write-Host -ForegroundColor White "- Done Creating WSS Usage Application."
		}
		Else {Write-Host -ForegroundColor White "- WSS Usage Application exists, continuing..."}
	}
catch
	{
		Write-Output $_
	}
}
If ($CreateWSSUsageApp -eq "1") {CreateWSSUsageApp}
#EndRegion

#Region Create Secure Store Service Application
Function CreateSecureStoreServiceApp
{
	try
	{
        Write-Host -ForegroundColor White "- Creating Secure Store Service..."
		$GetSPSecureStoreServiceApplication = Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])}
		If ($GetSPSecureStoreServiceApplication -eq $Null)
		{
			## Get the service instance
            $SecureStoreServiceInstance = Get-SPServiceInstance | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
            if (-not $?) { throw "- Failed to find Secure Store service instance" }

            ## Start Service instance
            if($SecureStoreServiceInstance.Status -eq "Disabled")
			{ 
                Write-Host -ForegroundColor White " - Starting Secure Store Service Instance..."
                $SecureStoreServiceInstance | Start-SPServiceInstance | Out-Null
                if (-not $?) { throw "- Failed to start Secure Store service instance" }
                ## Wait
			    Write-Host -ForegroundColor Blue " - Waiting for Secure Store service to start" -NoNewline
				While ($SecureStoreServiceInstance.Status -ne "Online") 
			    {
					Write-Host -ForegroundColor Blue "." -NoNewline
					sleep 1
				    $SecureStoreServiceInstance = Get-SPServiceInstance | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
			    }
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!"
            }

			Write-Host -ForegroundColor White " - Creating Secure Store Service Application..."
			New-SPSecureStoreServiceApplication -Name "Secure Store Service" -PartitionMode:$false -Sharing:$false -DatabaseName $SecureStoreDB -ApplicationPool "SharePoint Web Services System" -AuditingEnabled:$true -AuditLogMaxSize 30 | Out-Null
			Write-Host -ForegroundColor White " - Creating Secure Store Service Application Proxy..."
			Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])} | New-SPSecureStoreServiceApplicationProxy -Name "Secure Store Service Proxy" -DefaultProxyGroup | Out-Null
			Write-Host -ForegroundColor White " - Done creating Secure Store Service Application."
		}
		Else {Write-Host -ForegroundColor White " - Secure Store Service Application exists, continuing..."}
		
		$secureStore=Get-SPServiceApplicationProxy | Where {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplicationProxy])} 
		Write-Host -ForegroundColor White " - Creating the Master Key..."
 		Update-SPSecureStoreMasterKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase"
		Write-Host -ForegroundColor White " - Creating the Application Key..."
		Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase" -ErrorAction SilentlyContinue
		If (!$?)
		{
			## Try again...
			Write-Host -ForegroundColor White " - Creating the Application Key (2nd attempt)..."
			Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase"
		}
		Write-Host -ForegroundColor White " - Setting the unattended account for Performance Point Services..."
		Get-SPPerformancePointServiceApplication | Set-SPPerformancePointSecureDataValues -DataSourceUnattendedServiceAccount $cred_farm
	}
catch
	{
		Write-Output $_
	}
	Write-Host -ForegroundColor White "- Done creating/configuring Secure Store Service."
}
If ($CreateSecureStoreServiceApp -eq "1") {CreateSecureStoreServiceApp}

#EndRegion

#Region Start Search Query and Site Settings Service
Function StartSearchQueryAndSiteSettingsService
{
try
{
	## Get the service instance
    $SearchQueryAndSiteSettingsService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
    if (-not $?) { throw "- Failed to find Search Query and Site Settings service instance" }

    ## Start Service instance
    Write-Host -ForegroundColor White "- Starting Search Query and Site Settings Service Instance..."
    if($SearchQueryAndSiteSettingsService.Status -eq "Disabled")
	{ 
        $SearchQueryAndSiteSettingsService | Start-SPServiceInstance | Out-Null
        if (-not $?) { throw " - Failed to start Search Query and Site Settings service instance" }

        ## Wait
    	Write-Host -ForegroundColor Blue " - Waiting for Search Query and Site Settings service to start" -NoNewline
		While ($SearchQueryAndSiteSettingsService.Status -ne "Online") 
	    {
			Write-Host -ForegroundColor Blue "." -NoNewline
		  	start-sleep 1
		  	$SearchQueryAndSiteSettingsService = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
	    }
		Write-Host -BackgroundColor Blue -ForegroundColor Black "Started!"
    }
    Else {Write-Host -ForegroundColor White "- Search Query and Site Settings Service already started, continuing..."}
}
catch
{
	Write-Output $_ 
}
}
If ($StartSearchQueryAndSiteSettingsService -eq "1") {StartSearchQueryAndSiteSettingsService}
#EndRegion

#Region Create PowerPivot Service Application
Function CreatePowerPivotService
{
	Try
	{
		Write-Host -ForegroundColor White "- Creating PowerPivot Service Application..."
		If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.AnalysisServices.SharePoint.Integration.GeminiServiceApplication"})-eq $null)
		{
			New-PowerPivotServiceApplication -ServiceApplicationName "Default PowerPivot Service Application" -DatabaseServerName "$DBServer" -DatabaseName $DBPrefix"DefaultPowerPivotServiceApp_DB" –AddToDefaultProxyGroup
		}
		#Start-Process -NoNewWindow -Wait -FilePath $stsadm -ArgumentList "-o deploysolution -name PowerPivotWebApp.wsp -url $PortalURL -local -allowgacdeployment"
		Write-Host -ForegroundColor White " - Installing powerpivotwebapp solution..."
		Get-SPSolution | ? {$_.Name -eq "powerpivotwebapp.wsp"} | Install-SPSolution -WebApplication $PortalURL -GACDeployment -Local -Force
		#Start-Process -NoNewWindow -Wait -FilePath $stsadm -ArgumentList "-o activatefeature -id 1A33A234-B4A4-4fc6-96C2-8BDB56388BD5 -url $PortalURL -force"
		Write-Host -ForegroundColor White " - Enabling PowerPivotSite feature on `"$PortalURL`"..."
		Get-SPFeature | ? {$_.DisplayName -eq "PowerPivotSite"} | Enable-SPFeature -Url $PortalURL -Force
		Write-Host -ForegroundColor White "- Done."
	}
	Catch
	{
		$_
		Write-Warning "- An error occurred with the PowerPivot Service App, solution or feature."
	}
}
If ($CreatePowerPivot -eq "1") {CreatePowerPivotService}
#EndRegion

#Region End Banner
Stop-SPAssignment -Global | Out-Null
If ($CreateCentralAdmin -eq "1")
{
	## Run Farm configuration Wizard for whatever's left to configure...
	Write-Host -ForegroundColor White " - Launching Configuration Wizard..."
	Start-Process "http://$($env:COMPUTERNAME):$CentralAdminPort/_admin/adminconfigintro.aspx?scenarioid=adminconfig&welcomestringid=farmconfigurationwizard_welcome" -WindowStyle Normal
}
Write-Progress -Activity "Installing SharePoint (Unattended)" -Status "Done." -Completed
Write-Host -ForegroundColor White "- Finished!`a"
$EndDate = Get-Date
Write-Host -ForegroundColor White "-----------------------------------"
Write-Host -ForegroundColor White "| Automated SP2010 install script |"
Write-Host -ForegroundColor White "| Started on: $StartDate |"
Write-Host -ForegroundColor White "| Completed:  $EndDate |"
Write-Host -ForegroundColor White "-----------------------------------"
Stop-Transcript
Pause
Invoke-Item $LogFile
#EndRegion