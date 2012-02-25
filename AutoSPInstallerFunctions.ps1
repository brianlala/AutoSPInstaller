# ===================================================================================
# EXTERNAL FUNCTIONS
# ===================================================================================

#Region Validate Passphrase
Function ValidatePassphrase([xml]$xmlinput)
{
	# Check if passphrase is supplied
	$FarmPassphrase = $xmlinput.Configuration.Farm.Passphrase
	If (!($FarmPassphrase) -or ($FarmPassphrase -eq ""))
	{		
		Return
	}
	$groups=0
	If ($FarmPassphrase -match "[a-z]") { $groups = $groups + 1 }
	If ($FarmPassphrase -match "[A-Z]") { $groups = $groups + 1 }
	If ($FarmPassphrase -match "[0-9]") { $groups = $groups + 1 }
	If ($FarmPassphrase -match "[^a-zA-Z0-9]") { $groups = $groups + 1 }
	
	If (($groups -lt 3) -or ($FarmPassphrase.length -lt 8))
	{
		Write-Host -ForegroundColor Yellow " - Farm passphrase does not meet complexity requirements."
        Write-Host -ForegroundColor Yellow " - It must be at least 8 characters long and contain three of these types:"
		Write-Host -ForegroundColor Yellow "  - Upper case letters"
		Write-Host -ForegroundColor Yellow "  - Lower case letters"
		Write-Host -ForegroundColor Yellow "  - Digits"
		Write-Host -ForegroundColor Yellow "  - Other characters"
		Throw " - Farm passphrase does not meet complexity requirements."
	}
}
#EndRegion

#Region Validate Credentials
Function ValidateCredentials([xml]$xmlinput)
{
	WriteLine
	Write-Host -ForegroundColor White " - Validating user accounts and passwords..."
	If ($env:COMPUTERNAME -eq $env:USERDOMAIN)
	{
		Throw " - You are running this script under a local machine user account. You must be a domain user"
	}
	
	ForEach($node in $xmlinput.SelectNodes("//*[@Password]|//*[@password]|//*[@ContentAccessAccountPassword]|//*[@UnattendedIDPassword]|//*[Password]|//*[password]|//*[ContentAccessAccountPassword]|//*[UnattendedIDPassword]"))
	{													
		$user = (GetFromNode $node "username")
		If ($user -eq "") { $user = (GetFromNode $node "Username") }
		If ($user -eq "") { $user = (GetFromNode $node "Account") }
		If ($user -eq "") { $user = (GetFromNode $node "ContentAccessAccount") }
		If ($user -eq "") { $user = (GetFromNode $node "UnattendedIDUser") }
		
		$password = (GetFromNode $node "password")
		If ($password -eq "") { $password = (GetFromNode $node "Password") }
		If ($password -eq "") { $password = (GetFromNode $node "ContentAccessAccountPassword") }
		If ($password -eq "") { $password = (GetFromNode $node "UnattendedIDPassword") }
			
		If (($password -ne "") -and ($user -ne "")) 
		{
			$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
			Write-Host -ForegroundColor White " - Account `"$user`"..." -NoNewline
			$dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$user,$password)
			If ($dom.Path -eq $null)
			{
				Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid!"
                $AcctInvalid = $true
			}
			Else 
			{
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Verified."
			}
		}
	}
        If ($AcctInvalid) {Throw " - At least one set of credentials is invalid.`n - Check usernames and passwords in each place they are used."}
	WriteLine
}
#EndRegion

#Region Remove IE Enhanced Security
Function RemoveIEEnhancedSecurity([xml]$xmlinput)
{
	WriteLine
	If ($xmlinput.Configuration.Install.Disable.IEEnhancedSecurity -eq "True") 
	{
		Write-Host -ForegroundColor White " - Disabling IE Enhanced Security..."
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name isinstalled -Value 0
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name isinstalled -Value 0
		Rundll32 iesetup.dll, IEHardenLMSettings,1,True
		Rundll32 iesetup.dll, IEHardenUser,1,True
		Rundll32 iesetup.dll, IEHardenAdmin,1,True
		If (Test-Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}") 
		{
			Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
		}
		If (Test-Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}")
		{
			Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
		}
		
		#This doesn't always exist
		Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" "First Home Page" -ErrorAction SilentlyContinue
	}	
	Else 
	{
		Write-Host -ForegroundColor White " - Not configured to change IE Enhanced Security."
	}
	WriteLine
}
#EndRegion

#Region Disable Certificate Revocation List checks
Function DisableCRLCheck([xml]$xmlinput)
{
	WriteLine
	If ($xmlinput.Configuration.Install.Disable.CertificateRevocationListCheck -eq "True") 
	{
		Write-Host -ForegroundColor White " - Disabling Certificate Revocation List (CRL) check..."
		ForEach($bitsize in ("","64")) 
		{			
			$xml = [xml](Get-Content $env:windir\Microsoft.NET\Framework$bitsize\v2.0.50727\CONFIG\Machine.config)
			If (!$xml.DocumentElement.SelectSingleNode("runtime")) { 
				$runtime = $xml.CreateElement("runtime")
				$xml.DocumentElement.AppendChild($runtime) | Out-Null
			}
			If (!$xml.DocumentElement.SelectSingleNode("runtime/generatePublisherEvidence")) {
				$gpe = $xml.CreateElement("generatePublisherEvidence")
				$xml.DocumentElement.SelectSingleNode("runtime").AppendChild($gpe)  | Out-Null
			}
			$xml.DocumentElement.SelectSingleNode("runtime/generatePublisherEvidence").SetAttribute("enabled","false")  | Out-Null
			$xml.Save("$env:windir\Microsoft.NET\Framework$bitsize\v2.0.50727\CONFIG\Machine.config")
		}
	}	
	Else 
	{
		Write-Host -ForegroundColor White " - Not changing CRL check behavior."		
	}
	WriteLine
}
#EndRegion

#Region Start logging to user's desktop
Function StartTracing ($Server)
{
    If (!$isTracing)
    {
        $LogTime = Get-Date -Format yyyy-MM-dd_h-mm
        if ($server) {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$server-$LogTime.rtf"}
        else {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$LogTime.rtf"}
        Start-Transcript -Path $LogFile -Force
        If ($?) {$script:isTracing = $true}
    }
}
#EndRegion

#Region Check Configuration File 
Function CheckConfig
{
    # Check that the config file exists.
    If (-not $(Test-Path -Path $InputFile -Type Leaf))
    {
    	Write-Error -message (" - Configuration file '" + $InputFile + "' does not exist.")
    }
}
#EndRegion

#Region Check Installation Account
# ===================================================================================
# Func: CheckInstallAccount
# Desc: Check the install account and 
# ===================================================================================
Function CheckInstallAccount([xml]$xmlinput)
{
    # Check if we are running under Farm Account credentials
    If ($env:USERDOMAIN+"\"+$env:USERNAME -eq $FarmAcct) 
    {
        Write-Host  -ForegroundColor Yellow " - WARNING: Running install using Farm Account: $FarmAcct"
    }
}
#EndRegion

#Region Disable Loopback Check and Services
# ===================================================================================
# Func: DisableLoopbackCheck
# Desc: Disable Loopback Check
# ===================================================================================
Function DisableLoopbackCheck([xml]$xmlinput)
{
    # Disable the Loopback Check on stand alone demo servers.  
    # This setting usually kicks out a 401 error when you try to navigate to sites that resolve to a loopback address e.g.  127.0.0.1 
    If ($xmlinput.Configuration.Install.Disable.LoopbackCheck -eq $true)
    {
    	WriteLine
        Write-Host -ForegroundColor White " - Disabling Loopback Check..."

        $LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $LsaPathValue = Get-ItemProperty -path $LsaPath
        If (-not ($LsaPathValue.DisableLoopbackCheck -eq "1"))
        {
            New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -value "1" -PropertyType dword -Force | Out-Null
        }
    	WriteLine    
    }
}

# ===================================================================================
# Func: DisableServices
# Desc: Disable Unused Services or set status to Manual
# ===================================================================================
Function DisableServices([xml]$xmlinput)
{        
    If ($xmlinput.Configuration.Install.Disable.UnusedServices -eq $true)
    {
    	WriteLine
        Write-Host -ForegroundColor White " - Setting services Spooler, AudioSrv and TabletInputService to Manual..."

        $ServicesToSetManual = "Spooler","AudioSrv","TabletInputService"
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
    	
        Write-Host -ForegroundColor White " - Setting unused services WerSvc to Disabled..."
        $ServicesToDisable = "WerSvc"
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
        Write-Host -ForegroundColor White " - Finished disabling services."
        WriteLine
    }
    
}
#EndRegion

#Region Install Prerequisites
# ===================================================================================
# Func: Install Prerequisites
# Desc: If SharePoint is not already installed install the Prerequisites
# ===================================================================================
Function InstallPrerequisites([xml]$xmlinput)
{
    WriteLine
    $SPInstalled = Get-SharePointInstall
    If ($SPInstalled)
    {
    	Write-Host -ForegroundColor White " - SP2010 prerequisites appear be already installed - skipping install."
    }
    Else
    {
    	Write-Host -ForegroundColor White " - Installing Prerequisite Software:"
    	Try 
    	{
            If ((Gwmi Win32_OperatingSystem).Version -eq "6.1.7601") # Win2008 R2 SP1
            {
                # Due to the issue described in http://support.microsoft.com/kb/2581903 (related to installing the KB976462 hotfix) 
                # we install the .Net 3.5.1 features prior to attempting the PrerequisiteInstaller on Win2008 R2 SP1
                Write-Host -ForegroundColor White "  - .Net Framework..."
                # Get the current progress preference
                $pref = $ProgressPreference
                # Hide the progress bar since it tends to not disappear
                $ProgressPreference = "SilentlyContinue"
                Import-Module ServerManager
                Add-WindowsFeature NET-Framework | Out-Null
                # Restore progress preference
                $ProgressPreference = $pref
            }
            If ($xmlinput.Configuration.Install.OfflineInstall -eq $true) # Install all prerequisites from local folder
    		{
				Write-Host -ForegroundColor White "  - SQL Native Client..."
                # Install SQL native client before running pre-requisite installer as newest versions require an IACCEPTSQLNCLILICENSETERMS=YES argument
				Start-Process "$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi" -Wait -ArgumentList "/passive /norestart IACCEPTSQLNCLILICENSETERMS=YES"
			    Write-Host -ForegroundColor Blue "  - Running Prerequisite Installer..." -NoNewline
                $startTime = Get-Date
    			Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended `
    																				/SQLNCli:`"$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi`" `
    																				/ChartControl:`"$env:SPbits\PrerequisiteInstallerFiles\MSChart.exe`" `
    																				/NETFX35SP1:`"$env:SPbits\PrerequisiteInstallerFiles\dotnetfx35.exe`" `
    																				/PowerShell:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.0-KB968930-x64.msu`" `
    																				/KB976394:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.0-KB976394-x64.msu`" `
    																				/KB976462:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.1-KB976462-v2-x64.msu`" `
    																				/IDFX:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.0-KB974405-x64.msu`" `
    																				/IDFXR2:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu`" `
    																				/Sync:`"$env:SPbits\PrerequisiteInstallerFiles\Synchronization.msi`" `
    																				/FilterPack:`"$env:SPbits\PrerequisiteInstallerFiles\FilterPack\FilterPack.msi`" `
    																				/ADOMD:`"$env:SPbits\PrerequisiteInstallerFiles\SQLSERVER2008_ASADOMD10.msi`" `
    																				/ReportingServices:`"$env:SPbits\PrerequisiteInstallerFiles\rsSharePoint.msi`" `
    																				/Speech:`"$env:SPbits\PrerequisiteInstallerFiles\SpeechPlatformRuntime.msi`" `
    																				/SpeechLPK:`"$env:SPbits\PrerequisiteInstallerFiles\MSSpeech_SR_en-US_TELE.msi`""																		
    			If (-not $?) {Throw}
    		}
    		Else # Regular prerequisite install - download required files
    		{
			    Write-Host -ForegroundColor Blue "  - Running Prerequisite Installer..." -NoNewline
                $startTime = Get-Date
    			Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended" -WindowStyle Minimized
    			If (-not $?) {Throw}
    		}
            Show-Progress -Process PrerequisiteInstaller -Color Blue -Interval 5
            $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            Write-Host -ForegroundColor White "  - Prerequisite Installer completed in $delta."
    	}
    	Catch 
    	{
    		Write-Host -ForegroundColor Red " - Error: $LastExitCode"
    		If ($LastExitCode -eq "1") {Throw " - Another instance of this application is already running"}
    		ElseIf ($LastExitCode -eq "2") {Throw " - Invalid command line parameter(s)"}
    		ElseIf ($LastExitCode -eq "1001") {Throw " - A pending restart blocks installation"}
    		ElseIf ($LastExitCode -eq "3010") {Throw " - A restart is needed"}
			ElseIf ($LastExitCode -eq "-2145124329") {Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites"; InstallPreRequisites ([xml]$xmlinput)}
    		Else {Throw " - An unknown error occurred installing prerequisites"}
    	}
    	# Parsing most recent PreRequisiteInstaller log for errors or restart requirements, since $LastExitCode doesn't seem to work...
    	$PreReqLog = get-childitem $env:TEMP | ? {$_.Name -like "PrerequisiteInstaller.*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
    	If ($PreReqLog -eq $null) 
    	{
    		Write-Warning " - Could not find PrerequisiteInstaller log file"
    	}
    	Else 
    	{
    		# Get error(s) from log
    		$PreReqLastError = $PreReqLog | select-string -SimpleMatch -Pattern "Error" -Encoding Unicode | ? {$_.Line  -notlike "*Startup task*"}
    		If ($PreReqLastError)
    		{
    			Write-Warning $PreReqLastError.Line
    			$PreReqLastReturncode = $PreReqLog | select-string -SimpleMatch -Pattern "Last return code" -Encoding Unicode | Select-Object -Last 1
    			If ($PreReqLastReturnCode) {Write-Warning $PreReqLastReturncode.Line}
				If (($PreReqLastReturncode -like "*-2145124329*") -or ($PreReqLastReturncode -like "*2359302*") -or ($PreReqLastReturncode -eq "5"))
				{
					Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites - retrying..."
					InstallPreRequisites ([xml]$xmlinput)
				}
				Else
    			{
					Invoke-Item $env:TEMP\$PreReqLog
	    			Throw " - Review the log file and try to correct any error conditions."
				}
    		}
    		# Look for restart requirement in log
    		$PreReqRestartNeeded = $PreReqLog | select-string -SimpleMatch -Pattern "0XBC2=3010" -Encoding Unicode
    		If ($PreReqRestartNeeded)
    		{
    			Throw " - One or more of the prerequisites requires a restart."
    		}
	    	Write-Host -ForegroundColor White " - All Prerequisite Software installed successfully."	
    	}
    }
	WriteLine
}
#EndRegion

#Region Install SharePoint
# ===================================================================================
# Func: InstallSharePoint
# Desc: Installs the SharePoint binaries in unattended mode
# ===================================================================================
Function InstallSharePoint([xml]$xmlinput)
{
    WriteLine
    $SPInstalled = Get-SharePointInstall
    If ($SPInstalled)
    {
    	Write-Host -ForegroundColor White " - SP2010 binaries appear to be already installed - skipping installation."
    }
    Else
    {
    	# Install SharePoint Binaries
        $config = $env:dp0 + "\" + $xmlinput.Configuration.Install.ConfigFile
    	If (Test-Path "$env:SPbits\setup.exe")
    	{
    		Write-Host -ForegroundColor Blue " - Installing SharePoint binaries..." -NoNewline
            $StartTime = Get-Date
			Start-Process "$env:SPbits\setup.exe" -ArgumentList "/config `"$config`"" -WindowStyle Minimized
            Show-Progress -Process setup -Color Blue -Interval 5
            $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            Write-Host -ForegroundColor White " - SharePoint setup completed in $delta."
			If (-not $?)
            {
				Throw " - Error $LastExitCode occurred running $env:SPbits\setup.exe"
			}
    		
    		# Parsing most recent SharePoint Server Setup log for errors or restart requirements, since $LastExitCode doesn't seem to work...
    		$SetupLog = get-childitem $env:TEMP | ? {$_.Name -like "SharePoint Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
    		If ($SetupLog -eq $null) 
    		{
    			Throw " - Could not find SharePoint Server Setup log file!"
    		}

			# Get error(s) from log
			$SetupLastError = $SetupLog | select-string -SimpleMatch -Pattern "Error:" | Select-Object -Last 1 #| ? {$_.Line  -notlike "*Startup task*"}
			If ($SetupLastError)
			{
				Write-Warning $SetupLastError.Line
				Invoke-Item $env:TEMP\$SetupLog
				Throw " - Review the log file and try to correct any error conditions."
			}
			# Look for restart requirement in log
			$SetupRestartNotNeeded = $SetupLog | select-string -SimpleMatch -Pattern "System reboot is not pending."
			If (!($SetupRestartNotNeeded))
			{
				Throw " - SharePoint setup requires a restart. Run the script again after restarting to continue."
			}

    		Write-Host -ForegroundColor Blue " - Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
    		While ((Get-Process |?{$_.ProcessName -like "psconfigui*"}) -eq $null)
    		{
    			Write-Host -ForegroundColor Blue "." -NoNewline
    			Start-Sleep 1
    		}
    		Write-Host -ForegroundColor Blue "Done."
      		Write-Host -ForegroundColor White " - Exiting Products and Technologies Wizard - using Powershell instead!"
    		Stop-Process -Name psconfigui
    	}
    	Else
    	{
    	  	Throw " - Install path $env:SPbits not found!!"
    	}
    }
	WriteLine
}
#EndRegion

#Region Install Office Web Apps
# ===================================================================================
# Func: InstallOfficeWebApps
# Desc: Installs the OWA binaries in unattended mode
# From: Ported over by user http://www.codeplex.com/site/users/view/cygoh originally from the InstallSharePoint function, fixed up by brianlala
# Originally posted on: http://autospinstaller.codeplex.com/discussions/233530
# ===================================================================================
Function InstallOfficeWebApps([xml]$xmlinput)
{
	If ($xmlinput.Configuration.OfficeWebApps.Install -eq $true)
	{
		WriteLine
		If (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\TEMPLATE\FEATURES\OfficeWebApps\feature.xml") # Crude way of checking if Office Web Apps is already installed
		{
			Write-Host -ForegroundColor White " - Office Web Apps binaries appear to be already installed - skipping install."
		}
		Else
		{
			# Install Office Web Apps Binaries
	        $config = $env:dp0 + "\" + $xmlinput.Configuration.OfficeWebApps.ConfigFile
			If (Test-Path "$bits\OfficeWebApps\setup.exe")
			{
				Write-Host -ForegroundColor Blue " - Installing Office Web Apps binaries..." -NoNewline
                $startTime = Get-Date
				Start-Process "$bits\OfficeWebApps\setup.exe" -ArgumentList "/config `"$config`"" -WindowStyle Minimized
                Show-Progress -Process setup -Color Blue -Interval 5
                $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White " - Office Web Apps setup completed in $delta."
				If (-not $?) {
					Throw " - Error $LastExitCode occurred running $bits\OfficeWebApps\setup.exe"					
				}
				# Parsing most recent Office Web Apps Setup log for errors or restart requirements, since $LastExitCode doesn't seem to work...
				$SetupLog = get-childitem $env:TEMP | ? {$_.Name -like "Wac Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
				If ($SetupLog -eq $null) 
				{
					Throw " - Could not find Office Web Apps Setup log file!"
				}
				# Get error(s) from log
				$SetupLastError = $SetupLog | select-string -SimpleMatch -Pattern "Error:" | Select-Object -Last 1 #| ? {$_.Line -notlike "*Startup task*"}
				If ($SetupLastError)
				{
					Write-Warning $SetupLastError.Line
					Invoke-Item $env:TEMP\$SetupLog
					Throw " - Review the log file and try to correct any error conditions."					
				}
				# Look for restart requirement in log
				$SetupRestartNotNeeded = $SetupLog | select-string -SimpleMatch -Pattern "System reboot is not pending."
				If (!($SetupRestartNotNeeded))
				{
					Throw " - Office Webapps setup requires a restart. Run the script again after restarting to continue."
				}
				Write-Host -ForegroundColor Blue " - Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
				While ((Get-Process |?{$_.ProcessName -like "psconfigui*"}) -eq $null)
				{
					Write-Host -ForegroundColor Blue "." -NoNewline
					Start-Sleep 1
				}
				# The Connect-SPConfigurationDatabase cmdlet throws an error about an "upgrade required" if we don't at least *launch* the Wizard, so we wait to let it launch, then kill it.
				Start-Sleep 10
				Write-Host -ForegroundColor Blue "Done."
				Write-Host -ForegroundColor White " - Exiting Products and Technologies Wizard - using Powershell instead!"
				Stop-Process -Name psconfigui
			}
			Else
			{
				Throw " - Install path $bits\OfficeWebApps not found!!"
			}
		}
		WriteLine
	}
}
#EndRegion

#Region Configure Office Web Apps
Function ConfigureOfficeWebApps([xml]$xmlinput)
{
	If ($xmlinput.Configuration.OfficeWebApps.Install -eq $true)
	{
		Writeline
		<#Start-Process -FilePath $PSConfig -ArgumentList "-cmd upgrade -inplace b2b -wait -force -cmd installcheck -noinstallcheck" -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
		$PSConfigLog = get-childitem "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\LOGS" | ? {$_.Name -like "PSCDiagnostics*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
		If ($PSConfigLog -eq $null) 
		{
			Throw " - Could not find PSConfig log file!"
		}
		Else 
		{
			# Get error(s) from log
			##$PSConfigLastError = $PSConfigLog | select-string -SimpleMatch -CaseSensitive -Pattern "ERR" | Select-Object -Last 1
			If ($PSConfigLastError)
			{
				Write-Warning $PSConfigLastError.Line
				Write-Host -ForegroundColor White " - An error occurred configuring Office Web Apps, trying again..."
				ConfigureOfficeWebApps $xmlinput
			}
		}#>
		Try
		{
			Write-Host -ForegroundColor White " - Configuring Office Web Apps..."
			# Install Help Files
			Write-Host -ForegroundColor White " - Installing Help Collection..."
			Install-SPHelpCollection -All
			# Install application content 
			Write-Host -ForegroundColor White " - Installing Application Content..."
			Install-SPApplicationContent
			# Secure resources
			Write-Host -ForegroundColor White " - Securing Resources..."
			Initialize-SPResourceSecurity
			# Install Services
			Write-Host -ForegroundColor White " - Installing Services..."
			Install-SPService
			If (!$?) {Throw}
			# Install (all) features
			Write-Host -ForegroundColor White " - Installing Features..."
		    $Features = Install-SPFeature -AllExistingFeatures -Force
		}
		Catch	
		{
			Write-Output $_
			Throw " - Error configuring Office Web Apps!"
		}
		Writeline
	}
}
#EndRegion

#Region Install Language Packs
# ===================================================================================
# Func: Install Language Packs
# Desc: Install language packs and report on any languages installed
# ===================================================================================
Function InstallLanguagePacks([xml]$xmlinput)
{
	WriteLine
   	#Get installed languages from registry (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office Server\14.0\InstalledLanguages)
    $InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
	# Look for extracted language packs
	$ExtractedLanguagePacks = (Get-ChildItem "$bits\LanguagePacks" -Name -Include "??-??" -ErrorAction SilentlyContinue)
    $serverLanguagePacks = (Get-ChildItem "$bits\LanguagePacks" -Name -Include ServerLanguagePack_*.exe -ErrorAction SilentlyContinue)
	If ($ExtractedLanguagePacks)
	{
    	Write-Host -ForegroundColor White " - Installing SharePoint Language Packs:"
    	ForEach ($LanguagePackFolder in $ExtractedLanguagePacks)
		{
			$Language = $InstalledOfficeServerLanguages | ? {$_ -eq $LanguagePackFolder}
            If (!$Language)
			{
    	        Write-Host -ForegroundColor Blue " - Installing extracted language pack $LanguagePackFolder..." -NoNewline
    	        Start-Process -WorkingDirectory "$bits\LanguagePacks\$LanguagePackFolder\" -FilePath "setup.exe" -ArgumentList "/config $bits\LanguagePacks\$LanguagePackFolder\Files\SetupSilent\config.xml"
                Show-Progress -Process PrerequisiteInstaller -Color Blue -Interval 5
			}
		}
    	Write-Host -ForegroundColor White " - Language Pack installation complete."
	}
    # Look for Server language pack installers
    ElseIf ($serverLanguagePacks)
    {
    	Write-Host -ForegroundColor White " - Installing SharePoint Language Packs:"
    <#
    	#Another way to get installed languages, thanks to Anders Rask (@AndersRask)!
    	##$InstalledOfficeServerLanguages = [Microsoft.SharePoint.SPRegionalSettings]::GlobalInstalledLanguages
    #>
    	ForEach ($LanguagePack in $serverLanguagePacks)
    	{
            # Slightly convoluted check to see if language pack is already installed, based on name of language pack file.
            # This only works if you've renamed your language pack(s) to follow the convention "ServerLanguagePack_XX-XX.exe" where <XX-XX> is a culture such as <en-us>.
    		$Language = $InstalledOfficeServerLanguages | ? {$_ -eq (($LanguagePack -replace "ServerLanguagePack_","") -replace ".exe","")}
            If (!$Language)
            {
    	        Write-Host -ForegroundColor Blue " - Installing $LanguagePack..." -NoNewline
    	        Start-Process -FilePath "$bits\LanguagePacks\$LanguagePack" -ArgumentList "/quiet /norestart"
                Show-Progress -Process $($LanguagePack -replace ".exe", "") -Color Blue -Interval 5
				$Language = (($LanguagePack -replace "ServerLanguagePack_","") -replace ".exe","")
				# Install Foundation Language Pack SP1, then Server Language Pack SP1, if found
				If (Get-ChildItem "$bits\LanguagePacks" -Name -Include spflanguagepack2010sp1-kb2460059-x64-fullfile-$Language.exe -ErrorAction SilentlyContinue)
				{
					Write-Host -ForegroundColor Blue " - Installing Foundation language pack SP1 for $Language..." -NoNewline
					Start-Process -WorkingDirectory "$bits\LanguagePacks\" -FilePath "spflanguagepack2010sp1-kb2460059-x64-fullfile-$Language.exe" -ArgumentList "/quiet /norestart"
                    Show-Progress -Process spflanguagepack2010sp1-kb2460059-x64-fullfile-$Language -Color Blue -Interval 5
					# Install Server Language Pack SP1, if found
					If (Get-ChildItem "$bits\LanguagePacks" -Name -Include serverlanguagepack2010sp1-kb2460056-x64-fullfile-$Language.exe -ErrorAction SilentlyContinue)
					{
						Write-Host -ForegroundColor Blue " - Installing Server language pack SP1 for $Language..." -NoNewline
						Start-Process -WorkingDirectory "$bits\LanguagePacks\" -FilePath "serverlanguagepack2010sp1-kb2460056-x64-fullfile-$Language.exe" -ArgumentList "/quiet /norestart"
                        Show-Progress -Process serverlanguagepack2010sp1-kb2460056-x64-fullfile-$Language -Color Blue -Interval 5
					}
					Else
					{
						Write-Warning " - Server Language Pack SP1 not found for $Language!" 
						Write-Warning " - You must install it for the language service pack patching process to be complete."
					}
				}
				Else {Write-Host -ForegroundColor White " - No Language Pack service packs found."}
            }
            Else
            {
                Write-Host -ForegroundColor White " - Language $Language already appears to be installed, skipping."
            }
    	}
    	Write-Host -ForegroundColor White " - Language Pack installation complete."
    }
    Else 
    {
        Write-Host -ForegroundColor White " - No language packs found in $bits\LanguagePacks, skipping."
    }

    # Get and note installed languages
    $InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    Write-Host -ForegroundColor White " - Currently installed languages:" 
    ForEach ($Language in $InstalledOfficeServerLanguages)
    {
    	Write-Host "  -" ([System.Globalization.CultureInfo]::GetCultureInfo($Language).DisplayName)
    }
	WriteLine
}
#EndRegion

#Region Configure Farm Account
# ===================================================================================
# Func: ConfigureFarmAdmin
# Desc: Sets up the farm account and adds to Local admins if needed
# ===================================================================================
Function ConfigureFarmAdmin([xml]$xmlinput)
{        
	If (($xmlinput.Configuration.Farm.Account.getAttribute("AddToLocalAdminsDuringSetup") -eq $true) -and (ShouldIProvision($xmlinput.Configuration.ServiceApps.UserProfileServiceApp) -eq $true))
    {
        WriteLine
		#Add to Admins Group
        $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
        Write-Host -ForegroundColor White " - Adding $FarmAcct to local Administrators" -NoNewline
		If ($xmlinput.Configuration.Farm.Account.LeaveInLocalAdmins -ne $true) {Write-Host -ForegroundColor White " (only for install)..."}
		Else {Write-Host -ForegroundColor White " ..."}
        $FarmAcctDomain,$FarmAcctUser = $FarmAcct -Split "\\"
        Try
    	{
            $builtinAdminGroup = Get-AdministratorsGroup
            ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$FarmAcctDomain/$FarmAcctUser")
            If (-not $?) {Throw}
			# Restart the SPTimerV4 service if it's running, so it will pick up the new credential
			If ((Get-Service -Name SPTimerV4).Status -eq "Running")
			{
				Write-Host -ForegroundColor White " - Restarting SharePoint Timer Service..."
				Restart-Service SPTimerV4
			}
    	}
        Catch {Write-Host -ForegroundColor White " - $FarmAcct is already a member of `"$builtinAdminGroup`"."}
		WriteLine
    }
}

# ===================================================================================
# Func: GetFarmCredentials
# Desc: Return the credentials for the farm account, prompt the user if need more info
# ===================================================================================
Function GetFarmCredentials([xml]$xmlinput)
{        
    $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
    $FarmAcctPWD = $xmlinput.Configuration.Farm.Account.Password
    If (!($FarmAcct) -or $FarmAcct -eq "" -or !($FarmAcctPWD) -or $FarmAcctPWD -eq "") 
    {
        Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Farm Account:"
    	$script:farmCredential = $host.ui.PromptForCredential("Farm Setup", "Enter Farm Account Credentials:", "$FarmAcct", "NetBiosUserName" )
    } 
    Else
    {
        $secPassword = ConvertTo-SecureString "$FarmAcctPWD" -AsPlaintext -Force 
        $script:farmCredential = New-Object System.Management.Automation.PsCredential $FarmAcct,$secPassword
    }
    Return $farmCredential
}
#EndRegion

#Region Get Farm Passphrase
Function GetFarmPassphrase([xml]$xmlinput)
{
	$FarmPassphrase = $xmlinput.Configuration.Farm.Passphrase
	If (!($FarmPassphrase) -or ($FarmPassphrase -eq ""))
	{
		$FarmPassphrase = Read-Host -Prompt " - Please enter the farm passphrase now" -AsSecureString
		If (!($FarmPassphrase) -or ($FarmPassphrase -eq "")) { Throw " - Farm passphrase is required!" }
    }
	Return $FarmPassphrase
}
#EndRegion

#Region Get Secure Farm Passphrase
# ===================================================================================
# Func: GetSecureFarmPassphrase
# Desc: Return the Farm Phrase as a secure string
# ===================================================================================
Function GetSecureFarmPassphrase([xml]$xmlinput)
{        
    If (!($FarmPassphrase) -or ($FarmPassphrase -eq ""))
    {
    	$FarmPassphrase = GetFarmPassPhrase $xmlinput
	}
	If ($FarmPassPhrase.GetType().Name -ne "SecureString")
	{
		$SecPhrase = ConvertTo-SecureString $FarmPassphrase -AsPlaintext -Force
	}
	Else {$SecPhrase = $FarmPassphrase}
 	Return $SecPhrase
}
#EndRegion

#Region Update Service Process Identity

# ====================================================================================
# Func: UpdateProcessIdentity
# Desc: Updates the account a specified service runs under to the general app pool account
# ====================================================================================
Function UpdateProcessIdentity ($ServiceToUpdate)
{
	$spservice = Get-spserviceaccountxml $xmlinput
	# Managed Account
   	$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
   	If ($ManagedAccountGen -eq $NULL) { Throw " - Managed Account $($spservice.username) not found" }
	Write-Host -ForegroundColor White " - Updating $($ServiceToUpdate.TypeName) to run as $($ManagedAccountGen.UserName)..."
	# Set the Process Identity to our general App Pool Account; otherwise it's set by default to the Farm Account and gives warnings in the Health Analyzer
	$ServiceToUpdate.Service.ProcessIdentity.CurrentIdentityType = "SpecificUser"
	$ServiceToUpdate.Service.ProcessIdentity.ManagedAccount = $ManagedAccountGen
	$ServiceToUpdate.Service.ProcessIdentity.Update()
	$ServiceToUpdate.Service.ProcessIdentity.Deploy()
	$ServiceToUpdate.Update()
}
#EndRegion

#Region Create or Join Farm
# ===================================================================================
# Func: CreateOrJoinFarm
# Desc: Check if the farm is created 
# ===================================================================================
Function CreateOrJoinFarm([xml]$xmlinput, $SecPhrase, $farmCredential)
{
    WriteLine
    $ConfigDB = $DBPrefix+$xmlinput.Configuration.Farm.Database.ConfigDB
    
    # Look for an existing farm and join the farm if not already joined, or create a new farm
    Try
    {
    	Write-Host -ForegroundColor White " - Checking farm membership for $env:COMPUTERNAME in `"$ConfigDB`"..."
    	$SPFarm = Get-SPFarm | Where-Object {$_.Name -eq $ConfigDB} -ErrorAction SilentlyContinue
    }
    Catch {""}
    If ($SPFarm -eq $null)
    {
		$DBServer = $xmlinput.Configuration.Farm.Database.DBServer
		$CentralAdminContentDB = $DBPrefix+$xmlinput.Configuration.Farm.CentralAdmin.Database
		
		Write-Host -ForegroundColor White " - Attempting to join farm on `"$ConfigDB`"..."
		$connectFarm = Connect-SPConfigurationDatabase -DatabaseName "$ConfigDB" -Passphrase $SecPhrase -DatabaseServer "$DBServer" -ErrorAction SilentlyContinue
		If (-not $?)
		{
			Write-Host -ForegroundColor White " - No existing farm found.`n - Creating config database `"$ConfigDB`"..."
			# Waiting a few seconds seems to help with the Connect-SPConfigurationDatabase barging in on the New-SPConfigurationDatabase command; not sure why...
			Start-Sleep 5
			New-SPConfigurationDatabase -DatabaseName "$ConfigDB" -DatabaseServer "$DBServer" -AdministrationContentDatabaseName "$CentralAdminContentDB" -Passphrase $SecPhrase -FarmCredentials $farmCredential
			If (-not $?) {Throw " - Error creating new farm configuration database"}
			Else {$FarmMessage = " - Done creating configuration database for farm."}
		}
		Else 
		{
			$FarmMessage = " - Done joining farm."
			[bool]$script:FarmExists = $true

		}
    }
    Else 
    {
       	[bool]$script:FarmExists = $true
		$FarmMessage = " - $env:COMPUTERNAME is already joined to farm on `"$ConfigDB`"."
    }
    
    Write-Host -ForegroundColor White $FarmMessage
	WriteLine
}
#EndRegion

#Region Configure Farm
# ===================================================================================
# Func: CreateCentralAdmin
# Desc: Setup Central Admin Web Site, Check the topology of an existing farm, and configure the farm as required.
# ===================================================================================
Function CreateCentralAdmin([xml]$xmlinput)
{
	If (ShouldIProvision($xmlinput.Configuration.Farm.CentralAdmin) -eq $true)
	{
		Try
		{
			$CentralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.Port
			# Check if there is already a Central Admin provisioned in the farm; if not, create one
			If (!(Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*:$CentralAdminPort*"}))
			{
				# Create Central Admin for farm
				Write-Host -ForegroundColor White " - Creating Central Admin site..."
				$NewCentralAdmin = New-SPCentralAdministration -Port $CentralAdminPort -WindowsAuthProvider "NTLM" -ErrorVariable err
				If (-not $?) {Throw " - Error creating central administration application"}
				Write-Host -ForegroundColor Blue " - Waiting for Central Admin site..." -NoNewline
				$CentralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*$($env:COMPUTERNAME):$CentralAdminPort*"}
				While ($CentralAdmin.Status -ne "Online") 
				{
					Write-Host -ForegroundColor Blue "." -NoNewline
					Start-Sleep 1
					$CentralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*$($env:COMPUTERNAME):$CentralAdminPort*"}
				}
				Write-Host -BackgroundColor Blue -ForegroundColor Black $($CentralAdmin.Status)
				If ($xmlinput.Configuration.Farm.CentralAdmin.UseSSL -eq $true)
				{
					Write-Host -ForegroundColor White " - Enabling SSL for Central Admin..."
					$SSLHostHeader = $env:COMPUTERNAME
					$SSLPort = $CentralAdminPort
					$SSLSiteName = $CentralAdmin.DisplayName
					New-SPAlternateURL -Url "https://$($env:COMPUTERNAME):$CentralAdminPort" -Zone Default -WebApplication $CentralAdmin | Out-Null
					AssignCert
				}
			}
			Else #Create a Central Admin site locally, with an AAM to the existing Central Admin
			{
				Write-Host -ForegroundColor White " - Creating local Central Admin site..."
				$NewCentralAdmin = New-SPCentralAdministration
			}
		}
		Catch	
		{
	   		If ($err -like "*update conflict*")
			{
				Write-Warning " - A concurrency error occured, trying again."
				CreateCentralAdmin $xmlinput
			}
			Else 
			{
				Throw $_
			}
		}
	}
}

# ===================================================================================
# Func: CheckFarmTopology
# Desc: Check if there is already more than one server in the farm (not including the database server)
# ===================================================================================
Function CheckFarmTopology([xml]$xmlinput)
{
	$ConfigDB = $DBPrefix+$xmlinput.Configuration.Farm.Database.ConfigDB
    $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
	$SPFarm = Get-SPFarm | Where-Object {$_.Name -eq $ConfigDB}
	ForEach ($Srv in $SPFarm.Servers) {If (($Srv -like "*$DBServer*") -and ($DBServer -ne $env:COMPUTERNAME)) {[bool]$DBLocal = $false}}
	If (($($SPFarm.Servers.Count) -gt 1) -and ($DBLocal -eq $false)) {[bool]$script:FirstServer = $false}
	Else {[bool]$script:FirstServer = $true}
}

# ===================================================================================
# Func: ConfigureFarm
# Desc: Setup Central Admin Web Site, Check the topology of an existing farm, and configure the farm as required.
# ===================================================================================
Function ConfigureFarm([xml]$xmlinput)
{
	WriteLine
	Write-Host -ForegroundColor White " - Configuring the SharePoint farm/server..."
	# Force a full configuration if this is the first web/app server in the farm
	If ((!($FarmExists)) -or ($FirstServer -eq $true) -or (CheckIfUpgradeNeeded -eq $true)) {[bool]$DoFullConfig = $true}
	Try
	{
		If ($DoFullConfig)
		{
			# Install Help Files
				Write-Host -ForegroundColor White " - Installing Help Collection..."
				Install-SPHelpCollection -All
		}
		# Secure resources
		Write-Host -ForegroundColor White " - Securing Resources..."
		Initialize-SPResourceSecurity
		# Install Services
		Write-Host -ForegroundColor White " - Installing Services..."
		Install-SPService
		If ($DoFullConfig)
		{
			# Install (all) features
			Write-Host -ForegroundColor White " - Installing Features..."
			$Features = Install-SPFeature -AllExistingFeatures -Force
		}
		# Detect if Central Admin URL already exists, i.e. if Central Admin web app is already provisioned on the local computer
		$CentralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.Port
		$CentralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Status -eq "Online"} | ? {$_.Url -like "*$($env:COMPUTERNAME):$CentralAdminPort*"}
		
		# Provision CentralAdmin if indicated in AutoSPInstallerInput.xml and the CA web app doesn't already exist
		If ((ShouldIProvision($xmlinput.Configuration.Farm.CentralAdmin) -eq $true) -and (!($CentralAdmin))) {CreateCentralAdmin $xmlinput}
		# Install application content if this is a new farm
		If ($DoFullConfig)
		{
			Write-Host -ForegroundColor White " - Installing Application Content..."
			Install-SPApplicationContent
		}
	}
	Catch	
	{
	    If ($err -like "*update conflict*")
		{
			Write-Warning " - A concurrency error occured, trying again."
			CreateCentralAdmin $xmlinput
		}
		Else 
		{
			Throw $_
		}
	}
	$SPRegVersion = (Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\').GetValue("Version")
	If (!($SPRegVersion))
	{
		Write-Host -ForegroundColor White " - Creating Version registry value (workaround for bug in PS-based install)"
		Write-Host -ForegroundColor White -NoNewline " - Getting version number... "
		$SPBuild = "$($(Get-SPFarm).BuildVersion.Major).0.0.$($(Get-SPFarm).BuildVersion.Build)"
		Write-Host -ForegroundColor White "$SPBuild"
		New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\' -Name Version -Value $SPBuild -ErrorAction SilentlyContinue | Out-Null
	}
    # Set an environment variable for the 14 hive (SharePoint root)
    $env:14="$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14"
    [Environment]::SetEnvironmentVariable("14", $env:14, "Machine")
    
	# Let's make sure the SharePoint Timer Service (SPTimerV4) is running
	# Per workaround in http://www.paulgrimley.com/2010/11/side-effects-of-attaching-additional.html
	If ((Get-Service SPTimerV4).Status -eq "Stopped")
	{
		Write-Host -ForegroundColor White " - Starting $((Get-Service SPTimerV4).DisplayName) Service..."
		Start-Service SPTimerV4
		If (!$?) {Throw " - Could not start Timer service!"}
	}
	Write-Host -ForegroundColor White " - Done initial farm/server config."
	WriteLine
}

#EndRegion

#Region Configure Language Packs
Function ConfigureLanguagePacks([xml]$xmlinput)
{	
    If (!($FarmPassphrase) -or ($FarmPassphrase -eq ""))
    {
    	$FarmPassphrase = GetFarmPassPhrase $xmlinput
	}
	# If the farm passphrase is a secure string (it would be if we prompted for input earlier), we need to convert it back to plain text for PSConfig.exe to understand it
	If ($FarmPassphrase.GetType().Name -eq "SecureString") {$FarmPassphrase = ConvertTo-PlainText $FarmPassphrase}
	$InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
	$LanguagePackInstalled = (Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\WSS\').GetValue("LanguagePackInstalled")
	# If there were language packs installed we need to run psconfig to configure them
	If (($LanguagePackInstalled -eq "1") -and ($InstalledOfficeServerLanguages.Count -gt 1))
	{
		WriteLine
		Write-Host -ForegroundColor White " - Configuring language packs..."
		# Let's sleep for a while to let the farm config catch up...
		Start-Sleep 20
        If ($AttemptNum -eq $null) {$AttemptNum += 1}
		# Run PSConfig.exe per http://technet.microsoft.com/en-us/library/cc262108.aspx
		Start-Process -FilePath $PSConfig -ArgumentList "-cmd upgrade -inplace v2v -passphrase `"$FarmPassphrase`" -wait -force" -NoNewWindow -Wait
        $PSConfigLogLocation = $((Get-SPDiagnosticConfig).LogLocation) -replace "%CommonProgramFiles%","$env:CommonProgramFiles"
   		$PSConfigLog = get-childitem $PSConfigLogLocation | ? {$_.Name -like "PSCDiagnostics*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
    	If ($PSConfigLog -eq $null) 
    	{
    		Throw " - Could not find PSConfig log file!"
    	}
    	Else 
    	{
    		# Get error(s) from log
    		$PSConfigLastError = $PSConfigLog | select-string -SimpleMatch -CaseSensitive -Pattern "ERR" | Select-Object -Last 1
    		If ($PSConfigLastError)
    		{
    			Write-Warning $PSConfigLastError.Line
    			While ($AttemptNum -le 4)
                {
                    Write-Host -ForegroundColor White " - An error occurred configuring language packs, trying again ($AttemptNum)..."
                    ConfigureLanguagePacks $xmlinput
                }
			    If ($AttemptNum -ge 5)
                {
    				Write-Host -ForegroundColor White " - After $AttemptNum attempts to configure language packs, trying GUI-based..."
                    Start-Process -FilePath $PSConfigUI -NoNewWindow -Wait
                    $PSConfigLastError = $null
                }
    		}
    	}
		WriteLine
	}
}
#EndRegion

#Region Add Managed Accounts
# ===================================================================================
# FUNC: AddManagedAccounts
# DESC: Adds existing accounts to SharePoint managed accounts and creates local profiles for each
# TODO: Make this more robust, prompt for blank values etc.
# ===================================================================================
Function AddManagedAccounts([xml]$xmlinput)
{
	WriteLine
	Write-Host -ForegroundColor White " - Adding Managed Accounts"
	If ($xmlinput.Configuration.Farm.ManagedAccounts)
	{
		# Get the members of the local Administrators group
        $builtinAdminGroup = Get-AdministratorsGroup
		$AdminGroup = ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group")
		# This syntax comes from Ying Li (http://myitforum.com/cs2/blogs/yli628/archive/2007/08/30/powershell-script-to-add-remove-a-domain-user-to-the-local-administrators-group-on-a-remote-machine.aspx)
		$LocalAdmins = $AdminGroup.psbase.invoke("Members") | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
		
		ForEach ($account in $xmlinput.Configuration.Farm.ManagedAccounts.ManagedAccount)
		{
            $username = $account.username
            $password = $account.Password
            $password = ConvertTo-SecureString "$password" -AsPlaintext -Force 
			# The following was suggested by Matthias Einig (http://www.codeplex.com/site/users/view/matein78)
			# And inspired by http://todd-carter.com/post/2010/05/03/Give-your-Application-Pool-Accounts-A-Profile.aspx & http://blog.brainlitter.com/archive/2010/06/08/how-to-revolve-event-id-1511-windows-cannot-find-the-local-profile-on-windows-server-2008.aspx
	        Try
			{
				Write-Host -ForegroundColor White " - Creating local profile for $username..." -NoNewline
				$credAccount = New-Object System.Management.Automation.PsCredential $username,$password
				$ManagedAccountDomain,$ManagedAccountUser = $username -Split "\\"
				# Add managed account to local admins (very) temporarily so it can log in and create its profile
	    		If (!($LocalAdmins -contains $ManagedAccountUser))
				{
					$builtinAdminGroup = Get-AdministratorsGroup
                    ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$ManagedAccountDomain/$ManagedAccountUser")
				}
				Else
				{
					$AlreadyAdmin = $true
				}
				# Spawn a command window using the managed account's credentials, create the profile, and exit immediately
				Start-Process -WorkingDirectory "$env:SYSTEMROOT\System32\" -FilePath "cmd.exe" -ArgumentList "/C" -LoadUserProfile -NoNewWindow -Credential $credAccount
				# Remove managed account from local admins unless it was already there
                $builtinAdminGroup = Get-AdministratorsGroup
	    		If (-not $AlreadyAdmin) {([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$ManagedAccountDomain/$ManagedAccountUser")}
				Write-Host -BackgroundColor Blue -ForegroundColor Black "Done."
			}
			Catch
			{
				$_
				Write-Host -ForegroundColor White "."
				Write-Warning " - Could not create local user profile for $username"
				Pause "continue"
				break
			}
            $ManagedAccount = Get-SPManagedAccount | Where-Object {$_.UserName -eq $username}
            If ($ManagedAccount -eq $NULL) 
            { 
            	Write-Host -ForegroundColor White " - Registering managed account $username..."
                If ($username -eq $null -or $password -eq $null) 
                {
                    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Account: "
                	$credAccount = $host.ui.PromptForCredential("Managed Account", "Enter Account Credentials:", "", "NetBiosUserName" )
                } 
                Else
                {
                    $credAccount = New-Object System.Management.Automation.PsCredential $username,$password
                }
            	New-SPManagedAccount -Credential $credAccount | Out-Null
				If (-not $?) { Throw " - Failed to create managed account" }
            }
            Else 
            {
                Write-Host -ForegroundColor White " - Managed account $username already exists."
            }
        }
	}
	Write-Host -ForegroundColor White " - Done Adding Managed Accounts"
	WriteLine
}
#EndRegion

#Region Return SP Service Account
Function Get-spserviceaccountxml([xml]$xmlinput)
{
    $spservice = $xmlinput.Configuration.Farm.ManagedAccounts.ManagedAccount | Where-Object { $_.CommonName -eq "spservice" }
    Return $spservice
}
#EndRegion

#Region Get or Create Hosted Services Application Pool
# ====================================================================================
# Func: Get-HostedServicesAppPool
# Desc: Creates and/or returns the Hosted Services Application Pool
# ====================================================================================
Function Get-HostedServicesAppPool ([xml]$xmlinput)
{
	$spservice = Get-spserviceaccountxml $xmlinput
	# Managed Account
   	$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
   	If ($ManagedAccountGen -eq $NULL) { Throw " - Managed Account $($spservice.username) not found" }
	# App Pool
   	$ApplicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
   	If ($ApplicationPool -eq $null)
	{
    	Write-Host -ForegroundColor White " - Creating SharePoint Hosted Services Application Pool..."
		$ApplicationPool = New-SPServiceApplicationPool -Name "SharePoint Hosted Services" -account $ManagedAccountGen
       	If (-not $?) { Throw "Failed to create the application pool" }
   	}
	Return $ApplicationPool
}
#EndRegion

#Region Create Basic Service Application
# ===================================================================================
# Func: CreateBasicServiceApplication
# Desc: Creates a basic service application
# ===================================================================================
Function CreateBasicServiceApplication()
{
    param
    (
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]
        [String]$ServiceConfig,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]
        [String]$ServiceInstanceType,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]
        [String]$ServiceName,
        [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()]
        [String]$ServiceProxyName,
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]
        [String]$ServiceGetCmdlet,
		[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()]
        [String]$ServiceProxyGetCmdlet,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]
        [String]$ServiceNewCmdlet,
        [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()]
        [String]$ServiceProxyNewCmdlet,
        [Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()]
		[String]$ServiceProxyNewParams
	)
	
	Try
	{
		$ApplicationPool = Get-HostedServicesAppPool $xmlinput
		Write-Host -ForegroundColor White " - Provisioning $($ServiceName)..."
	    # get the service instance
	    $ServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $ServiceInstanceType}
		$ServiceInstance = $ServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	    If (!$ServiceInstance) { Throw " - Failed to get service instance - check product version (Standard vs. Enterprise)" }
		# Start Service instance
	  	Write-Host -ForegroundColor White " - Checking $($ServiceInstance.TypeName) instance..."
	    If (($ServiceInstance.Status -eq "Disabled") -or ($ServiceInstance.Status -ne "Online"))
  		{  
            Write-Host -ForegroundColor White " - Starting $($ServiceInstance.TypeName) instance..."
			$ServiceInstance.Provision()
            If (-not $?) { Throw " - Failed to start $($ServiceInstance.TypeName) instance" }
            # Wait
  			Write-Host -ForegroundColor Blue " - Waiting for $($ServiceInstance.TypeName) instance..." -NoNewline
  			While ($ServiceInstance.Status -ne "Online") 
  			{
 				Write-Host -ForegroundColor Blue "." -NoNewline
  				Start-Sleep 1
   				$ServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $ServiceInstanceType}
				$ServiceInstance = $ServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
   			}
   				Write-Host -BackgroundColor Blue -ForegroundColor Black $($ServiceInstance.Status)
        }
		Else 
		{
   			Write-Host -ForegroundColor White " - $($ServiceInstance.TypeName) instance already started."
		}
		# Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
		If (!(Get-Command $ServiceGetCmdlet -ErrorAction SilentlyContinue))
		{
			Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
			Remove-PSSnapin Microsoft.SharePoint.PowerShell
			Load-SharePoint-Powershell
		}
		$GetServiceApplication = Invoke-Expression "$ServiceGetCmdlet | ? {`$_.Name -eq `"$ServiceName`"}"
		If ($GetServiceApplication -eq $null)
		{
			Write-Host -ForegroundColor White " - Creating $ServiceName..."
			# A bit kludgey to accomodate the new PerformancePoint cmdlet in Service Pack 1 (and still be able to use the CreateBasicServiceApplication function)
			If ((CheckForSP1) -and ($ServiceInstanceType -eq "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"))
			{
				$NewServiceApplication = Invoke-Expression "$ServiceNewCmdlet -Name `"$ServiceName`" -ApplicationPool `$ApplicationPool -DatabaseServer `$DBServer -DatabaseName `$PerformancePointDB"
			}
			Else # Just do the regular non-database-bound service app creation
			{
				$NewServiceApplication = Invoke-Expression "$ServiceNewCmdlet -Name `"$ServiceName`" -ApplicationPool `$ApplicationPool"
			}
			Write-Host -ForegroundColor White " - Provisioning $ServiceName Proxy..."
			# Because apparently the teams developing the cmdlets for the various service apps didn't communicate with each other, we have to account for the different ways each proxy is provisioned!
			Switch ($ServiceInstanceType)
			{
				"Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance" {& $ServiceProxyNewCmdlet -Name "$ServiceProxyName" -ServiceApplication $NewServiceApplication -AddToDefaultGroup | Out-Null}
				"Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance" {& $ServiceProxyNewCmdlet -Name "$ServiceProxyName" -ServiceApplication $NewServiceApplication.Name | Out-Null}
				"Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance" {& $ServiceProxyNewCmdlet -Name "$ServiceProxyName" -ServiceApplication $NewServiceApplication -Default | Out-Null}
				"Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
				"Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
				"Microsoft.Office.Word.Server.Service.WordServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
				Default {& $ServiceProxyNewCmdlet -Name "$ServiceProxyName" -ServiceApplication $NewServiceApplication | Out-Null}
			}
		}
		Else
		{
			Write-Host -ForegroundColor White " - $ServiceName already created."
		}
	}
	Catch
	{
		Write-Output $_
		Pause "exit"
	}
}
#EndRegion

#Region Sandboxed Code Service
# ===================================================================================
# Func: StartSandboxedCodeService
# Desc: Starts the SharePoint Foundation Sandboxed (User) Code Service
# ===================================================================================
Function StartSandboxedCodeService
{
    If (ShouldIProvision($xmlinput.Configuration.Farm.Services.SandboxedCodeService) -eq $true)
	{
		WriteLine
		Write-Host -ForegroundColor White " - Starting Sandboxed Code Service"
		$SandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
   	 	$SandboxedCodeService = $SandboxedCodeServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
		If ($SandboxedCodeService.Status -ne "Online")
   	 	{
    		Try
    		{
    			Write-Host -ForegroundColor White " - Starting Microsoft SharePoint Foundation Sandboxed Code Service..."
				UpdateProcessIdentity ($SandboxedCodeService)
    			$SandboxedCodeService.Provision()
    			If (-not $?) {Throw " - Failed to start Sandboxed Code Service"}
    		}
    		Catch 
        	{
        	    Throw " - An error occurred starting the Microsoft SharePoint Foundation Sandboxed Code Service"
        	}
    		#Wait
        	Write-Host -ForegroundColor Blue " - Waiting for Sandboxed Code service..." -NoNewline
        	While ($SandboxedCodeService.Status -ne "Online") 
        	{
				Write-Host -ForegroundColor Blue "." -NoNewline
				Start-Sleep 1
				$SandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
				$SandboxedCodeService = $SandboxedCodeServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
			}
			Write-Host -BackgroundColor Blue -ForegroundColor Black $($SandboxedCodeService.Status)
    	}
		Else 
		{
			Write-Host -ForegroundColor White " - Sandboxed Code Service already started."
		}
		WriteLine
	}
}
#EndRegion

#Region Create Metadata Service Application
# ===================================================================================
# Func: CreateMetadataServiceApp
# Desc: Managed Metadata Service Application
# ===================================================================================
Function CreateMetadataServiceApp([xml]$xmlinput)
{
    If (ShouldIProvision($xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp) -eq $true) 
    {
    	WriteLine
		Try
    	{
			$MetaDataDB = $DBPrefix+$xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Database.Name
            $DBServer = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
			$MetadataServiceName = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Name
			$MetadataServiceProxyName = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.ProxyName
			If($MetadataServiceName -eq $null) {$MetadataServiceName = "Metadata Service Application"}
			If($MetadataServiceProxyName -eq $null) {$MetadataServiceProxyName = $MetadataServiceName}
			Write-Host -ForegroundColor White " - Provisioning Managed Metadata Service Application"
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
			Write-Host -ForegroundColor White " - Starting Managed Metadata Service:"
            # Get the service instance
            $MetadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
            $MetadataServiceInstance = $MetadataServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
			If (-not $?) { Throw " - Failed to find Metadata service instance" }
            # Start Service instances
			If($MetadataServiceInstance.Status -eq "Disabled")
  			{ 
        	    Write-Host -ForegroundColor White " - Starting Metadata Service Instance..."
           	    $MetadataServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start Metadata service instance" }
				# Wait
    			Write-Host -ForegroundColor Blue " - Waiting for Metadata service..." -NoNewline
    			While ($MetadataServiceInstance.Status -ne "Online") 
    			{
    				Write-Host -ForegroundColor Blue "." -NoNewline
    				Start-Sleep 1
    				$MetadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
					$MetadataServiceInstance = $MetadataServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
    			}
    			Write-Host -BackgroundColor Blue -ForegroundColor Black ($MetadataServiceInstance.Status)
			}
			Else {Write-Host -ForegroundColor White " - Managed Metadata Service already started."}

     	    # Create a Metadata Service Application
          	If((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}) -eq $null)
    	  	{      
    			# Create Service App
       			Write-Host -ForegroundColor White " - Creating Metadata Service Application..."
                $MetaDataServiceApp = New-SPMetadataServiceApplication -Name $MetadataServiceName -ApplicationPool $ApplicationPool -DatabaseServer $DBServer -DatabaseName $MetaDataDB ##-AdministratorAccount $FarmAcct -FullAccessAccount $FarmAcct ## Removed due to apparent conflict with proxy switches below!
                If (-not $?) { Throw " - Failed to create Metadata Service Application" }
                # create proxy
    			Write-Host -ForegroundColor White " - Creating Metadata Service Application Proxy..."
                $MetaDataServiceAppProxy = New-SPMetadataServiceApplicationProxy -Name $MetadataServiceProxyName -ServiceApplication $MetaDataServiceApp -DefaultProxyGroup -ContentTypePushdownEnabled -DefaultKeywordTaxonomy -DefaultSiteCollectionTaxonomy
                If (-not $?) { Throw " - Failed to create Metadata Service Application Proxy" }
    			Write-Host -ForegroundColor White " - Granting rights to Metadata Service Application..."
    			# Get ID of "Managed Metadata Service"
    			$MetadataServiceAppToSecure = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
    			$MetadataServiceAppIDToSecure = $MetadataServiceAppToSecure.Id
    			# Create a variable that contains the list of administrators for the service application 
    			$MetadataServiceAppSecurity = Get-SPServiceApplicationSecurity $MetadataServiceAppIDToSecure
        		ForEach ($account in ($xmlinput.Configuration.Farm.ManagedAccounts.ManagedAccount))
        		{
        			# Create a variable that contains the claims principal for the service accounts
        			$AccountPrincipal = New-SPClaimsPrincipal -Identity $account.username -IdentityType WindowsSamAccountName			
        			# Give permissions to the claims principal you just created
        			Grant-SPObjectSecurity $MetadataServiceAppSecurity -Principal $AccountPrincipal -Rights "Full Access to Term Store"
                }    			
    			# Apply the changes to the Metadata Service application
    			Set-SPServiceApplicationSecurity $MetadataServiceAppIDToSecure -objectSecurity $MetadataServiceAppSecurity
    			Write-Host -ForegroundColor White " - Done creating Managed Metadata Service Application."
          	}
    	  	Else 
			{
				Write-Host -ForegroundColor White " - Managed Metadata Service Application already provisioned."
			}
    	}
    	Catch
    	{
    		Write-Output $_ 
			Throw " - Error provisioning the Managed Metadata Service Application"
    	}
    	WriteLine
    }
}
#EndRegion

#Region Assign Certificate
# ===================================================================================
# Func: AssignCert
# Desc: Create and assign SSL Certificate
# ===================================================================================
Function AssignCert([xml]$xmlinput)
{
	ImportWebAdministration
	Write-Host -ForegroundColor White " - Assigning certificate to site `"https://$SSLHostHeader`:$SSLPort`""
	# Check for sub-domains
 	$NumDomainLevels = ($env:USERDNSDOMAIN -split "\.").Count
	If ($NumDomainLevels -gt 2) # For example, corp.domain.net
	{
		# Get only the last two (domain + TLD)
		$TopDomain = $env:USERDNSDOMAIN.Split("\.")[($NumDomainLevels - 2)] + "." + $env:USERDNSDOMAIN.Split("\.")[($NumDomainLevels - 1)]
	}
	# If our SSL host header is a FQDN containing the local domain (or part of it, if the local domain is a subdomain), look for an existing wildcard cert
	If ($SSLHostHeader -like "*.$env:USERDNSDOMAIN")
	{
		Write-Host -ForegroundColor White " - Looking for existing `"*.$env:USERDNSDOMAIN`" wildcard certificate..."
		$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$env:USERDNSDOMAIN*"}
	}
	ElseIf (($NumDomainLevels -gt 2) -and ($SSLHostHeader -like "*.$TopDomain"))
	{
		Write-Host -ForegroundColor White " - Looking for existing `"*.$TopDomain`" wildcard certificate..."
		$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$TopDomain*"}
	}
	Else
	{
		Write-Host -ForegroundColor White " - Looking for existing `"$SSLHostHeader`" certificate..."
		$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
	}
	If (!$Cert)
	{
		Write-Host -ForegroundColor White " - None found."
		# Get the actual location of makecert.exe in case we installed SharePoint in the non-default location
		$SPInstallPath = (Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Office Server\14.0').GetValue("InstallPath")
		$MakeCert = "$SPInstallPath\Tools\makecert.exe"
		If (Test-Path "$MakeCert")
		{
			Write-Host -ForegroundColor White " - Creating new self-signed certificate..."
			If ($SSLHostHeader -like "*.$env:USERDNSDOMAIN")
			{
				# Create a new wildcard cert so we can potentially use it on other sites too
				Start-Process -NoNewWindow -Wait -FilePath "$MakeCert" -ArgumentList "-r -pe -n `"CN=*.$env:USERDNSDOMAIN`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
				$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$env:USERDNSDOMAIN*"}
			}
			ElseIf (($NumDomainLevels -gt 2) -and ($SSLHostHeader -like "*.$TopDomain"))
			{
				# Create a new wildcard cert so we can potentially use it on other sites too
				Start-Process -NoNewWindow -Wait -FilePath "$MakeCert" -ArgumentList "-r -pe -n `"CN=*.$TopDomain`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
				$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$TopDomain*"}
			}
			Else
			{
				# Just create a cert that matches the SSL host header
				Start-Process -NoNewWindow -Wait -FilePath "$MakeCert" -ArgumentList "-r -pe -n `"CN=$SSLHostHeader`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
				$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
			}
		}
		Else 
		{
			Write-Host -ForegroundColor White " - `"$MakeCert`" not found."
			Write-Host -ForegroundColor White " - Looking for any machine-named certificates we can use..."
			# Select the first certificate with the most recent valid date
			$Cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "*$env:COMPUTERNAME"} | Sort-Object NotBefore -Desc | Select-Object -First 1
			If (!$Cert)
			{
				Write-Host -ForegroundColor White " - None found, skipping certificate creation."
			}
		}
	}
	If ($Cert)
	{
		$CertSubject = $Cert.Subject
		Write-Host -ForegroundColor White " - Certificate `"$CertSubject`" found."
		# Fix up the cert subject name to a file-friendly format
		$CertSubjectName = $CertSubject.Split(",")[0] -replace "CN=","" -replace "\*","wildcard"
		# Export our certificate to a file, then import it to the Trusted Root Certification Authorites store so we don't get nasty browser warnings
		# This will actually only work if the Subject and the host part of the URL are the same
		# Borrowed from https://www.orcsweb.com/blog/james/powershell-ing-on-windows-server-how-to-import-certificates-using-powershell/
		Write-Host -ForegroundColor White " - Exporting `"$CertSubject`" to `"$CertSubjectName.cer`"..."
		$Cert.Export("Cert") | Set-Content "$env:TEMP\$CertSubjectName.cer" -Encoding byte
		$Pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		Write-Host -ForegroundColor White " - Importing `"$CertSubjectName.cer`" to Local Machine\Root..."
		$Pfx.Import("$env:TEMP\$CertSubjectName.cer")
		$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
		$Store.Open("MaxAllowed")
		$Store.Add($Pfx)
		$Store.Close()
		Write-Host -ForegroundColor White " - Assigning certificate `"$CertSubject`" to SSL-enabled site..."
		#Set-Location IIS:\SslBindings -ErrorAction Inquire
		$Cert | New-Item IIS:\SslBindings\0.0.0.0!$SSLPort -ErrorAction SilentlyContinue | Out-Null
		Set-ItemProperty IIS:\Sites\$SSLSiteName -Name bindings -Value @{protocol="https";bindingInformation="*:$($SSLPort):$($SSLHostHeader)"}
		## Set-WebBinding -Name $SSLSiteName -BindingInformation ":$($SSLPort):" -PropertyName Port -Value $SSLPort -PropertyName Protocol -Value https 
		Write-Host -ForegroundColor White " - Certificate has been assigned to site `"https://$SSLHostHeader`:$SSLPort`""
	}
	Else {Write-Host -ForegroundColor White " - No certificates were found, and none could be created."}
	$Cert = $null
}
#EndRegion

#Region Create Web Applications
# ===================================================================================
# Func: CreateWebApplications
# Desc: Create and  configure the required web applications
# ===================================================================================
Function CreateWebApplications([xml]$xmlinput)
{
	WriteLine
	If ($xmlinput.Configuration.WebApplications)
	{
		Write-Host -ForegroundColor White " - Creating web applications..."
		ForEach ($WebApp in $xmlinput.Configuration.WebApplications.WebApplication)
		{
			CreateWebApp $WebApp
			ConfigureObjectCache $WebApp
			ConfigureOnlineWebPartCatalog $WebApp
			Add-LocalIntranetURL $WebApp.URL
			WriteLine
		}
		If (($xmlinput.Configuration.WebApplications.AddURLsToHOSTS) -eq $true)
		{AddToHOSTS}
	}
	WriteLine
}
# ===================================================================================
# Func: CreateWebApp
# Desc: Create the web application
# ===================================================================================
Function CreateWebApp([System.Xml.XmlElement]$WebApp)
{
	$account = $WebApp.applicationPoolAccount
    $WebAppName = $WebApp.name
    $AppPool = $WebApp.applicationPool
    $database = $DBPrefix+$WebApp.databaseName
    $DBServer = $WebApp.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($DBServer))
    {
        $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
    }
    $url = $WebApp.url
    $port = $WebApp.port
	$useSSL = $false
	$InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    If ($url -like "https://*") {$UseSSL = $true; $HostHeader = $url -replace "https://",""}        
    Else {$HostHeader = $url -replace "http://",""}
    $GetSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $WebAppName}
	If ($GetSPWebApplication -eq $null)
   	{
        Write-Host -ForegroundColor White " - Creating Web App `"$WebAppName`""
   		If ($($WebApp.useClaims) -eq $true)
  		{
  			# Configure new web app to use Claims-based authentication
   			If ($($WebApp.useBasicAuthentication) -eq $true)
			{
				$AuthProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication -UseBasicAuthentication
			}
			Else
			{			
	   			$AuthProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication
			}  
   			New-SPWebApplication -Name $WebAppName -ApplicationPoolAccount $account -ApplicationPool $AppPool -DatabaseServer $DBServer -DatabaseName $database -HostHeader $HostHeader -Url $url -Port $port -SecureSocketsLayer:$UseSSL -AuthenticationProvider $AuthProvider | Out-Null
			If (-not $?) { Throw " - Failed to create web application" }

			If ((Gwmi Win32_OperatingSystem).Version -ne "6.1.7601") # If we aren't running SP1 for Win2008 R2, we may need the claims hotfix
			{
				[bool]$ClaimsHotfixRequired = $true
				Write-Host -ForegroundColor Yellow " - Web Applications using Claims authentication require an update"
				Write-Host -ForegroundColor Yellow " - Apply the http://go.microsoft.com/fwlink/?LinkID=184705 update after setup."
			}
   		}
   		Else
   		{
    		# Create the web app using Classic mode authentication
   			New-SPWebApplication -Name $WebAppName -ApplicationPoolAccount $account -ApplicationPool $AppPool -DatabaseServer $DBServer -DatabaseName $database -HostHeader $HostHeader -Url $url -Port $port -SecureSocketsLayer:$UseSSL | Out-Null
			If (-not $?) { Throw " - Failed to create web application" }
   		}
        SetupManagedPaths $WebApp
	}	
    Else {Write-Host -ForegroundColor White " - Web app `"$WebAppName`" already provisioned."}
	If ($UseSSL)
	{
		$SSLHostHeader = $HostHeader
		$SSLPort = $Port
		$SSLSiteName = $WebAppName
		AssignCert
	}

    # If we are provisioning any Office Web Apps, Visio, Excel, Access or PerformancePoint services, we need to grant the generic app pool account access to the newly-created content database
    # Per http://technet.microsoft.com/en-us/library/ff829837.aspx and http://autospinstaller.codeplex.com/workitem/16224 (thanks oceanfly!)
    If ((ShouldIProvision($xmlinput.Configuration.OfficeWebApps.ExcelService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.OfficeWebApps.PowerPointService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.OfficeWebApps.WordViewingService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.VisioService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.AccessService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -eq $true))
    {
        $spservice = Get-spserviceaccountxml $xmlinput
        Write-Host -ForegroundColor White " - Granting $($spservice.username) rights to `"$WebAppName`"..." -NoNewline
        $wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $WebAppName}
        $wa.GrantAccessToProcessIdentity("$($spservice.username)")
        Write-Host -ForegroundColor White "Done."
    }

    ForEach ($SiteCollection in $WebApp.SiteCollections.SiteCollection)
	{
		$SiteCollectionName = $SiteCollection.name
		$SiteURL = $SiteCollection.siteURL
		$template = $SiteCollection.template
		$OwnerAlias = $SiteCollection.Owner
		$LCID = $SiteCollection.LCID
		$SiteCollectionLocale = $SiteCollection.Locale
		$SiteCollectionTime24 = $SiteCollection.Time24
		$GetSPSiteCollection = Get-SPSite | Where-Object {$_.Url -eq $SiteURL}
		If (($GetSPSiteCollection -eq $null) -and ($SiteURL -ne $null))
		{
			Write-Host -ForegroundColor White " - Creating Site Collection `"$SiteURL`"..."
			# Verify that the Language we're trying to create the site in is currently installed on the server
			$Culture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($LCID)))
			$CultureDisplayName = $Culture.DisplayName
			If (!($InstalledOfficeServerLanguages | Where-Object {$_ -eq $Culture.Name}))
			{
		  		Write-Warning " - You must install the `"$Culture ($CultureDisplayName)`" Language Pack before you can create a site using LCID $LCID"
			}
			Else
			{
				# If a template has been pre-specified, use it when creating the Portal site collection; otherwise, leave it blank so we can select one when the portal first loads
				If (($Template -ne $null) -and ($Template -ne "")) {
					$Site = New-SPSite -Url $SiteURL -OwnerAlias $OwnerAlias -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $database -Description $SiteCollectionName -Name $SiteCollectionName -Language $LCID -Template $Template -ErrorAction Stop
				}
				Else 
				{
					$Site = New-SPSite -Url $SiteURL -OwnerAlias $OwnerAlias -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $database -Description $SiteCollectionName -Name $SiteCollectionName -Language $LCID  -ErrorAction Stop
				}

				# Add the Portal Site Connection to the web app, unless of course the current web app *is* the portal
				# Inspired by http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=264
				$PortalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
				$PortalSiteColl = $PortalWebApp.SiteCollections.SiteCollection | Select-Object -First 1
				If ($Site.URL -ne $PortalSiteColl.siteURL)
				{
					Write-Host -ForegroundColor White " - Setting the Portal Site Connection for `"$SiteCollectionName`"..."
					$Site.PortalName = $PortalSiteColl.Name
					$Site.PortalUrl = $PortalSiteColl.siteUrl
				}
				If ($SiteCollectionLocale) 
				{
					Write-Host -ForegroundColor White " - Updating the locale for `"$SiteCollectionName`" to `"$SiteCollectionLocale`"..."
					$Site.RootWeb.Locale = [System.Globalization.CultureInfo]::CreateSpecificCulture($SiteCollectionLocale) 
				}
				If ($SiteCollectionTime24) 
				{
					Write-Host -ForegroundColor White " - Updating 24 hour time format for `"$SiteCollectionName`" to `"$SiteCollectionTime24`"..."
					$Site.RootWeb.RegionalSettings.Time24 = $([System.Convert]::ToBoolean($SiteCollectionTime24))
				}
				$Site.RootWeb.Update()
			}
		}
		Else {Write-Host -ForegroundColor White " - Skipping creation of site `"$SiteCollectionName`" - already provisioned."}
		WriteLine
	}
}

# ===================================================================================
# Func: Set-WebAppUserPolicy
# AMW 1.7.2
# Desc: Set the web application user policy
# Refer to http://technet.microsoft.com/en-us/library/ff758656.aspx
# Updated based on Gary Lapointe example script to include Policy settings 18/10/2010
# ===================================================================================
Function Set-WebAppUserPolicy($wa, $userName, $displayName, $perm) 
{
    [Microsoft.SharePoint.Administration.SPPolicyCollection]$policies = $wa.Policies
    [Microsoft.SharePoint.Administration.SPPolicy]$policy = $policies.Add($userName, $displayName)
    [Microsoft.SharePoint.Administration.SPPolicyRole]$policyRole = $wa.PolicyRoles | where {$_.Name -eq $perm}
    If ($policyRole -ne $null) {
        $policy.PolicyRoleBindings.Add($policyRole)
    }
    $wa.Update()
}

# ===================================================================================
# Func: ConfigureObjectCache
# Desc: Applies the portal super accounts to the object cache for a web application
# ===================================================================================
Function ConfigureObjectCache([System.Xml.XmlElement]$WebApp)
{
	Try
	{
   		$url = $WebApp.Url + ":" + $WebApp.Port
		$wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $WebApp.Name}
		$SuperUserAcc = $xmlinput.Configuration.Farm.ObjectCacheAccounts.SuperUser
		$SuperReaderAcc = $xmlinput.Configuration.Farm.ObjectCacheAccounts.SuperReader
		# If the web app is using Claims auth, change the user accounts to the proper syntax
		If ($wa.UseClaimsAuthentication -eq $true) 
		{
			$SuperUserAcc = 'i:0#.w|' + $SuperUserAcc
			$SuperReaderAcc = 'i:0#.w|' + $SuperReaderAcc
		}
		Write-Host -ForegroundColor White " - Applying object cache accounts to `"$url`"..."
        $wa.Properties["portalsuperuseraccount"] = $SuperUserAcc
	    Set-WebAppUserPolicy $wa $SuperUserAcc "Super User (Object Cache)" "Full Control"
        $wa.Properties["portalsuperreaderaccount"] = $SuperReaderAcc
	    Set-WebAppUserPolicy $wa $SuperReaderAcc "Super Reader (Object Cache)" "Full Read"
        $wa.Update()        
    	Write-Host -ForegroundColor White " - Done applying object cache accounts to `"$url`""
	}
	Catch
	{
		$_
		Write-Warning " - An error occurred applying object cache to `"$url`""
		Pause "exit"
	}
}

# ===================================================================================
# Func: ConfigureOnlineWebPartCatalog
# Desc: Enables / Disables access to the online web parts catalog for each web application
# ===================================================================================
Function ConfigureOnlineWebPartCatalog([System.Xml.XmlElement]$WebApp)
{
	If ($webapp.GetAttribute("useOnlineWebPartCatalog") -ne "")
	{
		$url = $WebApp.Url + ":" + $WebApp.Port
		If ($url -like "*localhost*") {$url = $url -replace "localhost","$env:COMPUTERNAME"}
		Write-Host -ForegroundColor White " - Setting online webpart catalog access for `"$url`""
		
		$wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $WebApp.Name}
		If ($webapp.GetAttribute("useOnlineWebPartCatalog") -eq "True") 
		{
			$wa.AllowAccessToWebpartCatalog=$true
		}
		Else
		{			
			$wa.AllowAccessToWebpartCatalog=$false
		}
		$wa.Update()
	}
}

# ===================================================================================
# Func: SetupManagedPaths
# Desc: Sets up managed paths for a given web application
# ===================================================================================
Function SetupManagedPaths([System.Xml.XmlElement]$WebApp)
{
	$url = $WebApp.Url + ":" + $WebApp.Port
    If ($url -like "*localhost*") {$url = $url -replace "localhost","$env:COMPUTERNAME"}
	Write-Host -ForegroundColor White " - Setting up managed paths for `"$url`""

	If ($WebApp.ManagedPaths)
	{
	    ForEach ($managedPath in $WebApp.ManagedPaths.ManagedPath)
		{
            If ($managedPath.Delete -eq "true")
            {
                Write-Host -ForegroundColor White " - Deleting managed path `"$($managedPath.RelativeUrl)`" at `"$url`""            
                Remove-SPManagedPath -Identity $managedPath.RelativeUrl -WebApplication $url -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
            Else
            {
    			If ($managedPath.Explicit -eq "true")
    			{
    				Write-Host -ForegroundColor White " - Setting up explicit managed path `"$($managedPath.RelativeUrl)`" at `"$url`""
    			    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -WebApplication $url -Explicit -ErrorAction SilentlyContinue | Out-Null
    			}
    			Else
    			{
    				Write-Host -ForegroundColor White " - Setting up managed path `"$($managedPath.RelativeUrl)`" at `"$url`""
    			    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -WebApplication $url -ErrorAction SilentlyContinue | Out-Null
    			}
            }
		}
	}

	Write-Host -ForegroundColor White " - Done setting up managed paths at `"$url`""
}
#EndRegion

#Region Create User Profile Service Application
# ===================================================================================
# Func: CreateUserProfileServiceApplication
# Desc: Create the User Profile Service Application
# ===================================================================================
Function CreateUserProfileServiceApplication([xml]$xmlinput)
{
    WriteLine
	# Based on http://sharepoint.microsoft.com/blogs/zach/Lists/Posts/Post.aspx?ID=50
	Try
	{   
        $UserProfile = $xmlinput.Configuration.ServiceApps.UserProfileServiceApp
		$MySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.type -eq "MySiteHost"} 
		$MySiteName = $MySiteWebApp.name
		$MySiteURL = $MySiteWebApp.url
		$MySitePort = $MySiteWebApp.port
        $MySiteDBServer = $MySiteWebApp.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($DBServer))
        {
            $MySiteDBServer = $xmlinput.Configuration.Farm.Database.DBServer
        }
    	$MySiteDB = $DBPrefix+$MySiteWebApp.databaseName
		$MySiteAppPoolAcct = $MySiteWebApp.applicationPoolAccount
		$PortalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
		$PortalAppPoolAcct = $PortalWebApp.applicationPoolAccount
        $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
		$FarmAcctPWD = $xmlinput.Configuration.Farm.Account.Password
		$ContentAccessAcct = $xmlinput.Configuration.ServiceApps.EnterpriseSearchService.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount
		If (($FarmAcctPWD -ne "") -and ($FarmAcctPWD -ne $null)) {$FarmAcctPWD = (ConvertTo-SecureString $FarmAcctPWD -AsPlainText -force)}
		$MySiteTemplate = $MySiteWebApp.SiteCollections.SiteCollection.Template
		$MySiteLCID = $MySiteWebApp.SiteCollections.SiteCollection.LCID
		$UserProfileServiceName = $UserProfile.Name
		$UserProfileServiceProxyName = $UserProfile.ProxyName
		If($UserProfileServiceName -eq $null) {$UserProfileServiceName = "User Profile Service Application"}
		If($UserProfileServiceProxyName -eq $null) {$UserProfileServiceProxyName = $UserProfileServiceName}
		If (!$farmCredential) {[System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput}

        If (ShouldIProvision($UserProfile) -eq $true) 
        {        
          	Write-Host -ForegroundColor White " - Provisioning $($UserProfile.Name)"
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
            # get the service instance
            $ProfileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
			$ProfileServiceInstance = $ProfileServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find User Profile Service instance" }
            # Start Service instance
  			Write-Host -ForegroundColor White " - Starting User Profile Service instance..."
            If (($ProfileServiceInstance.Status -eq "Disabled") -or ($ProfileServiceInstance.Status -ne "Online"))
  			{  
                $ProfileServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start User Profile Service instance" }
                # Wait
  				Write-Host -ForegroundColor Blue " - Waiting for User Profile Service..." -NoNewline
  			    While ($ProfileServiceInstance.Status -ne "Online") 
  			    {
 					Write-Host -ForegroundColor Blue "." -NoNewline
  					Start-Sleep 1
   				    $ProfileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
					$ProfileServiceInstance = $ProfileServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
   			    }
   				Write-Host -BackgroundColor Blue -ForegroundColor Black $($ProfileServiceInstance.Status)
            }
          	# Create a Profile Service Application
          	If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileApplication"}) -eq $null)
    	  	{      
    			# Create MySites Web Application
    			$GetSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $MySiteName}
    			If ($GetSPWebApplication -eq $Null)
    			{
    			    Write-Host -ForegroundColor White " - Creating Web App `"$MySiteName`"..."
    				New-SPWebApplication -Name $MySiteName -ApplicationPoolAccount $MySiteAppPoolAcct -ApplicationPool $MySiteAppPool -DatabaseServer $MySiteDBServer -DatabaseName $MySiteDB -HostHeader $MySiteHostHeader -Url $MySiteURL -Port $MySitePort -SecureSocketsLayer:$MySiteUseSSL | Out-Null
    			}
    			Else
    			{
    				Write-Host -ForegroundColor White " - Web app `"$MySiteName`" already provisioned."
    			}
    			
                # Create MySites Site Collection
    			If ((Get-SPContentDatabase | Where-Object {$_.Name -eq $MySiteDB})-eq $null)
    			{
    				Write-Host -ForegroundColor White " - Creating My Sites content DB..."
    				$NewMySitesDB = New-SPContentDatabase -DatabaseServer $MySiteDBServer -Name $MySiteDB -WebApplication "$MySiteURL`:$MySitePort"
    				If (-not $?) { Throw " - Failed to create My Sites content DB" }
    			}
				If (!(Get-SPSite | Where-Object {(($_.Url -like "$MySiteURL*") -and ($_.Port -eq "$MySitePort"))}))
    			{
    				Write-Host -ForegroundColor White " - Creating My Sites site collection $MySiteURL`:$MySitePort..."
    				# Verify that the Language we're trying to create the site in is currently installed on the server
                    $MySiteCulture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($MySiteLCID))) 
    		        $MySiteCultureDisplayName = $MySiteCulture.DisplayName
					$InstalledOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\14.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
					If (!($InstalledOfficeServerLanguages | Where-Object {$_ -eq $MySiteCulture.Name}))
    				{
    		            Throw " - You must install the `"$MySiteCulture ($MySiteCultureDisplayName)`" Language Pack before you can create a site using LCID $MySiteLCID"
    	            }
    	            Else
    	            {
        				$NewMySitesCollection = New-SPSite -Url "$MySiteURL`:$MySitePort" -OwnerAlias $FarmAcct -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $MySiteDB -Description $MySiteName -Name $MySiteName -Template $MySiteTemplate -Language $MySiteLCID | Out-Null
    				    If (-not $?) {Throw " - Failed to create My Sites site collection"}
                        # Assign SSL certificate, if required
    			        If ($MySiteUseSSL)
    			        {
    				    	$SSLHostHeader = $MySiteHostHeader
    				    	$SSLPort = $MySitePort
							$SSLSiteName = $MySiteName
    				    	AssignCert
    			        }
                    }
    			}
    			# Create Service App
    			Write-Host -ForegroundColor White " - Creating $UserProfileServiceName..."
				CreateUPSAsAdmin $xmlinput
				Write-Host -ForegroundColor Blue " - Waiting for $UserProfileServiceName..." -NoNewline
				$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
    			While ($ProfileServiceApp.Status -ne "Online") 
    			{
					[int]$UPSWaitTime = 0
  					# Wait 2 minutes for either the UPS to be created, or the UAC prompt to time out
					While (($UPSWaitTime -lt 120) -and ($ProfileServiceApp.Status -ne "Online"))
					{
						Write-Host -ForegroundColor Blue "." -NoNewline
    					Start-Sleep 1
						$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
						[int]$UPSWaitTime += 1
					}
					# If it still isn't Online after 2 minutes, prompt to try again
					If (!($ProfileServiceApp))
					{
						Write-Host -ForegroundColor Blue "."
						Write-Warning " - Timed out waiting for service creation (maybe a UAC prompt?)"
						Write-Host "`a`a`a" # System beeps
                        Pause "try again"
                        CreateUPSAsAdmin $xmlinput
						Write-Host -ForegroundColor Blue " - Waiting for $UserProfileServiceName..." -NoNewline
						$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
					}
					Else {break}
    			}
    			Write-Host -BackgroundColor Blue -ForegroundColor Black $($ProfileServiceApp.Status)
				# Wait a few seconds for the CreateUPSAsAdmin function to complete
				Start-Sleep 30

				# Get our new Profile Service App
				$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
				If (!($ProfileServiceApp)) {Throw " - Could not get $UserProfileServiceName!";}
				
				# Create Proxy
    			Write-Host -ForegroundColor White " - Creating $UserProfileServiceName Proxy..."
                $ProfileServiceAppProxy  = New-SPProfileServiceApplicationProxy -Name "$UserProfileServiceProxyName" -ServiceApplication $ProfileServiceApp -DefaultProxyGroup
                If (-not $?) { Throw " - Failed to create $UserProfileServiceName Proxy" }
    			
    			Write-Host -ForegroundColor White " - Granting rights to $UserProfileServiceName..."
    			# Create a variable that contains the guid for the User Profile service for which you want to delegate permissions
				$ServiceAppIDToSecure = Get-SPServiceApplication $($ProfileServiceApp.Id)

    			# Create a variable that contains the list of administrators for the service application 
				$ProfileServiceAppSecurity = Get-SPServiceApplicationSecurity $ServiceAppIDToSecure -Admin
				# Create a variable that contains the permissions for the service application
				$ProfileServiceAppPermissions = Get-SPServiceApplicationSecurity $ServiceAppIDToSecure

    			# Create variables that contains the claims principals for current (Setup) user, MySite App Pool, Portal App Pool and Content Access accounts
				$CurrentUserAcctPrincipal = New-SPClaimsPrincipal -Identity $env:USERDOMAIN\$env:USERNAME -IdentityType WindowsSamAccountName
    			If ($MySiteAppPoolAcct) {$MySiteAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $MySiteAppPoolAcct -IdentityType WindowsSamAccountName}
				If ($PortalAppPoolAcct) {$PortalAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $PortalAppPoolAcct -IdentityType WindowsSamAccountName}
    			If ($ContentAccessAcct) {$ContentAccessAcctPrincipal = New-SPClaimsPrincipal -Identity $ContentAccessAcct -IdentityType WindowsSamAccountName}

    			# Give 'Full Control' permissions to the current (Setup) user, MySite App Pool and Portal App Pool account claims principals
				Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $CurrentUserAcctPrincipal -Rights "Full Control"
				Grant-SPObjectSecurity $ProfileServiceAppPermissions -Principal $CurrentUserAcctPrincipal -Rights "Full Control"
    			If ($MySiteAppPoolAcct) {Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $MySiteAppPoolAcctPrincipal -Rights "Full Control"}
				If ($PortalAppPoolAcct) {Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $PortalAppPoolAcctPrincipal -Rights "Full Control"}
				# Give 'Retrieve People Data for Search Crawlers' permissions to the Content Access claims principal
    			If ($ContentAccessAcct) {Grant-SPObjectSecurity $ProfileServiceAppSecurity -Principal $ContentAccessAcctPrincipal -Rights "Retrieve People Data for Search Crawlers"}

    			# Apply the changes to the User Profile service application
				Set-SPServiceApplicationSecurity $ServiceAppIDToSecure -objectSecurity $ProfileServiceAppSecurity -Admin
				Set-SPServiceApplicationSecurity $ServiceAppIDToSecure -objectSecurity $ProfileServiceAppPermissions
				
				If ($PortalAppPoolAcct)
				{
					# Grant the Portal App Pool account rights to the Profile and Social DBs
					$ProfileDB = $DBPrefix+$UserProfile.ProfileDB
					$SocialDB = $DBPrefix+$UserProfile.SocialDB
					Write-Host -ForegroundColor White " - Granting $PortalAppPoolAcct rights to $ProfileDB..."
					Get-SPDatabase | ? {$_.Name -eq $ProfileDB} | Add-SPShellAdmin -UserName $PortalAppPoolAcct
					Write-Host -ForegroundColor White " - Granting $PortalAppPoolAcct rights to $SocialDB..."
					Get-SPDatabase | ? {$_.Name -eq $SocialDB} | Add-SPShellAdmin -UserName $PortalAppPoolAcct
				}
				Write-Host -ForegroundColor White " - Enabling the Activity Feed Timer Job.."
				If ($ProfileServiceApp) {Get-SPTimerJob | ? {$_.TypeName -eq "Microsoft.Office.Server.ActivityFeed.ActivityFeedUPAJob"} | Enable-SPTimerJob}
				
    			Write-Host -ForegroundColor White " - Done creating $UserProfileServiceName."
          	}
    		# Start User Profile Synchronization Service
    		# Get User Profile Service
    		$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
    		If ($ProfileServiceApp -and ($UserProfile.StartProfileSync -eq $true))
    		{
				If ($UserProfile.EnableNetBIOSDomainNames -eq $true)
				{
					Write-Host -ForegroundColor White " - Enabling NetBIOS domain names for $UserProfileServiceName..."
					$ProfileServiceApp.NetBIOSDomainNamesEnabled = 1
					$ProfileServiceApp.Update()
				}
				
				# Get User Profile Synchronization Service
    			Write-Host -ForegroundColor White " - Checking User Profile Synchronization Service..." -NoNewline
    			$ProfileSyncServices = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"})
				$ProfileSyncService = $ProfileSyncServices | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
				# Attempt to start only if there are no online Profile Sync Service instances in the farm as we don't want to start multiple Sync instances (running against the same Profile Service at least)
				If (!($ProfileSyncServices | ? {$_.Status -eq "Online"}))
    			{
					# Inspired by http://technet.microsoft.com/en-us/library/ee721049.aspx
    				If (!($FarmAcct)) {$FarmAcct = (Get-SPFarm).DefaultServiceAccount}
    				If (!($FarmAcctPWD)) 
    				{
    					Write-Host -ForegroundColor White "`n"
    					$FarmAcctPWD = Read-Host -Prompt " - Please (re-)enter the Farm Account Password" -AsSecureString
    				}
    				Write-Host -ForegroundColor White "`n"
					# Check for an existing UPS credentials timer job (e.g. from a prior provisioning attempt), and delete it
    				$UPSCredentialsJob = Get-SPTimerJob | ? {$_.Name -eq "windows-service-credentials-FIMSynchronizationService"}
					If ($UPSCredentialsJob.Status -eq "Online")
					{
						Write-Host -ForegroundColor White " - Deleting existing sync credentials timer job..."
						$UPSCredentialsJob.Delete()
					}
    				UpdateProcessIdentity ($ProfileSyncService)
    				Write-Host -ForegroundColor White " - Waiting for User Profile Synchronization Service..." -NoNewline
					# Provision the User Profile Sync Service
					$ProfileServiceApp.SetSynchronizationMachine($env:COMPUTERNAME, $ProfileSyncService.Id, $FarmAcct, (ConvertTo-PlainText $FarmAcctPWD))
    				If (($ProfileSyncService.Status -ne "Provisioning") -and ($ProfileSyncService.Status -ne "Online")) {Write-Host -ForegroundColor Blue "`n - Waiting for User Profile Synchronization Service to start..." -NoNewline}
					# Monitor User Profile Sync service status
    				While ($ProfileSyncService.Status -ne "Online")
    				{
    					While ($ProfileSyncService.Status -ne "Provisioning")
    					{
    						Write-Host -ForegroundColor Blue "." -NoNewline
    						Start-Sleep 1
    						$ProfileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
    					}
    					If ($ProfileSyncService.Status -eq "Provisioning")
    					{
    						Write-Host -BackgroundColor Blue -ForegroundColor Black $($ProfileSyncService.Status)
                			Write-Host -ForegroundColor Blue " - Provisioning User Profile Sync Service, please wait..." -NoNewline
    					}
    					While($ProfileSyncService.Status -eq "Provisioning" -and $ProfileSyncService.Status -ne "Disabled")
    					{
    						Write-Host -ForegroundColor Blue "." -NoNewline
    						Start-Sleep 1
    						$ProfileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
    					}
    					If ($ProfileSyncService.Status -ne "Online")
    					{
    						Write-Host -ForegroundColor Red ".`a`a"
    						Write-Host -BackgroundColor Red -ForegroundColor Black " - User Profile Synchronization Service could not be started!"
    						break
    					}
    					Else
    					{
    						Write-Host -BackgroundColor Blue -ForegroundColor Black $($ProfileSyncService.Status)
    						# Need to recycle the Central Admin app pool before we can do anything with the User Profile Sync Service
    						Write-Host -ForegroundColor White " - Recycling Central Admin app pool..."
                            # From http://sharepoint.nauplius.net/2011/09/iisreset-not-required-after-starting.html
                            $appPool = gwmi -Namespace "root\MicrosoftIISv2" -class "IIsApplicationPool" | where {$_.Name -eq "W3SVC/APPPOOLS/SharePoint Central Administration v4"}
                            $appPool.Recycle()
							$NewlyProvisionedSync = $true
                        }
    				}
					#Add link to resources list
					AddResourcesLink "User Profile Administration" ("_layouts/ManageUserProfileServiceApplication.aspx?ApplicationID=" +  $ProfileServiceApp.Id)
					
					# Attempt to create a sync connection only on a successful, newly-provisioned User Profile Sync service
					# We don't have the ability to check for existing connections and we don't want to overwrite/duplicate any existing sync connections
				    # Note that this isn't really supported anyhow, and that only SharePoint 2010 Service Pack 1 and above includes the Add-SPProfileSyncConnection cmdlet
					If ((CheckForSP1) -and ($UserProfile.CreateDefaultSyncConnection -eq $true) -and ($NewlyProvisionedSync -eq $true))
					{
						Write-Host -ForegroundColor White " - Creating a default Profile Sync connection..."
						$ProfileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $UserProfileServiceName}
						# Thanks to Codeplex user Reshetkov for this ingenious one-liner to build the default domain OU
						$ConnectionSyncOU = "DC="+$env:USERDNSDOMAIN -replace "\.",",DC="
						$SyncConnectionDomain,$SyncConnectionAcct = ($UserProfile.SyncConnectionAccount) -split "\\"
						$AddProfileSyncCmd = @"
Add-PsSnapin Microsoft.SharePoint.PowerShell
Write-Host -ForegroundColor White " - Creating default Sync connection..."
`$SyncConnectionAcctPWD = (ConvertTo-SecureString -String "$($UserProfile.SyncConnectionAccountPassword)" -AsPlainText -Force)
Add-SPProfileSyncConnection -ProfileServiceApplication $($ProfileServiceApp.Id) -ConnectionForestName $env:USERDNSDOMAIN -ConnectionDomain $SyncConnectionDomain -ConnectionUserName "$SyncConnectionAcct" -ConnectionSynchronizationOU "$ConnectionSyncOU" -ConnectionPassword `$SyncConnectionAcctPWD
If (!`$?) 
{
Write-Host "Press any key to exit..."
`$null = `$host.UI.RawUI.ReadKey(`"NoEcho,IncludeKeyDown`")
}
Else {Write-Host -ForegroundColor White " - Done.";Start-Sleep 15}
"@
						$AddProfileScriptFile = "$env:TEMP\AutoSPInstaller-AddProfileSyncCmd.ps1"
						$AddProfileSyncCmd | Out-File $AddProfileScriptFile
						# Run our Add-SPProfileSyncConnection script as the Farm Account - doesn't seem to work otherwise
		                Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$AddProfileScriptFile'`" -Verb Runas" -Wait
						# Give Add-SPProfileSyncConnection time to complete before continuing
						Start-Sleep 120
						Remove-Item -LiteralPath $AddProfileScriptFile -Force -ErrorAction SilentlyContinue
					}
    			}
    			Else {Write-Host -ForegroundColor White "Already started."}
    		}
    		Else 
    		{
    			Write-Host -ForegroundColor White " - Could not get User Profile Service, or StartProfileSync is False."
    		}
        }
	}
	Catch
    {
        Write-Output $_
		Throw " - Error Provisioning the User Profile Service Application"
    }
	WriteLine
}
# ===================================================================================
# Func: CreateUPSAsAdmin
# Desc: Create the User Profile Service Application itself as the Farm Admin account, in a session with elevated privileges
# 		This incorporates the workaround by @harbars & @glapointe http://www.harbar.net/archive/2010/10/30/avoiding-the-default-schema-issue-when-creating-the-user-profile.aspx
# 		Modified to work within AutoSPInstaller (to pass our script variables to the Farm Account credential's Powershell session)
# ===================================================================================

Function CreateUPSAsAdmin([xml]$xmlinput)
{
	Try
	{
		$MySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.type -eq "MySiteHost"}
		$MySiteURL = $MySiteWebApp.url
		$MySitePort = $MySiteWebApp.port
        $FarmAcct = $xmlinput.Configuration.Farm.Account.Username
		$UserProfileServiceName = $UserProfile.Name
        $DBServer = $UserProfile.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($DBServer))
        {
            $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
        }
        # Set the ProfileDBServer, SyncDBServer and SocialDBServer to the same value ($DBServer). Maybe in the future we'll want to get more granular...?
        $ProfileDBServer = $DBServer
        $SyncDBServer = $DBServer
		$SocialDBServer = $DBServer
   		$ProfileDB = $DBPrefix+$UserProfile.Database.ProfileDB
		$SyncDB = $DBPrefix+$UserProfile.Database.SyncDB
        $SocialDB = $DBPrefix+$UserProfile.Database.SocialDB
       	$ApplicationPool = Get-HostedServicesAppPool $xmlinput
        If (!$farmCredential) {[System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput}
		$ScriptFile = "$env:TEMP\AutoSPInstaller-ScriptBlock.ps1"
		# Write the script block, with expanded variables to a temporary script file that the Farm Account can get at
		Write-Output "Write-Host -ForegroundColor White `"Creating $UserProfileServiceName as $FarmAcct...`"" | Out-File $ScriptFile -Width 400
		Write-Output "Add-PsSnapin Microsoft.SharePoint.PowerShell" | Out-File $ScriptFile -Width 400 -Append
		Write-Output "`$NewProfileServiceApp = New-SPProfileServiceApplication -Name `"$UserProfileServiceName`" -ApplicationPool `"$($ApplicationPool.Name)`" -ProfileDBServer $ProfileDBServer -ProfileDBName $ProfileDB -ProfileSyncDBServer $SyncDBServer -ProfileSyncDBName $SyncDB -SocialDBServer $SocialDBServer -SocialDBName $SocialDB -MySiteHostLocation `"$MySiteURL`:$MySitePort`"" | Out-File $ScriptFile -Width 400 -Append
		Write-Output "If (-not `$?) {Write-Error `" - Failed to create $UserProfileServiceName`"; Write-Host `"Press any key to exit...`"; `$null = `$host.UI.RawUI.ReadKey`(`"NoEcho,IncludeKeyDown`"`)}" | Out-File $ScriptFile -Width 400 -Append
		# Grant the current install account rights to the newly-created Profile DB - needed since it's going to be running PowerShell commands against it
		Write-Output "`$ProfileDBId = Get-SPDatabase | ? {`$_.Name -eq `"$ProfileDB`"}" | Out-File $ScriptFile -Width 400 -Append
		Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$ProfileDBId" | Out-File $ScriptFile -Width 400 -Append
		# Grant the current install account rights to the newly-created Social DB as well
		Write-Output "`$SocialDBId = Get-SPDatabase | ? {`$_.Name -eq `"$SocialDB`"}" | Out-File $ScriptFile -Width 400 -Append
		Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$SocialDBId" | Out-File $ScriptFile -Width 400 -Append
		If (Confirm-LocalSession) # Create the UPA as usual if this isn't a remote session
        {
            # Start a process under the Farm Account's credentials, then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$ScriptFile'`" -Verb Runas" -Wait
        }
        Else # Do some fancy stuff to get this to work over a remote session
        {
            Write-Host -ForegroundColor White " - Enabling remoting to $env:COMPUTERNAME..."
            Enable-WSManCredSSP -Role Client -Force -DelegateComputer $env:COMPUTERNAME | Out-Null # Yes that's right, we're going to "remote" into the local computer...
            Start-Sleep 10
            Write-Host -ForegroundColor White " - Creating temporary `"remote`" session to $env:COMPUTERNAME..."
            $UPSession = New-PSSession -Name "UPS-Session" -Authentication Credssp -Credential $farmCredential -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue
            If (!$UPSession) 
            {
                # Try again
                Write-Warning " - Couldn't create remote session to $env:COMPUTERNAME; trying again..."
                CreateUPSAsAdmin $xmlinput
            }
            # Pass the value of $ScriptFile to the new session
            Invoke-Command -ScriptBlock {param ($Value) Set-Variable -Name ScriptFile -Value $Value} -ArgumentList $ScriptFile -Session $UPSession
            Write-Host -ForegroundColor White " - Creating $UserProfileServiceName under `"remote`" session..."
            # Start a (local) process (on our "remote" session), then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Invoke-Command -ScriptBlock {Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList $ScriptFile -Verb Runas} -Session $UPSession
        }
	}
	Catch
	{
		Write-Output $_
		Pause "exit"
	}
	finally
	{
		# Delete the temporary script file if we were successful in creating the UPA
		$ProfileServiceApp = Get-SPServiceApplication | ? {$_.DisplayName -eq $UserProfileServiceName}
		If ($ProfileServiceApp) {Remove-Item -LiteralPath $ScriptFile -Force}
	}
}
#EndRegion

#Region Create State Service Application
Function CreateStateServiceApp([xml]$xmlinput)
{
    $StateService = $xmlinput.Configuration.ServiceApps.StateService
	If (ShouldIProvision($StateService) -eq $true) 
	{
		WriteLine
		Try
		{
	        $DBServer = $StateService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
			$StateServiceDB = $DBPrefix+$StateService.Database.Name
			$StateServiceName = $StateService.Name
			$StateServiceProxyName = $StateService.ProxyName
			If ($StateServiceName -eq $null) {$StateServiceName = "State Service Application"}
			If ($StateServiceProxyName -eq $null) {$StateServiceProxyName = $StateServiceName}
			$GetSPStateServiceApplication = Get-SPStateServiceApplication
			If ($GetSPStateServiceApplication -eq $Null)
			{
				Write-Host -ForegroundColor White " - Provisioning State Service Application..."
				New-SPStateServiceDatabase -DatabaseServer $DBServer -Name $StateServiceDB | Out-Null
				New-SPStateServiceApplication -Name $StateServiceName -Database $StateServiceDB | Out-Null
				Get-SPStateServiceDatabase | Initialize-SPStateServiceDatabase | Out-Null
				Write-Host -ForegroundColor White " - Creating State Service Application Proxy..."
				Get-SPStateServiceApplication | New-SPStateServiceApplicationProxy -Name $StateServiceProxyName -DefaultProxyGroup | Out-Null
				Write-Host -ForegroundColor White " - Done creating State Service Application."
			}
			Else {Write-Host -ForegroundColor White " - State Service Application already provisioned."}
		}
		Catch
		{
			Write-Output $_
			Throw " - Error provisioning the state service application"
		}
		WriteLine
	}
}
#EndRegion

#Region Create SP Usage Application
# ===================================================================================
# Func: CreateSPUsageApp
# Desc: Creates the Usage and Health Data Collection service application
# ===================================================================================
Function CreateSPUsageApp([xml]$xmlinput)
{
    If (ShouldIProvision($xmlinput.Configuration.ServiceApps.SPUsageService) -eq $true) 
	{
		WriteLine
		Try
		{
	        $DBServer = $xmlinput.Configuration.ServiceApps.SPUsageService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
			$SPUsageApplicationName = $xmlinput.Configuration.ServiceApps.SPUsageService.Name
			$SPUsageDB = $DBPrefix+$xmlinput.Configuration.ServiceApps.SPUsageService.Database.Name
			$GetSPUsageApplication = Get-SPUsageApplication
			If ($GetSPUsageApplication -eq $Null)
			{
				Write-Host -ForegroundColor White " - Provisioning SP Usage Application..."
				New-SPUsageApplication -Name $SPUsageApplicationName -DatabaseServer $DBServer -DatabaseName $SPUsageDB | Out-Null
				# Need this to resolve a known issue with the Usage Application Proxy not automatically starting/provisioning
				# Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 ! 
				Write-Host -ForegroundColor White " - Fixing Usage and Health Data Collection Proxy..."
				$SPUsageApplicationProxy = Get-SPServiceApplicationProxy | where {$_.DisplayName -eq $SPUsageApplicationName}
				$SPUsageApplicationProxy.Provision()
				# End Usage Proxy Fix
				Write-Host -ForegroundColor White " - Enabling usage processing timer job..."
                                $UsageProcessingJob = Get-SPTimerJob | ? {$_.TypeName -eq "Microsoft.SharePoint.Administration.SPUsageProcessingJobDefinition"}
                                $UsageProcessingJob.IsDisabled = $False
                                $UsageProcessingJob.Update()                
				Write-Host -ForegroundColor White " - Done provisioning SP Usage Application."
			}
			Else {Write-Host -ForegroundColor White " - SP Usage Application already provisioned."}
		}
		Catch
		{
			Write-Output $_
			Throw " - Error provisioning the SP Usage Application"
		}
		WriteLine
	}
}
#EndRegion

#Region Configure Logging

# ===================================================================================
# Func: ConfigureIISLogging
# Desc: Configures IIS Logging for the local server
# ===================================================================================
Function ConfigureIISLogging([xml]$xmlinput)
{
    WriteLine
	$IISLogConfig = $xmlinput.Configuration.Farm.Logging.IISLogs
	Write-Host -ForegroundColor White " - Configuring IIS logging..."
	If (!([string]::IsNullOrEmpty($IISLogConfig.Path)))
	{
		$IISLogDir = $IISLogConfig.Path
		EnsureFolder $IISLogDir
		ImportWebAdministration
		$OldIISLogDir = Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory.Value
		$OldIISLogDir = $OldIISLogDir -replace ("%SystemDrive%","$env:SystemDrive")
		If ($IISLogDir -ne $OldIISLogDir) # Only change the global IIS logging location if the desired location is different than the current
		{
			Write-Host -ForegroundColor White " - Setting the global IIS logging location..."
			# The line below is from http://stackoverflow.com/questions/4626791/powershell-command-to-set-iis-logging-settings
			Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory -value $IISLogDir
			If (Test-Path -Path $OldIISLogDir)
			{
				Write-Host -ForegroundColor White " - Moving any contents in old location $OldIISLogDir to $IISLogDir..."
				ForEach ($Item in $(Get-ChildItem $OldIISLogDir)) 
				{
					Move-Item -Path $OldIISLogDir\$Item -Destination $IISLogDir -Force -ErrorAction SilentlyContinue
				}
			}
		}
	}
	Else # Assume default value if none was specified in the XML input file
	{
		$IISLogDir = "$env:SystemDrive\Inetpub\logs" # We omit the trailing \LogFiles so we can compress the entire \logs\ folder including Failed Requests etc.
	}
	# Finally, enable NTFS compression on the IIS log location to save disk space
	If ($IISLogConfig.Compress -eq $true)
	{
		CompressFolder $IISLogDir
	}
    WriteLine
}

# ===================================================================================
# Func: ConfigureDiagnosticLogging
# Desc: Configures Diagnostic (ULS) Logging for the farm
# From: Originally suggested by Codeplex user leowu70: http://autospinstaller.codeplex.com/discussions/254499
# 	    And Codeplex user timiun: http://autospinstaller.codeplex.com/discussions/261598
# ===================================================================================
Function ConfigureDiagnosticLogging([xml]$xmlinput)
{
    WriteLine
	$ULSLogConfig = $xmlinput.Configuration.Farm.Logging.ULSLogs
	$ULSLogDir = $ULSLogConfig.LogLocation
	$ULSLogDiskSpace = $ULSLogConfig.LogDiskSpaceUsageGB
	$ULSLogRetention = $ULSLogConfig.DaysToKeepLogs
	$ULSLogCutInterval = $ULSLogConfig.LogCutInterval
	Write-Host -ForegroundColor White " - Configuring SharePoint diagnostic (ULS) logging..."	
	If (!([string]::IsNullOrEmpty($ULSLogDir)))
	{
		$DoConfig = $true
		EnsureFolder $ULSLogDir
		$OldULSLogDir = $(Get-SPDiagnosticConfig).LogLocation
		$OldULSLogDir = $OldULSLogDir -replace ("%CommonProgramFiles%","$env:CommonProgramFiles")
	}
	Else # Assume default value if none was specified in the XML input file
	{
		$ULSLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\LOGS"
	}
	If (!([string]::IsNullOrEmpty($ULSLogDiskSpace)))
	{
		$DoConfig = $true
		$ULSLogMaxDiskSpaceUsageEnabled = $true
	}
	Else # Assume default values if none were specified in the XML input file
	{
		$ULSLogDiskSpace = 1000
		$ULSLogMaxDiskSpaceUsageEnabled = $false
	}
	If (!([string]::IsNullOrEmpty($ULSLogRetention)))
	{$DoConfig = $true}
	Else # Assume default value if none was specified in the XML input file
	{
		$ULSLogRetention = 14
	}
	If (!([string]::IsNullOrEmpty($ULSLogCutInterval)))
	{$DoConfig = $true}
	Else # Assume default value if none was specified in the XML input file
	{
		$ULSLogCutInterval = 30
	}
	# Only modify the Diagnostic Config if we have specified at least one value in the XML input file
	If ($DoConfig)
	{
		Write-Host -ForegroundColor White " - Setting SharePoint diagnostic (ULS) logging options:"
		Write-Host -ForegroundColor White "  - DaysToKeepLogs: $ULSLogRetention" 
		Write-Host -ForegroundColor White "  - LogMaxDiskSpaceUsageEnabled: $ULSLogMaxDiskSpaceUsageEnabled"
		Write-Host -ForegroundColor White "  - LogDiskSpaceUsageGB: $ULSLogDiskSpace"
		Write-Host -ForegroundColor White "  - LogLocation: $ULSLogDir"
		Write-Host -ForegroundColor White "  - LogCutInterval: $ULSLogCutInterval"
		Set-SPDiagnosticConfig -DaysToKeepLogs $ULSLogRetention -LogMaxDiskSpaceUsageEnabled:$ULSLogMaxDiskSpaceUsageEnabled -LogDiskSpaceUsageGB $ULSLogDiskSpace -LogLocation $ULSLogDir -LogCutInterval $ULSLogCutInterval
		If ($ULSLogDir -ne $OldULSLogDir)
		{
			Write-Host -ForegroundColor White " - Moving any contents in old location $OldULSLogDir to $ULSLogDir..."
			ForEach ($Item in $(Get-ChildItem $OldULSLogDir) | Where-Object {$_.Name -like "*.log"}) 
			{
				Move-Item -Path $OldULSLogDir\$Item -Destination $ULSLogDir -Force -ErrorAction SilentlyContinue
			}
		}
	}
	# Finally, enable NTFS compression on the ULS log location to save disk space
	If ($ULSLogConfig.Compress -eq $true)
	{
		CompressFolder $ULSLogDir
	}
    WriteLine
}

# ===================================================================================
# Func: ConfigureUsageLogging
# Desc: Configures Usage Logging for the farm
# From: Submitted by Codeplex user deedubya (http://www.codeplex.com/site/users/view/deedubya); additional tweaks by @brianlala
# ===================================================================================
Function ConfigureUsageLogging([xml]$xmlinput)
{
    WriteLine
	If (Get-SPUsageService)
	{
		$UsageLogConfig = $xmlinput.Configuration.Farm.Logging.UsageLogs
		$UsageLogDir = $UsageLogConfig.UsageLogDir
		$UsageLogMaxSpaceGB = $UsageLogConfig.UsageLogMaxSpaceGB
		$UsageLogCutTime = $UsageLogConfig.UsageLogCutTime
		Write-Host -ForegroundColor White " - Configuring Usage Logging..."
        # Syntax for command: Set-SPUsageService [-LoggingEnabled {1 | 0}] [-UsageLogLocation <Path>] [-UsageLogMaxSpaceGB <1-20>] [-Verbose]
        # These are a per-farm settings, not per WSS Usage service application, as there can only be one per farm.
        Try
        {
	        If (!([string]::IsNullOrEmpty($UsageLogDir)))
			{
				EnsureFolder $UsageLogDir
				$OldUsageLogDir = $(Get-SPUsageService).UsageLogDir
				$OldUsageLogDir = $OldUsageLogDir -replace ("%CommonProgramFiles%","$env:CommonProgramFiles")
			}
			Else # Assume default value if none was specified in the XML input file
			{
				$UsageLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\LOGS"
			}
			# UsageLogMaxSpaceGB must be between 1 and 20.
	        If (($UsageLogMaxSpaceGB -lt 1) -or ([string]::IsNullOrEmpty($UsageLogMaxSpaceGB))) {$UsageLogMaxSpaceGB = 5} # Default value
	        If ($UsageLogMaxSpaceGB -gt 20) {$UsageLogMaxSpaceGB = 20} # Maximum value
	        # UsageLogCutTime must be between 1 and 1440
	        If (($UsageLogCutTime -lt 1) -or ([string]::IsNullOrEmpty($UsageLogCutTime))) {$UsageLogCutTime = 30} # Default value
	        If ($UsageLogCutTime -gt 1440) {$UsageLogCutTime = 1440} # Maximum value
	        # Set-SPUsageService's LoggingEnabled is 0 for disabled, and 1 for enabled
	        $LoggingEnabled = 1
	        Set-SPUsageService -LoggingEnabled $LoggingEnabled -UsageLogLocation "$UsageLogDir" -UsageLogMaxSpaceGB $UsageLogMaxSpaceGB -UsageLogCutTime $UsageLogCutTime | Out-Null
			If ($UsageLogDir -ne $OldUsageLogDir)
			{
				Write-Host -ForegroundColor White " - Moving any contents in old location $OldUsageLogDir to $UsageLogDir..."
				ForEach ($Item in $(Get-ChildItem $OldUsageLogDir) | Where-Object {$_.Name -like "*.usage"}) 
				{
					Move-Item -Path $OldUsageLogDir\$Item -Destination $UsageLogDir -Force -ErrorAction SilentlyContinue
				}
			}			
			# Finally, enable NTFS compression on the usage log location to save disk space
			If ($UsageLogConfig.Compress -eq $true)
			{
				CompressFolder $UsageLogDir
			}
        }
        Catch
        {
           	Write-Output $_
			Throw " - Error configuring usage logging"
        }
		Write-Host -ForegroundColor White " - Done configuring usage logging."
	}
	Else 
	{
		Write-Host -ForegroundColor White " - No usage service; skipping usage logging config."
	}
    WriteLine
}

#EndRegion

#Region Create Web Analytics Service Application
# Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 !

Function CreateWebAnalyticsApp([xml]$xmlinput)
{
	If (ShouldIProvision($xmlinput.Configuration.ServiceApps.WebAnalyticsService) -eq $true) 
	{
		WriteLine
		Try
		{
	        $DBServer = $xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
			$WebAnalyticsReportingDB = $DBPrefix+$xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.ReportingDB
			$WebAnalyticsStagingDB = $DBPrefix+$xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.StagingDB
			$WebAnalyticsServiceName = $xmlinput.Configuration.ServiceApps.WebAnalyticsService.Name
			$GetWebAnalyticsServiceApplication = Get-SPWebAnalyticsServiceApplication $WebAnalyticsServiceName -ea SilentlyContinue
			Write-Host -ForegroundColor White " - Provisioning $WebAnalyticsServiceName..."
	    	# Start Analytics service instances
			Write-Host -ForegroundColor White " - Checking Analytics Service instances..."
            $AnalyticsWebServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsWebServiceInstance"}
            $AnalyticsWebServiceInstance = $AnalyticsWebServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
			If (-not $?) { Throw " - Failed to find Analytics Web Service instance" }
			Write-Host -ForegroundColor White " - Starting local Analytics Web Service instance..."
	    	$AnalyticsWebServiceInstance.Provision()
			$AnalyticsDataProcessingInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsServiceInstance"}
			$AnalyticsDataProcessingInstance = $AnalyticsDataProcessingInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
			If (-not $?) { Throw " - Failed to find Analytics Data Processing Service instance" }
			UpdateProcessIdentity ($AnalyticsDataProcessingInstance)
			Write-Host -ForegroundColor White " - Starting local Analytics Data Processing Service instance..."
			$AnalyticsDataProcessingInstance.Provision()
			If ($GetWebAnalyticsServiceApplication -eq $null)
			{
				$StagerSubscription = "<StagingDatabases><StagingDatabase ServerName='$DBServer' DatabaseName='$WebAnalyticsStagingDB'/></StagingDatabases>"
				$WarehouseSubscription = "<ReportingDatabases><ReportingDatabase ServerName='$DBServer' DatabaseName='$WebAnalyticsReportingDB'/></ReportingDatabases>" 
				Write-Host -ForegroundColor White " - Creating $WebAnalyticsServiceName..."
		    	$ServiceApplication = New-SPWebAnalyticsServiceApplication -Name $WebAnalyticsServiceName -ReportingDataRetention 20 -SamplingRate 100 -ListOfReportingDatabases $WarehouseSubscription -ListOfStagingDatabases $StagerSubscription -ApplicationPool $ApplicationPool 
		    	# Create Web Analytics Service Application Proxy
				Write-Host -ForegroundColor White " - Creating $WebAnalyticsServiceName Proxy..."
				$NewWebAnalyticsServiceApplicationProxy = New-SPWebAnalyticsServiceApplicationProxy  -Name $WebAnalyticsServiceName -ServiceApplication $ServiceApplication.Name
			}
			Else {Write-Host -ForegroundColor White " - Web Analytics Service Application already provisioned."}
		}
		Catch
		{
			Write-Output $_
			Throw " - Error Provisioning Web Analytics Service Application"
		}
		WriteLine
	}
}
#EndRegion

#Region Create Secure Store Service Application
Function CreateSecureStoreServiceApp
{
    If (ShouldIProvision($xmlinput.Configuration.ServiceApps.SecureStoreService) -eq $true) 
	{
		WriteLine
		Try
		{
		    If (!($FarmPassphrase) -or ($FarmPassphrase -eq ""))
		    {
    			$FarmPassphrase = GetFarmPassPhrase $xmlinput
			}
			$SecureStoreServiceAppName = $xmlinput.Configuration.ServiceApps.SecureStoreService.Name
			$SecureStoreServiceAppProxyName = $xmlinput.Configuration.ServiceApps.SecureStoreService.ProxyName
			If ($SecureStoreServiceAppName -eq $null) {$SecureStoreServiceAppName = "State Service Application"}
			If ($SecureStoreServiceAppProxyName -eq $null) {$SecureStoreServiceAppProxyName = $SecureStoreServiceAppName}
	        $DBServer = $xmlinput.Configuration.ServiceApps.SecureStoreService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
			$SecureStoreDB = $DBPrefix+$xmlinput.Configuration.ServiceApps.SecureStoreService.Database.Name
	        Write-Host -ForegroundColor White " - Provisioning Secure Store Service Application..."
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
			# Get the service instance
           	$SecureStoreServiceInstances = Get-SPServiceInstance | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
			$SecureStoreServiceInstance = $SecureStoreServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
           	If (-not $?) { Throw " - Failed to find Secure Store service instance" }
			# Start Service instance
        	If ($SecureStoreServiceInstance.Status -eq "Disabled")
			{ 
                Write-Host -ForegroundColor White " - Starting Secure Store Service Instance..."
            	$SecureStoreServiceInstance.Provision()
            	If (-not $?) { Throw " - Failed to start Secure Store service instance" }
            	# Wait
		    	Write-Host -ForegroundColor Blue " - Waiting for Secure Store service..." -NoNewline
				While ($SecureStoreServiceInstance.Status -ne "Online") 
		    	{
					Write-Host -ForegroundColor Blue "." -NoNewline
					Start-Sleep 1
			    	$SecureStoreServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance"}
					$SecureStoreServiceInstance = $SecureStoreServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
		    	}
				Write-Host -BackgroundColor Blue -ForegroundColor Black $($SecureStoreServiceInstance.Status)
        	}
			# Create Service Application
			$GetSPSecureStoreServiceApplication = Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])}
			If ($GetSPSecureStoreServiceApplication -eq $Null)
			{
				Write-Host -ForegroundColor White " - Creating Secure Store Service Application..."
				New-SPSecureStoreServiceApplication -Name $SecureStoreServiceAppName -PartitionMode:$false -Sharing:$false -DatabaseServer $DBServer -DatabaseName $SecureStoreDB -ApplicationPool $($ApplicationPool.Name) -AuditingEnabled:$true -AuditLogMaxSize 30 | Out-Null
				Write-Host -ForegroundColor White " - Creating Secure Store Service Application Proxy..."
				Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])} | New-SPSecureStoreServiceApplicationProxy -Name $SecureStoreServiceAppProxyName -DefaultProxyGroup | Out-Null
				Write-Host -ForegroundColor White " - Done creating Secure Store Service Application."
			}
			Else {Write-Host -ForegroundColor White " - Secure Store Service Application already provisioned."}
			
			$secureStore = Get-SPServiceApplicationProxy | Where {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplicationProxy])}
			Start-Sleep 5
			Write-Host -ForegroundColor White " - Creating the Master Key..."
 			Update-SPSecureStoreMasterKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase"
			Start-Sleep 5
			Write-Host -ForegroundColor White " - Creating the Application Key..."
			Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase" -ErrorAction SilentlyContinue
			Start-Sleep 5
			If (!$?)
			{
				# Try again...
				Write-Host -ForegroundColor White " - Creating the Application Key (2nd attempt)..."
				Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$FarmPassPhrase"
			}
		}
		Catch
		{
			Write-Output $_
			Throw " - Error provisioning secure store application"
		}
		Write-Host -ForegroundColor White " - Done creating/configuring Secure Store Service Application."
		WriteLine
	}
}
#EndRegion

#Region Start Search Query and Site Settings Service
Function StartSearchQueryAndSiteSettingsService
{
	If (ShouldIProvision($xmlinput.Configuration.Farm.Services.SearchQueryAndSiteSettingsService) -eq $true)
	{
		WriteLine
		Try
		{
			# Get the service instance
		    $SearchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
			$SearchQueryAndSiteSettingsService = $SearchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
		    If (-not $?) { Throw " - Failed to find Search Query and Site Settings service instance" }
		    # Start Service instance
   		 	Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
			If($SearchQueryAndSiteSettingsService.Status -eq "Disabled")
			{ 
			    $SearchQueryAndSiteSettingsService.Provision()
        		If (-not $?) { Throw " - Failed to start Search Query and Site Settings service instance" }
        		# Wait
    			Write-Host -ForegroundColor Blue " - Waiting for Search Query and Site Settings service..." -NoNewline
				While ($SearchQueryAndSiteSettingsService.Status -ne "Online") 
	    		{
					Write-Host -ForegroundColor Blue "." -NoNewline
		  			Start-Sleep 1
				    $SearchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
		  			$SearchQueryAndSiteSettingsService = $SearchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	    		}
				Write-Host -BackgroundColor Blue -ForegroundColor Black $($SearchQueryAndSiteSettingsService.Status)
    		}
    		Else {Write-Host -ForegroundColor White " - Search Query and Site Settings Service already started."}
		}
		Catch
		{
			Write-Output $_ 
			Throw " - Error provisioning Search Query and Site Settings Service"
		}
		WriteLine
	}
}
#EndRegion

#Region Start Claims to Windows Token Service
Function StartClaimsToWindowsTokenService
{
	# C2WTS is required by Excel Services, Visio Services and PerformancePoint Services; if any of these are being provisioned we should start it.
    If ((ShouldIProvision($xmlinput.Configuration.Farm.Services.ClaimsToWindowsTokenService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.VisioService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -eq $true) -or `
        (ShouldIProvision($xmlinput.Configuration.OfficeWebApps.ExcelService) -eq $true))
	{
		WriteLine
		# Ensure Claims to Windows Token Service is started
		$ClaimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
		$ClaimsService = $ClaimsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
		If ($ClaimsService.Status -ne "Online")
		{
			Try
			{
				Write-Host -ForegroundColor White " - Starting $($ClaimsService.DisplayName)..."
				$ClaimsService.Provision()
    			If (-not $?) {throw " - Failed to start $($ClaimsService.DisplayName)"}
			}
			Catch
			{
        	    Throw " - An error occurred starting $($ClaimsService.DisplayName)"
			}
		    #Wait
        	Write-Host -ForegroundColor Blue " - Waiting for $($ClaimsService.DisplayName)..." -NoNewline
        	While ($ClaimsService.Status -ne "Online") 
        	{
				Write-Host -ForegroundColor Blue "." -NoNewline
				sleep 1
				$ClaimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
				$ClaimsService = $ClaimsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
			}
			Write-Host -BackgroundColor Blue -ForegroundColor Black $($ClaimsService.Status)
		}
		Else 
		{
			Write-Host -ForegroundColor White " - $($ClaimsService.DisplayName) already started."
		}
		WriteLine
	}
}
#EndRegion

#Region Stop Foundation Web Service
# ===================================================================================
# Func: StopFoundationWebService
# Desc: Disables the Microsoft SharePoint Foundation Web Application service instance (for App servers)
# ===================================================================================
Function StopFoundationWebService
{
	$FoundationWebServices = Get-SPServiceInstance | ? {$_.Service.ToString() -eq "SPWebService"}
	$FoundationWebService = $FoundationWebServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	Write-Host -ForegroundColor White " - Stopping $($FoundationWebService.TypeName)..."
	$FoundationWebService.Unprovision()
   	If (-not $?) {Throw " - Failed to stop $($FoundationWebService.TypeName)" }
    # Wait
	Write-Host -ForegroundColor Blue " - Waiting for $($FoundationWebService.TypeName) to stop..." -NoNewline
	While ($FoundationWebService.Status -ne "Disabled") 
	{
		Write-Host -ForegroundColor Blue "." -NoNewline
		Start-Sleep 1
		$FoundationWebServices = Get-SPServiceInstance | ? {$_.Service.ToString() -eq "SPWebService"}
		$FoundationWebService = $FoundationWebServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	}
	Write-Host -BackgroundColor Blue -ForegroundColor Black $($FoundationWebService.Status)
}
#EndRegion

#Region Stop Workflow Timer Service
# ===================================================================================
# Func: StopWorkflowTimerService
# Desc: Disables the Microsoft SharePoint Foundation Workflow Timer Service
# ===================================================================================
Function StopWorkflowTimerService
{
	$WorkflowTimerServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Workflow.SPWorkflowTimerServiceInstance"}
	$WorkflowTimerService = $WorkflowTimerServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	Write-Host -ForegroundColor White " - Stopping $($WorkflowTimerService.TypeName)..."
	$WorkflowTimerService.Unprovision()
   	If (-not $?) {Throw " - Failed to stop $($WorkflowTimerService.TypeName)" }
    # Wait
	Write-Host -ForegroundColor Blue " - Waiting for $($WorkflowTimerService.TypeName) to stop..." -NoNewline
	While ($WorkflowTimerService.Status -ne "Disabled") 
	{
		Write-Host -ForegroundColor Blue "." -NoNewline
		Start-Sleep 1
		$WorkflowTimerServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Workflow.SPWorkflowTimerServiceInstance"}
		$WorkflowTimerService = $WorkflowTimerServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	}
	Write-Host -BackgroundColor Blue -ForegroundColor Black $($WorkflowTimerService.Status)
}
#EndRegion

#Region Configure Foundation Search
# ====================================================================================
# Func: ConfigureFoundationSearch
# Desc: Updates the service account for SPSearch4 (SharePoint Foundation (Help) Search)
# ====================================================================================

Function ConfigureFoundationSearch ([xml]$xmlinput)
# Does not actually provision Foundation Search as of yet, just updates the service account it would run under to mitigate Health Analyzer warnings
{
    # Make sure a credential deployment job doesn't already exist
    if (!(Get-SPTimerJob -Identity "windows-service-credentials-SPSearch4"))
    {
        WriteLine
    	Try
    	{
    		$FoundationSearchService = (Get-SPFarm).Services | where {$_.Name -eq "SPSearch4"}
    		$spservice = Get-spserviceaccountxml $xmlinput
    		$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    		Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service SPSearch4..."
            $FoundationSearchService.ProcessIdentity.CurrentIdentityType = "SpecificUser"
            $FoundationSearchService.ProcessIdentity.ManagedAccount = $ManagedAccountGen
            $FoundationSearchService.ProcessIdentity.Update()
            $FoundationSearchService.ProcessIdentity.Deploy()
            $FoundationSearchService.Update()
     		Write-Host -ForegroundColor White " - Done."
    	}
    	Catch
    	{
    		Write-Output $_
    		Throw " - An error occurred updating the service account for SPSearch4."
    	}
    	WriteLine
    }
}
#EndRegion

#Region Configure SPTraceV4 (Logging)
# ====================================================================================
# Func: ConfigureTracing
# Desc: Updates the service account for SPTraceV4 (SharePoint Foundation (Help) Search)
# ====================================================================================

Function ConfigureTracing ([xml]$xmlinput)
{
    # Make sure a credential deployment job doesn't already exist
    if (!(Get-SPTimerJob -Identity "windows-service-credentials-SPTraceV4"))
    {
        WriteLine
    	$spservice = Get-spserviceaccountxml $xmlinput
    	$SPTraceV4 = (Get-SPFarm).Services | where {$_.Name -eq "SPTraceV4"}
        $AppPoolAcctDomain,$AppPoolAcctUser = $spservice.username -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service SPTraceV4..."
    	#Add to Performance Monitor Users group
        Write-Host -ForegroundColor White " - Adding $($spservice.username) to local Performance Monitor Users group..."
        Try
      	{
       		([ADSI]"WinNT://$env:COMPUTERNAME/Performance Monitor Users,group").Add("WinNT://$AppPoolAcctDomain/$AppPoolAcctUser")
            If (-not $?) {Throw}
       	}
        Catch 
        {
            Write-Host -ForegroundColor White " - $($spservice.username) is already a member of Performance Monitor Users."
        }
        #Add to Performance Log Users group
        Write-Host -ForegroundColor White " - Adding $($spservice.username) to local Performance Log Users group..."
        Try
      	{
       		([ADSI]"WinNT://$env:COMPUTERNAME/Performance Log Users,group").Add("WinNT://$AppPoolAcctDomain/$AppPoolAcctUser")
            If (-not $?) {Throw}
       	}
        Catch 
        {
            Write-Host -ForegroundColor White " - $($spservice.username) is already a member of Performance Log Users."
        }
    	$ManagedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    	Try
    	{
    		Write-Host -ForegroundColor White " - Updating service account..."
    		$SPTraceV4.ProcessIdentity.CurrentIdentityType = "SpecificUser"
        	$SPTraceV4.ProcessIdentity.ManagedAccount = $ManagedAccountGen
        	$SPTraceV4.ProcessIdentity.Update()
        	$SPTraceV4.ProcessIdentity.Deploy()
        	$SPTraceV4.Update()
    		Write-Host -ForegroundColor White " - Restarting service SPTraceV4..."
    		Restart-Service -Name "SPTraceV4"
    		Write-Host -ForegroundColor White " - Done."
    	}
    	Catch
    	{
    		Write-Output $_
    		Throw " - An error occurred updating the service account for service SPTraceV4."
    	}
    	WriteLine
    }
}
#EndRegion

#Region Provision Enterprise Search

# Original script for SharePoint 2010 beta2 by Gary Lapointe ()
# 
# Modified by S?ren Laurits Nielsen (soerennielsen.wordpress.com):
# 
# Modified to fix some errors since some cmdlets have changed a bit since beta 2 and added support for "ShareName" for 
# the query component. It is required for non DC computers. 
# 
# Modified to support "localhost" moniker in config file. 
# 
# Note: Accounts, Shares and directories specified in the config file must be setup beforehand.

function CreateEnterpriseSearchServiceApp([xml]$xmlinput)
{
	If (ShouldIProvision($xmlinput.Configuration.ServiceApps.EnterpriseSearchService) -eq $true)
	{
	WriteLine
	Write-Host -ForegroundColor White " - Provisioning Enterprise Search..."
	# SLN: Added support for local host
    $svcConfig = $xmlinput.Configuration.ServiceApps.EnterpriseSearchService
	$PortalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
	$PortalURL = $PortalWebApp.URL
	$PortalPort = $PortalWebApp.Port
	$MySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "MySiteHost"}
	$MySiteURL = $MySiteWebApp.URL
	$MySitePort = $MySiteWebApp.Port
    If ($MySiteURL -like "https://*") {$MySiteHostHeader = $MySiteURL -replace "https://",""}        
    Else {$MySiteHostHeader = $MySiteURL -replace "http://",""}
	$secSearchServicePassword = ConvertTo-SecureString -String $svcConfig.Password -AsPlainText -Force
	$secContentAccessAcctPWD = ConvertTo-SecureString -String $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccountPassword -AsPlainText -Force

    $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
    If ($searchSvc -eq $null) {
        Throw " - Unable to retrieve search service."
    }

    Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService  `
      -ContactEmail $svcConfig.ContactEmail -ConnectionTimeout $svcConfig.ConnectionTimeout `
      -AcknowledgementTimeout $svcConfig.AcknowledgementTimeout -ProxyType $svcConfig.ProxyType `
      -IgnoreSSLWarnings $svcConfig.IgnoreSSLWarnings -InternetIdentity $svcConfig.InternetIdentity -PerformanceLevel $svcConfig.PerformanceLevel `
	  -ServiceAccount $svcConfig.Account -ServicePassword $secSearchServicePassword

	Write-Host -ForegroundColor White " - Setting default index location on search service..."
    $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $svcConfig.IndexLocation -ErrorAction SilentlyContinue -ErrorVariable err

    $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication | ForEach-Object {
        $appConfig = $_
		If (($appConfig.DatabaseServer -ne "") -and ($appConfig.DatabaseServer -ne $null))
		{
			$DBServer = $appConfig.DatabaseServer
		}
		Else
		{
			$DBServer = $xmlinput.Configuration.Farm.Database.DBServer
		}

        # Try and get the application pool if it already exists
        $pool = Get-ApplicationPool $appConfig.ApplicationPool
        $adminPool = Get-ApplicationPool $appConfig.AdminComponent.ApplicationPool

        $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name -ErrorAction SilentlyContinue

        If ($searchApp -eq $null) {
            Write-Host -ForegroundColor White " - Creating $($appConfig.Name)..."
            $searchApp = New-SPEnterpriseSearchServiceApplication -Name $appConfig.Name `
                -DatabaseServer $DBServer `
                -DatabaseName $($DBPrefix+$appConfig.DatabaseName) `
                -FailoverDatabaseServer $appConfig.FailoverDatabaseServer `
                -ApplicationPool $pool `
                -AdminApplicationPool $adminPool `
                -Partitioned:([bool]::Parse($appConfig.Partitioned)) `
                -SearchApplicationType $appConfig.SearchServiceApplicationType
        } Else {
            Write-Host -ForegroundColor White " - Enterprise search service application already exists, skipping creation."
        }
		
		#Add link to resources list
		AddResourcesLink "Search Administration" ("searchadministration.aspx?appid=" +  $SearchApp.Id)

        $installCrawlSvc = (($appConfig.CrawlServers.Server | where {$_.Name -eq $env:computername}) -ne $null)
        $installQuerySvc = (($appConfig.QueryServers.Server | where {$_.Name -eq $env:computername}) -ne $null)
        $installAdminCmpnt = (($appConfig.AdminComponent.Server | where {$_.Name -eq $env:computername}) -ne $null)
        $installSyncSvc = (($appConfig.SearchQueryAndSiteSettingsServers.Server | where {$_.Name -eq $env:computername}) -ne $null)

        If ($searchSvc.Status -ne "Online" -and ($installCrawlSvc -or $installQuerySvc)) {
            $searchSvc | Start-SPEnterpriseSearchServiceInstance
        }

        If ($installAdminCmpnt) {
            Write-Host -ForegroundColor White " - Setting administration component..."
            Set-SPEnterpriseSearchAdministrationComponent -SearchApplication $searchApp -SearchServiceInstance $searchSvc
        
			$AdminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
			If ($AdminCmpnt.Initialized -eq $false)
			{
				Write-Host -ForegroundColor Blue " - Waiting for administration component initialization..." -NoNewline
				While ($AdminCmpnt.Initialized -ne $true)
				{
					Write-Host -ForegroundColor Blue "." -NoNewline
  					Start-Sleep 1
					$AdminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
				}
				Write-Host -BackgroundColor Blue -ForegroundColor Black $($AdminCmpnt.Initialized -replace "True","Done.")
			}
			Else {Write-Host -ForegroundColor White " - Administration component already initialized."}
		}
		
		Write-Host -ForegroundColor White " - Setting content access account for $($appconfig.Name)..."
		$searchApp | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount `
												 			  -DefaultContentAccessAccountPassword $secContentAccessAcctPWD

        $crawlTopology = Get-SPEnterpriseSearchCrawlTopology -SearchApplication $searchApp | where {$_.CrawlComponents.Count -gt 0 -or $_.State -eq "Inactive"}

        If ($crawlTopology -eq $null) {
            Write-Host -ForegroundColor White " - Creating new crawl topology..."
            $crawlTopology = $searchApp | New-SPEnterpriseSearchCrawlTopology
        } Else {
            Write-Host -ForegroundColor White " - A crawl topology with crawl components already exists, skipping crawl topology creation."
        }
 
        If ($installCrawlSvc) {
            $crawlComponent = $crawlTopology.CrawlComponents | where {$_.ServerName -eq $env:ComputerName}
            If ($crawlTopology.CrawlComponents.Count -eq 0 -and $crawlComponent -eq $null) {
                $crawlStore = $searchApp.CrawlStores | where {$_.Name -eq "$($DBPrefix+$appConfig.DatabaseName)_CrawlStore"}
                Write-Host -ForegroundColor White " - Creating new crawl component..."
                $crawlComponent = New-SPEnterpriseSearchCrawlComponent -SearchServiceInstance $searchSvc -SearchApplication $searchApp -CrawlTopology $crawlTopology -CrawlDatabase $crawlStore.Id.ToString() -IndexLocation $appConfig.IndexLocation
            } Else {
                Write-Host -ForegroundColor White " - Crawl component already exist, skipping crawl component creation."
            }
        }

        $queryTopology = Get-SPEnterpriseSearchQueryTopology -SearchApplication $searchApp | where {$_.QueryComponents.Count -gt 0 -or $_.State -eq "Inactive"}

        If ($queryTopology -eq $null) {
            Write-Host -ForegroundColor White " - Creating new query topology..."
            $queryTopology = $searchApp | New-SPEnterpriseSearchQueryTopology -Partitions $appConfig.Partitions
        } Else {
            Write-Host -ForegroundColor White " - A query topology with query components already exists, skipping query topology creation."
        }

        If ($installQuerySvc) {
            $queryComponent = $queryTopology.QueryComponents | where {$_.ServerName -eq $env:ComputerName}
            If ($queryComponent -eq $null) {
                $partition = ($queryTopology | Get-SPEnterpriseSearchIndexPartition)
                Write-Host -ForegroundColor White " - Creating new query component..."
                $queryComponent = New-SPEnterpriseSearchQueryComponent -IndexPartition $partition -QueryTopology $queryTopology -SearchServiceInstance $searchSvc -ShareName $svcConfig.ShareName
                Write-Host -ForegroundColor White " - Setting index partition and property store database..."
                $propertyStore = $searchApp.PropertyStores | where {$_.Name -eq "$($DBPrefix+$appConfig.DatabaseName)_PropertyStore"}
                $partition | Set-SPEnterpriseSearchIndexPartition -PropertyDatabase $propertyStore.Id.ToString()
            } Else {
                Write-Host -ForegroundColor White " - Query component already exists, skipping query component creation."
            }
        }

        If ($installSyncSvc) {            
            # SLN: Updated to new syntax
			$SearchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
			$SearchQueryAndSiteSettingsService = $SearchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
		    If (-not $?) { Throw " - Failed to find Search Query and Site Settings service instance" }
		    # Start Service instance
   		 	Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
			If($SearchQueryAndSiteSettingsService.Status -eq "Disabled")
			{ 
			    $SearchQueryAndSiteSettingsService.Provision()
        		If (-not $?) { Throw " - Failed to start Search Query and Site Settings service instance" }
        		# Wait
    			Write-Host -ForegroundColor Blue " - Waiting for Search Query and Site Settings service..." -NoNewline
				While ($SearchQueryAndSiteSettingsService.Status -ne "Online") 
	    		{
					Write-Host -ForegroundColor Blue "." -NoNewline
		  			Start-Sleep 1
				    $SearchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
		  			$SearchQueryAndSiteSettingsService = $SearchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
	    		}
				Write-Host -BackgroundColor Blue -ForegroundColor Black $($SearchQueryAndSiteSettingsService.Status)
    		}
    		Else {Write-Host -ForegroundColor White " - Search Query and Site Settings Service already started."}
			}

        # Don't activate until we've added all components
        $allCrawlServersDone = $true
        $appConfig.CrawlServers.Server | ForEach-Object {
            $crawlServer = $_.Name
            $top = $crawlTopology.CrawlComponents | where {$_.ServerName -eq $crawlServer}
            If ($top -eq $null) { $allCrawlServersDone = $false }
        }

        If ($allCrawlServersDone -and $crawlTopology.State -ne "Active") {
            Write-Host -ForegroundColor White " - Setting new crawl topology to active..."
            $crawlTopology | Set-SPEnterpriseSearchCrawlTopology -Active -Confirm:$false
			Write-Host -ForegroundColor Blue " - Waiting for Crawl Components..." -NoNewLine
			while ($true) 
			{
				$ct = Get-SPEnterpriseSearchCrawlTopology -Identity $crawlTopology -SearchApplication $searchApp
				$state = $ct.CrawlComponents | where {$_.State -ne "Ready"}
				If ($ct.State -eq "Active" -and $state -eq $null) 
				{
					break
				}
				Write-Host -ForegroundColor Blue "." -NoNewLine
				Start-Sleep 1
			}
            Write-Host -BackgroundColor Blue -ForegroundColor Black $($crawlTopology.State)

			# Need to delete the original crawl topology that was created by default
            $searchApp | Get-SPEnterpriseSearchCrawlTopology | where {$_.State -eq "Inactive"} | Remove-SPEnterpriseSearchCrawlTopology -Confirm:$false
        }

        $allQueryServersDone = $true
        $appConfig.QueryServers.Server | ForEach-Object {
            $queryServer = $_.Name
            $top = $queryTopology.QueryComponents | where {$_.ServerName -eq $queryServer}
            If ($top -eq $null) { $allQueryServersDone = $false }
        }

        # Make sure we have a crawl component added and started before trying to enable the query component
        If ($allCrawlServersDone -and $allQueryServersDone -and $queryTopology.State -ne "Active") {
            Write-Host -ForegroundColor White " - Setting query topology as active..."
            $queryTopology | Set-SPEnterpriseSearchQueryTopology -Active -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err
			Write-Host -ForegroundColor Blue " - Waiting for Query Components..." -NoNewLine
			while ($true) 
			{
				$qt = Get-SPEnterpriseSearchQueryTopology -Identity $queryTopology -SearchApplication $searchApp
				$state = $qt.QueryComponents | where {$_.State -ne "Ready"}
				If ($qt.State -eq "Active" -and $state -eq $null) 
				{
				    break
				}
				Write-Host -ForegroundColor Blue "." -NoNewLine
				Start-Sleep 1
			}
            Write-Host -BackgroundColor Blue -ForegroundColor Black $($queryTopology.State)
			
            # Need to delete the original query topology that was created by default
            $origQueryTopology = $searchApp | Get-SPEnterpriseSearchQueryTopology | where {$_.QueryComponents.Count -eq 0}
            If ($origQueryTopology.State -eq "Inactive")
            {
                Write-Host -ForegroundColor White " - Removing original (default) query topology..."
                $origQueryTopology | Remove-SPEnterpriseSearchQueryTopology -Confirm:$false 
            }
        }

        $proxy = Get-SPEnterpriseSearchServiceApplicationProxy -Identity $appConfig.Proxy.Name -ErrorAction SilentlyContinue
        If ($proxy -eq $null) {
            Write-Host -ForegroundColor White " - Creating enterprise search service application proxy..."
            $proxy = New-SPEnterpriseSearchServiceApplicationProxy -Name $appConfig.Proxy.Name -SearchApplication $searchApp -Partitioned:([bool]::Parse($appConfig.Proxy.Partitioned))
        } Else {
            Write-Host -ForegroundColor White " - Enterprise search service application proxy already exists, skipping creation."
        }

        If ($proxy.Status -ne "Online") {
            $proxy.Status = "Online"
            $proxy.Update()
        }

        $proxy | Set-ProxyGroupsMembership $appConfig.Proxy.ProxyGroup
    }

    # SLN: Create the network share (will report an error if exist)
    # default to primitives 
    $PathToShare = """" + $svcConfig.ShareName + "=" + $svcConfig.IndexLocation + """"
	# The path to be shared should exist if the Enterprise Search App creation succeeded earlier
	EnsureFolder $svcConfig.IndexLocation
    Write-Host -ForegroundColor White " - Creating network share $PathToShare"
    Start-Process -FilePath net.exe -ArgumentList "share $PathToShare `"/GRANT:WSS_WPG,CHANGE`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue

	# Set the crawl start addresses (including the elusive sps3:// URL required for People Search, if My Sites are provisioned)
	$CrawlStartAddresses = $PortalURL+":"+$PortalPort
	If ($MySiteURL -and $MySitePort -and $MySiteHostHeader)
	{	
		# Need to set the correct sps (People Search) URL protocol in case My Sites are SSL-bound
		If ($MySiteURL -like "https*") {$PeopleSearchProtocol = "sps3s://"}
		Else {$PeopleSearchProtocol = "sps3://"}
		$CrawlStartAddresses += ","+$MySiteURL+":"+$MySitePort+","+$PeopleSearchProtocol+$MySiteHostHeader+":"+$MySitePort
	}
	Get-SPEnterpriseSearchServiceApplication | Get-SPEnterpriseSearchCrawlContentSource | Set-SPEnterpriseSearchCrawlContentSource -StartAddresses $CrawlStartAddresses
	
	WriteLine
	}
	Else
	{
		WriteLine
		#Set the service account to something other than Local System to avoid Health Analyzer warnings
	    $svcConfig = $xmlinput.Configuration.ServiceApps.EnterpriseSearchService
		$secSearchServicePassword = ConvertTo-SecureString -String $svcConfig.Password -AsPlainText -Force
		If (($svcConfig.Account) -and ($secSearchServicePassword))
		{
    		# Use the values for Search Service account and password, if they've been defined
			$username = $svcConfig.Account
			$password = $secSearchServicePassword
		}
		Else
		{
			$spservice = Get-spserviceaccountxml $xmlinput
			$username = $spservice.username
			$password = ConvertTo-SecureString "$($spservice.password)" -AsPlaintext -Force
		}
		Write-Host -ForegroundColor White " - Applying service account $username to Search Service..."
		Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService -ServiceAccount $username -ServicePassword $password
		If (!$?) {Write-Error " - An error occurred setting the Search Service account!"}
		WriteLine
	}
}

function Set-ProxyGroupsMembership([System.Xml.XmlElement[]]$groups, [Microsoft.SharePoint.Administration.SPServiceApplicationProxy[]]$InputObject)
{
    begin {}
    process {
        $proxy = $_
        
        # Clear any existing proxy group assignments
        Get-SPServiceApplicationProxyGroup | where {$_.Proxies -contains $proxy} | ForEach-Object {
            $proxyGroupName = $_.Name
            If ([string]::IsNullOrEmpty($proxyGroupName)) { $proxyGroupName = "Default" }
            $group = $null
            [bool]$matchFound = $false
            ForEach ($g in $groups) {
                $group = $g.Name
                If ($group -eq $proxyGroupName) { 
                    $matchFound = $true
                    break 
                }
            }
            If (!$matchFound) {
                Write-Host -ForegroundColor White " - Removing ""$($proxy.DisplayName)"" from ""$proxyGroupName"""
                $_ | Remove-SPServiceApplicationProxyGroupMember -Member $proxy -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
        ForEach ($g in $groups) {
            $group = $g.Name

            $pg = $null
            If ($group -eq "Default" -or [string]::IsNullOrEmpty($group)) {
                $pg = [Microsoft.SharePoint.Administration.SPServiceApplicationProxyGroup]::Default
            } Else {
                $pg = Get-SPServiceApplicationProxyGroup $group -ErrorAction SilentlyContinue -ErrorVariable err
                If ($pg -eq $null) {
                    $pg = New-SPServiceApplicationProxyGroup -Name $name
                }
            }
            
            $pg = $pg | where {$_.Proxies -notcontains $proxy}
            If ($pg -ne $null) { 
                Write-Host -ForegroundColor White " - Adding ""$($proxy.DisplayName)"" to ""$($pg.DisplayName)"""
                $pg | Add-SPServiceApplicationProxyGroupMember -Member $proxy 
            }
        }
    }
    end {}
}

Function Get-ApplicationPool([System.Xml.XmlElement]$appPoolConfig) {
    # Try and get the application pool if it already exists
    # SLN: Updated names
    $pool = Get-SPServiceApplicationPool -Identity $appPoolConfig.Name -ErrorVariable err -ErrorAction SilentlyContinue
    If ($err) {
        # The application pool does not exist so create.
        Write-Host -ForegroundColor White " - Getting $($appPoolConfig.Account) account for application pool..."
        $ManagedAccountSearch = (Get-SPManagedAccount -Identity $appPoolConfig.Account -ErrorVariable err -ErrorAction SilentlyContinue)
        If ($err) {
            If (($appPoolConfig.Password -ne "") -and ($appPoolConfig.Password -ne $null)) 
			{
				$appPoolConfigPWD = (ConvertTo-SecureString $appPoolConfig.Password -AsPlainText -force)
				$accountCred = New-Object System.Management.Automation.PsCredential $appPoolConfig.Account,$appPoolConfigPWD
			}
			Else
			{
				$accountCred = Get-Credential $appPoolConfig.Account
			}
            $ManagedAccountSearch = New-SPManagedAccount -Credential $accountCred
        }
        Write-Host -ForegroundColor White " - Creating $($appPoolConfig.Name)..."
        $pool = New-SPServiceApplicationPool -Name $($appPoolConfig.Name) -Account $ManagedAccountSearch
    }
    Return $pool
}

#EndRegion

#Region Create Business Data Catalog Service Application
# ===================================================================================
# Func: CreateBusinessDataConnectivityServiceApp
# Desc: Business Data Catalog Service Application
# From: http://autospinstaller.codeplex.com/discussions/246532 (user bunbunaz)
# ===================================================================================
Function CreateBusinessDataConnectivityServiceApp([xml]$xmlinput)
{
    If (ShouldIProvision($xmlinput.Configuration.ServiceApps.BusinessDataConnectivity) -eq $true) 
    {
		WriteLine
	 	Try
     	{
	        $DBServer = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($DBServer))
            {
                $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
			$BdcAppName = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Name
   			$BdcDataDB = $DBPrefix+$($xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Database.Name)
			$BdcAppProxyName = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.ProxyName
   			Write-Host -ForegroundColor White " - Provisioning $BdcAppName"
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
			Write-Host -ForegroundColor White " - Checking local service instance..."
   			# Get the service instance
   			$BdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
            $BdcServiceInstance = $BdcServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
   			If (-not $?) { Throw " - Failed to find the service instance" }
   			# Start Service instances
   			If($BdcServiceInstance.Status -eq "Disabled")
     		{ 
             	Write-Host -ForegroundColor White " - Starting $($BdcServiceInstance.TypeName)..."
                $BdcServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start $($BdcServiceInstance.TypeName)" }
    			# Wait
       			Write-Host -ForegroundColor Blue " - Waiting for $($BdcServiceInstance.TypeName)..." -NoNewline
       			While ($BdcServiceInstance.Status -ne "Online") 
       			{
        			Write-Host -ForegroundColor Blue "." -NoNewline
        			Start-Sleep 1
        			$BdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
     				$BdcServiceInstance = $BdcServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
       			}
       			Write-Host -BackgroundColor Blue -ForegroundColor Black ($BdcServiceInstance.Status)
   			}
   			Else 
   			{
    			Write-Host -ForegroundColor White " - $($BdcServiceInstance.TypeName) already started."
   			}
          	# Create a Business Data Catalog Service Application 
   			If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceApplication"}) -eq $null)
        	{      
       			# Create Service App
          		Write-Host -ForegroundColor White " - Creating $BdcAppName..."   
    			$BdcDataServiceApp = New-SPBusinessDataCatalogServiceApplication -Name $BdcAppName -ApplicationPool $ApplicationPool -DatabaseServer $DBServer -DatabaseName $BdcDataDB
    			If (-not $?) { Throw " - Failed to create $BdcAppName" }
           	}
        	Else 
   			{
    			Write-Host -ForegroundColor White " - $BdcAppName already provisioned."
   			}
   			Write-Host -ForegroundColor White " - Done creating $BdcAppName."
     	}
     	Catch
     	{
     	 	Write-Output $_ 
			Throw " - Error provisioning Business Data Connectivity application"
     	}
	 	WriteLine
    }
}
#EndRegion

#Region Create Excel Service
Function CreateExcelServiceApp ([xml]$xmlinput)
{
    If (ShouldIProvision($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices) -eq $true)
	{
		Try
	 	{
			WriteLine
			$ExcelAppName = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.Name
			$PortalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
			$PortalURL = $PortalWebApp.URL
			$PortalPort = $PortalWebApp.Port
			Write-Host -ForegroundColor White " - Provisioning $ExcelAppName..."
			$ApplicationPool = Get-HostedServicesAppPool $xmlinput
			Write-Host -ForegroundColor White " - Checking local service instance..."
   			# Get the service instance
   			$ExcelServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
            $ExcelServiceInstance = $ExcelServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
   			If (-not $?) { Throw " - Failed to find the service instance" }
   			# Start Service instances
   			If($ExcelServiceInstance.Status -eq "Disabled")
     		{ 
             	Write-Host -ForegroundColor White " - Starting $($ExcelServiceInstance.TypeName)..."
                $ExcelServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start $($ExcelServiceInstance.TypeName) instance" }
    			# Wait
       			Write-Host -ForegroundColor Blue " - Waiting for $($ExcelServiceInstance.TypeName)..." -NoNewline
       			While ($ExcelServiceInstance.Status -ne "Online") 
       			{
        			Write-Host -ForegroundColor Blue "." -NoNewline
        			Start-Sleep 1
        			$ExcelServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
     				$ExcelServiceInstance = $ExcelServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
       			}
       			Write-Host -BackgroundColor Blue -ForegroundColor Black ($ExcelServiceInstance.Status)
   			}
   			Else 
   			{
    			Write-Host -ForegroundColor White " - $($ExcelServiceInstance.TypeName) already started."
   			}
          	# Create an Excel Service Application 
   			If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceApplication"}) -eq $null)
        	{      
       			# Create Service App
          		Write-Host -ForegroundColor White " - Creating $ExcelAppName..."
				# Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
				If (!(Get-Command New-SPExcelServiceApplication -ErrorAction SilentlyContinue))
				{
					Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
					Remove-PSSnapin Microsoft.SharePoint.PowerShell
					Load-SharePoint-Powershell
				}
    			$ExcelServiceApp = New-SPExcelServiceApplication -name $ExcelAppName -ApplicationPool $($ApplicationPool.Name) -Default
    			If (-not $?) { Throw " - Failed to create $ExcelAppName" }
				Write-Host -ForegroundColor White " - Configuring service app settings..."
				Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $PortalURL`:$PortalPort -ExcelServiceApplication $ExcelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10

				# Configure unattended accounts, based on:
				# http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
				If (($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser) -and ($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword))
				{
					Write-Host -ForegroundColor White " - Setting unattended account credentials..."
					
					# Reget application to prevent update conflict error message
					$ExcelServiceApp = Get-SPExcelServiceApplication
					
					# Get account credentials
					$ExcelAcct = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser
					$ExcelAcctPWD = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword
					If (!($ExcelAcct) -or $ExcelAcct -eq "" -or !($ExcelAcctPWD) -or $ExcelAcctPWD -eq "") 
					{
						Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Excel Unattended Account:"
						$unattendedAccount = $host.ui.PromptForCredential("Excel Setup", "Enter Excel Unattended Account Credentials:", "$ExcelAcct", "NetBiosUserName" )
					} 
					Else
					{
						$secPassword = ConvertTo-SecureString "$ExcelAcctPWD" -AsPlaintext -Force 
						$unattendedAccount = New-Object System.Management.Automation.PsCredential $ExcelAcct,$secPassword
					}
								
					# Set the group claim and admin principals
					$groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
					$adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName

					# Set the field values
					$secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
					$securePassword = $unattendedAccount.Password
					$credentialValues = $secureUserName, $securePassword
					
					# Set the Target App Name and create the Target App
					$name = "$($ExcelServiceApp.ID)-ExcelUnattendedAccount"
					Write-Host -ForegroundColor White " - Creating Secure Store Target Application $name..."
					$secureStoreTargetApp = New-SPSecureStoreTargetApplication -Name $name `
						-FriendlyName "Excel Services Unattended Account Target App" `
						-ApplicationType Group `
						-TimeoutInMinutes 3

					# Set the account fields
					$usernameField = New-SPSecureStoreApplicationField -Name "User Name" -Type WindowsUserName -Masked:$false
					$passwordField = New-SPSecureStoreApplicationField -Name "Password" -Type WindowsPassword -Masked:$false
					$fields = $usernameField, $passwordField

					# Get the service context
					$subId = [Microsoft.SharePoint.SPSiteSubscriptionIdentifier]::Default
					$context = [Microsoft.SharePoint.SPServiceContext]::GetContext($ExcelServiceApp.ServiceApplicationProxyGroup, $subId)

					# Check to see if the Secure Store App already exists
					$secureStoreApp = Get-SPSecureStoreApplication -ServiceContext $context -Name $name -ErrorAction SilentlyContinue
					If ($secureStoreApp -eq $null) {
						# Doesn't exist so create.
						Write-Host -ForegroundColor White " - Creating Secure Store Application..."
						$secureStoreApp = New-SPSecureStoreApplication -ServiceContext $context `
							-TargetApplication $secureStoreTargetApp `
							-Administrator $adminPrincipal `
							-CredentialsOwnerGroup $groupClaim `
							-Fields $fields
					}
					# Update the field values
					Write-Host -ForegroundColor White " - Updating Secure Store Group Credential Mapping..."
					Update-SPSecureStoreGroupCredentialMapping -Identity $secureStoreApp -Values $credentialValues

					# Set the unattended service account application ID
					Set-SPExcelServiceApplication -Identity $ExcelServiceApp -UnattendedAccountApplicationId $name
				}
				Else 
				{
					Write-Host -ForegroundColor Yellow " - Unattended account credentials not supplied in configuration file - skipping."
				}
			}
        	Else 
   			{
    			Write-Host -ForegroundColor White " - $ExcelAppName already provisioned."
   			}
   			Write-Host -ForegroundColor White " - Done creating $ExcelAppName."
		}
		Catch
	 	{
	  		Write-Output $_
			Throw " - Error provisioning Excel Service Application"
	 	}
		WriteLine
	}
}
#EndRegion

#Region Create Visio Graphics Service
Function CreateVisioServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.EnterpriseServiceApps.VisioService
	If (ShouldIProvision($ServiceConfig) -eq $true)
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPVisioServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPVisioServiceApplicationProxy" `
  									  -ServiceNewCmdlet "New-SPVisioServiceApplication" `
									  -ServiceProxyNewCmdlet "New-SPVisioServiceApplicationProxy"
									  
		If (Get-Command -Name Get-SPVisioServiceApplication -ErrorAction SilentlyContinue)
		{
			# http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
			If ($ServiceConfig.UnattendedIDUser -and $ServiceConfig.UnattendedIDPassword) 
			{
				Write-Host -ForegroundColor White " - Setting unattended account credentials..."

				$ServiceApplication = Get-SPServiceApplication -name $ServiceConfig.Name
			
				# Get account credentials
				$VisioAcct = $xmlinput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDUser
				$VisioAcctPWD = $xmlinput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDPassword
				If (!($VisioAcct) -or $VisioAcct -eq "" -or !($VisioAcctPWD) -or $VisioAcctPWD -eq "") 
				{
					Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Visio Unattended Account:"
					$unattendedAccount = $host.ui.PromptForCredential("Visio Setup", "Enter Visio Unattended Account Credentials:", "$VisioAcct", "NetBiosUserName" )
				} 
				Else
				{
					$secPassword = ConvertTo-SecureString "$VisioAcctPWD" -AsPlaintext -Force 
					$unattendedAccount = New-Object System.Management.Automation.PsCredential $VisioAcct,$secPassword
				}
				
				# Set the group claim and admin principals
				$groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
				$adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName

				# Set the field values
				$secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
				$securePassword = $unattendedAccount.Password
				$credentialValues = $secureUserName, $securePassword

				# Set the Target App Name and create the Target App
				$name = "$($ServiceApplication.ID)-VisioUnattendedAccount"
				Write-Host -ForegroundColor White " - Creating Secure Store Target Application $name..."
				$secureStoreTargetApp = New-SPSecureStoreTargetApplication -Name $name `
					-FriendlyName "Visio Services Unattended Account Target App" `
					-ApplicationType Group `
					-TimeoutInMinutes 3

				# Set the account fields
				$usernameField = New-SPSecureStoreApplicationField -Name "User Name" -Type WindowsUserName -Masked:$false
				$passwordField = New-SPSecureStoreApplicationField -Name "Password" -Type WindowsPassword -Masked:$false
				$fields = $usernameField, $passwordField

				# Get the service context
				$subId = [Microsoft.SharePoint.SPSiteSubscriptionIdentifier]::Default
				$context = [Microsoft.SharePoint.SPServiceContext]::GetContext($ServiceApplication.ServiceApplicationProxyGroup, $subId)

				# Check to see if the Secure Store App already exists
				$secureStoreApp = Get-SPSecureStoreApplication -ServiceContext $context -Name $name -ErrorAction SilentlyContinue
				If (!($secureStoreApp))
				{
					# Doesn't exist so create.
					Write-Host -ForegroundColor White " - Creating Secure Store Application..."
					$secureStoreApp = New-SPSecureStoreApplication -ServiceContext $context `
						-TargetApplication $secureStoreTargetApp `
						-Administrator $adminPrincipal `
						-CredentialsOwnerGroup $groupClaim `
						-Fields $fields
				}
				# Update the field values
				Write-Host -ForegroundColor White " - Updating Secure Store Group Credential Mapping..."
				Update-SPSecureStoreGroupCredentialMapping -Identity $secureStoreApp -Values $credentialValues

				# Set the unattended service account application ID
				Write-Host -ForegroundColor White " - Setting Application ID for Visio Service..."
				$ServiceApplication | Set-SPVisioExternalData -UnattendedServiceAccountApplicationID $name
			}
			Else 
			{
				Write-Host -ForegroundColor Yellow " - Unattended account credentials not supplied in configuration file - skipping."
			}
		}
		WriteLine
	}
}
#EndRegion

#Region Create PerformancePoint Service
Function CreatePerformancePointServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService
    $DBServer = $ServiceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($DBServer))
    {
        $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
    }
	$PerformancePointDB = $DBPrefix+$ServiceConfig.Database.Name
	If (ShouldIProvision($ServiceConfig) -eq $true)
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPPerformancePointServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPPerformancePointServiceApplication" `
									  -ServiceProxyNewCmdlet "New-SPPerformancePointServiceApplicationProxy"
		
		$Application = Get-SPPerformancePointServiceApplication | ? {$_.Name -eq $ServiceConfig.Name}
	    If ($Application)
		{
			$FarmAcct = $xmlinput.Configuration.Farm.Account.Username
			Write-Host -ForegroundColor White " - Granting $FarmAcct rights to database $PerformancePointDB..."
			Get-SPDatabase | Where {$_.Name -eq $PerformancePointDB} | Add-SPShellAdmin -UserName $FarmAcct
			Write-Host -ForegroundColor White " - Setting PerformancePoint Data Source Unattended Service Account..."
			$PerformancePointAcct = $ServiceConfig.UnattendedIDUser
		    $PerformancePointAcctPWD = $ServiceConfig.UnattendedIDPassword
		    If (!($PerformancePointAcct) -or $PerformancePointAcct -eq "" -or !($PerformancePointAcctPWD) -or $PerformancePointAcctPWD -eq "") 
		    {
		        Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for PerformancePoint Unattended Service Account:"
		    	$PerformancePointCredential = $host.ui.PromptForCredential("PerformancePoint Setup", "Enter PerformancePoint Unattended Account Credentials:", "$PerformancePointAcct", "NetBiosUserName" )
		    } 
		    Else
		    {
		        $secPassword = ConvertTo-SecureString "$PerformancePointAcctPWD" -AsPlaintext -Force 
		        $PerformancePointCredential = New-Object System.Management.Automation.PsCredential $PerformancePointAcct,$secPassword
		    }
			$Application | Set-SPPerformancePointSecureDataValues -DataSourceUnattendedServiceAccount $PerformancePointCredential
			
			If (!(CheckForSP1)) # Only need this if our environment isn't up to Service Pack 1 for SharePoint 2010
			{
				# Rename the performance point service application database
				Write-Host -ForegroundColor White " - Renaming Performance Point Service Application Database"
				$settingsDB = $Application.SettingsDatabase		
				$newDB = $PerformancePointDB
				$sqlServer = ($settingsDB -split "\\\\")[0]
				$oldDB = ($settingsDB -split "\\\\")[1]
				If (!($newDB -eq $oldDB)) # Check if it's already been renamed, in case we're running the script again
				{
					Write-Host -ForegroundColor White " - Renaming Performance Point Service Application Database"
					RenameDatabase -sqlServer $sqlServer -oldName $oldDB -newName $newDB
					Set-SPPerformancePointServiceApplication  -Identity $ServiceConfig.Name -SettingsDatabase $newDB | Out-Null
				}
				Else
				{
				Write-Host -ForegroundColor White " - Database already named: $newDB"
				}
			}
		}
		WriteLine
	}
}
#EndRegion

#Region Create Access Service
Function CreateAccessServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.EnterpriseServiceApps.AccessService
	If (ShouldIProvision($ServiceConfig) -eq $true)
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPAccessServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPAccessServiceApplication -Default" `
									  -ServiceProxyNewCmdlet "New-SPAccessServiceApplicationProxy" # Fake cmdlet (and not needed for Access Services), but the CreateBasicServiceApplication function expects something
		WriteLine
	}
}
#EndRegion

#Region Create Word Automation Service
Function CreateWordAutomationServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.ServiceApps.WordAutomationService
    $DBPrefix = $xmlinput.Configuration.Farm.Database.DBPrefix
	If (($DBPrefix -ne "") -and ($DBPrefix -ne $null)) {$DBPrefix += "_"}
	If ($DBPrefix -like "*localhost*") {$DBPrefix = $DBPrefix -replace "localhost","$env:COMPUTERNAME"}
    $DBServer = $ServiceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($DBServer))
    {
        $DBServer = $xmlinput.Configuration.Farm.Database.DBServer
    }
	$WordDatabase = $DBPrefix+$($ServiceConfig.Database.Name)
	If (ShouldIProvision($ServiceConfig) -eq $true)
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.Office.Word.Server.Service.WordServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPWordConversionServiceApplication -DatabaseServer $DBServer -DatabaseName $WordDatabase -Default" `
									  -ServiceProxyNewCmdlet "New-SPWordConversionServiceApplicationProxy" # Fake cmdlet, but the CreateBasicServiceApplication function expects something
		# Run the Word Automation Timer Job immediately; otherwise we will have a Health Analyzer error condition until the job runs as scheduled
		If (Get-SPServiceApplication | ? {$_.DisplayName -eq $($ServiceConfig.Name)})
		{
			Get-SPTimerJob | ? {$_.GetType().ToString() -eq "Microsoft.Office.Word.Server.Service.QueueJob"} | ForEach-Object {$_.RunNow()}
		}
		WriteLine
	}
}
#EndRegion

#Region Create Office Web Apps
Function CreateExcelOWAServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.OfficeWebApps.ExcelService
	If ((ShouldIProvision($ServiceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
	{
		WriteLine
		$PortalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
		$PortalURL = $PortalWebApp.URL
		$PortalPort = $PortalWebApp.Port
		$ServiceInstanceType = "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPExcelServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPExcelServiceApplication -Default" `
									  -ServiceProxyNewCmdlet "New-SPExcelServiceApplicationProxy" # Fake cmdlet (and not needed for Excel Services), but the CreateBasicServiceApplication function expects something
									  
		If (Get-SPExcelServiceApplication)
		{
			Write-Host -ForegroundColor White " - Setting Excel Services Trusted File Location..."
			Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $PortalURL`:$PortalPort -ExcelServiceApplication $($ServiceConfig.Name) -ExternalDataAllowed 2 -WorkbookSizeMax 10
		}
		WriteLine
	}
}

Function CreatePowerPointServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.OfficeWebApps.PowerPointService
	If ((ShouldIProvision($ServiceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPPowerPointServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPPowerPointServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPPowerPointServiceApplication" `
									  -ServiceProxyNewCmdlet "New-SPPowerPointServiceApplicationProxy"
		WriteLine
	}
}

Function CreateWordViewingServiceApp ([xml]$xmlinput)
{
	$ServiceConfig = $xmlinput.Configuration.OfficeWebApps.WordViewingService
	If ((ShouldIProvision($ServiceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
	{
		WriteLine
		$ServiceInstanceType = "Microsoft.Office.Web.Environment.Sharepoint.ConversionServiceInstance"
		CreateBasicServiceApplication -ServiceConfig $ServiceConfig `
									  -ServiceInstanceType $ServiceInstanceType `
									  -ServiceName $ServiceConfig.Name `
									  -ServiceProxyName $ServiceConfig.ProxyName `
									  -ServiceGetCmdlet "Get-SPServiceApplication" `
									  -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPWordViewingServiceApplication" `
									  -ServiceProxyNewCmdlet "New-SPWordViewingServiceApplicationProxy"
		WriteLine
	}
}
#EndRegion

#Region Configure Outgoing Email
# This is from http://autospinstaller.codeplex.com/discussions/228507?ProjectName=autospinstaller courtesy of rybocf
Function ConfigureOutgoingEmail
{
	If ($($xmlinput.Configuration.Farm.Services.OutgoingEmail.Configure) -eq $true)
	{
		WriteLine
		Try
		{
			$SMTPServer = $xmlinput.Configuration.Farm.Services.OutgoingEmail.SMTPServer
			$EmailAddress = $xmlinput.Configuration.Farm.Services.OutgoingEmail.EmailAddress
			$ReplyToEmail = $xmlinput.Configuration.Farm.Services.OutgoingEmail.ReplyToEmail
			Write-Host -ForegroundColor White " - Configuring Outgoing Email..."
			$loadasm = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint")
			$SPGlobalAdmin = New-Object Microsoft.SharePoint.Administration.SPGlobalAdmin
			$SPGlobalAdmin.UpdateMailSettings($SMTPServer, $EmailAddress, $ReplyToEmail, 65001)
		}
		Catch
		{
			Write-Output $_
		}
		WriteLine
	}
}
#EndRegion

#Region Configure Adobe PDF Indexing and Display
# ====================================================================================
# Func: Configure-PDFSearchAndIcon
# Desc: Downloads and installs the PDF iFilter, registers the PDF search file type and document icon for display in SharePoint
# From: Adapted/combined from @brianlala's additions, @tonifrankola's http://www.sharepointusecases.com/index.php/2011/02/automate-pdf-configuration-for-sharepoint-2010-via-powershell/
# And : Paul Hickman's Patch 9609 at http://autospinstaller.codeplex.com/SourceControl/list/patches
# ====================================================================================

Function Configure-PDFSearchAndIcon
{
	WriteLine
	Write-Host -ForegroundColor White " - Configuring PDF file search, display and handling..."
	$SharePointRoot = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14"
	$SourceFileLocations = @("$bits\PDF\","$bits\AdobePDF\","$env:TEMP\")
	If (ShouldIProvision($xmlinput.Configuration.AdobePDF.iFilter) -eq $true)
	{
		$PDFiFilterUrl = "http://download.adobe.com/pub/adobe/acrobat/win/9.x/PDFiFilter64installer.zip"
		Write-Host -ForegroundColor White " - Configuring PDF file iFilter and indexing..."
		# Look for the installer or the installer zip in the possible locations
		ForEach ($SourceFileLocation in $SourceFileLocations)
		{
			If (Get-Item $($SourceFileLocation+"PDFFilter64installer.msi") -ErrorAction SilentlyContinue)
			{
				Write-Host -ForegroundColor White " - PDF iFilter installer found in $SourceFileLocation."
				$iFilterInstaller = $SourceFileLocation+"PDFFilter64installer.msi"
				Break
			}
			ElseIf (Get-Item $($SourceFileLocation+"PDFiFilter64installer.zip") -ErrorAction SilentlyContinue)
			{
				Write-Host -ForegroundColor White " - PDF iFilter installer zip file found in $SourceFileLocation."
				$ZipLocation = $SourceFileLocation
				$SourceFile = $SourceFileLocation+"PDFiFilter64installer.zip"
				Break
			}
		}
		# If the MSI hasn't been extracted from the zip yet then extract it
		If (!($iFilterInstaller))
		{
			# If the zip file isn't present then download it first
			If (!($SourceFile))
			{
				Write-Host -ForegroundColor White " - PDF iFilter installer or zip not found, downloading..."
				$ZipLocation = $env:TEMP
				$DestinationFile = $ZipLocation+"\PDFiFilter64installer.zip"
				Import-Module BitsTransfer | Out-Null
				Start-BitsTransfer -Source $PDFiFilterUrl -Destination $DestinationFile -DisplayName "Downloading Adobe PDF iFilter..." -Priority High -Description "From $PDFiFilterUrl..." -ErrorVariable err
				If ($err) {Write-Warning " - Could not download Adobe PDF iFilter!"; Pause "exit"; break}
				$SourceFile = $DestinationFile
			}
			Write-Host -ForegroundColor White " - Extracting Adobe PDF iFilter installer..."
			$Shell = New-Object -ComObject Shell.Application
			$iFilterZip = $Shell.Namespace($SourceFile)
			$Location = $Shell.Namespace($ZipLocation)
	    	$Location.Copyhere($iFilterZip.items())
			$iFilterInstaller = $ZipLocation+"\PDFFilter64installer.msi"
		}
		Try
		{
			Write-Host -ForegroundColor White " - Installing Adobe PDF iFilter..."
			Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $iFilterInstaller /passive /norestart" -NoNewWindow -Wait
		}
		Catch {$_}
		If ((Get-PsSnapin |?{$_.Name -eq "Microsoft.SharePoint.PowerShell"})-eq $null)
		{
		   	Write-Host -ForegroundColor White " - Loading SharePoint Powershell Snapin..."
			$PSSnapin = Add-PsSnapin Microsoft.SharePoint.PowerShell
		}
		Write-Host -ForegroundColor White " - Setting PDF search crawl extension..."
		$searchApplications = Get-SPEnterpriseSearchServiceApplication
		If ($searchApplications)
		{		
			ForEach ($searchApplication in $searchApplications)
			{
				Try
				{
					Get-SPEnterpriseSearchCrawlExtension -SearchApplication $searchApplication -Identity "pdf" -ErrorAction Stop | Out-Null
					Write-Host -ForegroundColor White " - PDF file extension already set for $($searchApplication.DisplayName)."
				}
				Catch
				{
					New-SPEnterpriseSearchCrawlExtension -SearchApplication $searchApplication -Name "pdf" | Out-Null
					Write-Host -ForegroundColor White " - PDF extension for $($searchApplication.DisplayName) now set."
				}
			}
		}
		Else {Write-Warning " - No search applications found."}
		Write-Host -ForegroundColor White " - Updating registry..."
		If ((Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\14.0\Search\Setup\Filters\.pdf" -ErrorAction SilentlyContinue) -eq $null)
		{
			$item = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\14.0\Search\Setup\Filters\.pdf"
			$item | New-ItemProperty -Name Extension -PropertyType String -Value "pdf" | Out-Null
			$item | New-ItemProperty -Name FileTypeBucket -PropertyType DWord -Value 1 | Out-Null
			$item | New-ItemProperty -Name MimeTypes -PropertyType String -Value "application/pdf" | Out-Null
		}
		If ((Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\14.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf" -ErrorAction SilentlyContinue) -eq $null)
		{
			$registryItem = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\14.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf"
			$registryItem | New-ItemProperty -Name "(default)" -PropertyType String -Value "{E8978DA6-047F-4E3D-9C78-CDBE46041603}" | Out-Null
		}
		##Write-Host -ForegroundColor White " - Restarting SharePoint Foundation Search Service..."
		##Restart-Service SPSearch4
		If ((Get-Service OSearch14).Status -eq "Running")
		{
			Write-Host -ForegroundColor White " - Restarting SharePoint Search Service..."
			Restart-Service OSearch14
		}
		Write-Host -ForegroundColor White " - Done configuring PDF iFilter and indexing."
    }
    If ($xmlinput.Configuration.AdobePDF.Icon.Configure -eq $true)
	{
		$PDFIconUrl = "http://www.adobe.com/images/pdficon_small.gif"
		$DocIconFolderPath = "$SharePointRoot\TEMPLATE\XML"
		$DocIconFilePath = "$DocIconFolderPath\DOCICON.XML"
		Write-Host -ForegroundColor White " - Configuring PDF Icon..."
		$pdfIcon = "icpdf.gif"
		If (!(Get-Item $SharePointRoot\Template\Images\$pdfIcon -ErrorAction SilentlyContinue))
		{
			ForEach ($SourceFileLocation in $SourceFileLocations)
			{
				# Check each possible source file location for the PDF icon
				$CopyIcon = Copy-Item -Path $SourceFileLocation\$pdfIcon -Destination $SharePointRoot\Template\Images\$pdfIcon -PassThru -ErrorAction SilentlyContinue
				If ($CopyIcon)
				{
					Write-Host -ForegroundColor White " - PDF icon found at $SourceFileLocation\$pdfIcon"
					Break
				}
			}
			If (!($CopyIcon))
			{
				Write-Host -ForegroundColor White " - `"$pdfIcon`" not found; downloading it now..."
				Import-Module BitsTransfer | Out-Null
				Start-BitsTransfer -Source $PDFIconUrl -Destination "$SharePointRoot\Template\Images\$pdfIcon" -DisplayName "Downloading PDF Icon..." -Priority High -Description "From $PDFIconUrl..." -ErrorVariable err
				If ($err) {Write-Warning " - Could not download PDF Icon!"; Pause "exit"; break}
			}
			If (Get-Item $SharePointRoot\Template\Images\$pdfIcon) {Write-Host -ForegroundColor White " - PDF icon copied successfully."}
			Else {Throw}
		}
		$xml = New-Object XML
		$xml.Load($DocIconFilePath)
		If ($xml.SelectSingleNode("//Mapping[@Key='pdf']") -eq $null)
		{
			Try
			{
				Write-Host -ForegroundColor White " - Creating backup of DOCICON.XML file..."
				$backupFile = "$DocIconFolderPath\DOCICON_Backup.xml"
				Copy-Item $DocIconFilePath $backupFile
				Write-Host -ForegroundColor White " - Writing new DOCICON.XML..."
				$pdf = $xml.CreateElement("Mapping")
				$pdf.SetAttribute("Key","pdf")
				$pdf.SetAttribute("Value",$pdfIcon)
				$xml.DocIcons.ByExtension.AppendChild($pdf) | Out-Null
			    $xml.Save($DocIconFilePath)
				Write-Host -ForegroundColor White " - Restarting IIS..."
                iisreset
			}
			Catch {$_; Pause "exit"; Break}
		}
	}
    If ($xmlinput.Configuration.AdobePDF.MIMEType.Configure -eq $true)
	{
		# Add the PDF MIME type to each web app so PDFs can be directly viewed/opened without saving locally first
		# More granular and generally preferable to setting the whole web app to "Permissive" file handling
		$MimeType = "application/pdf"
		Write-Host -ForegroundColor White " - Adding PDF MIME type `"$MimeType`" web apps..."
		ForEach ($WebAppConfig in $xmlinput.Configuration.WebApplications.WebApplication)
		{
			$WebAppUrl = $($WebAppConfig.url)+":"+$($WebAppConfig.Port)
            $WebApp = Get-SPWebApplication -Identity $WebAppUrl
			If ($WebApp.AllowedInlineDownloadedMimeTypes -notcontains $MimeType)
            {
                Write-Host -ForegroundColor White "  - "$WebAppUrl": Adding "`"$MimeType"`"..." -NoNewline
                $WebApp.AllowedInlineDownloadedMimeTypes.Add($MimeType)
                $WebApp.Update()
				Write-Host -ForegroundColor White "Done."
            }
			Else
			{
                Write-Host -ForegroundColor White "  - "$WebAppUrl": "`"$MimeType"`" already added."
            }
		}
    }		
	Write-Host -ForegroundColor White " - Done configuring PDF indexing and icon display."
	WriteLine
}
#EndRegion

#Region Install Forefront
# ====================================================================================
# Func: InstallForeFront
# Desc: Installs ForeFront Protection 2010 for SharePoint Sites
# ====================================================================================
Function InstallForeFront
{
	If (ShouldIProvision($xmlinput.Configuration.ForeFront) -eq $true)
	{
		WriteLine
		If (Test-Path "$env:PROGRAMFILES\Microsoft ForeFront Protection for SharePoint\Launcher.exe")
		{
			Write-Host -ForegroundColor White " - ForeFront binaries appear to be already installed - skipping install."
		}
		Else
		{
			# Install ForeFront
			$config = $env:dp0 + "\" + $xmlinput.Configuration.ForeFront.ConfigFile
			If (Test-Path "$bits\Forefront\setup.exe")
			{
				Write-Host -ForegroundColor White " - Installing ForeFront binaries..."
				Try
				{
					Start-Process "$bits\Forefront\setup.exe" -ArgumentList "/a `"$config`" /p" -Wait
					If (-not $?) {Throw}
					Write-Host -ForegroundColor White " - Done installing ForeFront."
				}
				Catch 
				{
					Throw " - Error $LastExitCode occurred running $bits\ForeFront\setup.exe"
				}
			}
			Else 
			{
				Throw " - ForeFront installer not found in $bits\ForeFront folder"
			}
		}
		WriteLine
	}
}
#EndRegion

#Region Remote Functions
Function Get-FarmServers ([xml]$xmlinput)
{
    $server = $null
    $FarmServers = @()
    # Look for server name references in the XML
    ForEach ($node in $xmlinput.SelectNodes("//*[@Provision]|//*[@Install]|//*[CrawlServers]|//*[QueryServers]|//*[SearchQueryAndSiteSettingsServers]|//*[AdminComponent]|//*[@Start]"))
    {
        # Try to set the server name from the various elements/attributes
    	$server = @(GetFromNode $node "Provision")
    	If ([string]::IsNullOrEmpty($server)) { $server = @(GetFromNode $node "Install") }
    	If ([string]::IsNullOrEmpty($server)) { $server = @(GetFromNode $node "Start") }
        If ([string]::IsNullOrEmpty($server)) 
        {
            foreach ($serverElement in $node.CrawlServers.Server) {$crawlServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.QueryServers.Server) {$queryServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.SearchQueryAndSiteSettingsServers.Server) {$siteQueryAndSSServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.AdminComponent.Server) {$adminServers += @($serverElement.GetAttribute("Name"))}
            $server = $crawlServers+$queryServers+$siteQueryAndSSServers+$adminServers
        }
       
        # Accomodate and clean up comma and/or space-separated server names
        $server = $server -split "," -replace " ", ""
        # Remove any "true", "false" or zero-length values as we only want server names
        If ($server -eq "true" -or $server -eq "false" -or [string]::IsNullOrEmpty($server))
        {
            $server = $null
        }
        else
        {
            # Add any server(s) we found to our $FarmServers array
            $FarmServers = @($FarmServers+$server)
        }
    }

    # Remove any duplicates
    $FarmServers = $FarmServers | Select-Object -Unique
    Return $FarmServers
}

Function Enable-CredSSP ($RemoteFarmServers)
{
    ForEach ($server in $RemoteFarmServers) {Write-Host -ForegroundColor White " - Enabling WSManCredSSP for `"$server`""}
    Enable-WSManCredSSP -Role Client -Force -DelegateComputer $RemoteFarmServers | Out-Null
    If (!$?) {Pause "exit..."; throw $_}
}

Function Test-ServerConnection ($Server)
{
    Write-Host -ForegroundColor White " - Testing connection (via Ping) to `"$server`"..." -NoNewline
    $CanConnect = Test-Connection -ComputerName $server -Count 1 -Quiet
    If ($CanConnect) {Write-Host -ForegroundColor Blue -BackgroundColor Black $($CanConnect.ToString() -replace "True","Success.")}
    If (!$CanConnect)
    {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black $($CanConnect.ToString() -replace "False","Failed.")
        Write-Host -ForegroundColor Yellow " - Check that `"$server`":"
        Write-Host -ForegroundColor Yellow "  - Is online" 
        Write-Host -ForegroundColor Yellow "  - Has the required Windows Firewall exceptions set (or turned off)"
        Write-Host -ForegroundColor Yellow "  - Has a valid DNS entry for $server.$($env:USERDNSDOMAIN)"
    }
}

Function Enable-RemoteSession ($Server, $Password)
{
    If ($Password) {$Credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$Credential) {$Credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    $username = $Credential.Username
    $password = ConvertTo-PlainText $Credential.Password
    $ConfigureTargetScript = "$env:dp0\AutoSPInstallerConfigureRemoteTarget.ps1"
    $PsExec = $env:dp0+"\PsExec.exe"
    If (!(Get-Item ($PsExec) -ErrorAction SilentlyContinue))
	{
		Write-Host -ForegroundColor White " - PsExec.exe not found; downloading..."
		$PsExecUrl = "http://live.sysinternals.com/PsExec.exe"
		Import-Module BitsTransfer | Out-Null
		Start-BitsTransfer -Source $PsExecUrl -Destination $PsExec -DisplayName "Downloading Sysinternals PsExec..." -Priority High -Description "From $PsExecUrl..." -ErrorVariable err
		If ($err) {Write-Warning " - Could not download PsExec!"; Pause "exit"; break}
		$SourceFile = $DestinationFile
    }
    Write-Host -ForegroundColor White " - Updating PowerShell execution policy on `"$server`" via PsExec..."
    Start-Process -FilePath "$PsExec" `
                  -ArgumentList "/acceptEula \\$server -h powershell.exe -Command `"Set-ExecutionPolicy Bypass -Force ; Stop-Process -Id `$PID`"" `
                  -Wait -NoNewWindow
    # Another way to exit powershell when running over PsExec from http://www.leeholmes.com/blog/2007/10/02/using-powershell-and-PsExec-to-invoke-expressions-on-remote-computers/
    # PsExec \\server cmd /c "echo . | powershell {command}"                      
    Write-Host -ForegroundColor White " - Enabling PowerShell remoting on `"$server`" via PsExec..."
    Start-Process -FilePath "$PsExec" `
                  -ArgumentList "/acceptEula \\$server -u $Username -p $Password -h powershell.exe -Command `"$ConfigureTargetScript`"" `
                  -Wait -NoNewWindow
}

Function Install-NetFramework ($Server, $Password)
{
    If ($Password) {$Credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$Credential) {$Credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($Session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $Session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $Credential -ComputerName $server
    }
    Write-Host -ForegroundColor White " - Pre-installing .Net Framework feature on $server..."
    Invoke-Command -ScriptBlock {Import-Module ServerManager | Out-Null
                                # Get the current progress preference
                                $pref = $ProgressPreference
                                # Hide the progress bar since it tends to not disappear
                                $ProgressPreference = "SilentlyContinue"
                                Import-Module ServerManager
                                Add-WindowsFeature NET-Framework | Out-Null
                                # Restore progress preference
                                $ProgressPreference = $pref} -Session $Session
}

Function Install-WindowsIdentityFoundation ($Server, $Password)
{
    # This step is required due to a known issue with the PrerequisiteInstaller.exe over a remote session; 
    # Specifically, because Windows Update Standalone Installer (wusa.exe) blows up with error code 5
    # With a fully-patched Windows 2008 R2 server though, the rest of the prerequisites seem OK; so this function only deals with KB974405 (Windows Identity Foundation).
    # Thanks to Ravikanth Chaganti (@ravikanth) for describing the issue, and working around it so effectively: http://www.ravichaganti.com/blog/?p=1888
    If ($Password) {$Credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$Credential) {$Credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($Session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $Session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $Credential -ComputerName $server
    }
    Write-Host -ForegroundColor White " - Checking for KB974405 (Windows Identity Foundation)..." -NoNewline
    $wifHotfixInstalled = Invoke-Command -ScriptBlock {Get-HotFix -Id KB974405 -ErrorAction SilentlyContinue} -Session $Session
    If ($wifHotfixInstalled)
    {
        Write-Host -ForegroundColor White "already installed."
    }
    Else
    {
        Write-Host -ForegroundColor Black -BackgroundColor White "needed."
        $username = $Credential.UserName
        $password = ConvertTo-PlainText $Credential.Password
        $remoteQueryOS = Invoke-Command -ScriptBlock {Get-WmiObject Win32_OperatingSystem} -Session $Session
    	If ($remoteQueryOS.Version.contains("6.1"))
        {
            $wifHotfix = "Windows6.1-KB974405-x64.msu"
        }
    	ElseIf ($remoteQueryOS.Version.contains("6.0"))
        {
            $wifHotfix = "Windows6.0-KB974405-x64.msu"
        }
        Else {Write-Warning " - Could not detect OS of `"$server`", or unsupported OS."}
        If (!(Get-Item $env:SPbits\PrerequisiteInstallerFiles\$wifHotfix -ErrorAction SilentlyContinue))
        {
            Write-Host -ForegroundColor White " - Windows Identity Foundation KB974405 not found in $env:SPbits\PrerequisiteInstallerFiles"
            Write-Host -ForegroundColor White " - Attempting to download..."
            $wifURL = "http://download.microsoft.com/download/D/7/2/D72FD747-69B6-40B7-875B-C2B40A6B2BDD/$wifHotfix"
            Import-Module BitsTransfer | Out-Null
            Start-BitsTransfer -Source $wifURL -Destination "$env:SPbits\PrerequisiteInstallerFiles\$wifHotfix" -DisplayName "Downloading `'$wifHotfix`' to $env:SPbits\PrerequisiteInstallerFiles" -Priority High -Description "From $wifURL..." -ErrorVariable err
            if ($err) {Throw " - Could not download from $wifURL!"; Pause "exit"; break}
        }
        $PsExec = $env:dp0+"\PsExec.exe"
        If (!(Get-Item ($PsExec) -ErrorAction SilentlyContinue))
    	{
    		Write-Host -ForegroundColor White " - PsExec.exe not found; downloading..."
    		$PsExecUrl = "http://live.sysinternals.com/PsExec.exe"
    		Import-Module BitsTransfer | Out-Null
    		Start-BitsTransfer -Source $PsExecUrl -Destination $PsExec -DisplayName "Downloading Sysinternals PsExec..." -Priority High -Description "From $PsExecUrl..." -ErrorVariable err
    		If ($err) {Write-Warning " - Could not download PsExec!"; Pause "exit"; break}
    		$SourceFile = $DestinationFile
        }
        Write-Host -ForegroundColor White " - Pre-installing Windows Identity Foundation on `"$server`" via PsExec..."
        Start-Process -FilePath "$PsExec" `
                      -ArgumentList "/acceptEula \\$server -u $Username -p $Password -h wusa.exe `"$env:SPbits\PrerequisiteInstallerFiles\$wifHotfix`" /quiet /norestart" `
                      -Wait -NoNewWindow
    }
}

Function Start-RemoteInstaller ($Server, $Password, $InputFile)
{
    If ($Password) {$Credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$Credential) {$Credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($Session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $Session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $Credential -ComputerName $server
    }
    # Crude way of checking if SP2010 is already installed
    $SPInstalledOnRemote = Invoke-Command -ScriptBlock {Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\BIN\stsadm.exe"} -Session $Session
    Write-Host -ForegroundColor Green " - Sharepoint binaries are"($SPInstalledOnRemote -replace "True","already" -replace "False","not yet") "installed on $server."
    # Set some remote variables that we will need...
    Invoke-Command -ScriptBlock {param ($Value) Set-Variable -Name dp0 -Value $Value} -ArgumentList $env:dp0 -Session $Session
    Invoke-Command -ScriptBlock {param ($Value) Set-Variable -Name InputFile -Value $Value} -ArgumentList $InputFile -Session $Session
    Write-Host -ForegroundColor White " - Launching AutoSPInstaller..."
    Invoke-Command -ScriptBlock {& "$dp0\AutoSPInstallerMain.ps1" "$InputFile"} -Session $Session
    Write-Host -ForegroundColor White " - Removing session `"$($Session.Name)...`""
    Remove-PSSession $Session
}

#EndRegion

#Region Miscellaneous/Utility Functions
# ===================================================================================
# Func: Load SharePoint Powershell Snapin
# Desc: Load SharePoint Powershell Snapin
# ===================================================================================
Function Load-SharePoint-Powershell
{
	If ((Get-PsSnapin |?{$_.Name -eq "Microsoft.SharePoint.PowerShell"})-eq $null)
	{
    	WriteLine
		Write-Host -ForegroundColor White " - Loading SharePoint Powershell Snapin"
        # Added the line below to match what the SharePoint.ps1 file implements (normally called via the SharePoint 2010 Management Shell Start Menu shortcut)
        If (Confirm-LocalSession) {$Host.Runspace.ThreadOptions = "ReuseThread"}
		Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop
		WriteLine
	}
}

# ===================================================================================
# Func: ConvertTo-PlainText
# Desc: Convert string to secure phrase
#       Used (for example) to get the Farm Account password into plain text as input to provision the User Profile Sync Service
#       From http://www.vistax64.com/powershell/159190-read-host-assecurestring-problem.html
# ===================================================================================
Function ConvertTo-PlainText( [security.securestring]$secure )
{
	$marshal = [Runtime.InteropServices.Marshal]
	$marshal::PtrToStringAuto( $marshal::SecureStringToBSTR($secure) )
}

# ===================================================================================
# Func: Pause
# Desc: Wait for user to press a key - normally used after an error has occured or input is required
# ===================================================================================
Function Pause($action)
{
	#From http://www.microsoft.com/technet/scriptcenter/resources/pstips/jan08/pstip0118.mspx
	Write-Host "Press any key to $action..."
	$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===================================================================================
# Func: ShouldIProvision
# Desc: Returns TRUE if the item whose configuration node is passed in should be provisioned.
#       on this machine.
# ===================================================================================
Function ShouldIProvision([System.Xml.XmlNode] $node)
{
	If (!$node) {Return $false} # In case the node doesn't exist in the XML file
	# Allow for comma- or space-delimited list of server names in Provision or Start attribute
	If ($node.GetAttribute("Provision")) {$v = $node.GetAttribute("Provision").Replace(","," ")}
    ElseIf ($node.GetAttribute("Start")) {$v = $node.GetAttribute("Start").Replace(","," ")}
	ElseIf ($node.GetAttribute("Install")) {$v = $node.GetAttribute("Install").Replace(","," ")}
	If ($v -eq $true) { Return $true; }
	$v = " " + $v.ToUpper() + " ";
	If ($v.IndexOf(" " + $env:COMPUTERNAME.ToUpper() + " ") -ge 0) { Return $true; }
	Return $false;
}

# ====================================================================================
# Func: Add-SQLAlias
# Desc: Creates a local SQL alias (like using cliconfg.exe) so the real SQL server/name doesn't get hard-coded in SharePoint
# From: Bill Brockbank, SharePoint MVP (billb@navantis.com)
# ====================================================================================

Function Add-SQLAlias()
{
    <#
    .Synopsis
        Add a new SQL server Alias
    .Description
        Adds a new SQL server Alias with the provided parameters.
    .Example
                Add-SQLAlias -AliasName "SharePointDB" -SQLInstance $env:COMPUTERNAME
    .Example
                Add-SQLAlias -AliasName "SharePointDB" -SQLInstance $env:COMPUTERNAME -Port '1433'
    .Parameter AliasName
        The new alias Name.
    .Parameter SQLInstance
                The SQL server Name os Instance Name
    .Parameter Port
        Port number of SQL server instance. This is an optional parameter.
    #>
    [CmdletBinding(DefaultParameterSetName="BuildPath+SetupInfo")]
    param
    (
        [Parameter(Mandatory=$false, ParameterSetName="BuildPath+SetupInfo")][ValidateNotNullOrEmpty()]
        [String]$AliasName = "SharePointDB",
    
        [Parameter(Mandatory=$false, ParameterSetName="BuildPath+SetupInfo")][ValidateNotNullOrEmpty()]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [Parameter(Mandatory=$false, ParameterSetName="BuildPath+SetupInfo")][ValidateNotNullOrEmpty()]
        [String]$Port = ""
    )

    $serverAliasConnection="DBMSSOCN,$SQLInstance"
    If ($Port -ne "")
    {
         $serverAliasConnection += ",$Port"
    }
    $NotExist=$true
    $Client=Get-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client'
    $Client.GetSubKeyNames() | ForEach-Object -Process { If ( $_ -eq 'ConnectTo') { $NotExist=$false }}
    If ($NotExist)
    {
        $Data = New-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo'
    }
    #Add Alias
    $Data = New-ItemProperty HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo -Name $AliasName -Value $serverAliasConnection -PropertyType "String" -Force -ErrorAction SilentlyContinue
}

# ====================================================================================
# Func: CheckSQLAccess
# Desc: Checks if the install account has the correct SQL database access and permissions
# By: 	Sameer Dhoot (http://sharemypoint.in/about/sameerdhoot/)
# From:	http://sharemypoint.in/2011/04/18/powershell-script-to-check-sql-server-connectivity-version-custering-status-user-permissions/
# Adapted for use in AutoSPInstaller by @brianlala
# ====================================================================================
Function CheckSQLAccess
{
	WriteLine
	# Look for references to DB Servers, Aliases, etc. in the XML
    ForEach ($node in $xmlinput.SelectNodes("//*[DBServer]|//*[@DatabaseServer]|//*[@FailoverDatabaseServer]"))
    {
        $DBServer = (GetFromNode $node "DBServer")
       	If ($node.DatabaseServer) {$DBServer = GetFromNode $node "DatabaseServer"}
        #If the DBServer has been specified, and we've asked to set up an alias, create one
       	If (!([string]::IsNullOrEmpty($DBServer)) -and ($node.DBAlias.Create -eq $true))
        {
            $DBInstance = GetFromNode $node.DBAlias "DBInstance"
            $DBPort = GetFromNode $Node.DBAlias "DBPort"
    		# If no DBInstance has been specified, but Create="$True", set the Alias to the server value
    		If (($DBInstance -eq $null) -and ($DBInstance -ne "")) {$DBInstance = $DBServer}
    		If (($DBPort -ne $null) -and ($DBPort -ne "")) 
    		{
    			Write-Host -ForegroundColor White " - Creating SQL alias `"$DBServer,$DBPort`"..."
    			Add-SQLAlias -AliasName $DBServer -SQLInstance $DBInstance -Port $DBPort
    		}
    		Else # Create the alias without specifying the port (use default)
    		{
    			Write-Host -ForegroundColor White " - Creating SQL alias `"$DBServer`"..."
    			Add-SQLAlias -AliasName $DBServer -SQLInstance $DBInstance
    		}
    	}
        $DBServers += @($DBServer)
    }

	$currentUser = "$env:USERDOMAIN\$env:USERNAME"
	$serverRolesToCheck = "dbcreator","securityadmin"
	# If we are provisioning PerformancePoint but aren't running SharePoint 2010 Service Pack 1 yet, we need sysadmin in order to run the RenameDatabase function
	If (($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -and (ShouldIProvision ($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -eq $true) -and (!(CheckForSP1)))  
	{
		$serverRolesToCheck = "dbcreator","securityadmin","sysadmin"	
	}

	ForEach ($sqlServer in ($DBServers | Select-Object -Unique))
	{
		If ($sqlServer) # Only check the SQL instance if it has a value
		{
			$objSQLConnection = New-Object System.Data.SqlClient.SqlConnection
			$objSQLCommand = New-Object System.Data.SqlClient.SqlCommand
			Try
			{
				$objSQLConnection.ConnectionString = "Server=$sqlServer;Integrated Security=SSPI;"
				Write-Host -ForegroundColor White " - Testing access to SQL server/instance/alias:" $sqlServer
				Write-Host -ForegroundColor White " - Trying to connect to `"$sqlServer`"..." -NoNewline
				$objSQLConnection.Open() | Out-Null
				Write-Host -ForegroundColor Black -BackgroundColor Blue "Success"
				$strCmdSvrDetails = "SELECT SERVERPROPERTY('productversion') as Version"
				$strCmdSvrDetails += ",SERVERPROPERTY('IsClustered') as Clustering"
				$objSQLCommand.CommandText = $strCmdSvrDetails
				$objSQLCommand.Connection = $objSQLConnection
				$objSQLDataReader = $objSQLCommand.ExecuteReader()
				If ($objSQLDataReader.Read())
				{
					Write-Host -ForegroundColor White (" - SQL Server version is: {0}" -f $objSQLDataReader.GetValue(0))
                    $SQLVersion = $objSQLDataReader.GetValue(0)
           			[int]$SQLMajorVersion,[int]$SQLMinorVersion,[int]$SQLBuild,$null = $SQLVersion -split "\."
                    # SharePoint needs minimum SQL 2008 10.0.2714.0 or SQL 2005 9.0.4220.0 per http://support.microsoft.com/kb/976215
            		If ((($SQLMajorVersion -eq 10) -and ($SQLMinorVersion -lt 5) -and ($SQLBuild -lt 2714)) -or (($SQLMajorVersion -eq 9) -and ($SQLBuild -lt 4220)))
            		{
            			Throw " - Unsupported SQL version!"
            		}
					If ($objSQLDataReader.GetValue(1) -eq 1)
					{
						Write-Host -ForegroundColor White " - This instance of SQL Server is clustered"
					} 
					Else 
					{
						Write-Host -ForegroundColor White " - This instance of SQL Server is not clustered"
					}
				}
				$objSQLDataReader.Close()
				ForEach($serverRole in $serverRolesToCheck) 
				{
					$objSQLCommand.CommandText = "SELECT IS_SRVROLEMEMBER('$serverRole')"
					$objSQLCommand.Connection = $objSQLConnection
					Write-Host -ForegroundColor White " - Check if $currentUser has $serverRole server role..." -NoNewline
					$objSQLDataReader = $objSQLCommand.ExecuteReader()
					If ($objSQLDataReader.Read() -and $objSQLDataReader.GetValue(0) -eq 1)
					{
						Write-Host -BackgroundColor Blue -ForegroundColor Black "Pass"
					}
					ElseIf($objSQLDataReader.GetValue(0) -eq 0) 
					{
						Throw " - $currentUser does not have `'$serverRole`' role!"
					}
					Else 
					{
						Write-Host -ForegroundColor Red "Invalid Role"
					}
					$objSQLDataReader.Close()
				}
				$objSQLConnection.Close()
			}
			Catch 
			{
				Write-Host -ForegroundColor Red " - Fail"
				$errText = $Error[0].ToString()
				If ($errText.Contains("network-related"))
				{
					Throw " - Connection Error. Check server name, port, firewall."
				}
				ElseIf ($errText.Contains("Login failed"))
				{
					Throw " - Not able to login. SQL Server login not created."
				}
                ElseIf ($errText.Contains("Unsupported SQL version"))
                {
                    Throw " - SharePoint 2010 requires SQL 2005 SP3+CU3, SQL 2008 SP1+CU2, or SQL 2008 R2."
                }
				Else
				{
					Throw " - $currentUser does not have `'$serverRole`' role!"
				}
			}
		}
	}
	WriteLine
}

# ====================================================================================
# Func: RenameDatabase()
# Desc: Renames a SQL database and the database files
# ====================================================================================
Function RenameDatabase([string]$sqlServer,[string]$oldName,[string]$newName)
{
	$objSQLConnection = New-Object System.Data.SqlClient.SqlConnection
	$objSQLCommand = New-Object System.Data.SqlClient.SqlCommand
	$objSQLConnection.ConnectionString = "Server=$sqlServer;Integrated Security=SSPI;"
	$objSQLConnection.Open() | Out-Null
	$strCmdSvrDetails = @"
EXEC ('
declare @oldname nvarchar(4000)
declare @newname nvarchar(4000)
set @oldname=''$oldName''
set @newname=''$newName''
EXEC sp_configure ''show advanced options'', 1
RECONFIGURE
create table #opt ( name sysname, minimum int, maximum int,config_value int, run_value int)
insert into #opt exec sp_configure ''xp_cmdshell''
DECLARE @oldcmdshell int
SELECT @oldcmdshell = config_value FROM #opt
EXEC sp_configure ''xp_cmdshell'', 1
RECONFIGURE
declare @datapath nvarchar(4000)
declare @logpath nvarchar(4000)
declare @dataname nvarchar(4000)
declare @logname nvarchar(4000)
select @datapath = replace(physical_name,@oldname + ''.mdf'',''''), @dataname=Name from master.sys.master_files where type=0 and database_id = DB_ID(@oldname)
select @logpath = replace(physical_name,@oldname + ''_log.ldf'',''''), @logname=Name from master.sys.master_files where type=1 and database_id = DB_ID(@oldname)
EXEC (''ALTER DATABASE ['' + @oldname + ''] SET SINGLE_USER WITH ROLLBACK IMMEDIATE'')
EXEC (''ALTER DATABASE ['' + @oldname + ''] MODIFY NAME = ['' + @newname + '']'')
EXEC (''ALTER DATABASE ['' + @newname + ''] MODIFY FILE (
	NAME=N'''''' + @dataname + '''''',
	NEWNAME=N'''''' + @newname + '''''',
	FILENAME=N'''''' + @datapath + @newname + ''.mdf'''')'')
EXEC (''ALTER DATABASE ['' + @newname + ''] MODIFY FILE (
	NAME=N'''''' + @logname + '''''', 
	NEWNAME=N'''''' + @newname + ''_log'''',
	FILENAME=N'''''' + @logpath + @newname + ''_log.ldf'''')'')
EXEC (''ALTER DATABASE ['' + @newname + ''] SET OFFLINE'')
EXEC (''EXEC xp_cmdshell ''''RENAME "'' + @datapath + @dataname + ''.mdf", "'' + @newname + ''.mdf"'''''')
EXEC (''EXEC xp_cmdshell ''''RENAME "'' + @logpath + @logname + ''.ldf", "'' + @newname + ''_log.ldf"'''''')
EXEC (''ALTER DATABASE ['' + @newname + ''] SET ONLINE'')
EXEC (''ALTER DATABASE ['' + @newname + ''] SET MULTI_USER WITH ROLLBACK IMMEDIATE'')
EXEC sp_configure ''xp_cmdshell'',@oldcmdshell
RECONFIGURE
drop table #opt
')
"@

	$objSQLCommand.CommandText = $strCmdSvrDetails
	$objSQLCommand.Connection = $objSQLConnection
	$objSQLCommand.ExecuteNonQuery()
	$objSQLConnection.Close()
}

# ====================================================================================
# Func: WriteLine
# Desc: Writes a nice line of dashes across the screen
# ====================================================================================
Function WriteLine
{
	Write-Host -ForegroundColor White "--------------------------------------------------------------"
}

# ====================================================================================
# Func: Run-HealthAnalyzerJobs
# Desc: Runs all Health Analyzer Timer Jobs Immediately
# From: http://www.sharepointconfig.com/2011/01/instant-sharepoint-health-analysis/
# ====================================================================================
Function Run-HealthAnalyzerJobs
{
	$HealthJobs = Get-SPTimerJob | Where {$_.DisplayName -match "Health Analysis Job"}
	Write-Host -ForegroundColor White " - Running all Health Analyzer jobs..."
	ForEach ($Job in $HealthJobs)
	{
		$Job.RunNow()
	}
}

# ====================================================================================
# Func: InstallSMTP
# Desc: Installs the SMTP Server Windows feature
# ====================================================================================
Function InstallSMTP
{
	If (ShouldIProvision($xmlinput.Configuration.Farm.Services.SMTP) -eq $true)
	{
		WriteLine
		Write-Host -ForegroundColor White " - Installing SMTP Server feature..."
		$QueryOS = Gwmi Win32_OperatingSystem
  		$QueryOS = $QueryOS.Version 
    	$OS = ""
    	If ($QueryOS.contains("6.1")) {$OS = "Win2008R2"}
    	ElseIf ($QueryOS.contains("6.0")) {$OS = "Win2008"}
		If ($OS -eq "Win2008R2")
		{
            # Get the current progress preference
            $pref = $ProgressPreference
            # Hide the progress bar since it tends to not disappear
            $ProgressPreference = "SilentlyContinue"
			Import-Module ServerManager
			Add-WindowsFeature -Name SMTP-Server | Out-Null
            # Restore progress preference
            $ProgressPreference = $pref
			If (!($?)) {Throw " - Failed to install SMTP Server!"}
		}
			Else # Win2008
		{
			Start-Process -FilePath servermanagercmd.exe -ArgumentList "-install smtp-server" -Wait -NoNewWindow
		}
		Write-Host -ForegroundColor White " - Done."
		WriteLine
	}
}

# ====================================================================================
# Func: FixTaxonomyPickerBug
# Desc: Renames the TaxonomyPicker.ascx file which doesn't seem to be used anyhow
# Desc: Goes one step further than the fix suggested in http://support.microsoft.com/kb/2481844 (which doesn't work at all)
# ====================================================================================
Function FixTaxonomyPickerBug
{
	$TaxonomyPicker = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\TEMPLATE\CONTROLTEMPLATES\TaxonomyPicker.ascx"
	If (Test-Path $TaxonomyPicker) 
	{
		WriteLine
		Write-Host -ForegroundColor White " - Renaming TaxonomyPicker.ascx..."
		Move-Item -Path $TaxonomyPicker -Destination $TaxonomyPicker".buggy" -Force
		Write-Host -ForegroundColor White " - Done."
		WriteLine
	}
}

# ====================================================================================
# Func: CheckForSP1
# Desc: Returns $true if the farm build number or SharePoint DLL is at Service Pack 1 (6029) or greater (or if slipstreamed SP1 is detected); otherwise returns $false
# Desc: Helps to determine whether certain new/updated cmdlets are available
# ====================================================================================
Function CheckForSP1
{
	If (Get-Command Get-SPFarm -ErrorAction SilentlyContinue)
	{
		# Try to get the version of the farm first
		$Build = (Get-SPFarm).BuildVersion.Build
		If (!($Build)) # Get the ProductVersion of a SharePoint DLL instead, since the farm doesn't seem to exist yet
		{
			$SP2010ProdVer = (Get-Command $env:CommonProgramFiles'\Microsoft Shared\Web Server Extensions\14\isapi\microsoft.sharepoint.portal.dll').FileVersionInfo.ProductVersion
			$null,$null,[int]$Build,$null = $SP2010ProdVer -split "\."
		}
		If ($Build -ge 6029)
		{
			Return $true
		}
	}
	#SharePoint probably isn't installed yet, so try to see if we have slipstreamed SP1 in the \Updates folder at least...
	ElseIf (Get-Item "$bits\SharePoint\Updates\oserversp1-x-none.msp" -ErrorAction SilentlyContinue)
	{
		Return $true
	}
	Else
	{
		Return $false
	}
}

# ====================================================================================
# Func: CheckIfUpgradeNeeded
# Desc: Returns $true if the server or farm requires an upgrade (i.e. requires PSConfig or the corresponding Powershell commands to be run)
# ====================================================================================
Function CheckIfUpgradeNeeded
{
	$SetupType = (Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\WSS\').GetValue("SetupType")
	<#If (((Get-SPServer $env:COMPUTERNAME).NeedsUpgrade -eq $True) -or `
		((Get-SPServer $env:COMPUTERNAME).NeedsUpgradeIncludeChildren -eq $True) -or `
		((Get-SPFarm).NeedsUpgrade -eq $True) -or `
		((Get-SPFarm).NeedsUpgradeIncludeChildren -eq $True))#>
	If ($SetupType -ne "CLEAN_INSTALL") # For example, if the value is "B2B_UPGRADE"
	{
		Return $true
	}
	Else
	{
		Return $false
	}
}

# ====================================================================================
# Func: AddToHOSTS
# Desc: This writes URLs to the server's local hosts file and points them to the server itself
# From: Check http://toddklindt.com/loopback for more information
# Copyright Todd Klindt 2011
# Originally published to http://www.toddklindt.com/blog
# ====================================================================================
Function AddToHOSTS
{
	Write-Host -ForegroundColor White " - Adding HOSTS file entries for local resolution..."
	# Make backup copy of the Hosts file with today's date
	$hostsfile = "$env:windir\System32\drivers\etc\HOSTS"
	$date = Get-Date -UFormat "%y%m%d%H%M%S"
	$filecopy = $hostsfile + '.' + $date + '.copy'
	Write-Host -ForegroundColor White " - Backing up HOSTS file to:"
	Write-Host -ForegroundColor White " - $filecopy"
	Copy-Item $hostsfile -Destination $filecopy

	# Get a list of the AAMs and weed out the duplicates
	$hosts = Get-SPAlternateURL | ForEach-Object {$_.incomingurl.replace("https://","").replace("http://","")} | where-Object { $_.tostring() -notlike "*:*" } | Select-Object -Unique
	 
	# Get the contents of the Hosts file
	$file = Get-Content $hostsfile
	$file = $file | Out-String

	# Write the AAMs to the hosts file, unless they already exist.
	ForEach ($hostname in $hosts)
	{
		If ($file.contains($hostname))
		{Write-Host -ForegroundColor White " - HOSTS file entry for `"$hostname`" already exists - skipping."} 
		Else
		{
			Write-Host -ForegroundColor White " - Adding HOSTS file entry for `"$hostname`"..."
			Add-Content -Path $hostsfile -Value "`r"
			Add-Content -Path $hostsfile -value "127.0.0.1 `t $hostname"
			$KeepHOSTSCopy = $true
		}
	}
	If (!$KeepHOSTSCopy)
	{
		Write-Host -ForegroundColor White " - Deleting HOSTS backup file since no changes were made..."
		Remove-Item $filecopy
	}
}

# ====================================================================================
# Func: Add-LocalIntranetURL
# Desc: Adds a URL to the local Intranet zone (Internet Control Panel) to allow pass-through authentication in Internet Explorer (avoid prompts)
# ====================================================================================
Function Add-LocalIntranetURL ($url)
{
	If (($url -like "*.*") -and (($WebApp.AddURLToLocalIntranetZone) -eq $true))
	{
		$url = $url -replace "https://",""
		$url = $url -replace "http://",""
		$SplitURL = $url -split "\."
		$urlDomain = $SplitURL[-2] + "." + $SplitURL[-1]
		Write-Host -ForegroundColor White " - Adding *.$urlDomain to local Intranet security zone..."
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Name $urlDomain -ItemType Leaf -Force | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$urlDomain" -Name '*' -value "1" -PropertyType dword -Force | Out-Null
	}
}

# ====================================================================================
# Func: CompressFolder
# Desc: Enables NTFS compression for a given folder
# From: Based on concepts & code found at http://www.humanstuff.com/2010/6/24/how-to-compress-a-file-using-powershell
# ====================================================================================
Function CompressFolder ($Folder)
{
	# Replace \ with \\ for WMI
    $WmiPath = $Folder.Replace("\","\\")
	$WmiDirectory = Get-WmiObject -Class "Win32_Directory" -Namespace "root\cimv2" -ComputerName $env:COMPUTERNAME -Filter "Name='$WmiPath'"
    # Check if folder is already compressed
    If (!($WmiDirectory.Compressed))
    {
        Write-Host -ForegroundColor White " - Compressing $Folder and subfolders..."
        $Compress = $WmiDirectory.CompressEx("","True")
    }
	Else {Write-Host -ForegroundColor White " - $Folder is already compressed."}
}

# ====================================================================================
# Func: EnsureFolder
# Desc: Checks for the existence and validity of a given path, and attempts to create if it doesn't exist.
# From: Modified from patch 9833 at http://autospinstaller.codeplex.com/SourceControl/list/patches by user timiun
# ====================================================================================
Function EnsureFolder ($Path)
{
		If (!(Test-Path -Path $Path -PathType Container))
		{
			Write-Host -ForegroundColor White " - $Path doesn't exist; creating..."
			Try 
			{
				New-Item -Path $Path -ItemType Directory | Out-Null
			}
			Catch
			{				
				Write-Warning " - $($_.Exception.Message)"
				Throw " - Could not create folder $Path!"
			}
		}
}

Function GetFromNode([System.Xml.XmlElement]$node, [string] $item)
{
	$value = $node.GetAttribute($item)
	If ($value -eq "") 
	{ 
		$child = $node.SelectSingleNode($item);
		If ($child -ne $null)
		{
			Return $child.InnerText;
		}
	}
	Return $value;
}

# ====================================================================================
# Func: ImportWebAdministration
# Desc: Load IIS WebAdministration Snapin/Module
# From: Inspired by http://stackoverflow.com/questions/1924217/powershell-load-webadministration-in-ps1-script-on-both-iis-7-and-iis-7-5
# ====================================================================================
Function ImportWebAdministration
{
    $QueryOS = Gwmi Win32_OperatingSystem
    $QueryOS = $QueryOS.Version 
    $OS = ""
    If ($QueryOS.contains("6.1")) {$OS = "Win2008R2"}
    ElseIf ($QueryOS.contains("6.0")) {$OS = "Win2008"}
    
	Try
	{
		If ($OS -eq "Win2008")
		{
			If (!(Get-PSSnapin WebAdministration -ErrorAction SilentlyContinue))
			{	 
  				If (!(Test-Path $env:ProgramFiles\IIS\PowerShellSnapin\IIsConsole.psc1)) 
				{
					Start-Process -Wait -NoNewWindow -FilePath msiexec.exe -ArgumentList "/i `"$env:SPbits\PrerequisiteInstallerFiles\iis7psprov_x64.msi`" /passive /promptrestart"
				}
				Add-PSSnapin WebAdministration
			}
		}
		Else # Win2008R2
		{ 
  			Import-Module WebAdministration
		}
	}
	Catch
	{
		Throw " - Could not load IIS Administration module."
		
	}
}

# ====================================================================================
# Func: AddResourcesLink
# Desc: Adds an item to the Resources list shown on the Central Admin homepage
#       $url should be relative to the central admin home page and should not include the leading /
# ====================================================================================

Function AddResourcesLink([string]$title,[string]$url)
{
	$centraladminapp = (Get-spwebapplication -includecentraladministration | where {$_.DisplayName -eq "SharePoint Central Administration v4"});
	$centraladminurl = $centraladminapp.Url
	$centraladmin = (Get-SPSite $centraladminurl)

	$item = $centraladmin.RootWeb.Lists["Resources"].Items | Where { $_["URL"] -match ".*, $title" }
	If ($item -eq $null )
	{
  		$item = $centraladmin.RootWeb.Lists["Resources"].Items.Add();
	}

	$url = $centraladminurl + $url + ", $title";
	$item["URL"] = $url;
	$item.Update();
}

# ====================================================================================
# Func: PinToTaskbar
# Desc: Pins a program to the taskbar
# From: http://techibee.com/powershell/pin-applications-to-task-bar-using-powershell/685
# ====================================================================================

Function PinToTaskbar([string]$application)
{
	$shell = New-Object -ComObject "Shell.Application"
	$folder = $shell.Namespace([System.IO.Path]::GetDirectoryName($application))
		
	Foreach ($verb in $folder.ParseName([System.IO.Path]::GetFileName($application)).verbs()) 
	{
		If($verb.name.replace("&","") -match "Pin to Taskbar") 
		{
			$verb.DoIt()
		}
	}	
}

# ====================================================================================
# Func: Get-AdministratorsGroup
# Desc: Returns the actual (localized) name of the built-in Administrators group
# From: Proposed by Codeplex user Sheppounet at http://autospinstaller.codeplex.com/discussions/265749
# ====================================================================================

Function Get-AdministratorsGroup
{
    If(!$builtinAdminGroup)
	{
		$builtinAdminGroup = (Get-WmiObject -Class Win32_Group -computername $env:COMPUTERNAME -Filter "SID='S-1-5-32-544' AND LocalAccount='True'" -errorAction "Stop").Name
	}
    Return $builtinAdminGroup
}

# ====================================================================================
# Func: Confirm-LocalSession
# Desc: Returns $false if we are running over a PS remote session, $true otherwise
# From: Brian Lalancette, 2012
# ====================================================================================

Function Confirm-LocalSession
{
    # Another way
    # If ((Get-Process -Id $PID).ProcessName -eq "wsmprovhost") {Return $false}
    If ($Host.Name -eq "ServerRemoteHost") {Return $false}
    Else {Return $true}   
}
Function Get-SharePointInstall
{
    #Crude way of checking if SP2010 is already installed
    If (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14\BIN\stsadm.exe")
    {
        return $true
    }
    Else {return $false}
}

# ====================================================================================
# Func: Show-Progress
# Desc: Shows a row of dots to let us know that $Process is still running
# From: Brian Lalancette, 2012
# ====================================================================================
Function Show-Progress ($Process, $Color, $Interval)
{
    $indicators = @("/","-","\","|")
    While (Get-Process -Name $Process -ErrorAction SilentlyContinue)
    {
        Write-Host -ForegroundColor $Color "." -NoNewline
        Start-Sleep $Interval
    }
    Write-Host -ForegroundColor $Color "Done."
}

#EndRegion