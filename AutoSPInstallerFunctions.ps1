# ===================================================================================
# EXTERNAL FUNCTIONS
# ===================================================================================

#Region Validate Passphrase
Function ValidatePassphrase([xml]$xmlinput)
{
    # Check if passphrase is supplied
    $farmPassphrase = $xmlinput.Configuration.Farm.Passphrase
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {       
        Return
    }
    $groups=0
    If ($farmPassphrase -match "[a-z]") { $groups = $groups + 1 }
    If ($farmPassphrase -match "[A-Z]") { $groups = $groups + 1 }
    If ($farmPassphrase -match "[0-9]") { $groups = $groups + 1 }
    If ($farmPassphrase -match "[^a-zA-Z0-9]") { $groups = $groups + 1 }
    
    If (($groups -lt 3) -or ($farmPassphrase.length -lt 8))
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
            $currentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            Write-Host -ForegroundColor White " - Account `"$user`"..." -NoNewline
            $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain,$user,$password)
            If ($dom.Path -eq $null)
            {
                Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid!"
                $acctInvalid = $true
            }
            Else 
            {
                Write-Host -ForegroundColor Black -BackgroundColor Green "Verified."
            }
        }
    }
        If ($acctInvalid) {Throw " - At least one set of credentials is invalid.`n - Check usernames and passwords in each place they are used."}
    WriteLine
}
#EndRegion

#Region Trust Source Path & Remove IE Enhanced Security
Function AddSourcePathToLocalIntranetZone
{
    # Ensure that if we're running from a UNC path, the host portion is added to the Local Intranet zone so we don't get the "Open File - Security Warning"
    If ($env:dp0 -like "\\*")
    {
        WriteLine
        $safeHost = ($env:dp0 -split "\\")[2]
        Write-Host -ForegroundColor White " - Adding `"$safeHost`" to local Intranet security zone..."
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Name $safeHost -ItemType Leaf -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$safeHost" -Name "file" -value "1" -PropertyType dword -Force | Out-Null
        WriteLine
    }
}

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
Function StartTracing ($server)
{
    If (!$isTracing)
    {
        # Look for an existing log file start time in the registry so we can re-use the same log file
		$regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue
		If ($regKey) {$script:Logtime = $regkey.GetValue("LogTime")}
		If ([string]::IsNullOrEmpty($logtime)) {$script:Logtime = Get-Date -Format yyyy-MM-dd_h-mm}
        If ($server) {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$server-$script:Logtime.rtf"}
        else {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$script:Logtime.rtf"}
        Start-Transcript -Path $logFile -Append -Force
        If ($?) {$script:isTracing = $true}
    }
}
#EndRegion

#Region Check Configuration File 
Function CheckConfig
{
    # Check that the config file exists.
    If (-not $(Test-Path -Path $inputFile -Type Leaf))
    {
        Write-Error -message (" - Configuration file '" + $inputFile + "' does not exist.")
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
    If ($env:USERDOMAIN+"\"+$env:USERNAME -eq $farmAcct) 
    {
        Write-Host  -ForegroundColor Yellow " - WARNING: Running install using Farm Account: $farmAcct"
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

        $lsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
        $lsaPathValue = Get-ItemProperty -path $lsaPath
        If (-not ($lsaPathValue.DisableLoopbackCheck -eq "1"))
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

        $servicesToSetManual = "Spooler","AudioSrv","TabletInputService"
        ForEach ($svcName in $servicesToSetManual)
        {
            $svc = get-wmiobject win32_service | where-object {$_.Name -eq $svcName} 
            $svcStartMode = $svc.StartMode
            $svcState = $svc.State
            If (($svcState -eq "Running") -and ($svcStartMode -eq "Auto"))
            {
                Stop-Service -Name $svcName
                Set-Service -name $svcName -StartupType Manual
                Write-Host -ForegroundColor White " - Service $svcName is now set to Manual start"
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $svcName is already stopped and set Manual, no action required."
            }
        }
        
        Write-Host -ForegroundColor White " - Setting unused services WerSvc to Disabled..."
        $servicesToDisable = "WerSvc"
        ForEach ($svcName in $servicesToDisable) 
        {
            $svc = get-wmiobject win32_service | where-object {$_.Name -eq $svcName} 
            $svcStartMode = $svc.StartMode
            $svcState = $svc.State
            If (($svcState -eq "Running") -and (($svcStartMode -eq "Auto") -or ($svcStartMode -eq "Manual")))
            {
                Stop-Service -Name $svcName
                Set-Service -name $svcName -StartupType Disabled
                Write-Host -ForegroundColor White " - Service $svcName is now stopped and disabled."
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $svcName is already stopped and disabled, no action required."
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
    # Remove any lingering registry restart requirement value first
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "RestartRequired" -ErrorAction SilentlyContinue
    # Check for whether UAC was previously enabled and should therefore be re-enabled after an automatic restart
	$regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue
	If ($regKey) {$UACWasEnabled = $regkey.GetValue("UACWasEnabled")}
	If ($UACWasEnabled -eq 1) {Set-UserAccountControl 1}
    # Now, remove the lingering registry UAC flag
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "UACWasEnabled" -ErrorAction SilentlyContinue
    # Create a hash table with major version to product year mappings
    $spYears = @{"14" = "2010"; "15" = "2013"}
    $spYear = $spYears.$env:spVer
    $spInstalled = Get-SharePointInstall
    If ($spInstalled)
    {
        Write-Host -ForegroundColor White " - SharePoint $spYear prerequisites appear be already installed - skipping install."
    }
    Else
    {
        Write-Host -ForegroundColor White " - Installing Prerequisite Software:"
        If (($env:spVer -eq "14") -and ((Gwmi Win32_OperatingSystem).Version -eq "6.1.7601")) # SP2010 on Win2008 R2 SP1
        {
            # Due to the issue described in http://support.microsoft.com/kb/2581903 (related to installing the KB976462 hotfix) 
            # we install the .Net 3.5.1 features prior to attempting the PrerequisiteInstaller on Win2008 R2 SP1
            Write-Host -ForegroundColor White "  - .Net Framework..."
            # Get the current progress preference
            $pref = $ProgressPreference
            # Hide the progress bar since it tends to not disappear
            $ProgressPreference = "SilentlyContinue"
            Import-Module ServerManager
            If (!(Get-WindowsFeature -Name NET-Framework).Installed) {Add-WindowsFeature -Name NET-Framework | Out-Null}
            # Restore progress preference
            $ProgressPreference = $pref
        }
        Try
        {
			# Install prerequisites manually without using PrerequisiteInstaller if we're installing SP2010 on on Windows Server 2012
            if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*") -and ($env:spVer -eq "14"))
            {
			    Throw " - SharePoint 2010 is officially unsupported on Windows Server 2012 - see http://support.microsoft.com/kb/2724471"
			}
            else # Install using PrerequisiteInstaller as usual
            {
                If ($xmlinput.Configuration.Install.OfflineInstall -eq $true) # Install all prerequisites from local folder
                {
                    If ($env:spVer -eq "14") # SP2010
                    {
                        Write-Host -ForegroundColor White "  - SQL Native Client..."
                        # Install SQL native client before running pre-requisite installer as newest versions require an IACCEPTSQLNCLILICENSETERMS=YES argument
                        Start-Process "$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi" -Wait -ArgumentList "/passive /norestart IACCEPTSQLNCLILICENSETERMS=YES"
                        Write-Host -ForegroundColor Blue "  - Running Prerequisite Installer (offline mode)..." -NoNewline
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
                    ElseIf ($env:spVer -eq "15") #SP2013
                    {
                        Write-Host -ForegroundColor Blue "  - Running Prerequisite Installer (offline mode)..." -NoNewline
                        $startTime = Get-Date
                        Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended `
                                                                                             /SQLNCli:`"$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi`" `
                                                                                             /PowerShell:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.1-KB2506143-x64.msu`" `
                                                                                             /NETFX:`"$env:SPbits\PrerequisiteInstallerFiles\dotNetFx45_Full_x86_x64.exe`" `
                                                                                             /IDFX:`"$env:SPbits\PrerequisiteInstallerFiles\Windows6.1-KB974405-x64.msu`" `
                                                                                             /IDFX11:`"$env:SPbits\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi`" `
                                                                                             /Sync:`"$env:SPbits\PrerequisiteInstallerFiles\Synchronization.msi`" `
                                                                                             /AppFabric:`"$env:SPbits\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe`" `
                                                                                             /KB2671763:`"$env:SPbits\PrerequisiteInstallerFiles\AppFabric1.1-RTM-KB2671763-x64-ENU.exe`" `
                                                                                             /MSIPCClient:`"$env:SPbits\PrerequisiteInstallerFiles\setup_msipc_x64.msi`" `
                                                                                             /WCFDataServices:`"$env:SPbits\PrerequisiteInstallerFiles\WcfDataServices.exe`""
                        If (-not $?) {Throw}                                                                                             
                    }
                }
                Else # Regular prerequisite install - download required files
                {
                    Write-Host -ForegroundColor Blue "  - Running Prerequisite Installer (online mode)..." -NoNewline
                    $startTime = Get-Date
                    Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended" -WindowStyle Minimized
                    If (-not $?) {Throw}
                }
                Show-Progress -Process PrerequisiteInstaller -Color Blue -Interval 5
                $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White "  - Prerequisite Installer completed in $delta."
            }
            If ($env:spVer -eq "15") # SP2013
            {
                # Install the "missing prerequisites" for SP2013 per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=349
                Write-Host -ForegroundColor White " - SharePoint 2013 `"missing hotfix`" prerequisites..."
                # Expand hotfix executable to $env:SPbits\PrerequisiteInstallerFiles\
                if ((Gwmi Win32_OperatingSystem).Version -eq "6.1.7601") # Win2008 R2 SP1
                {
                    $missingHotfixes = @{"Windows6.1-KB2554876-v2-x64.msu" = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix368051/7600/free/433385_intl_x64_zip.exe";
					    			     "Windows6.1-KB2708075-x64.msu" = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix402568/7600/free/447698_intl_x64_zip.exe";
                                         "Windows6.1-KB2472264-v3-x64.msu" = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix354400/7600/free/427087_intl_x64_zip.exe";
                                         "Windows6.1-KB2567680-x64.msu" = "http://download.microsoft.com/download/C/D/A/CDAF5DD8-3B9A-4F8D-A48F-BEFE53C5B249/Windows6.1-KB2567680-x64.msu";
                                         "NDP45-KB2759112-x64.exe" = "http://download.microsoft.com/download/5/6/3/5631B753-A009-48AF-826C-2D2C29B94172/NDP45-KB2759112-x64.exe"}
                }
                elseif ((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*") # Win2012
                {
                    $missingHotfixes = @{"Windows8-RT-KB2765317-x64.msu" = "http://download.microsoft.com/download/0/2/E/02E9E569-5462-48EB-AF57-8DCCF852E6F4/Windows8-RT-KB2765317-x64.msu"}
                }
                $hotfixLocation = $env:SPbits+"\PrerequisiteInstallerFiles"
                ForEach ($hotfixPatch in $missingHotfixes.Keys)
                {
                    $hotfixKB = $hotfixPatch.Split('-') | Where-Object {$_ -like "KB*"}
                    # Check if the hotfix is already installed
                    Write-Host -ForegroundColor White "  - Checking for $hotfixKB..." -NoNewline
                    If (!(Get-HotFix -Id $hotfixKB -ErrorAction SilentlyContinue))
                    {
                        Write-Host -ForegroundColor White "Missing; attempting to install..."
                        $hotfixUrl = $missingHotfixes.$hotfixPatch
                        $hotfixFile = $hotfixUrl.Split('/')[-1]
                        $hotfixFileZip = $hotfixFile+".zip"
                        $hotfixZipPath = Join-Path -Path $hotfixLocation -ChildPath $hotfixFileZip
                        # Check if the .msu/.exe file is already present
                        If (Test-Path "$env:SPbits\PrerequisiteInstallerFiles\$hotfixPatch")
                        {
                            Write-Host -ForegroundColor White "  - Hotfix file `"$hotfixPatch`" found."
                        }
                        Else
                        {
                            # Check if the downloaded package exists with a .zip extension
                            If (!([string]::IsNullOrEmpty($hotfixFileZip)) -and (Test-Path "$hotfixLocation\$hotfixFileZip"))
                            {
                                Write-Host -ForegroundColor White "  - File $hotfixFile (zip) found."
                            }
                        	Else
                            {
                                # Check if the downloaded package exists
                                If (Test-Path "$hotfixLocation\$hotfixFile")
                            	{
                            		Write-Host -ForegroundColor White "  - File $hotfixFile found."
                            	}
                                Else # Go ahead and download the missing package
                            	{
                                    Try
                                    {
                                		# Begin download
                                        Write-Host -ForegroundColor White "  - Hotfix $hotfixPatch not found in $env:SPbits\PrerequisiteInstallerFiles"
                                        Write-Host -ForegroundColor White "  - Attempting to download..." -NoNewline
                                        Import-Module BitsTransfer | Out-Null
                                        Start-BitsTransfer -Source $hotfixUrl -Destination "$hotfixLocation\$hotfixFile" -DisplayName "Downloading `'$hotfixFile`' to $hotfixLocation" -Priority Foreground -Description "From $hotfixUrl..." -ErrorVariable err
                                        if ($err) {Write-Host "."; Throw "  - Could not download from $hotfixUrl!"}
                                        Write-Host -ForegroundColor White "Done!"
                                	}
                                    Catch
                                    {
                                    	Write-Warning "  - An error occurred attempting to download `"$hotfixFile`"."
                                    	break
                                    }
                                }
                                if ($hotfixFile -like "*zip.exe") # The hotfix is probably a self-extracting exe
                                {
                                    # Give the file a .zip extension so we can work with it like a compressed folder
                                    Write-Host -ForegroundColor White "  - Renaming $hotfixFile to $hotfixFileZip..."
                                    Rename-Item -Path "$hotfixLocation\$hotfixFile" -NewName $hotfixFileZip -Force -ErrorAction SilentlyContinue
                                }
                            }
                            If (Test-Path "$hotfixLocation\$hotfixFileZip") # The zipped hotfix exists, ands needs to be extracted
                            {
                                Write-Host -ForegroundColor White "  - Extracting `"$hotfixPatch`" from `"$hotfixFile`"..." -NoNewline
                                $shell = New-Object -ComObject Shell.Application
                                $hotfixFileZipNs = $shell.Namespace($hotfixZipPath)
                                $hotfixLocationNs = $shell.Namespace($hotfixLocation)
                                $hotfixLocationNs.Copyhere($hotfixFileZipNs.items())
                                Write-Host -ForegroundColor White "Done."
                            }
                        }
                        # Install the hotfix
                        $extractedHotfixPath = Join-Path -Path $hotfixLocation -ChildPath $hotfixPatch
                        Write-Host -ForegroundColor White "  - Installing hotfix $hotfixPatch..." -NoNewline
                        if ($hotfixPatch -like "*.msu") # Treat as a Windows Update patch
                        {
                            Start-Process -FilePath "wusa.exe" -ArgumentList "`"$extractedHotfixPath`" /quiet /norestart" -Wait -NoNewWindow
                        }
                        else # Treat as an executable (.exe) patch
                        {
                            Start-Process -FilePath "$extractedHotfixPath" -ArgumentList "/passive /norestart" -Wait -NoNewWindow
                        }
                        Write-Host -ForegroundColor White "Done."
                    }
                    Else {Write-Host -ForegroundColor White "Already installed."}
                }
            }
        }
        Catch 
        {
            Write-Host -ForegroundColor Blue "."
            Write-Host -ForegroundColor Red " - Error: $_ $LASTEXITCODE"
            If ($LASTEXITCODE -eq "1") {Throw " - Another instance of this application is already running"}
            ElseIf ($LASTEXITCODE -eq "2") {Throw " - Invalid command line parameter(s)"}
            ElseIf ($LASTEXITCODE -eq "1001") {Throw " - A pending restart blocks installation"}
            ElseIf ($LASTEXITCODE -eq "3010") {Throw " - A restart is needed"}
            ElseIf ($LASTEXITCODE -eq "-2145124329") {Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites"; InstallPreRequisites ([xml]$xmlinput)}
            Else {Throw " - An unknown error occurred installing prerequisites"}
        }
        # Parsing most recent PreRequisiteInstaller log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
        $preReqLog = get-childitem $env:TEMP | ? {$_.Name -like "PrerequisiteInstaller.*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
        If ($preReqLog -eq $null) 
        {
            Write-Warning " - Could not find PrerequisiteInstaller log file"
        }
        Else 
        {
            # Get error(s) from log
            $preReqLastError = $preReqLog | Select-String -SimpleMatch -Pattern "Error" -Encoding Unicode | ? {$_.Line  -notlike "*Startup task*"}
            If ($preReqLastError)
            {
                ForEach ($preReqError in ($preReqLastError | ForEach {$_.Line})) {Write-Warning $preReqError}
                $preReqLastReturncode = $preReqLog | Select-String -SimpleMatch -Pattern "Last return code" -Encoding Unicode | Select-Object -Last 1
                If ($preReqLastReturnCode) {Write-Warning $preReqLastReturncode.Line}
                If (($preReqLastReturncode -like "*-2145124329*") -or ($preReqLastReturncode -like "*2359302*") -or ($preReqLastReturncode -eq "5"))
                {
                    Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites - retrying..."
                    InstallPreRequisites ([xml]$xmlinput)
                }
                ElseIf ($preReqLog | Select-String -SimpleMatch -Pattern "Error when enabling ASP.NET v4.0.30319" -Encoding Unicode)
                {
                    # Account for new issue with Win2012 RC and SP2013
                    Write-Host -ForegroundColor White " - A known issue occurred configuring .NET 4 / IIS."
                    $preReqKnownIssueRestart = $true
                }
                ElseIf ($preReqLog | Select-String -SimpleMatch -Pattern "pending restart blocks the installation" -Encoding Unicode)
                {
                    Write-Host -ForegroundColor White " - A pending restart blocks the installation."
                    $preReqKnownIssueRestart = $true
                }
                Else
                {
                    Invoke-Item $env:TEMP\$preReqLog
                    Throw " - Review the log file and try to correct any error conditions."
                }
            }
            # Look for restart requirement in log
            $preReqRestartNeeded = ($preReqLog | Select-String -SimpleMatch -Pattern "0XBC2=3010" -Encoding Unicode) -or ($preReqLog | Select-String -SimpleMatch -Pattern "0X3E9=1001" -Encoding Unicode)
            If ($preReqRestartNeeded -or $preReqKnownIssueRestart)
            {
                Write-Host -ForegroundColor White " - Setting AutoSPInstaller information in the registry..."
                New-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue | Out-Null
				$regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\"
                $regKey | New-ItemProperty -Name "RestartRequired" -PropertyType String -Value "1" -Force | Out-Null
				$regKey | New-ItemProperty -Name "LogTime" -PropertyType String -Value $script:Logtime -ErrorAction SilentlyContinue | Out-Null
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
    # Create a hash table with major version to product year mappings
    $spYears = @{"14" = "2010"; "15" = "2013"}
    $spYear = $spYears.$env:spVer
    $spInstalled = Get-SharePointInstall
    If ($spInstalled)
    {
        Write-Host -ForegroundColor White " - SharePoint $spYear binaries appear to be already installed - skipping installation."
    }
    Else
    {
        # Install SharePoint Binaries
        $config = $env:dp0 + "\" + $xmlinput.Configuration.Install.ConfigFile
        If (Test-Path "$env:SPbits\setup.exe")
        {
            Write-Host -ForegroundColor Blue " - Installing SharePoint $spYear binaries..." -NoNewline
            $startTime = Get-Date
            Start-Process "$env:SPbits\setup.exe" -ArgumentList "/config `"$config`"" -WindowStyle Minimized
            Show-Progress -Process setup -Color Blue -Interval 5
            $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            Write-Host -ForegroundColor White " - SharePoint $spYear setup completed in $delta."
            If (-not $?)
            {
                Throw " - Error $LASTEXITCODE occurred running $env:SPbits\setup.exe"
            }
            
            # Parsing most recent SharePoint Server Setup log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
            $setupLog = get-childitem $env:TEMP | ? {$_.Name -like "SharePoint Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
            If ($setupLog -eq $null) 
            {
                Throw " - Could not find SharePoint Server Setup log file!"
            }

            # Get error(s) from log
            $setupLastError = $setupLog | Select-String -SimpleMatch -Pattern "Error:" | Select-Object -Last 1
            $setupSuccess = $setupLog | Select-String -SimpleMatch -Pattern "Successfully installed package: oserver"
            If ($setupLastError -and !$setupSuccess)
            {
                Write-Warning $setupLastError.Line
                Invoke-Item $env:TEMP\$setupLog
                Throw " - Review the log file and try to correct any error conditions."
            }
            # Look for restart requirement in log
            $setupRestartNotNeeded = $setupLog | select-string -SimpleMatch -Pattern "System reboot is not pending."
            If (!($setupRestartNotNeeded))
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
        If (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml") # Crude way of checking if Office Web Apps is already installed
        {
            Write-Host -ForegroundColor White " - Office Web Apps binaries appear to be already installed - skipping install."
        }
        Else
        {
            $spYears = @{"14" = "2010"; "15" = "2013"}
            $spYear = $spYears.$env:spVer
            # Install Office Web Apps Binaries
            $config = $env:dp0 + "\" + $xmlinput.Configuration.OfficeWebApps.ConfigFile
            If (Test-Path "$bits\$spYear\OfficeWebApps\setup.exe")
            {
                Write-Host -ForegroundColor Blue " - Installing Office Web Apps binaries..." -NoNewline
                $startTime = Get-Date
                Start-Process "$bits\$spYear\OfficeWebApps\setup.exe" -ArgumentList "/config `"$config`"" -WindowStyle Minimized
                Show-Progress -Process setup -Color Blue -Interval 5
                $delta,$null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White " - Office Web Apps setup completed in $delta."
                If (-not $?) {
                    Throw " - Error $LASTEXITCODE occurred running $bits\$spYear\OfficeWebApps\setup.exe"                   
                }
                # Parsing most recent Office Web Apps Setup log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
                $setupLog = get-childitem $env:TEMP | ? {$_.Name -like "Wac Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -first 1
                If ($setupLog -eq $null) 
                {
                    Throw " - Could not find Office Web Apps Setup log file!"
                }
                # Get error(s) from log
                $setupLastError = $setupLog | select-string -SimpleMatch -Pattern "Error:" | Select-Object -Last 1 #| ? {$_.Line -notlike "*Startup task*"}
                If ($setupLastError)
                {
                    Write-Warning $setupLastError.Line
                    Invoke-Item $env:TEMP\$setupLog
                    Throw " - Review the log file and try to correct any error conditions."                 
                }
                # Look for restart requirement in log
                $setupRestartNotNeeded = $setupLog | select-string -SimpleMatch -Pattern "System reboot is not pending."
                If (!($setupRestartNotNeeded))
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
                Throw " - Install path $bits\$spYear\OfficeWebApps not found!!"
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
        Try
        {
            Write-Host -ForegroundColor White " - Configuring Office Web Apps..."
            # Install Help Files
            Write-Host -ForegroundColor White " - Installing Help Collection..."
            Install-SPHelpCollection -All
            ##WaitForHelpInstallToFinish
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
            $features = Install-SPFeature -AllExistingFeatures -Force
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
    $spYears = @{"14" = "2010"; "15" = "2013"}
    $spYear = $spYears.$env:spVer
    #Get installed languages from registry (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office Server\$env:spVer.0\InstalledLanguages)
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$env:spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}   # Look for extracted language packs
    $extractedLanguagePacks = (Get-ChildItem "$bits\$spYear\LanguagePacks" -Name -Include "??-??" -ErrorAction SilentlyContinue)
    $serverLanguagePacks = (Get-ChildItem "$bits\$spYear\LanguagePacks" -Name -Include ServerLanguagePack_*.exe -ErrorAction SilentlyContinue)
    If ($extractedLanguagePacks)
    {
        Write-Host -ForegroundColor White " - Installing SharePoint Language Packs:"
        ForEach ($languagePackFolder in $extractedLanguagePacks)
        {
            $language = $installedOfficeServerLanguages | ? {$_ -eq $languagePackFolder}
            If (!$language)
            {
                Write-Host -ForegroundColor Blue " - Installing extracted language pack $languagePackFolder..." -NoNewline
                Start-Process -WorkingDirectory "$bits\$spYear\LanguagePacks\$languagePackFolder\" -FilePath "setup.exe" -ArgumentList "/config $bits\$spYear\LanguagePacks\$languagePackFolder\Files\SetupSilent\config.xml"
                Show-Progress -Process setup -Color Blue -Interval 5
            }
        }
        Write-Host -ForegroundColor White " - Language Pack installation complete."
    }
    # Look for Server language pack installers
    ElseIf ($serverLanguagePacks)
    {
        Write-Host -ForegroundColor White " - Installing SharePoint Language Packs:"
        ForEach ($languagePack in $serverLanguagePacks)
        {
            # Slightly convoluted check to see if language pack is already installed, based on name of language pack file.
            # This only works if you've renamed your language pack(s) to follow the convention "ServerLanguagePack_XX-XX.exe" where <XX-XX> is a culture such as <en-us>.
            $language = $installedOfficeServerLanguages | ? {$_ -eq (($languagePack -replace "ServerLanguagePack_","") -replace ".exe","")}
            If (!$language)
            {
                Write-Host -ForegroundColor Blue " - Installing $languagePack..." -NoNewline
                Start-Process -FilePath "$bits\$spYear\LanguagePacks\$languagePack" -ArgumentList "/quiet /norestart"
                Show-Progress -Process $($languagePack -replace ".exe", "") -Color Blue -Interval 5
                $language = (($languagePack -replace "ServerLanguagePack_","") -replace ".exe","")
                # Install Foundation Language Pack SP1, then Server Language Pack SP1, if found
                If (Get-ChildItem "$bits\$spYear\LanguagePacks" -Name -Include spflanguagepack2010sp1-kb2460059-x64-fullfile-$language.exe -ErrorAction SilentlyContinue)
                {
                    Write-Host -ForegroundColor Blue " - Installing Foundation language pack SP1 for $language..." -NoNewline
                    Start-Process -WorkingDirectory "$bits\$spYear\LanguagePacks\" -FilePath "spflanguagepack2010sp1-kb2460059-x64-fullfile-$language.exe" -ArgumentList "/quiet /norestart"
                    Show-Progress -Process spflanguagepack2010sp1-kb2460059-x64-fullfile-$language -Color Blue -Interval 5
                    # Install Server Language Pack SP1, if found
                    If (Get-ChildItem "$bits\$spYear\LanguagePacks" -Name -Include serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language.exe -ErrorAction SilentlyContinue)
                    {
                        Write-Host -ForegroundColor Blue " - Installing Server language pack SP1 for $language..." -NoNewline
                        Start-Process -WorkingDirectory "$bits\$spYear\LanguagePacks\" -FilePath "serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language.exe" -ArgumentList "/quiet /norestart"
                        Show-Progress -Process serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language -Color Blue -Interval 5
                    }
                    Else
                    {
                        Write-Warning " - Server Language Pack SP1 not found for $language!" 
                        Write-Warning " - You must install it for the language service pack patching process to be complete."
                    }
                }
                Else {Write-Host -ForegroundColor White " - No Language Pack service packs found."}
            }
            Else
            {
                Write-Host -ForegroundColor White " - Language $language already appears to be installed, skipping."
            }
        }
        Write-Host -ForegroundColor White " - Language Pack installation complete."
    }
    Else 
    {
        Write-Host -ForegroundColor White " - No language packs found in $bits\$spYear\LanguagePacks, skipping."
    }

    # Get and note installed languages
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$env:spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    Write-Host -ForegroundColor White " - Currently installed languages:" 
    ForEach ($language in $installedOfficeServerLanguages)
    {
        Write-Host "  -" ([System.Globalization.CultureInfo]::GetCultureInfo($language).DisplayName)
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
        $farmAcct = $xmlinput.Configuration.Farm.Account.Username
        Write-Host -ForegroundColor White " - Adding $farmAcct to local Administrators" -NoNewline
        If ($xmlinput.Configuration.Farm.Account.LeaveInLocalAdmins -ne $true) {Write-Host -ForegroundColor White " (only for install)..."}
        Else {Write-Host -ForegroundColor White " ..."}
        $farmAcctDomain,$farmAcctUser = $farmAcct -Split "\\"
        Try
        {
            $builtinAdminGroup = Get-AdministratorsGroup
            ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$farmAcctDomain/$farmAcctUser")
            If (-not $?) {Throw}
            # Restart the SPTimerV4 service if it's running, so it will pick up the new credential
            If ((Get-Service -Name SPTimerV4).Status -eq "Running")
            {
                Write-Host -ForegroundColor White " - Restarting SharePoint Timer Service..."
                Restart-Service SPTimerV4
            }
        }
        Catch {Write-Host -ForegroundColor White " - $farmAcct is already a member of `"$builtinAdminGroup`"."}
        WriteLine
    }
}

# ===================================================================================
# Func: GetFarmCredentials
# Desc: Return the credentials for the farm account, prompt the user if need more info
# ===================================================================================
Function GetFarmCredentials([xml]$xmlinput)
{        
    $farmAcct = $xmlinput.Configuration.Farm.Account.Username
    $farmAcctPWD = $xmlinput.Configuration.Farm.Account.Password
    If (!($farmAcct) -or $farmAcct -eq "" -or !($farmAcctPWD) -or $farmAcctPWD -eq "") 
    {
        Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Farm Account:"
        $script:farmCredential = $host.ui.PromptForCredential("Farm Setup", "Enter Farm Account Credentials:", "$farmAcct", "NetBiosUserName" )
    } 
    Else
    {
        $secPassword = ConvertTo-SecureString "$farmAcctPWD" -AsPlaintext -Force 
        $script:farmCredential = New-Object System.Management.Automation.PsCredential $farmAcct,$secPassword
    }
    Return $farmCredential
}
#EndRegion

#Region Get Farm Passphrase
Function GetFarmPassphrase([xml]$xmlinput)
{
    $farmPassphrase = $xmlinput.Configuration.Farm.Passphrase
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        $farmPassphrase = Read-Host -Prompt " - Please enter the farm passphrase now" -AsSecureString
        If (!($farmPassphrase) -or ($farmPassphrase -eq "")) { Throw " - Farm passphrase is required!" }
    }
    Return $farmPassphrase
}
#EndRegion

#Region Get Secure Farm Passphrase
# ===================================================================================
# Func: GetSecureFarmPassphrase
# Desc: Return the Farm Phrase as a secure string
# ===================================================================================
Function GetSecureFarmPassphrase([xml]$xmlinput)
{        
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        $farmPassphrase = GetFarmPassPhrase $xmlinput
    }
    If ($farmPassPhrase.GetType().Name -ne "SecureString")
    {
        $secPhrase = ConvertTo-SecureString $farmPassphrase -AsPlaintext -Force
    }
    Else {$secPhrase = $farmPassphrase}
    Return $secPhrase
}
#EndRegion

#Region Update Service Process Identity

# ====================================================================================
# Func: UpdateProcessIdentity
# Desc: Updates the account a specified service runs under to the general app pool account
# ====================================================================================
Function UpdateProcessIdentity ($serviceToUpdate)
{
    $spservice = Get-spserviceaccountxml $xmlinput
    # Managed Account
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    if ($managedAccountGen -eq $null) { Throw " - Managed Account $($spservice.username) not found" }
    if ($serviceToUpdate.Service) {$serviceToUpdate = $serviceToUpdate.Service}
    if ($serviceToUpdate.ProcessIdentity.Username -ne $managedAccountGen.UserName)
    {
        Write-Host -ForegroundColor White " - Updating $($serviceToUpdate.TypeName) to run as $($managedAccountGen.UserName)..."
        # Set the Process Identity to our general App Pool Account; otherwise it's set by default to the Farm Account and gives warnings in the Health Analyzer
        $serviceToUpdate.ProcessIdentity.CurrentIdentityType = "SpecificUser"
        $serviceToUpdate.ProcessIdentity.ManagedAccount = $managedAccountGen
        $serviceToUpdate.ProcessIdentity.Update()
        $serviceToUpdate.ProcessIdentity.Deploy()
        Write-Host -ForegroundColor White " - Done."
    }
    else {Write-Host -ForegroundColor White " - $($serviceToUpdate.TypeName) is already configured to run as $($managedAccountGen.UserName)."}
}
#EndRegion

#Region Create or Join Farm
# ===================================================================================
# Func: CreateOrJoinFarm
# Desc: Check if the farm is created 
# ===================================================================================
Function CreateOrJoinFarm([xml]$xmlinput, $secPhrase, $farmCredential)
{
    WriteLine
    $configDB = $dbPrefix+$xmlinput.Configuration.Farm.Database.ConfigDB
    
    # Look for an existing farm and join the farm if not already joined, or create a new farm
    Try
    {
        Write-Host -ForegroundColor White " - Checking farm membership for $env:COMPUTERNAME in `"$configDB`"..."
        $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB} -ErrorAction SilentlyContinue
    }
    Catch {""}
    If ($spFarm -eq $null)
    {
        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
        $centralAdminContentDB = $dbPrefix+$xmlinput.Configuration.Farm.CentralAdmin.Database
        
        Write-Host -ForegroundColor White " - Attempting to join farm on `"$configDB`"..."
        $connectFarm = Connect-SPConfigurationDatabase -DatabaseName "$configDB" -Passphrase $secPhrase -DatabaseServer "$dbServer" -ErrorAction SilentlyContinue
        If (-not $?)
        {
            Write-Host -ForegroundColor White " - No existing farm found.`n - Creating config database `"$configDB`"..."
            # Waiting a few seconds seems to help with the Connect-SPConfigurationDatabase barging in on the New-SPConfigurationDatabase command; not sure why...
            Start-Sleep 5
            New-SPConfigurationDatabase -DatabaseName "$configDB" -DatabaseServer "$dbServer" -AdministrationContentDatabaseName "$centralAdminContentDB" -Passphrase $secPhrase -FarmCredentials $farmCredential
            If (-not $?) {Throw " - Error creating new farm configuration database"}
            Else {$farmMessage = " - Done creating configuration database for farm."}
        }
        Else 
        {
            $farmMessage = " - Done joining farm."
            [bool]$script:FarmExists = $true

        }
    }
    Else 
    {
        [bool]$script:FarmExists = $true
        $farmMessage = " - $env:COMPUTERNAME is already joined to farm on `"$configDB`"."
    }
    
    Write-Host -ForegroundColor White $farmMessage
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
            $centralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.Port
            # Check if there is already a Central Admin provisioned in the farm; if not, create one
            If (!(Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*:$centralAdminPort*"}))
            {
                # Create Central Admin for farm
                Write-Host -ForegroundColor White " - Creating Central Admin site..."
                $newCentralAdmin = New-SPCentralAdministration -Port $centralAdminPort -WindowsAuthProvider "NTLM" -ErrorVariable err
                If (-not $?) {Throw " - Error creating central administration application"}
                Write-Host -ForegroundColor Blue " - Waiting for Central Admin site..." -NoNewline
                $centralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*$($env:COMPUTERNAME):$centralAdminPort*"}
                While ($centralAdmin.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $centralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Url -like "*$($env:COMPUTERNAME):$centralAdminPort*"}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($centralAdmin.Status)
                If ($xmlinput.Configuration.Farm.CentralAdmin.UseSSL -eq $true)
                {
                    Write-Host -ForegroundColor White " - Enabling SSL for Central Admin..."
                    $SSLHostHeader = $env:COMPUTERNAME
                    $SSLPort = $centralAdminPort
                    $SSLSiteName = $centralAdmin.DisplayName
                    New-SPAlternateURL -Url "https://$($env:COMPUTERNAME):$centralAdminPort" -Zone Default -WebApplication $centralAdmin | Out-Null
                    AssignCert
                }
            }
            Else #Create a Central Admin site locally, with an AAM to the existing Central Admin
            {
                Write-Host -ForegroundColor White " - Creating local Central Admin site..."
                $newCentralAdmin = New-SPCentralAdministration
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
    $configDB = $dbPrefix+$xmlinput.Configuration.Farm.Database.ConfigDB
    $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
    $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB}
    ForEach ($srv in $spFarm.Servers) {If (($srv -like "*$dbServer*") -and ($dbServer -ne $env:COMPUTERNAME)) {[bool]$dbLocal = $false}}
    If (($($spFarm.Servers.Count) -gt 1) -and ($dbLocal -eq $false)) {[bool]$script:FirstServer = $false}
    Else {[bool]$script:FirstServer = $true}
}

# ===================================================================================
# Func: WaitForHelpInstallToFinish
# Desc: Waits for the Help Collection timer job to complete before proceeding, in order to avoid concurrency errors
# From: Adapted from a function submitted by CodePlex user jwthompson98
# ===================================================================================
Function WaitForHelpInstallToFinish
{
    Write-Host -ForegroundColor Blue "  - Waiting for Help Collection Installation timer job..." -NoNewline
    # Wait for the timer job to start
    Do
    {
        Write-Host -ForegroundColor Blue "." -NoNewline
        Start-Sleep -Seconds 1
    }
    Until
    (
        (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"}
    )
    Write-Host -ForegroundColor Blue "Started."
    Write-Host -ForegroundColor Blue "  - Waiting for Help Collection Installation timer job to complete: " -NoNewline
    # Monitor the timer job and display progress
    $helpJob = (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"} | Sort StartTime | Select -Last 1
    While ($helpJob -ne $null)
    {
        Write-Host -ForegroundColor White "$($helpJob.PercentageDone)%" -NoNewline
        Start-Sleep -Milliseconds 250
        for ($i = 0; $i -lt 3; $i++)
        {   
            Write-Host -ForegroundColor Blue "." -NoNewline
            Start-Sleep -Milliseconds 250
        }
        $backspaceCount = (($helpJob.PercentageDone).ToString()).Length + 3
        for ($count = 0; $count -le $backspaceCount; $count++) {Write-Host "`b `b" -NoNewline}
        $helpJob = (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"} | Sort StartTime | Select -Last 1
    }
    Write-Host -ForegroundColor Blue "Done."
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
    If ((!($farmExists)) -or ($firstServer -eq $true) -or (CheckIfUpgradeNeeded -eq $true)) {[bool]$doFullConfig = $true}
    Try
    {
        If ($doFullConfig)
        {
            # Install Help Files
                Write-Host -ForegroundColor White " - Installing Help Collection..."
                Install-SPHelpCollection -All
                ##WaitForHelpInstallToFinish
        }
        # Secure resources
        Write-Host -ForegroundColor White " - Securing Resources..."
        Initialize-SPResourceSecurity
        # Install Services
        Write-Host -ForegroundColor White " - Installing Services..."
        Install-SPService
        If ($doFullConfig)
        {
            # Install (all) features
            Write-Host -ForegroundColor White " - Installing Features..."
            $features = Install-SPFeature -AllExistingFeatures -Force
        }
        # Detect if Central Admin URL already exists, i.e. if Central Admin web app is already provisioned on the local computer
        $centralAdminPort = $xmlinput.Configuration.Farm.CentralAdmin.Port
        $centralAdmin = Get-SPWebApplication -IncludeCentralAdministration | ? {$_.Status -eq "Online"} | ? {$_.Url -like "*$($env:COMPUTERNAME):$centralAdminPort*"}
        
        # Provision CentralAdmin if indicated in AutoSPInstallerInput.xml and the CA web app doesn't already exist
        If ((ShouldIProvision($xmlinput.Configuration.Farm.CentralAdmin) -eq $true) -and (!($centralAdmin))) {CreateCentralAdmin $xmlinput}
        # Install application content if this is a new farm
        If ($doFullConfig)
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
    $spRegVersion = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$env:spVer.0\").GetValue("Version")
    If (!($spRegVersion))
    {
        Write-Host -ForegroundColor White " - Creating Version registry value (workaround for bug in PS-based install)"
        Write-Host -ForegroundColor White -NoNewline " - Getting version number... "
        $spBuild = "$($(Get-SPFarm).BuildVersion.Major).0.0.$($(Get-SPFarm).BuildVersion.Build)"
        Write-Host -ForegroundColor White "$spBuild"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$env:spVer.0\" -Name Version -Value $spBuild -ErrorAction SilentlyContinue | Out-Null
    }
    # Set an environment variable for the 14/15 hive (SharePoint root)
    [Environment]::SetEnvironmentVariable($env:spVer, "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer", "Machine")
    
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
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        $farmPassphrase = GetFarmPassPhrase $xmlinput
    }
    # If the farm passphrase is a secure string (it would be if we prompted for input earlier), we need to convert it back to plain text for PSConfig.exe to understand it
    If ($farmPassphrase.GetType().Name -eq "SecureString") {$farmPassphrase = ConvertTo-PlainText $farmPassphrase}
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$env:spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    $languagePackInstalled = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$env:spVer.0\WSS\").GetValue("LanguagePackInstalled")
    # If there were language packs installed we need to run psconfig to configure them
    If (($languagePackInstalled -eq "1") -and ($installedOfficeServerLanguages.Count -gt 1))
    {
        WriteLine
        Write-Host -ForegroundColor White " - Configuring language packs..."
        # Let's sleep for a while to let the farm config catch up...
        Start-Sleep 20
        $attemptNum += 1
        # Run PSConfig.exe per http://sharepoint.stackexchange.com/questions/9927/sp2010-psconfig-fails-trying-to-configure-farm-after-installing-language-packs
        # Note this was changed from v2v to b2b as suggested by CodePlex user jwthompson98 
        Start-Process -FilePath $PSConfig -ArgumentList "-cmd upgrade -inplace b2b -force -cmd applicationcontent -install -cmd installfeatures" -NoNewWindow -Wait
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
                While ($attemptNum -le 4)
                {
                    Write-Host -ForegroundColor White " - An error occurred configuring language packs, trying again ($attemptNum)..."
                    Start-Sleep -Seconds 5
                    ConfigureLanguagePacks $xmlinput
                }
                If ($attemptNum -ge 5)
                {
                    Write-Host -ForegroundColor White " - After $attemptNum attempts to configure language packs, trying GUI-based..."
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
        $adminGroup = ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group")
        # This syntax comes from Ying Li (http://myitforum.com/cs2/blogs/yli628/archive/2007/08/30/powershell-script-to-add-remove-a-domain-user-to-the-local-administrators-group-on-a-remote-machine.aspx)
        $localAdmins = $adminGroup.psbase.invoke("Members") | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        # Ensure Secondary Logon service is enabled and started
        If (!((Get-Service -Name seclogon).Status -eq "Running"))
        {
            Write-Host -ForegroundColor White " - Enabling Secondary Logon service..."
            Set-Service -Name seclogon -StartupType Manual
            Write-Host -ForegroundColor White " - Starting Secondary Logon service..."
            Start-Service -Name seclogon
        }
        
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
                $managedAccountDomain,$managedAccountUser = $username -Split "\\"
                # Add managed account to local admins (very) temporarily so it can log in and create its profile
                If (!($localAdmins -contains $managedAccountUser))
                {
                    $builtinAdminGroup = Get-AdministratorsGroup
                    ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$managedAccountDomain/$managedAccountUser")
                }
                Else
                {
                    $alreadyAdmin = $true
                }
                # Spawn a command window using the managed account's credentials, create the profile, and exit immediately
                Start-Process -WorkingDirectory "$env:SYSTEMROOT\System32\" -FilePath "cmd.exe" -ArgumentList "/C" -LoadUserProfile -NoNewWindow -Credential $credAccount
                # Remove managed account from local admins unless it was already there
                $builtinAdminGroup = Get-AdministratorsGroup
                If (-not $alreadyAdmin) {([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$managedAccountDomain/$managedAccountUser")}
                Write-Host -BackgroundColor Blue -ForegroundColor Black "Done."
            }
            Catch
            {
                $_
                Write-Host -ForegroundColor White "."
                Write-Warning " - Could not create local user profile for $username"
                break
            }
            $managedAccount = Get-SPManagedAccount | Where-Object {$_.UserName -eq $username}
            If ($managedAccount -eq $null) 
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
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    If ($managedAccountGen -eq $null) { Throw " - Managed Account $($spservice.username) not found" }
    # App Pool
    $applicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
    If ($applicationPool -eq $null)
    {
        Write-Host -ForegroundColor White " - Creating SharePoint Hosted Services Application Pool..."
        $applicationPool = New-SPServiceApplicationPool -Name "SharePoint Hosted Services" -account $managedAccountGen
        If (-not $?) { Throw "Failed to create the application pool" }
    }
    Return $applicationPool
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
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceConfig,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceInstanceType,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceName,
        [Parameter(Mandatory=$false)]
        [String]$serviceProxyName,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceGetCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyGetCmdlet,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [String]$serviceNewCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewCmdlet,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewParams
    )
    
    Try
    {
        $applicationPool = Get-HostedServicesAppPool $xmlinput
        Write-Host -ForegroundColor White " - Provisioning $serviceName..."
        # get the service instance
        $serviceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $serviceInstanceType}
        $serviceInstance = $serviceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
        If (!$serviceInstance) { Throw " - Failed to get service instance - check product version (Standard vs. Enterprise)" }
        # Start Service instance
        Write-Host -ForegroundColor White " - Checking $($serviceInstance.TypeName) instance..."
        If (($serviceInstance.Status -eq "Disabled") -or ($serviceInstance.Status -ne "Online"))
        {  
            Write-Host -ForegroundColor White " - Starting $($serviceInstance.TypeName) instance..."
            $serviceInstance.Provision()
            If (-not $?) { Throw " - Failed to start $($serviceInstance.TypeName) instance" }
            # Wait
            Write-Host -ForegroundColor Blue " - Waiting for $($serviceInstance.TypeName) instance..." -NoNewline
            While ($serviceInstance.Status -ne "Online") 
            {
                Write-Host -ForegroundColor Blue "." -NoNewline
                Start-Sleep 1
                $serviceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq $serviceInstanceType}
                $serviceInstance = $serviceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($serviceInstance.Status)
        }
        Else 
        {
            Write-Host -ForegroundColor White " - $($serviceInstance.TypeName) instance already started."
        }
        # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
        If (!(Get-Command $serviceGetCmdlet -ErrorAction SilentlyContinue))
        {
            Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
            Remove-PSSnapin Microsoft.SharePoint.PowerShell
            Load-SharePoint-Powershell
        }
        $getServiceApplication = Invoke-Expression "$serviceGetCmdlet | ? {`$_.Name -eq `"$serviceName`"}"
        If ($getServiceApplication -eq $null)
        {
            Write-Host -ForegroundColor White " - Creating $serviceName..."
            # A bit kludgey to accomodate the new PerformancePoint cmdlet in Service Pack 1, and some new SP2010 service apps (and still be able to use the CreateBasicServiceApplication function)
            If ((CheckForSP1) -and ($serviceInstanceType -eq "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance" -or 
									$serviceInstanceType -eq "Microsoft.SharePoint.AppManagement.AppManagementServiceInstance" -or 
									$serviceInstanceType -eq "Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance"))
            {
                $newServiceApplication = Invoke-Expression "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool -DatabaseServer `$dbServer -DatabaseName `$serviceDB"
            }
            Else # Just do the regular non-database-bound service app creation
            {
                $newServiceApplication = Invoke-Expression "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool"
            }
            Write-Host -ForegroundColor White " - Provisioning $serviceName Proxy..."
            # Because apparently the teams developing the cmdlets for the various service apps didn't communicate with each other, we have to account for the different ways each proxy is provisioned!
            Switch ($serviceInstanceType)
            {
                "Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance" {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -AddToDefaultGroup | Out-Null}
                "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance" {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication.Name | Out-Null}
                "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance" {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -Default | Out-Null}
                "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
                "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
                "Microsoft.Office.Word.Server.Service.WordServiceInstance" {} # Do nothing because there is no cmdlet to create this services proxy
				"Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance" {& $serviceProxyNewCmdlet -ServiceApplication $newServiceApplication | Out-Null}
                Default {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication | Out-Null}
            }
			Write-Host -ForegroundColor White " - Done provisioning $serviceName. "
        }
        Else
        {
            Write-Host -ForegroundColor White " - $serviceName already created."
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
        $sandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
        $sandboxedCodeService = $sandboxedCodeServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
        If ($sandboxedCodeService.Status -ne "Online")
        {
            Try
            {
                Write-Host -ForegroundColor White " - Starting Microsoft SharePoint Foundation Sandboxed Code Service..."
                UpdateProcessIdentity $sandboxedCodeService
                $sandboxedCodeService.Update()
                $sandboxedCodeService.Provision()
                If (-not $?) {Throw " - Failed to start Sandboxed Code Service"}
            }
            Catch 
            {
                Throw " - An error occurred starting the Microsoft SharePoint Foundation Sandboxed Code Service"
            }
            #Wait
            Write-Host -ForegroundColor Blue " - Waiting for Sandboxed Code service..." -NoNewline
            While ($sandboxedCodeService.Status -ne "Online") 
            {
                Write-Host -ForegroundColor Blue "." -NoNewline
                Start-Sleep 1
                $sandboxedCodeServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
                $sandboxedCodeService = $sandboxedCodeServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Blue -ForegroundColor Black $($sandboxedCodeService.Status)
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
            $metaDataDB = $dbPrefix+$xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Database.Name
            $dbServer = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $farmAcct = $xmlinput.Configuration.Farm.Account.Username
            $metadataServiceName = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.Name
            $metadataServiceProxyName = $xmlinput.Configuration.ServiceApps.ManagedMetadataServiceApp.ProxyName
            If($metadataServiceName -eq $null) {$metadataServiceName = "Metadata Service Application"}
            If($metadataServiceProxyName -eq $null) {$metadataServiceProxyName = $metadataServiceName}
            Write-Host -ForegroundColor White " - Provisioning Managed Metadata Service Application"
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            Write-Host -ForegroundColor White " - Starting Managed Metadata Service:"
            # Get the service instance
            $metadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
            $metadataServiceInstance = $metadataServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find Metadata service instance" }
            # Start Service instances
            If($metadataServiceInstance.Status -eq "Disabled")
            { 
                Write-Host -ForegroundColor White " - Starting Metadata Service Instance..."
                $metadataServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start Metadata service instance" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for Metadata service..." -NoNewline
                While ($metadataServiceInstance.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $metadataServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
                    $metadataServiceInstance = $metadataServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black ($metadataServiceInstance.Status)
            }
            Else {Write-Host -ForegroundColor White " - Managed Metadata Service already started."}

            # Create a Metadata Service Application
            If((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}) -eq $null)
            {  
                # Create Service App
                Write-Host -ForegroundColor White " - Creating Metadata Service Application..."
                $metaDataServiceApp = New-SPMetadataServiceApplication -Name $metadataServiceName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $metaDataDB ##-AdministratorAccount $farmAcct -FullAccessAccount $farmAcct ## Removed due to apparent conflict with proxy switches below!
                If (-not $?) { Throw " - Failed to create Metadata Service Application" }
                # create proxy
                Write-Host -ForegroundColor White " - Creating Metadata Service Application Proxy..."
                $metaDataServiceAppProxy = New-SPMetadataServiceApplicationProxy -Name $metadataServiceProxyName -ServiceApplication $metaDataServiceApp -DefaultProxyGroup -ContentTypePushdownEnabled -DefaultKeywordTaxonomy -DefaultSiteCollectionTaxonomy
                If (-not $?) { Throw " - Failed to create Metadata Service Application Proxy" }
                # Added to enable Metadata Service Navigation for SP2013, per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=354
                If ($env:spVer -eq "15")
                {
                    If ($metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy -ne $true)
                    {
                        Write-Host -ForegroundColor White " - Configuring Metadata Service Application Proxy..."
                        $metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy = $true
                        $metaDataServiceAppProxy.Update()
                    }
                }
                Write-Host -ForegroundColor White " - Granting rights to Metadata Service Application..."
                # Get ID of "Managed Metadata Service"
                $metadataServiceAppToSecure = Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
                $metadataServiceAppIDToSecure = $metadataServiceAppToSecure.Id
                # Create a variable that contains the list of administrators for the service application 
                $metadataServiceAppSecurity = Get-SPServiceApplicationSecurity $metadataServiceAppIDToSecure
                ForEach ($account in ($xmlinput.Configuration.Farm.ManagedAccounts.ManagedAccount))
                {
                    # Create a variable that contains the claims principal for the service accounts
                    $accountPrincipal = New-SPClaimsPrincipal -Identity $account.username -IdentityType WindowsSamAccountName           
                    # Give permissions to the claims principal you just created
                    Grant-SPObjectSecurity $metadataServiceAppSecurity -Principal $accountPrincipal -Rights "Full Access to Term Store"
                }               
                # Apply the changes to the Metadata Service application
                Set-SPServiceApplicationSecurity $metadataServiceAppIDToSecure -objectSecurity $metadataServiceAppSecurity
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
    $numDomainLevels = ($env:USERDNSDOMAIN -split "\.").Count
    If ($numDomainLevels -gt 2) # For example, corp.domain.net
    {
        # Get only the last two (domain + TLD)
        $topDomain = $env:USERDNSDOMAIN.Split("\.")[($numDomainLevels - 2)] + "." + $env:USERDNSDOMAIN.Split("\.")[($numDomainLevels - 1)]
    }
    # If our SSL host header is a FQDN containing the local domain (or part of it, if the local domain is a subdomain), look for an existing wildcard cert
    If ($SSLHostHeader -like "*.$env:USERDNSDOMAIN")
    {
        Write-Host -ForegroundColor White " - Looking for existing `"*.$env:USERDNSDOMAIN`" wildcard certificate..."
        $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$env:USERDNSDOMAIN*"}
    }
    ElseIf (($numDomainLevels -gt 2) -and ($SSLHostHeader -like "*.$topDomain"))
    {
        Write-Host -ForegroundColor White " - Looking for existing `"*.$topDomain`" wildcard certificate..."
        $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$topDomain*"}
    }
    Else
    {
        Write-Host -ForegroundColor White " - Looking for existing `"$SSLHostHeader`" certificate..."
        $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
    }
    If (!$cert)
    {
        Write-Host -ForegroundColor White " - None found."
        # Get the actual location of makecert.exe in case we installed SharePoint in the non-default location
        $spInstallPath = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Office Server\$env:spVer.0").GetValue("InstallPath")
        $makeCert = "$spInstallPath\Tools\makecert.exe"
        If (Test-Path "$makeCert")
        {
            Write-Host -ForegroundColor White " - Creating new self-signed certificate..."
            If ($SSLHostHeader -like "*.$env:USERDNSDOMAIN")
            {
                # Create a new wildcard cert so we can potentially use it on other sites too
                Start-Process -NoNewWindow -Wait -FilePath "$makeCert" -ArgumentList "-r -pe -n `"CN=*.$env:USERDNSDOMAIN`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
                $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$env:USERDNSDOMAIN*"}
            }
            ElseIf (($numDomainLevels -gt 2) -and ($SSLHostHeader -like "*.$topDomain"))
            {
                # Create a new wildcard cert so we can potentially use it on other sites too
                Start-Process -NoNewWindow -Wait -FilePath "$makeCert" -ArgumentList "-r -pe -n `"CN=*.$topDomain`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
                $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "CN=``*.$topDomain*"}
            }
            Else
            {
                # Just create a cert that matches the SSL host header
                Start-Process -NoNewWindow -Wait -FilePath "$makeCert" -ArgumentList "-r -pe -n `"CN=$SSLHostHeader`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
                $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$SSLHostHeader"}
            }
        }
        Else 
        {
            Write-Host -ForegroundColor White " - `"$makeCert`" not found."
            Write-Host -ForegroundColor White " - Looking for any machine-named certificates we can use..."
            # Select the first certificate with the most recent valid date
            $cert = Get-ChildItem cert:\LocalMachine\My | ? {$_.Subject -like "*$env:COMPUTERNAME"} | Sort-Object NotBefore -Desc | Select-Object -First 1
            If (!$cert)
            {
                Write-Host -ForegroundColor White " - None found, skipping certificate creation."
            }
        }
    }
    If ($cert)
    {
        $certSubject = $cert.Subject
        Write-Host -ForegroundColor White " - Certificate `"$certSubject`" found."
        # Fix up the cert subject name to a file-friendly format
        $certSubjectName = $certSubject.Split(",")[0] -replace "CN=","" -replace "\*","wildcard"
        # Export our certificate to a file, then import it to the Trusted Root Certification Authorites store so we don't get nasty browser warnings
        # This will actually only work if the Subject and the host part of the URL are the same
        # Borrowed from https://www.orcsweb.com/blog/james/powershell-ing-on-windows-server-how-to-import-certificates-using-powershell/
        Write-Host -ForegroundColor White " - Exporting `"$certSubject`" to `"$certSubjectName.cer`"..."
        $cert.Export("Cert") | Set-Content "$env:TEMP\$certSubjectName.cer" -Encoding byte
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        Write-Host -ForegroundColor White " - Importing `"$certSubjectName.cer`" to Local Machine\Root..."
        $pfx.Import("$env:TEMP\$certSubjectName.cer")
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
        $store.Open("MaxAllowed")
        $store.Add($pfx)
        $store.Close()
        Write-Host -ForegroundColor White " - Assigning certificate `"$certSubject`" to SSL-enabled site..."
        #Set-Location IIS:\SslBindings -ErrorAction Inquire
        $cert | New-Item IIS:\SslBindings\0.0.0.0!$SSLPort -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty IIS:\Sites\$SSLSiteName -Name bindings -Value @{protocol="https";bindingInformation="*:$($SSLPort):$($SSLHostHeader)"}
        ## Set-WebBinding -Name $SSLSiteName -BindingInformation ":$($SSLPort):" -PropertyName Port -Value $SSLPort -PropertyName Protocol -Value https 
        Write-Host -ForegroundColor White " - Certificate has been assigned to site `"https://$SSLHostHeader`:$SSLPort`""
    }
    Else {Write-Host -ForegroundColor White " - No certificates were found, and none could be created."}
    $cert = $null
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
        ForEach ($webApp in $xmlinput.Configuration.WebApplications.WebApplication)
        {
            CreateWebApp $webApp
            ConfigureObjectCache $webApp
            ConfigureOnlineWebPartCatalog $webApp
            Add-LocalIntranetURL $webApp.URL
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
Function CreateWebApp([System.Xml.XmlElement]$webApp)
{
    $account = $webApp.applicationPoolAccount
    $webAppName = $webApp.name
    $appPool = $webApp.applicationPool
    $database = $dbPrefix+$webApp.databaseName
    $dbServer = $webApp.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
    }
    $url = $webApp.url
    $port = $webApp.port
    $useSSL = $false
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$env:spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
    If ($url -like "https://*") {$useSSL = $true; $hostHeader = $url -replace "https://",""}        
    Else {$hostHeader = $url -replace "http://",""}
    # Set the directory path for the web app to something a bit more friendly
    ImportWebAdministration    
    # Get the default root location for web apps
    $iisWebDir = (Get-ItemProperty "IIS:\Sites\Default Web Site\" -name physicalPath) -replace ("%SystemDrive%","$env:SystemDrive")
    If (!([string]::IsNullOrEmpty($iisWebDir)))
    {
        $pathSwitch = @{Path = "$iisWebDir\wss\VirtualDirectories\$webAppName-$port"}
    }

    $getSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $webAppName}
    If ($getSPWebApplication -eq $null)
    {
        Write-Host -ForegroundColor White " - Creating Web App `"$webAppName`""
        If ($($webApp.useClaims) -eq $true)
        {
            # Configure new web app to use Claims-based authentication
            If ($($webApp.useBasicAuthentication) -eq $true)
            {
                $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication -UseBasicAuthentication
            }
            Else
            {           
                $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication
            }  
            New-SPWebApplication -Name $webAppName -ApplicationPoolAccount $account -ApplicationPool $appPool -DatabaseServer $dbServer -DatabaseName $database -HostHeader $hostHeader -Url $url -Port $port -SecureSocketsLayer:$useSSL -AuthenticationProvider $authProvider @pathSwitch | Out-Null
            If (-not $?) { Throw " - Failed to create web application" }

            If ((Gwmi Win32_OperatingSystem).Version -like "6.0*") # If we are running Win2008 (non-R2), we may need the claims hotfix
            {
                [bool]$claimsHotfixRequired = $true
                Write-Host -ForegroundColor Yellow " - Web Applications using Claims authentication require an update"
                Write-Host -ForegroundColor Yellow " - Apply the http://go.microsoft.com/fwlink/?LinkID=184705 update after setup."
            }
        }
        Else
        {
            # Create the web app using Classic mode authentication
            New-SPWebApplication -Name $webAppName -ApplicationPoolAccount $account -ApplicationPool $appPool -DatabaseServer $dbServer -DatabaseName $database -HostHeader $hostHeader -Url $url -Port $port -SecureSocketsLayer:$useSSL @pathSwitch | Out-Null
            If (-not $?) { Throw " - Failed to create web application" }
        }
        SetupManagedPaths $webApp
    }   
    Else {Write-Host -ForegroundColor White " - Web app `"$webAppName`" already provisioned."}
    If ($useSSL)
    {
        $SSLHostHeader = $hostHeader
        $SSLPort = $port
        $SSLSiteName = $webAppName
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
        Write-Host -ForegroundColor White " - Granting $($spservice.username) rights to `"$webAppName`"..." -NoNewline
        $wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $webAppName}
        $wa.GrantAccessToProcessIdentity("$($spservice.username)")
        Write-Host -ForegroundColor White "Done."
    }

    ForEach ($siteCollection in $webApp.SiteCollections.SiteCollection)
    {
        $siteCollectionName = $siteCollection.name
        $siteURL = $siteCollection.siteURL
        $template = $siteCollection.template
        $ownerAlias = $siteCollection.Owner
        $LCID = $siteCollection.LCID
        $siteCollectionLocale = $siteCollection.Locale
        $siteCollectionTime24 = $siteCollection.Time24
        $getSPSiteCollection = Get-SPSite -Limit ALL | Where-Object {$_.Url -eq $siteURL}
        If (($getSPSiteCollection -eq $null) -and ($siteURL -ne $null))
        {
            Write-Host -ForegroundColor White " - Creating Site Collection `"$siteURL`"..."
            # Verify that the Language we're trying to create the site in is currently installed on the server
            $culture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($LCID)))
            $cultureDisplayName = $culture.DisplayName
            If (!($installedOfficeServerLanguages | Where-Object {$_ -eq $culture.Name}))
            {
                Write-Warning " - You must install the `"$culture ($cultureDisplayName)`" Language Pack before you can create a site using LCID $LCID"
            }
            Else
            {
                # If a template has been pre-specified, use it when creating the Portal site collection; otherwise, leave it blank so we can select one when the portal first loads
                If (($template -ne $null) -and ($template -ne "")) {
                    $site = New-SPSite -Url $siteURL -OwnerAlias $ownerAlias -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $database -Description $siteCollectionName -Name $siteCollectionName -Language $LCID -Template $template -ErrorAction Stop
                }
                Else 
                {
                    $site = New-SPSite -Url $siteURL -OwnerAlias $ownerAlias -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $database -Description $siteCollectionName -Name $siteCollectionName -Language $LCID  -ErrorAction Stop
                }

                # Add the Portal Site Connection to the web app, unless of course the current web app *is* the portal
                # Inspired by http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=264
                $portalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
                $portalSiteColl = $portalWebApp.SiteCollections.SiteCollection | Select-Object -First 1
                If ($site.URL -ne $portalSiteColl.siteURL)
                {
                    Write-Host -ForegroundColor White " - Setting the Portal Site Connection for `"$siteCollectionName`"..."
                    $site.PortalName = $portalSiteColl.Name
                    $site.PortalUrl = $portalSiteColl.siteUrl
                }
                If ($siteCollectionLocale) 
                {
                    Write-Host -ForegroundColor White " - Updating the locale for `"$siteCollectionName`" to `"$siteCollectionLocale`"..."
                    $site.RootWeb.Locale = [System.Globalization.CultureInfo]::CreateSpecificCulture($siteCollectionLocale) 
                }
                If ($siteCollectionTime24) 
                {
                    Write-Host -ForegroundColor White " - Updating 24 hour time format for `"$siteCollectionName`" to `"$siteCollectionTime24`"..."
                    $site.RootWeb.RegionalSettings.Time24 = $([System.Convert]::ToBoolean($siteCollectionTime24))
                }
                $site.RootWeb.Update()
            }
        }
        Else {Write-Host -ForegroundColor White " - Skipping creation of site `"$siteCollectionName`" - already provisioned."}
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
Function ConfigureObjectCache([System.Xml.XmlElement]$webApp)
{
    Try
    {
        $url = $webApp.Url + ":" + $webApp.Port
        $wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $webApp.Name}
        $superUserAcc = $xmlinput.Configuration.Farm.ObjectCacheAccounts.SuperUser
        $superReaderAcc = $xmlinput.Configuration.Farm.ObjectCacheAccounts.SuperReader
        # If the web app is using Claims auth, change the user accounts to the proper syntax
        If ($wa.UseClaimsAuthentication -eq $true) 
        {
            $superUserAcc = 'i:0#.w|' + $superUserAcc
            $superReaderAcc = 'i:0#.w|' + $superReaderAcc
        }
        Write-Host -ForegroundColor White " - Applying object cache accounts to `"$url`"..."
        $wa.Properties["portalsuperuseraccount"] = $superUserAcc
        Set-WebAppUserPolicy $wa $superUserAcc "Super User (Object Cache)" "Full Control"
        $wa.Properties["portalsuperreaderaccount"] = $superReaderAcc
        Set-WebAppUserPolicy $wa $superReaderAcc "Super Reader (Object Cache)" "Full Read"
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
Function ConfigureOnlineWebPartCatalog([System.Xml.XmlElement]$webApp)
{
    If ($webapp.GetAttribute("useOnlineWebPartCatalog") -ne "")
    {
        $url = $webApp.Url + ":" + $webApp.Port
        If ($url -like "*localhost*") {$url = $url -replace "localhost","$env:COMPUTERNAME"}
        Write-Host -ForegroundColor White " - Setting online webpart catalog access for `"$url`""
        
        $wa = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $webApp.Name}
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
Function SetupManagedPaths([System.Xml.XmlElement]$webApp)
{
    $url = $webApp.Url + ":" + $webApp.Port
    If ($url -like "*localhost*") {$url = $url -replace "localhost","$env:COMPUTERNAME"}
    Write-Host -ForegroundColor White " - Setting up managed paths for `"$url`""

    If ($webApp.ManagedPaths)
    {
        ForEach ($managedPath in $webApp.ManagedPaths.ManagedPath)
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
        $userProfile = $xmlinput.Configuration.ServiceApps.UserProfileServiceApp
        $mySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.type -eq "MySiteHost"} 
        $mySiteName = $mySiteWebApp.name
        $mySiteURL = $mySiteWebApp.url
        $mySitePort = $mySiteWebApp.port
        $mySiteDBServer = $mySiteWebApp.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($mySiteDBServer))
        {
            $mySiteDBServer = $xmlinput.Configuration.Farm.Database.DBServer
        }
        $mySiteDB = $dbPrefix+$mySiteWebApp.databaseName
        $mySiteAppPoolAcct = $mySiteWebApp.applicationPoolAccount
        $portalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
        $portalAppPoolAcct = $portalWebApp.applicationPoolAccount
        $farmAcct = $xmlinput.Configuration.Farm.Account.Username
        $farmAcctPWD = $xmlinput.Configuration.Farm.Account.Password
        $contentAccessAcct = $xmlinput.Configuration.ServiceApps.EnterpriseSearchService.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount
        If (($farmAcctPWD -ne "") -and ($farmAcctPWD -ne $null)) {$farmAcctPWD = (ConvertTo-SecureString $farmAcctPWD -AsPlainText -force)}
        $mySiteTemplate = $mySiteWebApp.SiteCollections.SiteCollection.Template
        $mySiteLCID = $mySiteWebApp.SiteCollections.SiteCollection.LCID
        $userProfileServiceName = $userProfile.Name
        $userProfileServiceProxyName = $userProfile.ProxyName
        If($userProfileServiceName -eq $null) {$userProfileServiceName = "User Profile Service Application"}
        If($userProfileServiceProxyName -eq $null) {$userProfileServiceProxyName = $userProfileServiceName}
        If (!$farmCredential) {[System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput}
        # Set the directory path for the web app to something a bit more friendly
        ImportWebAdministration    
        # Get the default root location for web apps
        $iisWebDir = (Get-ItemProperty "IIS:\Sites\Default Web Site\" -name physicalPath) -replace ("%SystemDrive%","$env:SystemDrive")
        If (!([string]::IsNullOrEmpty($iisWebDir)))
        {
            $pathSwitch = @{Path = "$iisWebDir\wss\VirtualDirectories\$webAppName-$port"}
        }        

        If (ShouldIProvision($userProfile) -eq $true) 
        {        
            Write-Host -ForegroundColor White " - Provisioning $($userProfile.Name)"
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            # get the service instance
            $profileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
            $profileServiceInstance = $profileServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find User Profile Service instance" }
            # Start Service instance
            Write-Host -ForegroundColor White " - Starting User Profile Service instance..."
            If (($profileServiceInstance.Status -eq "Disabled") -or ($profileServiceInstance.Status -ne "Online"))
            {  
                $profileServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start User Profile Service instance" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for User Profile Service..." -NoNewline
                While ($profileServiceInstance.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $profileServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
                    $profileServiceInstance = $profileServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($profileServiceInstance.Status)
            }
            # Create a Profile Service Application
            If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileApplication"}) -eq $null)
            {      
                # Create MySites Web Application
                $getSPWebApplication = Get-SPWebApplication | Where-Object {$_.DisplayName -eq $mySiteName}
                If ($getSPWebApplication -eq $null)
                {
                    Write-Host -ForegroundColor White " - Creating Web App `"$mySiteName`"..."
                    New-SPWebApplication -Name $mySiteName -ApplicationPoolAccount $mySiteAppPoolAcct -ApplicationPool $mySiteAppPool -DatabaseServer $mySiteDBServer -DatabaseName $mySiteDB -HostHeader $mySiteHostHeader -Url $mySiteURL -Port $mySitePort -SecureSocketsLayer:$mySiteUseSSL @pathSwitch | Out-Null
                }
                Else
                {
                    Write-Host -ForegroundColor White " - Web app `"$mySiteName`" already provisioned."
                }
                
                # Create MySites Site Collection
                If ((Get-SPContentDatabase | Where-Object {$_.Name -eq $mySiteDB})-eq $null)
                {
                    Write-Host -ForegroundColor White " - Creating My Sites content DB..."
                    $newMySitesDB = New-SPContentDatabase -DatabaseServer $mySiteDBServer -Name $mySiteDB -WebApplication "$mySiteURL`:$mySitePort"
                    If (-not $?) { Throw " - Failed to create My Sites content DB" }
                }
                If (!(Get-SPSite -Limit ALL | Where-Object {(($_.Url -like "$mySiteURL*") -and ($_.Port -eq "$mySitePort"))}))
                {
                    Write-Host -ForegroundColor White " - Creating My Sites site collection $mySiteURL`:$mySitePort..."
                    # Verify that the Language we're trying to create the site in is currently installed on the server
                    $mySiteCulture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($mySiteLCID))) 
                    $mySiteCultureDisplayName = $mySiteCulture.DisplayName
                    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$env:spVer.0\InstalledLanguages").GetValueNames() | ? {$_ -ne ""}
                    If (!($installedOfficeServerLanguages | Where-Object {$_ -eq $mySiteCulture.Name}))
                    {
                        Throw " - You must install the `"$mySiteCulture ($mySiteCultureDisplayName)`" Language Pack before you can create a site using LCID $mySiteLCID"
                    }
                    Else
                    {
                        $newMySitesCollection = New-SPSite -Url "$mySiteURL`:$mySitePort" -OwnerAlias $farmAcct -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $mySiteDB -Description $mySiteName -Name $mySiteName -Template $mySiteTemplate -Language $mySiteLCID | Out-Null
                        If (-not $?) {Throw " - Failed to create My Sites site collection"}
                        # Assign SSL certificate, if required
                        If ($mySiteUseSSL)
                        {
                            $SSLHostHeader = $mySiteHostHeader
                            $SSLPort = $mySitePort
                            $SSLSiteName = $mySiteName
                            AssignCert
                        }
                    }
                }
                # Create Service App
                Write-Host -ForegroundColor White " - Creating $userProfileServiceName..."
                CreateUPSAsAdmin $xmlinput
                Write-Host -ForegroundColor Blue " - Waiting for $userProfileServiceName..." -NoNewline
                $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                While ($profileServiceApp.Status -ne "Online") 
                {
                    [int]$UPSWaitTime = 0
                    # Wait 2 minutes for either the UPS to be created, or the UAC prompt to time out
                    While (($UPSWaitTime -lt 120) -and ($profileServiceApp.Status -ne "Online"))
                    {
                        Write-Host -ForegroundColor Blue "." -NoNewline
                        Start-Sleep 1
                        $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                        [int]$UPSWaitTime += 1
                    }
                    # If it still isn't Online after 2 minutes, prompt to try again
                    If (!($profileServiceApp))
                    {
                        Write-Host -ForegroundColor Blue "."
                        Write-Warning " - Timed out waiting for service creation (maybe a UAC prompt?)"
                        Write-Host "`a`a`a" # System beeps
                        Pause "try again"
                        CreateUPSAsAdmin $xmlinput
                        Write-Host -ForegroundColor Blue " - Waiting for $userProfileServiceName..." -NoNewline
                        $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                    }
                    Else {break}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($profileServiceApp.Status)
                # Wait a few seconds for the CreateUPSAsAdmin function to complete
                Start-Sleep 30

                # Get our new Profile Service App
                $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                If (!($profileServiceApp)) {Throw " - Could not get $userProfileServiceName!";}
                
                # Create Proxy
                Write-Host -ForegroundColor White " - Creating $userProfileServiceName Proxy..."
                $profileServiceAppProxy  = New-SPProfileServiceApplicationProxy -Name "$userProfileServiceProxyName" -ServiceApplication $profileServiceApp -DefaultProxyGroup
                If (-not $?) { Throw " - Failed to create $userProfileServiceName Proxy" }
                
                Write-Host -ForegroundColor White " - Granting rights to $userProfileServiceName..."
                # Create a variable that contains the guid for the User Profile service for which you want to delegate permissions
                $serviceAppIDToSecure = Get-SPServiceApplication $($profileServiceApp.Id)

                # Create a variable that contains the list of administrators for the service application 
                $profileServiceAppSecurity = Get-SPServiceApplicationSecurity $serviceAppIDToSecure -Admin
                # Create a variable that contains the permissions for the service application
                $profileServiceAppPermissions = Get-SPServiceApplicationSecurity $serviceAppIDToSecure

                # Create variables that contains the claims principals for current (Setup) user, MySite App Pool, Portal App Pool and Content Access accounts
                $currentUserAcctPrincipal = New-SPClaimsPrincipal -Identity $env:USERDOMAIN\$env:USERNAME -IdentityType WindowsSamAccountName
                If ($mySiteAppPoolAcct) {$mySiteAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $mySiteAppPoolAcct -IdentityType WindowsSamAccountName}
                If ($portalAppPoolAcct) {$portalAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $portalAppPoolAcct -IdentityType WindowsSamAccountName}
                If ($contentAccessAcct) {$contentAccessAcctPrincipal = New-SPClaimsPrincipal -Identity $contentAccessAcct -IdentityType WindowsSamAccountName}

                # Give 'Full Control' permissions to the current (Setup) user, MySite App Pool and Portal App Pool account claims principals
                Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $currentUserAcctPrincipal -Rights "Full Control"
                Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $currentUserAcctPrincipal -Rights "Full Control"
                If ($mySiteAppPoolAcct) {Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $mySiteAppPoolAcctPrincipal -Rights "Full Control"}
                If ($portalAppPoolAcct) {Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $portalAppPoolAcctPrincipal -Rights "Full Control"}
                # Give 'Retrieve People Data for Search Crawlers' permissions to the Content Access claims principal
                If ($contentAccessAcct) {Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $contentAccessAcctPrincipal -Rights "Retrieve People Data for Search Crawlers"}

                # Apply the changes to the User Profile service application
                Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppSecurity -Admin
                Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppPermissions

                # Add link to resources list
                AddResourcesLink "User Profile Administration" ("_layouts/ManageUserProfileServiceApplication.aspx?ApplicationID=" +  $profileServiceApp.Id)
                
                If ($portalAppPoolAcct)
                {
                    # Grant the Portal App Pool account rights to the Profile and Social DBs
                    $profileDB = $dbPrefix+$userProfile.Database.ProfileDB
                    $socialDB = $dbPrefix+$userProfile.Database.SocialDB
                    Write-Host -ForegroundColor White " - Granting $portalAppPoolAcct rights to $profileDB..."
                    Get-SPDatabase | ? {$_.Name -eq $profileDB} | Add-SPShellAdmin -UserName $portalAppPoolAcct
                    Write-Host -ForegroundColor White " - Granting $portalAppPoolAcct rights to $socialDB..."
                    Get-SPDatabase | ? {$_.Name -eq $socialDB} | Add-SPShellAdmin -UserName $portalAppPoolAcct
                }
                Write-Host -ForegroundColor White " - Enabling the Activity Feed Timer Job.."
                If ($profileServiceApp) {Get-SPTimerJob | ? {$_.TypeName -eq "Microsoft.Office.Server.ActivityFeed.ActivityFeedUPAJob"} | Enable-SPTimerJob}
                
                Write-Host -ForegroundColor White " - Done creating $userProfileServiceName."
            }
            # Start User Profile Synchronization Service
            # Get User Profile Service
            $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
            If ($profileServiceApp -and ($userProfile.StartProfileSync -eq $true))
            {
                If ($userProfile.EnableNetBIOSDomainNames -eq $true)
                {
                    Write-Host -ForegroundColor White " - Enabling NetBIOS domain names for $userProfileServiceName..."
                    $profileServiceApp.NetBIOSDomainNamesEnabled = 1
                    $profileServiceApp.Update()
                }
                
                # Get User Profile Synchronization Service
                Write-Host -ForegroundColor White " - Checking User Profile Synchronization Service..." -NoNewline
                $profileSyncServices = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"})
                $profileSyncService = $profileSyncServices | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
                # Attempt to start only if there are no online Profile Sync Service instances in the farm as we don't want to start multiple Sync instances (running against the same Profile Service at least)
                If (!($profileSyncServices | ? {$_.Status -eq "Online"}))
                {
                    # Inspired by http://technet.microsoft.com/en-us/library/ee721049.aspx
                    If (!($farmAcct)) {$farmAcct = (Get-SPFarm).DefaultServiceAccount}
                    If (!($farmAcctPWD)) 
                    {
                        Write-Host -ForegroundColor White "`n"
                        $farmAcctPWD = Read-Host -Prompt " - Please (re-)enter the Farm Account Password" -AsSecureString
                    }
                    Write-Host -ForegroundColor White "`n"
                    # Check for an existing UPS credentials timer job (e.g. from a prior provisioning attempt), and delete it
                    $UPSCredentialsJob = Get-SPTimerJob | ? {$_.Name -eq "windows-service-credentials-FIMSynchronizationService"}
                    If ($UPSCredentialsJob.Status -eq "Online")
                    {
                        Write-Host -ForegroundColor White " - Deleting existing sync credentials timer job..."
                        $UPSCredentialsJob.Delete()
                    }
                    UpdateProcessIdentity $profileSyncService
                    $profileSyncService.Update()
                    Write-Host -ForegroundColor White " - Waiting for User Profile Synchronization Service..." -NoNewline
                    # Provision the User Profile Sync Service
                    $profileServiceApp.SetSynchronizationMachine($env:COMPUTERNAME, $profileSyncService.Id, $farmAcct, (ConvertTo-PlainText $farmAcctPWD))
                    If (($profileSyncService.Status -ne "Provisioning") -and ($profileSyncService.Status -ne "Online")) {Write-Host -ForegroundColor Blue "`n - Waiting for User Profile Synchronization Service to start..." -NoNewline}
                    # Monitor User Profile Sync service status
                    While ($profileSyncService.Status -ne "Online")
                    {
                        While ($profileSyncService.Status -ne "Provisioning")
                        {
                            Write-Host -ForegroundColor Blue "." -NoNewline
                            Start-Sleep 1
                            $profileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
                        }
                        If ($profileSyncService.Status -eq "Provisioning")
                        {
                            Write-Host -BackgroundColor Blue -ForegroundColor Black $($profileSyncService.Status)
                            Write-Host -ForegroundColor Blue " - Provisioning User Profile Sync Service, please wait..." -NoNewline
                        }
                        While($profileSyncService.Status -eq "Provisioning" -and $profileSyncService.Status -ne "Disabled")
                        {
                            Write-Host -ForegroundColor Blue "." -NoNewline
                            Start-Sleep 1
                            $profileSyncService = @(Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | ? {$_.Parent.Address -eq $env:COMPUTERNAME}
                        }
                        If ($profileSyncService.Status -ne "Online")
                        {
                            Write-Host -ForegroundColor Red ".`a`a"
                            Write-Host -BackgroundColor Red -ForegroundColor Black " - User Profile Synchronization Service could not be started!"
                            break
                        }
                        Else
                        {
                            Write-Host -BackgroundColor Blue -ForegroundColor Black $($profileSyncService.Status)
                            # Need to recycle the Central Admin app pool before we can do anything with the User Profile Sync Service
                            Write-Host -ForegroundColor White " - Recycling Central Admin app pool..."
                            # From http://sharepoint.nauplius.net/2011/09/iisreset-not-required-after-starting.html
                            $appPool = gwmi -Namespace "root\MicrosoftIISv2" -class "IIsApplicationPool" | where {$_.Name -eq "W3SVC/APPPOOLS/SharePoint Central Administration v4"}
                            If ($appPool)
                            {
                                $appPool.Recycle()
                            }
                            $newlyProvisionedSync = $true                            
                        }
                    }
                    
                    # Attempt to create a sync connection only on a successful, newly-provisioned User Profile Sync service
                    # We don't have the ability to check for existing connections and we don't want to overwrite/duplicate any existing sync connections
                    # Note that this isn't really supported anyhow, and that only SharePoint 2010 Service Pack 1 and above includes the Add-SPProfileSyncConnection cmdlet
                    If ((CheckForSP1) -and ($userProfile.CreateDefaultSyncConnection -eq $true) -and ($newlyProvisionedSync -eq $true))
                    {
                        Write-Host -ForegroundColor White " - Creating a default Profile Sync connection..."
                        $profileServiceApp = Get-SPServiceApplication |?{$_.DisplayName -eq $userProfileServiceName}
                        # Thanks to Codeplex user Reshetkov for this ingenious one-liner to build the default domain OU
                        $connectionSyncOU = "DC="+$env:USERDNSDOMAIN -replace "\.",",DC="
                        $syncConnectionDomain,$syncConnectionAcct = ($userProfile.SyncConnectionAccount) -split "\\"
                        $addProfileSyncCmd = @"
Add-PsSnapin Microsoft.SharePoint.PowerShell
Write-Host -ForegroundColor White " - Creating default Sync connection..."
`$syncConnectionAcctPWD = (ConvertTo-SecureString -String "$($userProfile.SyncConnectionAccountPassword)" -AsPlainText -Force)
Add-SPProfileSyncConnection -ProfileServiceApplication $($profileServiceApp.Id) -ConnectionForestName $env:USERDNSDOMAIN -ConnectionDomain $syncConnectionDomain -ConnectionUserName "$syncConnectionAcct" -ConnectionSynchronizationOU "$connectionSyncOU" -ConnectionPassword `$syncConnectionAcctPWD
If (!`$?) 
{
Write-Host "Press any key to exit..."
`$null = `$host.UI.RawUI.ReadKey(`"NoEcho,IncludeKeyDown`")
}
Else {Write-Host -ForegroundColor White " - Done.";Start-Sleep 15}
"@
                        $addProfileScriptFile = "$env:TEMP\AutoSPInstaller-AddProfileSyncCmd.ps1"
                        $addProfileSyncCmd | Out-File $addProfileScriptFile
                        # Run our Add-SPProfileSyncConnection script as the Farm Account - doesn't seem to work otherwise
                        Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$addProfileScriptFile'`" -Verb Runas" -Wait
                        # Give Add-SPProfileSyncConnection time to complete before continuing
                        Start-Sleep 120
                        Remove-Item -LiteralPath $addProfileScriptFile -Force -ErrorAction SilentlyContinue
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
#       This incorporates the workaround by @harbars & @glapointe http://www.harbar.net/archive/2010/10/30/avoiding-the-default-schema-issue-when-creating-the-user-profile.aspx
#       Modified to work within AutoSPInstaller (to pass our script variables to the Farm Account credential's Powershell session)
# ===================================================================================

Function CreateUPSAsAdmin([xml]$xmlinput)
{
    Try
    {
        $mySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.type -eq "MySiteHost"}
        $mySiteURL = $mySiteWebApp.url
        $mySitePort = $mySiteWebApp.port
        $farmAcct = $xmlinput.Configuration.Farm.Account.Username
        $userProfileServiceName = $userProfile.Name
        $dbServer = $userProfile.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($dbServer))
        {
            $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
        }
        # Set the ProfileDBServer, SyncDBServer and SocialDBServer to the same value ($dbServer). Maybe in the future we'll want to get more granular...?
        $profileDBServer = $dbServer
        $syncDBServer = $dbServer
        $socialDBServer = $dbServer
        $profileDB = $dbPrefix+$userProfile.Database.ProfileDB
        $syncDB = $dbPrefix+$userProfile.Database.SyncDB
        $socialDB = $dbPrefix+$userProfile.Database.SocialDB
        $applicationPool = Get-HostedServicesAppPool $xmlinput
        If (!$farmCredential) {[System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlinput}
        $scriptFile = "$env:TEMP\AutoSPInstaller-ScriptBlock.ps1"
        # Write the script block, with expanded variables to a temporary script file that the Farm Account can get at
        Write-Output "Write-Host -ForegroundColor White `"Creating $userProfileServiceName as $farmAcct...`"" | Out-File $scriptFile -Width 400
        Write-Output "Add-PsSnapin Microsoft.SharePoint.PowerShell" | Out-File $scriptFile -Width 400 -Append
        Write-Output "`$newProfileServiceApp = New-SPProfileServiceApplication -Name `"$userProfileServiceName`" -ApplicationPool `"$($applicationPool.Name)`" -ProfileDBServer $profileDBServer -ProfileDBName $profileDB -ProfileSyncDBServer $syncDBServer -ProfileSyncDBName $syncDB -SocialDBServer $socialDBServer -SocialDBName $socialDB -MySiteHostLocation `"$mySiteURL`:$mySitePort`"" | Out-File $scriptFile -Width 400 -Append
        Write-Output "If (-not `$?) {Write-Error `" - Failed to create $userProfileServiceName`"; Write-Host `"Press any key to exit...`"; `$null = `$host.UI.RawUI.ReadKey`(`"NoEcho,IncludeKeyDown`"`)}" | Out-File $scriptFile -Width 400 -Append
        # Grant the current install account rights to the newly-created Profile DB - needed since it's going to be running PowerShell commands against it
        Write-Output "`$profileDBId = Get-SPDatabase | ? {`$_.Name -eq `"$profileDB`"}" | Out-File $scriptFile -Width 400 -Append
        Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$profileDBId" | Out-File $scriptFile -Width 400 -Append
        # Grant the current install account rights to the newly-created Social DB as well
        Write-Output "`$socialDBId = Get-SPDatabase | ? {`$_.Name -eq `"$socialDB`"}" | Out-File $scriptFile -Width 400 -Append
        Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$socialDBId" | Out-File $scriptFile -Width 400 -Append
        If (Confirm-LocalSession) # Create the UPA as usual if this isn't a remote session
        {
            # Start a process under the Farm Account's credentials, then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$scriptFile'`" -Verb Runas" -Wait
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
            # Pass the value of $scriptFile to the new session
            Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name ScriptFile -Value $value} -ArgumentList $scriptFile -Session $UPSession
            Write-Host -ForegroundColor White " - Creating $userProfileServiceName under `"remote`" session..."
            # Start a (local) process (on our "remote" session), then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Invoke-Command -ScriptBlock {Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList $scriptFile -Verb Runas} -Session $UPSession
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
        $profileServiceApp = Get-SPServiceApplication | ? {$_.DisplayName -eq $userProfileServiceName}
        If ($profileServiceApp) {Remove-Item -LiteralPath $scriptFile -Force}
    }
}
#EndRegion

#Region Create State Service Application
Function CreateStateServiceApp([xml]$xmlinput)
{
    $stateService = $xmlinput.Configuration.ServiceApps.StateService
    If (ShouldIProvision($stateService) -eq $true) 
    {
        WriteLine
        Try
        {
            $dbServer = $stateService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $stateServiceDB = $dbPrefix+$stateService.Database.Name
            $stateServiceName = $stateService.Name
            $stateServiceProxyName = $stateService.ProxyName
            If ($stateServiceName -eq $null) {$stateServiceName = "State Service Application"}
            If ($stateServiceProxyName -eq $null) {$stateServiceProxyName = $stateServiceName}
            $getSPStateServiceApplication = Get-SPStateServiceApplication
            If ($getSPStateServiceApplication -eq $null)
            {
                Write-Host -ForegroundColor White " - Provisioning State Service Application..."
                New-SPStateServiceDatabase -DatabaseServer $dbServer -Name $stateServiceDB | Out-Null
                New-SPStateServiceApplication -Name $stateServiceName -Database $stateServiceDB | Out-Null
                Get-SPStateServiceDatabase | Initialize-SPStateServiceDatabase | Out-Null
                Write-Host -ForegroundColor White " - Creating State Service Application Proxy..."
                Get-SPStateServiceApplication | New-SPStateServiceApplicationProxy -Name $stateServiceProxyName -DefaultProxyGroup | Out-Null
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
            $dbServer = $xmlinput.Configuration.ServiceApps.SPUsageService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $spUsageApplicationName = $xmlinput.Configuration.ServiceApps.SPUsageService.Name
            $spUsageDB = $dbPrefix+$xmlinput.Configuration.ServiceApps.SPUsageService.Database.Name
            $getSPUsageApplication = Get-SPUsageApplication
            If ($getSPUsageApplication -eq $null)
            {
                Write-Host -ForegroundColor White " - Provisioning SP Usage Application..."
                New-SPUsageApplication -Name $spUsageApplicationName -DatabaseServer $dbServer -DatabaseName $spUsageDB | Out-Null
                # Need this to resolve a known issue with the Usage Application Proxy not automatically starting/provisioning
                # Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 ! 
                Write-Host -ForegroundColor White " - Fixing Usage and Health Data Collection Proxy..."
                $spUsageApplicationProxy = Get-SPServiceApplicationProxy | where {$_.DisplayName -eq $spUsageApplicationName}
                $spUsageApplicationProxy.Provision()
                # End Usage Proxy Fix
                Write-Host -ForegroundColor White " - Enabling usage processing timer job..."
                $usageProcessingJob = Get-SPTimerJob | ? {$_.TypeName -eq "Microsoft.SharePoint.Administration.SPUsageProcessingJobDefinition"}
                $usageProcessingJob.IsDisabled = $false
                $usageProcessingJob.Update()                
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
        $oldIISLogDir = Get-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory.Value
        $oldIISLogDir = $oldIISLogDir -replace ("%SystemDrive%","$env:SystemDrive")
        If ($IISLogDir -ne $oldIISLogDir) # Only change the global IIS logging location if the desired location is different than the current
        {
            Write-Host -ForegroundColor White " - Setting the global IIS logging location..."
            # The line below is from http://stackoverflow.com/questions/4626791/powershell-command-to-set-iis-logging-settings
            Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults" -name logfile.directory -value $IISLogDir
            If (Test-Path -Path $oldIISLogDir)
            {
                Write-Host -ForegroundColor White " - Moving any contents in old location $oldIISLogDir to $IISLogDir..."
                ForEach ($item in $(Get-ChildItem $oldIISLogDir)) 
                {
                    Move-Item -Path $oldIISLogDir\$item -Destination $IISLogDir -Force -ErrorAction SilentlyContinue
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
#       And Codeplex user timiun: http://autospinstaller.codeplex.com/discussions/261598
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
        $doConfig = $true
        EnsureFolder $ULSLogDir
        $oldULSLogDir = $(Get-SPDiagnosticConfig).LogLocation
        $oldULSLogDir = $oldULSLogDir -replace ("%CommonProgramFiles%","$env:CommonProgramFiles")
    }
    Else # Assume default value if none was specified in the XML input file
    {
        $ULSLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\LOGS"
    }
    If (!([string]::IsNullOrEmpty($ULSLogDiskSpace)))
    {
        $doConfig = $true
        $ULSLogMaxDiskSpaceUsageEnabled = $true
    }
    Else # Assume default values if none were specified in the XML input file
    {
        $ULSLogDiskSpace = 1000
        $ULSLogMaxDiskSpaceUsageEnabled = $false
    }
    If (!([string]::IsNullOrEmpty($ULSLogRetention)))
    {$doConfig = $true}
    Else # Assume default value if none was specified in the XML input file
    {
        $ULSLogRetention = 14
    }
    If (!([string]::IsNullOrEmpty($ULSLogCutInterval)))
    {$doConfig = $true}
    Else # Assume default value if none was specified in the XML input file
    {
        $ULSLogCutInterval = 30
    }
    # Only modify the Diagnostic Config if we have specified at least one value in the XML input file
    If ($doConfig)
    {
        Write-Host -ForegroundColor White " - Setting SharePoint diagnostic (ULS) logging options:"
        Write-Host -ForegroundColor White "  - DaysToKeepLogs: $ULSLogRetention" 
        Write-Host -ForegroundColor White "  - LogMaxDiskSpaceUsageEnabled: $ULSLogMaxDiskSpaceUsageEnabled"
        Write-Host -ForegroundColor White "  - LogDiskSpaceUsageGB: $ULSLogDiskSpace"
        Write-Host -ForegroundColor White "  - LogLocation: $ULSLogDir"
        Write-Host -ForegroundColor White "  - LogCutInterval: $ULSLogCutInterval"
        Set-SPDiagnosticConfig -DaysToKeepLogs $ULSLogRetention -LogMaxDiskSpaceUsageEnabled:$ULSLogMaxDiskSpaceUsageEnabled -LogDiskSpaceUsageGB $ULSLogDiskSpace -LogLocation $ULSLogDir -LogCutInterval $ULSLogCutInterval
        # Only move log files if the old & new locations are different, and if the old location actually had a value
        If (($ULSLogDir -ne $oldULSLogDir) -and (!([string]::IsNullOrEmpty($oldULSLogDir))))
        {
            Write-Host -ForegroundColor White " - Moving any contents in old location $oldULSLogDir to $ULSLogDir..."
            ForEach ($item in $(Get-ChildItem $oldULSLogDir) | Where-Object {$_.Name -like "*.log"}) 
            {
                Move-Item -Path $oldULSLogDir\$item -Destination $ULSLogDir -Force -ErrorAction SilentlyContinue
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
        $usageLogConfig = $xmlinput.Configuration.Farm.Logging.UsageLogs
        $usageLogDir = $usageLogConfig.UsageLogDir
        $usageLogMaxSpaceGB = $usageLogConfig.UsageLogMaxSpaceGB
        $usageLogCutTime = $usageLogConfig.UsageLogCutTime
        Write-Host -ForegroundColor White " - Configuring Usage Logging..."
        # Syntax for command: Set-SPUsageService [-LoggingEnabled {1 | 0}] [-UsageLogLocation <Path>] [-UsageLogMaxSpaceGB <1-20>] [-Verbose]
        # These are a per-farm settings, not per WSS Usage service application, as there can only be one per farm.
        Try
        {
            If (!([string]::IsNullOrEmpty($usageLogDir)))
            {
                EnsureFolder $usageLogDir
                $oldUsageLogDir = $(Get-SPUsageService).UsageLogDir
                $oldUsageLogDir = $oldUsageLogDir -replace ("%CommonProgramFiles%","$env:CommonProgramFiles")
            }
            Else # Assume default value if none was specified in the XML input file
            {
                $usageLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\LOGS"
            }
            # UsageLogMaxSpaceGB must be between 1 and 20.
            If (($usageLogMaxSpaceGB -lt 1) -or ([string]::IsNullOrEmpty($usageLogMaxSpaceGB))) {$usageLogMaxSpaceGB = 5} # Default value
            If ($usageLogMaxSpaceGB -gt 20) {$usageLogMaxSpaceGB = 20} # Maximum value
            # UsageLogCutTime must be between 1 and 1440
            If (($usageLogCutTime -lt 1) -or ([string]::IsNullOrEmpty($usageLogCutTime))) {$usageLogCutTime = 30} # Default value
            If ($usageLogCutTime -gt 1440) {$usageLogCutTime = 1440} # Maximum value
            # Set-SPUsageService's LoggingEnabled is 0 for disabled, and 1 for enabled
            $loggingEnabled = 1
            Set-SPUsageService -LoggingEnabled $loggingEnabled -UsageLogLocation "$usageLogDir" -UsageLogMaxSpaceGB $usageLogMaxSpaceGB -UsageLogCutTime $usageLogCutTime | Out-Null
            # Only move log files if the old & new locations are different, and if the old location actually had a value
            If (($usageLogDir -ne $oldUsageLogDir) -and (!([string]::IsNullOrEmpty($oldUsageLogDir))))
            {
                Write-Host -ForegroundColor White " - Moving any contents in old location $oldUsageLogDir to $usageLogDir..."
                ForEach ($item in $(Get-ChildItem $oldUsageLogDir) | Where-Object {$_.Name -like "*.usage"}) 
                {
                    Move-Item -Path $oldUsageLogDir\$item -Destination $usageLogDir -Force -ErrorAction SilentlyContinue
                }
            }           
            # Finally, enable NTFS compression on the usage log location to save disk space
            If ($usageLogConfig.Compress -eq $true)
            {
                CompressFolder $usageLogDir
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
    If ((ShouldIProvision($xmlinput.Configuration.ServiceApps.WebAnalyticsService) -eq $true) -and ($env:spVer -eq "14")) 
    {
        WriteLine
        Try
        {
            $dbServer = $xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            $webAnalyticsReportingDB = $dbPrefix+$xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.ReportingDB
            $webAnalyticsStagingDB = $dbPrefix+$xmlinput.Configuration.ServiceApps.WebAnalyticsService.Database.StagingDB
            $webAnalyticsServiceName = $xmlinput.Configuration.ServiceApps.WebAnalyticsService.Name
            $getWebAnalyticsServiceApplication = Get-SPWebAnalyticsServiceApplication $webAnalyticsServiceName -ea SilentlyContinue
            Write-Host -ForegroundColor White " - Provisioning $webAnalyticsServiceName..."
            # Start Analytics service instances
            Write-Host -ForegroundColor White " - Checking Analytics Service instances..."
            $analyticsWebServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsWebServiceInstance"}
            $analyticsWebServiceInstance = $analyticsWebServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find Analytics Web Service instance" }
            Write-Host -ForegroundColor White " - Starting local Analytics Web Service instance..."
            $analyticsWebServiceInstance.Provision()
            $analyticsDataProcessingInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsServiceInstance"}
            $analyticsDataProcessingInstance = $analyticsDataProcessingInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find Analytics Data Processing Service instance" }
            UpdateProcessIdentity $analyticsDataProcessingInstance
            $analyticsDataProcessingInstance.Update()
            Write-Host -ForegroundColor White " - Starting local Analytics Data Processing Service instance..."
            $analyticsDataProcessingInstance.Provision()
            If ($getWebAnalyticsServiceApplication -eq $null)
            {
                $stagerSubscription = "<StagingDatabases><StagingDatabase ServerName='$dbServer' DatabaseName='$webAnalyticsStagingDB'/></StagingDatabases>"
                $warehouseSubscription = "<ReportingDatabases><ReportingDatabase ServerName='$dbServer' DatabaseName='$webAnalyticsReportingDB'/></ReportingDatabases>" 
                Write-Host -ForegroundColor White " - Creating $webAnalyticsServiceName..."
                $serviceApplication = New-SPWebAnalyticsServiceApplication -Name $webAnalyticsServiceName -ReportingDataRetention 20 -SamplingRate 100 -ListOfReportingDatabases $warehouseSubscription -ListOfStagingDatabases $stagerSubscription -ApplicationPool $applicationPool 
                # Create Web Analytics Service Application Proxy
                Write-Host -ForegroundColor White " - Creating $webAnalyticsServiceName Proxy..."
                $newWebAnalyticsServiceApplicationProxy = New-SPWebAnalyticsServiceApplicationProxy  -Name $webAnalyticsServiceName -ServiceApplication $serviceApplication.Name
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
            If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
            {
                $farmPassphrase = GetFarmPassPhrase $xmlinput
            }
            $secureStoreServiceAppName = $xmlinput.Configuration.ServiceApps.SecureStoreService.Name
            $secureStoreServiceAppProxyName = $xmlinput.Configuration.ServiceApps.SecureStoreService.ProxyName
            If ($secureStoreServiceAppName -eq $null) {$secureStoreServiceAppName = "State Service Application"}
            If ($secureStoreServiceAppProxyName -eq $null) {$secureStoreServiceAppProxyName = $secureStoreServiceAppName}
            $dbServer = $xmlinput.Configuration.ServiceApps.SecureStoreService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $secureStoreDB = $dbPrefix+$xmlinput.Configuration.ServiceApps.SecureStoreService.Database.Name
            Write-Host -ForegroundColor White " - Provisioning Secure Store Service Application..."
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            # Get the service instance
            $secureStoreServiceInstances = Get-SPServiceInstance | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
            $secureStoreServiceInstance = $secureStoreServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find Secure Store service instance" }
            # Start Service instance
            If ($secureStoreServiceInstance.Status -eq "Disabled")
            { 
                Write-Host -ForegroundColor White " - Starting Secure Store Service Instance..."
                $secureStoreServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start Secure Store service instance" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for Secure Store service..." -NoNewline
                While ($secureStoreServiceInstance.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $secureStoreServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance"}
                    $secureStoreServiceInstance = $secureStoreServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($secureStoreServiceInstance.Status)
            }
            # Create Service Application
            $getSPSecureStoreServiceApplication = Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])}
            If ($getSPSecureStoreServiceApplication -eq $null)
            {
                Write-Host -ForegroundColor White " - Creating Secure Store Service Application..."
                New-SPSecureStoreServiceApplication -Name $secureStoreServiceAppName -PartitionMode:$false -Sharing:$false -DatabaseServer $dbServer -DatabaseName $secureStoreDB -ApplicationPool $($applicationPool.Name) -AuditingEnabled:$true -AuditLogMaxSize 30 | Out-Null
                Write-Host -ForegroundColor White " - Creating Secure Store Service Application Proxy..."
                Get-SPServiceApplication | ? {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])} | New-SPSecureStoreServiceApplicationProxy -Name $secureStoreServiceAppProxyName -DefaultProxyGroup | Out-Null
                Write-Host -ForegroundColor White " - Done creating Secure Store Service Application."
            }
            Else {Write-Host -ForegroundColor White " - Secure Store Service Application already provisioned."}
            
            $secureStore = Get-SPServiceApplicationProxy | Where {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplicationProxy])}
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Master Key..."
            Update-SPSecureStoreMasterKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$farmPassPhrase"
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Application Key..."
            Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$farmPassPhrase" -ErrorAction SilentlyContinue
            Start-Sleep 5
            If (!$?)
            {
                # Try again...
                Write-Host -ForegroundColor White " - Creating the Application Key (2nd attempt)..."
                Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase "$farmPassPhrase"
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
            $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
            $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find Search Query and Site Settings service instance" }
            # Start Service instance
            Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
            If($searchQueryAndSiteSettingsService.Status -eq "Disabled")
            { 
                $searchQueryAndSiteSettingsService.Provision()
                If (-not $?) { Throw " - Failed to start Search Query and Site Settings service instance" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for Search Query and Site Settings service..." -NoNewline
                While ($searchQueryAndSiteSettingsService.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                    $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black $($searchQueryAndSiteSettingsService.Status)
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
        $claimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
        $claimsService = $claimsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
        If ($claimsService.Status -ne "Online")
        {
            Try
            {
                Write-Host -ForegroundColor White " - Starting $($claimsService.DisplayName)..."
                $claimsService.Provision()
                If (-not $?) {throw " - Failed to start $($claimsService.DisplayName)"}
            }
            Catch
            {
                Throw " - An error occurred starting $($claimsService.DisplayName)"
            }
            #Wait
            Write-Host -ForegroundColor Blue " - Waiting for $($claimsService.DisplayName)..." -NoNewline
            While ($claimsService.Status -ne "Online") 
            {
                Write-Host -ForegroundColor Blue "." -NoNewline
                sleep 1
                $claimsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
                $claimsService = $claimsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Blue -ForegroundColor Black $($claimsService.Status)
        }
        Else 
        {
            Write-Host -ForegroundColor White " - $($claimsService.DisplayName) already started."
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
    $foundationWebServices = Get-SPServiceInstance | ? {$_.Service.ToString() -eq "SPWebService"}
    $foundationWebService = $foundationWebServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
    Write-Host -ForegroundColor White " - Stopping $($foundationWebService.TypeName)..."
    $foundationWebService.Unprovision()
    If (-not $?) {Throw " - Failed to stop $($foundationWebService.TypeName)" }
    # Wait
    Write-Host -ForegroundColor Blue " - Waiting for $($foundationWebService.TypeName) to stop..." -NoNewline
    While ($foundationWebService.Status -ne "Disabled") 
    {
        Write-Host -ForegroundColor Blue "." -NoNewline
        Start-Sleep 1
        $foundationWebServices = Get-SPServiceInstance | ? {$_.Service.ToString() -eq "SPWebService"}
        $foundationWebService = $foundationWebServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
    }
    Write-Host -BackgroundColor Blue -ForegroundColor Black $($foundationWebService.Status)
}
#EndRegion

#Region Stop Workflow Timer Service
# ===================================================================================
# Func: StopWorkflowTimerService
# Desc: Disables the Microsoft SharePoint Foundation Workflow Timer Service
# ===================================================================================
Function StopWorkflowTimerService
{
    $workflowTimerServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Workflow.SPWorkflowTimerServiceInstance"}
    $workflowTimerService = $workflowTimerServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
    Write-Host -ForegroundColor White " - Stopping $($workflowTimerService.TypeName)..."
    $workflowTimerService.Unprovision()
    If (-not $?) {Throw " - Failed to stop $($workflowTimerService.TypeName)" }
    # Wait
    Write-Host -ForegroundColor Blue " - Waiting for $($workflowTimerService.TypeName) to stop..." -NoNewline
    While ($workflowTimerService.Status -ne "Disabled") 
    {
        Write-Host -ForegroundColor Blue "." -NoNewline
        Start-Sleep 1
        $workflowTimerServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.Workflow.SPWorkflowTimerServiceInstance"}
        $workflowTimerService = $workflowTimerServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
    }
    Write-Host -BackgroundColor Blue -ForegroundColor Black $($workflowTimerService.Status)
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
    # Make sure a credential deployment job doesn't already exist, and that we are running SP2010
    if ((!(Get-SPTimerJob -Identity "windows-service-credentials-SPSearch4")) -and ($env:spVer -eq "14"))
    {
        WriteLine
        Try
        {
            $foundationSearchService = (Get-SPFarm).Services | where {$_.Name -eq "SPSearch4"}
            $spservice = Get-spserviceaccountxml $xmlinput
            UpdateProcessIdentity $foundationSearchService
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
        $spTraceV4 = (Get-SPFarm).Services | where {$_.Name -eq "SPTraceV4"}
        $appPoolAcctDomain,$appPoolAcctUser = $spservice.username -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service SPTraceV4..."
        #Add to Performance Monitor Users group
        Write-Host -ForegroundColor White " - Adding $($spservice.username) to local Performance Monitor Users group..."
        Try
        {
            ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Monitor Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
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
            ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Log Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
            If (-not $?) {Throw}
        }
        Catch 
        {
            Write-Host -ForegroundColor White " - $($spservice.username) is already a member of Performance Log Users."
        }
        Try
        {
            UpdateProcessIdentity $spTraceV4
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

#Region Configure Distributed Cache Service
# ====================================================================================
# Func: ConfigureDistributedCacheService
# Desc: Updates the service account for AppFabricCachingService AKA Distributed Caching Service
# ====================================================================================

Function ConfigureDistributedCacheService ([xml]$xmlinput)
{
    # Make sure a credential deployment job doesn't already exist, and that we are running SP2013
    if ((!(Get-SPTimerJob -Identity "windows-service-credentials-AppFabricCachingService")) -and ($env:spVer -eq "15"))
    {
        WriteLine
        $spservice = Get-spserviceaccountxml $xmlinput
        $distributedCachingSvc = (Get-SPFarm).Services | where {$_.Name -eq "AppFabricCachingService"}
        $appPoolAcctDomain,$appPoolAcctUser = $spservice.username -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service AppFabricCachingService..."
        $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
        Try
        {
            UpdateProcessIdentity $distributedCachingSvc
        }
        Catch
        {
            Write-Output $_
            Write-Warning " - An error occurred updating the service account for service AppFabricCachingService."
        }
        WriteLine
    }
}
#EndRegion

#Region Provision Enterprise Search

# Original script for SharePoint 2010 beta2 by Gary Lapointe ()
# 
# Modified by Søren Laurits Nielsen (soerennielsen.wordpress.com):
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
        $portalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
        $portalURL = $portalWebApp.URL
        $portalPort = $portalWebApp.Port
        $mySiteWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "MySiteHost"}
        $mySiteURL = $mySiteWebApp.URL
        $mySitePort = $mySiteWebApp.Port
        If ($mySiteURL -like "https://*") {$mySiteHostHeader = $mySiteURL -replace "https://",""}        
        Else {$mySiteHostHeader = $mySiteURL -replace "http://",""}
        $secSearchServicePassword = ConvertTo-SecureString -String $svcConfig.Password -AsPlainText -Force
        $secContentAccessAcctPWD = ConvertTo-SecureString -String $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccountPassword -AsPlainText -Force

        $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
        If ($searchSvc -eq $null) {
            Throw " - Unable to retrieve search service."
        }
        Write-Host -ForegroundColor White " - Configuring search service..." -NoNewline
        Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService  `
          -ContactEmail $svcConfig.ContactEmail -ConnectionTimeout $svcConfig.ConnectionTimeout `
          -AcknowledgementTimeout $svcConfig.AcknowledgementTimeout -ProxyType $svcConfig.ProxyType `
          -IgnoreSSLWarnings $svcConfig.IgnoreSSLWarnings -InternetIdentity $svcConfig.InternetIdentity -PerformanceLevel $svcConfig.PerformanceLevel `
          -ServiceAccount $svcConfig.Account -ServicePassword $secSearchServicePassword
        If ($?) {Write-Host -ForegroundColor White "Done."}
        
        Write-Host -ForegroundColor White " - Setting default index location on search service instance..." -NoNewline
        $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $svcConfig.IndexLocation -ErrorAction SilentlyContinue
        If ($?) {Write-Host -ForegroundColor White "Done."}
        
        If ($env:spVer -eq "14") # SharePoint 2010 steps
        {
            $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication | ForEach-Object {
                $appConfig = $_
                If (($appConfig.DatabaseServer -ne "") -and ($appConfig.DatabaseServer -ne $null))
                {
                    $dbServer = $appConfig.DatabaseServer
                }
                Else
                {
                    $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
                }

                # Try and get the application pool if it already exists
                $pool = Get-ApplicationPool $appConfig.ApplicationPool
                $adminPool = Get-ApplicationPool $appConfig.AdminComponent.ApplicationPool

                $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name -ErrorAction SilentlyContinue

                If ($searchApp -eq $null) {
                    Write-Host -ForegroundColor White " - Creating $($appConfig.Name)..."
                    $searchApp = New-SPEnterpriseSearchServiceApplication -Name $appConfig.Name `
                        -DatabaseServer $dbServer `
                        -DatabaseName $($dbPrefix+$appConfig.DatabaseName) `
                        -FailoverDatabaseServer $appConfig.FailoverDatabaseServer `
                        -ApplicationPool $pool `
                        -AdminApplicationPool $adminPool `
                        -Partitioned:([bool]::Parse($appConfig.Partitioned)) `
                        -SearchApplicationType $appConfig.SearchServiceApplicationType
                } Else {
                    Write-Host -ForegroundColor White " - Enterprise search service application already exists, skipping creation."
                }
                
                #Add link to resources list
                AddResourcesLink "Search Administration" ("searchadministration.aspx?appid=" +  $searchApp.Id)

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
                
                    $adminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
                    If ($adminCmpnt.Initialized -eq $false)
                    {
                        Write-Host -ForegroundColor Blue " - Waiting for administration component initialization..." -NoNewline
                        While ($adminCmpnt.Initialized -ne $true)
                        {
                            Write-Host -ForegroundColor Blue "." -NoNewline
                            Start-Sleep 1
                            $adminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
                        }
                        Write-Host -BackgroundColor Blue -ForegroundColor Black $($adminCmpnt.Initialized -replace "True","Done.")
                    }
                    Else {Write-Host -ForegroundColor White " - Administration component already initialized."}
                }
                # Update the default Content Access Account
                try 
                {
                    Write-Host -ForegroundColor White " - Setting content access account for $($appconfig.Name)..."
                    $searchApp | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount `
                                                                          -DefaultContentAccessAccountPassword $secContentAccessAcctPWD -ErrorVariable err
                }
                catch   
                {
                    if ($err -like "*update conflict*")
                    {
                        Write-Warning " - A concurrency error occured, trying again."
                        Write-Host -ForegroundColor White " - Setting content access account for $($appconfig.Name)..."
                        $searchApp | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount `
                                                                              -DefaultContentAccessAccountPassword $secContentAccessAcctPWD -ErrorVariable err
                    }
                    else 
                    {
                        throw $_
                    }
                }
                finally {Clear-Variable err}
                
                $crawlTopology = Get-SPEnterpriseSearchCrawlTopology -SearchApplication $searchApp | where {$_.CrawlComponents.Count -gt 0 -or $_.State -eq "Inactive"}

                If ($crawlTopology -eq $null) {
                    Write-Host -ForegroundColor White " - Creating new crawl topology..."
                    $crawlTopology = $searchApp | New-SPEnterpriseSearchCrawlTopology
                } Else {
                    Write-Host -ForegroundColor White " - A crawl topology with crawl components already exists, skipping crawl topology creation."
                }
         
                If ($installCrawlSvc) {
                    $crawlComponent = $crawlTopology.CrawlComponents | where {$_.ServerName -eq $env:ComputerName}
                    If ($crawlTopology.CrawlComponents.Count -eq 0 -or $crawlComponent -eq $null) {
                        $crawlStore = $searchApp.CrawlStores | where {$_.Name -eq "$($dbPrefix+$appConfig.DatabaseName)_CrawlStore"}
                        Write-Host -ForegroundColor White " - Creating new crawl component..."
                        $crawlComponent = New-SPEnterpriseSearchCrawlComponent -SearchServiceInstance $searchSvc -SearchApplication $searchApp -CrawlTopology $crawlTopology -CrawlDatabase $crawlStore.Id.ToString() -IndexLocation $appConfig.IndexLocation
                    } Else {
                        Write-Host -ForegroundColor White " - Crawl component already exist, skipping crawl component creation."
                    }
                }

                $queryTopologies = Get-SPEnterpriseSearchQueryTopology -SearchApplication $searchApp | where {$_.QueryComponents.Count -gt 0 -or $_.State -eq "Inactive"}
                If ($queryTopologies.Count -lt 1) {
                    Write-Host -ForegroundColor White " - Creating new query topology..."
                    $queryTopology = $searchApp | New-SPEnterpriseSearchQueryTopology -Partitions $appConfig.Partitions
                } Else {
                    Write-Host -ForegroundColor White " - A query topology already exists, skipping query topology creation."
                    If ($queryTopologies.Count -gt 1)
                    {
                        # Try to select the query topology that has components
                        $queryTopology = $queryTopologies | Where-Object {$_.QueryComponents.Count -gt 0} | Select-Object -First 1
                        if (!$queryTopology)
                        {
                            # Just select the first query topology since none appear to have query components
                            $queryTopology = $queryTopologies | Select-Object -First 1
                        }
                    }
                    Else 
                    {
                        # Just set it to $queryTopologies since there is only one
                        $queryTopology = $queryTopologies
                    }
                }

                If ($installQuerySvc) {
                    $queryComponent = $queryTopology.QueryComponents | where {$_.ServerName -eq $env:ComputerName}
                    If ($queryComponent -eq $null) {
                        $partition = ($queryTopology | Get-SPEnterpriseSearchIndexPartition)
                        Write-Host -ForegroundColor White " - Creating new query component..."
                        $queryComponent = New-SPEnterpriseSearchQueryComponent -IndexPartition $partition -QueryTopology $queryTopology -SearchServiceInstance $searchSvc -ShareName $svcConfig.ShareName
                        Write-Host -ForegroundColor White " - Setting index partition and property store database..."
                        $propertyStore = $searchApp.PropertyStores | where {$_.Name -eq "$($dbPrefix+$appConfig.DatabaseName)_PropertyStore"}
                        $partition | Set-SPEnterpriseSearchIndexPartition -PropertyDatabase $propertyStore.Id.ToString()
                    } Else {
                        Write-Host -ForegroundColor White " - Query component already exists, skipping query component creation."
                    }
                }

                If ($installSyncSvc) {            
                    # SLN: Updated to new syntax
                    $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                    $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                    If (-not $?) { Throw " - Failed to find Search Query and Site Settings service instance" }
                    # Start Service instance
                    Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
                    If ($searchQueryAndSiteSettingsService.Status -eq "Disabled")
                    { 
                        $searchQueryAndSiteSettingsService.Provision()
                        If (-not $?) { Throw " - Failed to start Search Query and Site Settings service instance" }
                        # Wait
                        Write-Host -ForegroundColor Blue " - Waiting for Search Query and Site Settings service..." -NoNewline
                        While ($searchQueryAndSiteSettingsService.Status -ne "Online") 
                        {
                            Write-Host -ForegroundColor Blue "." -NoNewline
                            Start-Sleep 1
                            $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                            $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                        }
                        Write-Host -BackgroundColor Blue -ForegroundColor Black $($searchQueryAndSiteSettingsService.Status)
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
            WriteLine
        }
        ElseIf ($env:spVer -eq "15") # SharePoint 2013 steps
        {
            $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication | ForEach-Object {
                $appConfig = $_
                If (($appConfig.DatabaseServer -ne "") -and ($appConfig.DatabaseServer -ne $null))
                {
                    $dbServer = $appConfig.DatabaseServer
                }
                Else
                {
                    $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
                }

                $installAdminCmpnt = (($appConfig.AdminComponent.Server | where {$_.Name -eq $env:computername}) -ne $null)
                If ($installAdminCmpnt) {$searchServerName = $env:COMPUTERNAME}
                $pool = Get-ApplicationPool $appConfig.ApplicationPool
                $adminPool = Get-ApplicationPool $appConfig.AdminComponent.ApplicationPool            
                $appPoolUserName = $svcConfig.Account
                $searchSAName = $appConfig.Name

                $saAppPool = Get-SPServiceApplicationPool -Identity $pool -ErrorAction SilentlyContinue
                if($saAppPool -eq $null)
                {
                    Write-Host -ForegroundColor White " - Creating Service Application Pool..."

                    $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -ErrorAction SilentlyContinue
                    if($appPoolAccount -eq $null)
                    {
                        Write-Host -ForegroundColor White " - Please supply the password for the Service Account..."
                        $appPoolCred = Get-Credential $appPoolUserName
                        $appPoolAccount = New-SPManagedAccount -Credential $appPoolCred -ErrorAction SilentlyContinue
                    }

                    $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -ErrorAction SilentlyContinue

                    if($appPoolAccount -eq $null)
                    {
                        Throw " - Cannot create or find the managed account $appPoolUserName, please ensure the account exists."
                    }

                    New-SPServiceApplicationPool -Name $pool -Account $appPoolAccount -ErrorAction SilentlyContinue | Out-Null
                }

                Write-Host -ForegroundColor White " - Checking Search Service Instance..." -NoNewline
                If ($searchSvc.Status -eq "Disabled") ##-and ($installCrawlSvc -or $installQuerySvc))
                {
                    Write-Host -ForegroundColor White "Starting..." -NoNewline
                    $searchSvc | Start-SPEnterpriseSearchServiceInstance
                    If (!$?) {Throw " - Could not start the Search Service Instance."}
                    # Wait
                    While ($searchSvc.Status -ne "Online") 
                    {
                        Write-Host -ForegroundColor Blue "." -NoNewline
                        Start-Sleep 1
                        $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
                    }
                    Write-Host -BackgroundColor Blue -ForegroundColor Black $($searchSvc.Status)
                }
                Else {Write-Host -ForegroundColor White "Already $($searchSvc.Status)."}
                
                Write-Host -ForegroundColor White " - Checking Search Query and Site Settings Service Instance..." -NoNewline
                $searchQueryAndSiteSettingsService = Get-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance -Local
                If ($searchQueryAndSiteSettingsService.Status -eq "Disabled")
                {
                    Write-Host -ForegroundColor White "Starting..." -NoNewline
                    $searchQueryAndSiteSettingsService | Start-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance
                    If (!$?) {Throw " - Could not start the Search Query and Site Settings Service Instance."}
                    Write-Host -ForegroundColor White "Done."
                }
                Else {Write-Host -ForegroundColor White "Already $($searchQueryAndSiteSettingsService.Status)."}

                Write-Host -ForegroundColor White " - Checking Search Service Application..." -NoNewline
                $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name -ErrorAction SilentlyContinue
                If ($searchApp -eq $null)
                {
                    Write-Host -ForegroundColor White "Creating $($appConfig.Name)..." -NoNewline
                    $searchApp = New-SPEnterpriseSearchServiceApplication -Name $appConfig.Name `
                        -DatabaseServer $dbServer `
                        -DatabaseName $($dbPrefix+$appConfig.DatabaseName) `
                        -FailoverDatabaseServer $appConfig.FailoverDatabaseServer `
                        -ApplicationPool $pool `
                        -AdminApplicationPool $adminPool `
                        -Partitioned:([bool]::Parse($appConfig.Partitioned))
                    If (!$?) {Throw " - An error occurred creating the $($appConfig.Name) application."}
                    Write-Host -ForegroundColor White "Done."
                }
                Else {Write-Host -ForegroundColor White "Already exists."}

                # Update the default Content Access Account
                try 
                {
                    Write-Host -ForegroundColor White " - Setting content access account for $($appconfig.Name)..." -NoNewline
                    $searchApp | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount `
                                                                          -DefaultContentAccessAccountPassword $secContentAccessAcctPWD -ErrorVariable err
                    if ($?) {Write-Host -ForegroundColor White "Done."}
                }
                catch   
                {
                    if ($err -like "*update conflict*")
                    {
                        Write-Host -ForegroundColor White "."
                        Write-Warning " - A concurrency error occured, trying again."
                        Write-Host -ForegroundColor White " - Setting content access account for $($appconfig.Name)..." -NoNewline
                        $searchApp | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication.ContentAccessAccount `
                                                                              -DefaultContentAccessAccountPassword $secContentAccessAcctPWD -ErrorVariable err
                        if ($?) {Write-Host -ForegroundColor White "Done."}
                    }
                    else 
                    {
                        throw $_
                    }
                }
                finally {Clear-Variable err}
                
                #To clone the active topology
                $clone = $searchApp.ActiveTopology.Clone()
                $activateTopology = $false
                Write-Host -ForegroundColor White " - Checking administration component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "AdminComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchAdminComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                Write-Host -ForegroundColor White " - Checking content processing component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "ContentProcessingComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchContentProcessingComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                Write-Host -ForegroundColor White " - Checking analytics processing component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "AnalyticsProcessingComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchAnalyticsProcessingComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                Write-Host -ForegroundColor White " - Checking crawl component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "CrawlComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchCrawlComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                Write-Host -ForegroundColor White " - Checking index component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "IndexComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchIndexComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                Write-Host -ForegroundColor White " - Checking query processing component..." -NoNewline
                If (!($searchApp.ActiveTopology.GetComponents() | Where-Object {$_.Name -like "QueryProcessingComponent*"}))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchQueryProcessingComponent –SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                    $activateTopology = $true
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                
                $searchApp | Get-SPEnterpriseSearchAdministrationComponent | Set-SPEnterpriseSearchAdministrationComponent -SearchServiceInstance $searchSvc
                
                if ($activateTopology)
                {
                    Write-Host -ForegroundColor White " - Activating Search Topology..." -NoNewline
                    $clone.Activate()
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                else {$clone.Delete()}
                Write-Host -ForegroundColor White " - Checking search service application proxy..." -NoNewline
                If (!(Get-SPEnterpriseSearchServiceApplicationProxy -Identity $appConfig.Proxy.Name -ErrorAction SilentlyContinue))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    $searchAppProxy = New-SPEnterpriseSearchServiceApplicationProxy -Name $appConfig.Proxy.Name -SearchApplication $appConfig.Name
                    If ($?) {Write-Host -ForegroundColor White "Done."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}
                
                #Add link to resources list
                AddResourcesLink "Search Administration" ("searchadministration.aspx?appid=" +  $searchApp.Id)

                Write-Host -ForegroundColor White " - Search Service Application successfully provisioned."

                function SetSearchCenterUrl ($searchCenterURL, $searchApp)
                {
                    Start-Sleep 10 # Wait for stuff to catch up so we don't get a concurrency error
                    $searchApp.SearchCenterUrl = $searchCenterURL
                    $searchApp.Update()
                }

                If (!([string]::IsNullOrEmpty($appConfig.SearchCenterUrl)))
                {
                    # Set the SP2013 Search Center URL per http://blogs.technet.com/b/speschka/archive/2012/10/29/how-to-configure-the-global-search-center-url-for-sharepoint-2013-using-powershell.aspx
                    Write-Host -ForegroundColor White " - Setting the Global Search Center URL to $($appConfig.SearchCenterURL)..."
                    while ($done -ne $true)
                    {
                        try
                        {
                            $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name
                            SetSearchCenterUrl $appConfig.SearchCenterURL $searchApp
                            if ($?)
                            {
                                $done = $true
                                Write-Host -ForegroundColor White " - Done."
                            }
                        }
                        catch
                        {
                            Write-Output $_
                            if ($_ -like "*update conflict*")
                            {
                                Write-Host -ForegroundColor Yellow "  - An update conflict occurred, retrying..."
                            }
                            else {Write-Output $_; $done = $true}
                        }
                    }
                }
                Else {Write-Host -ForegroundColor Yellow " - SearchCenterUrl was not specified, skipping."}
                WriteLine
            }
        }
        
        # SLN: Create the network share (will report an error if exist)
        # default to primitives 
        $pathToShare = """" + $svcConfig.ShareName + "=" + $svcConfig.IndexLocation + """"
        # The path to be shared should exist if the Enterprise Search App creation succeeded earlier
        EnsureFolder $svcConfig.IndexLocation
        Write-Host -ForegroundColor White " - Creating network share $pathToShare"
        Start-Process -FilePath net.exe -ArgumentList "share $pathToShare `"/GRANT:WSS_WPG,CHANGE`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue

        # Set the crawl start addresses (including the elusive sps3:// URL required for People Search, if My Sites are provisioned)
        $crawlStartAddresses = $portalURL+":"+$portalPort
        If ($mySiteURL -and $mySitePort -and $mySiteHostHeader)
        {   
        	# Need to set the correct sps (People Search) URL protocol in case My Sites are SSL-bound
        	If ($mySiteURL -like "https*") {$peopleSearchProtocol = "sps3s://"}
        	Else {$peopleSearchProtocol = "sps3://"}
        	$crawlStartAddresses += ","+$mySiteURL+":"+$mySitePort+","+$peopleSearchProtocol+$mySiteHostHeader+":"+$mySitePort
        }
        Write-Host -ForegroundColor White " - Setting up crawl addresses for default content source..." -NoNewline
        Get-SPEnterpriseSearchServiceApplication | Get-SPEnterpriseSearchCrawlContentSource | Set-SPEnterpriseSearchCrawlContentSource -StartAddresses $crawlStartAddresses
        If ($?) {Write-Host -ForegroundColor White "Done."}
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

function Set-ProxyGroupsMembership([System.Xml.XmlElement[]]$groups, [Microsoft.SharePoint.Administration.SPServiceApplicationProxy[]]$inputObject)
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
        $managedAccountSearch = (Get-SPManagedAccount -Identity $appPoolConfig.Account -ErrorVariable err -ErrorAction SilentlyContinue)
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
            $managedAccountSearch = New-SPManagedAccount -Credential $accountCred
        }
        Write-Host -ForegroundColor White " - Creating $($appPoolConfig.Name)..."
        $pool = New-SPServiceApplicationPool -Name $($appPoolConfig.Name) -Account $managedAccountSearch
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
            $dbServer = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
            }
            $bdcAppName = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Name
            $bdcDataDB = $dbPrefix+$($xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.Database.Name)
            $bdcAppProxyName = $xmlinput.Configuration.ServiceApps.BusinessDataConnectivity.ProxyName
            Write-Host -ForegroundColor White " - Provisioning $bdcAppName"
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            Write-Host -ForegroundColor White " - Checking local service instance..."
            # Get the service instance
            $bdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
            $bdcServiceInstance = $bdcServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find the service instance" }
            # Start Service instances
            If($bdcServiceInstance.Status -eq "Disabled")
            { 
                Write-Host -ForegroundColor White " - Starting $($bdcServiceInstance.TypeName)..."
                $bdcServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start $($bdcServiceInstance.TypeName)" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for $($bdcServiceInstance.TypeName)..." -NoNewline
                While ($bdcServiceInstance.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $bdcServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
                    $bdcServiceInstance = $bdcServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black ($bdcServiceInstance.Status)
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $($bdcServiceInstance.TypeName) already started."
            }
            # Create a Business Data Catalog Service Application 
            If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceApplication"}) -eq $null)
            {      
                # Create Service App
                Write-Host -ForegroundColor White " - Creating $bdcAppName..."   
                $bdcDataServiceApp = New-SPBusinessDataCatalogServiceApplication -Name $bdcAppName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $bdcDataDB
                If (-not $?) { Throw " - Failed to create $bdcAppName" }
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $bdcAppName already provisioned."
            }
            Write-Host -ForegroundColor White " - Done creating $bdcAppName."
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
            $excelAppName = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.Name
            $portalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
            $portalURL = $portalWebApp.URL
            $portalPort = $portalWebApp.Port
            Write-Host -ForegroundColor White " - Provisioning $excelAppName..."
            $applicationPool = Get-HostedServicesAppPool $xmlinput
            Write-Host -ForegroundColor White " - Checking local service instance..."
            # Get the service instance
            $excelServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
            $excelServiceInstance = $excelServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find the service instance" }
            # Start Service instances
            If($excelServiceInstance.Status -eq "Disabled")
            { 
                Write-Host -ForegroundColor White " - Starting $($excelServiceInstance.TypeName)..."
                $excelServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start $($excelServiceInstance.TypeName) instance" }
                # Wait
                Write-Host -ForegroundColor Blue " - Waiting for $($excelServiceInstance.TypeName)..." -NoNewline
                While ($excelServiceInstance.Status -ne "Online") 
                {
                    Write-Host -ForegroundColor Blue "." -NoNewline
                    Start-Sleep 1
                    $excelServiceInstances = Get-SPServiceInstance | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
                    $excelServiceInstance = $excelServiceInstances | ? {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Blue -ForegroundColor Black ($excelServiceInstance.Status)
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $($excelServiceInstance.TypeName) already started."
            }
            # Create an Excel Service Application 
            If ((Get-SPServiceApplication | ? {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceApplication"}) -eq $null)
            {      
                # Create Service App
                Write-Host -ForegroundColor White " - Creating $excelAppName..."
                # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
                If (!(Get-Command New-SPExcelServiceApplication -ErrorAction SilentlyContinue))
                {
                    Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
                    Remove-PSSnapin Microsoft.SharePoint.PowerShell
                    Load-SharePoint-Powershell
                }
                $excelServiceApp = New-SPExcelServiceApplication -name $excelAppName -ApplicationPool $($applicationPool.Name) -Default
                If (-not $?) { Throw " - Failed to create $excelAppName" }
                Write-Host -ForegroundColor White " - Configuring service app settings..."
                Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $portalURL`:$portalPort -ExcelServiceApplication $excelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10 | Out-Null
                $caUrl = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$env:spVer.0\WSS").GetValue("CentralAdministrationURL")
                New-SPExcelFileLocation -LocationType SharePoint -IncludeChildren -Address $caUrl -ExcelServiceApplication $excelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10 | Out-Null

                # Configure unattended accounts, based on:
                # http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
                If (($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser) -and ($xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword))
                {
                    Write-Host -ForegroundColor White " - Setting unattended account credentials..."
                    
                    # Reget application to prevent update conflict error message
                    $excelServiceApp = Get-SPExcelServiceApplication
                    
                    # Get account credentials
                    $excelAcct = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser
                    $excelAcctPWD = $xmlinput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword
                    If (!($excelAcct) -or $excelAcct -eq "" -or !($excelAcctPWD) -or $excelAcctPWD -eq "") 
                    {
                        Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Excel Unattended Account:"
                        $unattendedAccount = $host.ui.PromptForCredential("Excel Setup", "Enter Excel Unattended Account Credentials:", "$excelAcct", "NetBiosUserName" )
                    } 
                    Else
                    {
                        $secPassword = ConvertTo-SecureString "$excelAcctPWD" -AsPlaintext -Force 
                        $unattendedAccount = New-Object System.Management.Automation.PsCredential $excelAcct,$secPassword
                    }
                                
                    # Set the group claim and admin principals
                    $groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
                    $adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName

                    # Set the field values
                    $secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
                    $securePassword = $unattendedAccount.Password
                    $credentialValues = $secureUserName, $securePassword
                    
                    # Set the Target App Name and create the Target App
                    $name = "$($excelServiceApp.ID)-ExcelUnattendedAccount"
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
                    $context = [Microsoft.SharePoint.SPServiceContext]::GetContext($excelServiceApp.ServiceApplicationProxyGroup, $subId)

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
                    Set-SPExcelServiceApplication -Identity $excelServiceApp -UnattendedAccountApplicationId $name
                }
                Else 
                {
                    Write-Host -ForegroundColor Yellow " - Unattended account credentials not supplied in configuration file - skipping."
                }
            }
            Else 
            {
                Write-Host -ForegroundColor White " - $excelAppName already provisioned."
            }
            Write-Host -ForegroundColor White " - Done creating $excelAppName."
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
    $serviceConfig = $xmlinput.Configuration.EnterpriseServiceApps.VisioService
    If (ShouldIProvision($serviceConfig) -eq $true)
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPVisioServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPVisioServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPVisioServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPVisioServiceApplicationProxy"
                                      
        If (Get-Command -Name Get-SPVisioServiceApplication -ErrorAction SilentlyContinue)
        {
            # http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
            If ($serviceConfig.UnattendedIDUser -and $serviceConfig.UnattendedIDPassword) 
            {
                Write-Host -ForegroundColor White " - Setting unattended account credentials..."

                $serviceApplication = Get-SPServiceApplication -name $serviceConfig.Name
            
                # Get account credentials
                $visioAcct = $xmlinput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDUser
                $visioAcctPWD = $xmlinput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDPassword
                If (!($visioAcct) -or $visioAcct -eq "" -or !($visioAcctPWD) -or $visioAcctPWD -eq "") 
                {
                    Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for Visio Unattended Account:"
                    $unattendedAccount = $host.ui.PromptForCredential("Visio Setup", "Enter Visio Unattended Account Credentials:", "$visioAcct", "NetBiosUserName" )
                } 
                Else
                {
                    $secPassword = ConvertTo-SecureString "$visioAcctPWD" -AsPlaintext -Force 
                    $unattendedAccount = New-Object System.Management.Automation.PsCredential $visioAcct,$secPassword
                }
                
                # Set the group claim and admin principals
                $groupClaim = New-SPClaimsPrincipal -Identity "nt authority\authenticated users" -IdentityType WindowsSamAccountName
                $adminPrincipal = New-SPClaimsPrincipal -Identity "$($env:userdomain)\$($env:username)" -IdentityType WindowsSamAccountName

                # Set the field values
                $secureUserName = ConvertTo-SecureString $unattendedAccount.UserName -AsPlainText -Force
                $securePassword = $unattendedAccount.Password
                $credentialValues = $secureUserName, $securePassword

                # Set the Target App Name and create the Target App
                $name = "$($serviceApplication.ID)-VisioUnattendedAccount"
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
                $context = [Microsoft.SharePoint.SPServiceContext]::GetContext($serviceApplication.ServiceApplicationProxyGroup, $subId)

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
                $serviceApplication | Set-SPVisioExternalData -UnattendedServiceAccountApplicationID $name
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
    $serviceConfig = $xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService
    If (ShouldIProvision($serviceConfig) -eq $true)
    {
        WriteLine
	    $dbServer = $serviceConfig.Database.DBServer
	    # If we haven't specified a DB Server then just use the default used by the Farm
	    If ([string]::IsNullOrEmpty($dbServer))
	    {
	        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
	    }
	    $serviceDB = $dbPrefix+$serviceConfig.Database.Name
        $serviceInstanceType = "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPPerformancePointServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPPerformancePointServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPPerformancePointServiceApplicationProxy"
        
        $application = Get-SPPerformancePointServiceApplication | ? {$_.Name -eq $serviceConfig.Name}
        If ($application)
        {
            $farmAcct = $xmlinput.Configuration.Farm.Account.Username
            Write-Host -ForegroundColor White " - Granting $farmAcct rights to database $serviceDB..."
            Get-SPDatabase | Where {$_.Name -eq $serviceDB} | Add-SPShellAdmin -UserName $farmAcct
            Write-Host -ForegroundColor White " - Setting PerformancePoint Data Source Unattended Service Account..."
            $performancePointAcct = $serviceConfig.UnattendedIDUser
            $performancePointAcctPWD = $serviceConfig.UnattendedIDPassword
            If (!($performancePointAcct) -or $performancePointAcct -eq "" -or !($performancePointAcctPWD) -or $performancePointAcctPWD -eq "") 
            {
                Write-Host -BackgroundColor Gray -ForegroundColor DarkBlue " - Prompting for PerformancePoint Unattended Service Account:"
                $performancePointCredential = $host.ui.PromptForCredential("PerformancePoint Setup", "Enter PerformancePoint Unattended Account Credentials:", "$performancePointAcct", "NetBiosUserName" )
            } 
            Else
            {
                $secPassword = ConvertTo-SecureString "$performancePointAcctPWD" -AsPlaintext -Force 
                $performancePointCredential = New-Object System.Management.Automation.PsCredential $performancePointAcct,$secPassword
            }
            $application | Set-SPPerformancePointSecureDataValues -DataSourceUnattendedServiceAccount $performancePointCredential
            
            If (!(CheckForSP1)) # Only need this if our environment isn't up to Service Pack 1 for SharePoint 2010
            {
                # Rename the performance point service application database
                Write-Host -ForegroundColor White " - Renaming Performance Point Service Application Database"
                $settingsDB = $application.SettingsDatabase     
                $newDB = $serviceDB
                $sqlServer = ($settingsDB -split "\\\\")[0]
                $oldDB = ($settingsDB -split "\\\\")[1]
                If (!($newDB -eq $oldDB)) # Check if it's already been renamed, in case we're running the script again
                {
                    Write-Host -ForegroundColor White " - Renaming Performance Point Service Application Database"
                    RenameDatabase -sqlServer $sqlServer -oldName $oldDB -newName $newDB
                    Set-SPPerformancePointServiceApplication  -Identity $serviceConfig.Name -SettingsDatabase $newDB | Out-Null
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

#Region Create Access 2010 Service
Function CreateAccessServiceApp ([xml]$xmlinput)
{
    $serviceConfig = $xmlinput.Configuration.EnterpriseServiceApps.AccessService
    If (ShouldIProvision($serviceConfig) -eq $true)
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
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
    $serviceConfig = $xmlinput.Configuration.ServiceApps.WordAutomationService
    $dbPrefix = $xmlinput.Configuration.Farm.Database.DBPrefix
    If (($dbPrefix -ne "") -and ($dbPrefix -ne $null)) {$dbPrefix += "_"}
    If ($dbPrefix -like "*localhost*") {$dbPrefix = $dbPrefix -replace "localhost","$env:COMPUTERNAME"}
    $dbServer = $serviceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
    }
    $wordDatabase = $dbPrefix+$($serviceConfig.Database.Name)
    If (ShouldIProvision($serviceConfig) -eq $true)
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Word.Server.Service.WordServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPWordConversionServiceApplication -DatabaseServer $dbServer -DatabaseName $wordDatabase -Default" `
                                      -ServiceProxyNewCmdlet "New-SPWordConversionServiceApplicationProxy" # Fake cmdlet, but the CreateBasicServiceApplication function expects something
        # Run the Word Automation Timer Job immediately; otherwise we will have a Health Analyzer error condition until the job runs as scheduled
        If (Get-SPServiceApplication | ? {$_.DisplayName -eq $($serviceConfig.Name)})
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
    $serviceConfig = $xmlinput.Configuration.OfficeWebApps.ExcelService
    If ((ShouldIProvision($serviceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        $portalWebApp = $xmlinput.Configuration.WebApplications.WebApplication | Where {$_.Type -eq "Portal"}
        $portalURL = $portalWebApp.URL
        $portalPort = $portalWebApp.Port
        $serviceInstanceType = "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPExcelServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPExcelServiceApplication -Default" `
                                      -ServiceProxyNewCmdlet "New-SPExcelServiceApplicationProxy" # Fake cmdlet (and not needed for Excel Services), but the CreateBasicServiceApplication function expects something
                                      
        If (Get-SPExcelServiceApplication)
        {
            Write-Host -ForegroundColor White " - Setting Excel Services Trusted File Location..."
            Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $portalURL`:$portalPort -ExcelServiceApplication $($serviceConfig.Name) -ExternalDataAllowed 2 -WorkbookSizeMax 10
        }
        WriteLine
    }
}

Function CreatePowerPointServiceApp ([xml]$xmlinput)
{
    $serviceConfig = $xmlinput.Configuration.OfficeWebApps.PowerPointService
    If ((ShouldIProvision($serviceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        If ($env:spVer -eq "14") {$serviceInstanceType = "Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance"}
        ElseIf ($env:spVer -eq "15") {$serviceInstanceType = "Microsoft.Office.Server.PowerPoint.Administration.PowerPointConversionServiceInstance"}
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPPowerPointServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPPowerPointServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPPowerPointServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPPowerPointServiceApplicationProxy"
        WriteLine
    }
}

Function CreateWordViewingServiceApp ([xml]$xmlinput)
{
    $serviceConfig = $xmlinput.Configuration.OfficeWebApps.WordViewingService
    If ((ShouldIProvision($serviceConfig) -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Web.Environment.Sharepoint.ConversionServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                      -ServiceNewCmdlet "New-SPWordViewingServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPWordViewingServiceApplicationProxy"
        WriteLine
    }
}
#EndRegion

#Region Create App Domain
Function CreateAppManagementServiceApp ([xml]$xmlinput)
{
    $serviceConfig = $xmlinput.Configuration.ServiceApps.AppManagementService
    If (ShouldIProvision($serviceConfig) -eq $true) 
    {
        WriteLine
	    # If we haven't specified a DB Server then just use the default used by the Farm
	    If ([string]::IsNullOrEmpty($dbServer))
	    {
	        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
	    }
	    $serviceDB = $dbPrefix+$serviceConfig.Database.Name
	    $dbServer = $serviceConfig.Database.DBServer
	    # If we haven't specified a DB Server then just use the default used by the Farm
	    If ([string]::IsNullOrEmpty($dbServer))
	    {
	        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
	    }
        $serviceInstanceType = "Microsoft.SharePoint.AppManagement.AppManagementServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceProxyName $serviceConfig.ProxyName `
                                      -ServiceGetCmdlet "Get-SPServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPAppManagementServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPAppManagementServiceApplicationProxy"

		# Configure your app domain and location
		Write-Host -ForegroundColor White " - Setting App Domain `"$($serviceConfig.AppDomain)`"..."
	    Set-SPAppDomain -AppDomain $serviceConfig.AppDomain
        WriteLine
    }
}

Function CreateSubscriptionSettingsServiceApp ([xml]$xmlinput)
{
    $serviceConfig = $xmlinput.Configuration.ServiceApps.SubscriptionSettingsService
    If (ShouldIProvision($serviceConfig) -eq $true) 
    {
        WriteLine
	    # If we haven't specified a DB Server then just use the default used by the Farm
	    If ([string]::IsNullOrEmpty($dbServer))
	    {
	        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
	    }
	    $serviceDB = $dbPrefix+$serviceConfig.Database.Name
	    $dbServer = $serviceConfig.Database.DBServer
	    # If we haven't specified a DB Server then just use the default used by the Farm
	    If ([string]::IsNullOrEmpty($dbServer))
	    {
	        $dbServer = $xmlinput.Configuration.Farm.Database.DBServer
	    }
        $serviceInstanceType = "Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance"
        CreateBasicServiceApplication -ServiceConfig $serviceConfig `
                                      -ServiceInstanceType $serviceInstanceType `
                                      -ServiceName $serviceConfig.Name `
                                      -ServiceGetCmdlet "Get-SPServiceApplication" `
                                      -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
									  -ServiceNewCmdlet "New-SPSubscriptionSettingsServiceApplication" `
                                      -ServiceProxyNewCmdlet "New-SPSubscriptionSettingsServiceApplicationProxy"
		
		Write-Host -ForegroundColor White " - Setting Site Subscription name `"$($serviceConfig.AppSiteSubscriptionName)`"..."
	    Set-SPAppSiteSubscriptionName -Name $serviceConfig.AppSiteSubscriptionName -Confirm:$false
        WriteLine
    }
}
#EndRegion

#Region Create Access Service

#EndRegion

#Region Create Machine Translation Service
#EndRegion

#Region Create Work Management Service
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
            $emailAddress = $xmlinput.Configuration.Farm.Services.OutgoingEmail.EmailAddress
            $replyToEmail = $xmlinput.Configuration.Farm.Services.OutgoingEmail.ReplyToEmail
            Write-Host -ForegroundColor White " - Configuring Outgoing Email..."
            $loadasm = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint")
            $spGlobalAdmin = New-Object Microsoft.SharePoint.Administration.SPGlobalAdmin
            $spGlobalAdmin.UpdateMailSettings($SMTPServer, $emailAddress, $replyToEmail, 65001)
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
    $sharePointRoot = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer"
    $sourceFileLocations = @("$bits\$spYear\PDF\","$bits\PDF\","$bits\AdobePDF\","$env:TEMP\")
    # Only install/configure iFilter if specified, and we are running SP2010 (as SP2013 includes one)
    If ((ShouldIProvision($xmlinput.Configuration.AdobePDF.iFilter) -eq $true) -and ($env:spVer -eq "14"))
    {
        $pdfIfilterUrl = "http://download.adobe.com/pub/adobe/acrobat/win/9.x/PDFiFilter64installer.zip"
        Write-Host -ForegroundColor White " - Configuring PDF file iFilter and indexing..."
        # Look for the installer or the installer zip in the possible locations
        ForEach ($sourceFileLocation in $sourceFileLocations)
        {
            If (Get-Item $($sourceFileLocation+"PDFFilter64installer.msi") -ErrorAction SilentlyContinue)
            {
                Write-Host -ForegroundColor White " - PDF iFilter installer found in $sourceFileLocation."
                $iFilterInstaller = $sourceFileLocation+"PDFFilter64installer.msi"
                Break
            }
            ElseIf (Get-Item $($sourceFileLocation+"PDFiFilter64installer.zip") -ErrorAction SilentlyContinue)
            {
                Write-Host -ForegroundColor White " - PDF iFilter installer zip file found in $sourceFileLocation."
                $zipLocation = $sourceFileLocation
                $sourceFile = $sourceFileLocation+"PDFiFilter64installer.zip"
                Break
            }
        }
        # If the MSI hasn't been extracted from the zip yet then extract it
        If (!($iFilterInstaller))
        {
            # If the zip file isn't present then download it first
            If (!($sourceFile))
            {
                Write-Host -ForegroundColor White " - PDF iFilter installer or zip not found, downloading..."
                If (Confirm-LocalSession)
                {
                    $zipLocation = $env:TEMP
                    $destinationFile = $zipLocation+"\PDFiFilter64installer.zip"
                    Import-Module BitsTransfer | Out-Null
                    Start-BitsTransfer -Source $pdfIfilterUrl -Destination $destinationFile -DisplayName "Downloading Adobe PDF iFilter..." -Priority Foreground -Description "From $pdfIfilterUrl..." -ErrorVariable err
                    If ($err) {Write-Warning " - Could not download Adobe PDF iFilter!"; Pause "exit"; break}
                    $sourceFile = $destinationFile
                }
                Else {Write-Warning " - The remote use of BITS is not supported. Please pre-download the PDF install files and try again."}
            }
            Write-Host -ForegroundColor White " - Extracting Adobe PDF iFilter installer..."
            $shell = New-Object -ComObject Shell.Application
            $iFilterZip = $shell.Namespace($sourceFile)
            $location = $shell.Namespace($zipLocation)
            $location.Copyhere($iFilterZip.items())
            $iFilterInstaller = $zipLocation+"\PDFFilter64installer.msi"
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
            Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
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
        If ((Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$env:spVer.0\Search\Setup\Filters\.pdf" -ErrorAction SilentlyContinue) -eq $null)
        {
            $item = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$env:spVer.0\Search\Setup\Filters\.pdf"
            $item | New-ItemProperty -Name Extension -PropertyType String -Value "pdf" | Out-Null
            $item | New-ItemProperty -Name FileTypeBucket -PropertyType DWord -Value 1 | Out-Null
            $item | New-ItemProperty -Name MimeTypes -PropertyType String -Value "application/pdf" | Out-Null
        }
        If ((Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$env:spVer.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf" -ErrorAction SilentlyContinue) -eq $null)
        {
            $registryItem = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$env:spVer.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf"
            $registryItem | New-ItemProperty -Name "(default)" -PropertyType String -Value "{E8978DA6-047F-4E3D-9C78-CDBE46041603}" | Out-Null
        }
        $spSearchService = "OSearch"+$env:spVer # Substitute the correct SharePoint version into the service name so we can handle SP2013 as well as SP2010
        If ((Get-Service $spSearchService).Status -eq "Running")
        {
            Write-Host -ForegroundColor White " - Restarting SharePoint Search Service..."
            Restart-Service $spSearchService
        }
        Write-Host -ForegroundColor White " - Done configuring PDF iFilter and indexing."
    }
    # Only configure PDF icon if we are running SP2010 (as SP2013 includes one)
    If (($xmlinput.Configuration.AdobePDF.Icon.Configure -eq $true) -and ($env:spVer -eq "14"))
    {
        $pdfIconUrl = "http://helpx.adobe.com/content/dam/kb/en/837/cpsid_83709/attachments/AdobePDF.png"
        $docIconFolderPath = "$sharePointRoot\TEMPLATE\XML"
        $docIconFilePath = "$docIconFolderPath\DOCICON.XML"
        Write-Host -ForegroundColor White " - Configuring PDF Icon..."
        $pdfIcon = "AdobePDF.png"
        If (!(Get-Item $sharePointRoot\Template\Images\$pdfIcon -ErrorAction SilentlyContinue))
        {
            ForEach ($sourceFileLocation in $sourceFileLocations)
            {
                # Check each possible source file location for the PDF icon
                $copyIcon = Copy-Item -Path $sourceFileLocation\$pdfIcon -Destination $sharePointRoot\Template\Images\$pdfIcon -PassThru -ErrorAction SilentlyContinue
                If ($copyIcon)
                {
                    Write-Host -ForegroundColor White " - PDF icon found at $sourceFileLocation\$pdfIcon"
                    Break
                }
            }
            If (!($copyIcon))
            {
                Write-Host -ForegroundColor White " - `"$pdfIcon`" not found; downloading it now..."
                If (Confirm-LocalSession)
                {
                    Import-Module BitsTransfer | Out-Null
                    Start-BitsTransfer -Source $pdfIconUrl -Destination "$sharePointRoot\Template\Images\$pdfIcon" -DisplayName "Downloading PDF Icon..." -Priority Foreground -Description "From $pdfIconUrl..." -ErrorVariable err
                    If ($err) {Write-Warning " - Could not download PDF Icon!"; Pause "exit"; break}
                }
                Else {Write-Warning " - The remote use of BITS is not supported. Please pre-download the PDF icon and try again."}
            }
            If (Get-Item $sharePointRoot\Template\Images\$pdfIcon) {Write-Host -ForegroundColor White " - PDF icon copied successfully."}
            Else {Throw}
        }
        $xml = New-Object XML
        $xml.Load($docIconFilePath)
        If ($xml.SelectSingleNode("//Mapping[@Key='pdf']") -eq $null)
        {
            Try
            {
                Write-Host -ForegroundColor White " - Creating backup of DOCICON.XML file..."
                $backupFile = "$docIconFolderPath\DOCICON_Backup.xml"
                Copy-Item $docIconFilePath $backupFile
                Write-Host -ForegroundColor White " - Writing new DOCICON.XML..."
                $pdf = $xml.CreateElement("Mapping")
                $pdf.SetAttribute("Key","pdf")
                $pdf.SetAttribute("Value",$pdfIcon)
                $pdf.SetAttribute("EditText","Adobe Acrobat or Reader X")
                $pdf.SetAttribute("OpenControl","AdobeAcrobat.OpenDocuments")
                $xml.DocIcons.ByExtension.AppendChild($pdf) | Out-Null
                $xml.Save($docIconFilePath)
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
        $mimeType = "application/pdf"
        Write-Host -ForegroundColor White " - Adding PDF MIME type `"$mimeType`" web apps..."
        ForEach ($webAppConfig in $xmlinput.Configuration.WebApplications.WebApplication)
        {
            $webAppUrl = $($webAppConfig.url)+":"+$($webAppConfig.Port)
            $webApp = Get-SPWebApplication -Identity $webAppUrl
            If ($webApp.AllowedInlineDownloadedMimeTypes -notcontains $mimeType)
            {
                Write-Host -ForegroundColor White "  - "$webAppUrl": Adding "`"$mimeType"`"..." -NoNewline
                $webApp.AllowedInlineDownloadedMimeTypes.Add($mimeType)
                $webApp.Update()
                Write-Host -ForegroundColor White "Done."
            }
            Else
            {
                Write-Host -ForegroundColor White "  - "$webAppUrl": "`"$mimeType"`" already added."
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
            If (Test-Path "$bits\$spYear\Forefront\setup.exe")
            {
                Write-Host -ForegroundColor White " - Installing ForeFront binaries..."
                Try
                {
                    Start-Process "$bits\$spYear\Forefront\setup.exe" -ArgumentList "/a `"$config`" /p" -Wait
                    If (-not $?) {Throw}
                    Write-Host -ForegroundColor White " - Done installing ForeFront."
                }
                Catch 
                {
                    Throw " - Error $LASTEXITCODE occurred running $bits\$spYear\ForeFront\setup.exe"
                }
            }
            Else 
            {
                Throw " - ForeFront installer not found in $bits\$spYear\ForeFront folder"
            }
        }
        WriteLine
    }
}
#EndRegion

#Region Remote Functions
Function Get-FarmServers ([xml]$xmlinput)
{
    $servers = $null
    $farmServers = @()
    # Look for server name references in the XML
    ForEach ($node in $xmlinput.SelectNodes("//*[@Provision]|//*[@Install]|//*[CrawlServers]|//*[QueryServers]|//*[SearchQueryAndSiteSettingsServers]|//*[AdminComponent]|//*[@Start]"))
    {
        # Try to set the server name from the various elements/attributes
        $servers = @(GetFromNode $node "Provision")
        If ([string]::IsNullOrEmpty($servers)) { $servers = @(GetFromNode $node "Install") }
        If ([string]::IsNullOrEmpty($servers)) { $servers = @(GetFromNode $node "Start") }
        If ([string]::IsNullOrEmpty($servers)) 
        {
            foreach ($serverElement in $node.CrawlServers.Server) {$crawlServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.QueryServers.Server) {$queryServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.SearchQueryAndSiteSettingsServers.Server) {$siteQueryAndSSServers += @($serverElement.GetAttribute("Name"))}
            foreach ($serverElement in $node.AdminComponent.Server) {$adminServers += @($serverElement.GetAttribute("Name"))}
            $servers = $crawlServers+$queryServers+$siteQueryAndSSServers+$adminServers
        }
       
        # Accomodate and clean up comma and/or space-separated server names
        # First get rid of any recurring spaces or commas
        While ($servers -match "  ")
        {
            $servers = $servers -replace "  ", " "
        }
        While ($servers -match ",,")
        {
            $servers = $servers -replace ",,", ","
        }
        $servers = $servers -split "," -split " "
        # Remove any "true", "false" or zero-length values as we only want server names
        If ($servers -eq "true" -or $servers -eq "false" -or [string]::IsNullOrEmpty($servers))
        {
            $servers = $null
        }
        else
        {
            # Add any server(s) we found to our $farmServers array
            $farmServers = @($farmServers+$servers)
        }
    }

    # Remove any blanks and duplicates
    $farmServers = $farmServers | Where-Object {$_ -ne ""} | Select-Object -Unique
    Return $farmServers
}

Function Enable-CredSSP ($remoteFarmServers)
{
    ForEach ($server in $remoteFarmServers) {Write-Host -ForegroundColor White " - Enabling WSManCredSSP for `"$server`""}
    Enable-WSManCredSSP -Role Client -Force -DelegateComputer $remoteFarmServers | Out-Null
    If (!$?) {Pause "exit..."; throw $_}
}

Function Test-ServerConnection ($server)
{
    Write-Host -ForegroundColor White " - Testing connection (via Ping) to `"$server`"..." -NoNewline
    $canConnect = Test-Connection -ComputerName $server -Count 1 -Quiet
    If ($canConnect) {Write-Host -ForegroundColor Blue -BackgroundColor Black $($canConnect.ToString() -replace "True","Success.")}
    If (!$canConnect)
    {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black $($canConnect.ToString() -replace "False","Failed.")
        Write-Host -ForegroundColor Yellow " - Check that `"$server`":"
        Write-Host -ForegroundColor Yellow "  - Is online" 
        Write-Host -ForegroundColor Yellow "  - Has the required Windows Firewall exceptions set (or turned off)"
        Write-Host -ForegroundColor Yellow "  - Has a valid DNS entry for $server.$($env:USERDNSDOMAIN)"
    }
}

Function Enable-RemoteSession ($server, $password)
{
    If ($password) {$credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$credential) {$credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    $username = $credential.Username
    $password = ConvertTo-PlainText $credential.Password
    $configureTargetScript = "$env:dp0\AutoSPInstallerConfigureRemoteTarget.ps1"
    $psExec = $env:dp0+"\PsExec.exe"
    If (!(Get-Item ($psExec) -ErrorAction SilentlyContinue))
    {
        Write-Host -ForegroundColor White " - PsExec.exe not found; downloading..."
        $psExecUrl = "http://live.sysinternals.com/PsExec.exe"
        Import-Module BitsTransfer | Out-Null
        Start-BitsTransfer -Source $psExecUrl -Destination $psExec -DisplayName "Downloading Sysinternals PsExec..." -Priority Foreground -Description "From $psExecUrl..." -ErrorVariable err
        If ($err) {Write-Warning " - Could not download PsExec!"; Pause "exit"; break}
        $sourceFile = $destinationFile
    }
    Write-Host -ForegroundColor White " - Updating PowerShell execution policy on `"$server`" via PsExec..."
    Start-Process -FilePath "$psExec" `
                  -ArgumentList "/acceptEula \\$server -h powershell.exe -Command `"Set-ExecutionPolicy Bypass -Force ; Stop-Process -Id `$PID`"" `
                  -Wait -NoNewWindow
    # Another way to exit powershell when running over PsExec from http://www.leeholmes.com/blog/2007/10/02/using-powershell-and-PsExec-to-invoke-expressions-on-remote-computers/
    # PsExec \\server cmd /c "echo . | powershell {command}"                      
    Write-Host -ForegroundColor White " - Enabling PowerShell remoting on `"$server`" via PsExec..."
    Start-Process -FilePath "$psExec" `
                  -ArgumentList "/acceptEula \\$server -u $username -p $password -h powershell.exe -Command `"$configureTargetScript`"" `
                  -Wait -NoNewWindow
}

Function Install-NetFramework ($server, $password)
{
	If ($password) {$credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$credential) {$credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $credential -ComputerName $server
    }
    $remoteQueryOS = Invoke-Command -ScriptBlock {Get-WmiObject Win32_OperatingSystem} -Session $session
	If (!($remoteQueryOS.Version.Contains("6.2"))) # Only perform the stuff below if we aren't on Windows 2012
	{
	    Write-Host -ForegroundColor White " - Pre-installing .Net Framework feature on $server..."
	    Invoke-Command -ScriptBlock {Import-Module ServerManager | Out-Null
	                                # Get the current progress preference
	                                $pref = $ProgressPreference
	                                # Hide the progress bar since it tends to not disappear
	                                $ProgressPreference = "SilentlyContinue"
	                                Import-Module ServerManager
	                                If (!(Get-WindowsFeature -Name NET-Framework).Installed) {Add-WindowsFeature -Name NET-Framework | Out-Null}
	                                # Restore progress preference
	                                $ProgressPreference = $pref} -Session $session
	}
}

Function Install-WindowsIdentityFoundation ($server, $password)
{
    # This step is required due to a known issue with the PrerequisiteInstaller.exe over a remote session; 
    # Specifically, because Windows Update Standalone Installer (wusa.exe) blows up with error code 5
    # With a fully-patched Windows 2008 R2 server though, the rest of the prerequisites seem OK; so this function only deals with KB974405 (Windows Identity Foundation).
    # Thanks to Ravikanth Chaganti (@ravikanth) for describing the issue, and working around it so effectively: http://www.ravichaganti.com/blog/?p=1888
    If ($password) {$credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$credential) {$credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $credential -ComputerName $server
    }
    $remoteQueryOS = Invoke-Command -ScriptBlock {Get-WmiObject Win32_OperatingSystem} -Session $session
	If (!($remoteQueryOS.Version.Contains("6.2"))) # Only perform the stuff below if we aren't on Windows 2012
	{
	    Write-Host -ForegroundColor White " - Checking for KB974405 (Windows Identity Foundation)..." -NoNewline
	    $wifHotfixInstalled = Invoke-Command -ScriptBlock {Get-HotFix -Id KB974405 -ErrorAction SilentlyContinue} -Session $session
	    If ($wifHotfixInstalled)
	    {
	        Write-Host -ForegroundColor White "already installed."
	    }
	    Else
	    {
	        Write-Host -ForegroundColor Black -BackgroundColor White "needed."
	        $username = $credential.UserName
	        $password = ConvertTo-PlainText $credential.Password
	        If ($remoteQueryOS.Version.Contains("6.1"))
	        {
	            $wifHotfix = "Windows6.1-KB974405-x64.msu"
	        }
	        ElseIf ($remoteQueryOS.Version.Contains("6.0"))
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
	            Start-BitsTransfer -Source $wifURL -Destination "$env:SPbits\PrerequisiteInstallerFiles\$wifHotfix" -DisplayName "Downloading `'$wifHotfix`' to $env:SPbits\PrerequisiteInstallerFiles" -Priority Foreground -Description "From $wifURL..." -ErrorVariable err
	            if ($err) {Throw " - Could not download from $wifURL!"; Pause "exit"; break}
	        }
	        $psExec = $env:dp0+"\PsExec.exe"
	        If (!(Get-Item ($psExec) -ErrorAction SilentlyContinue))
	        {
	            Write-Host -ForegroundColor White " - PsExec.exe not found; downloading..."
	            $psExecUrl = "http://live.sysinternals.com/PsExec.exe"
	            Import-Module BitsTransfer | Out-Null
	            Start-BitsTransfer -Source $psExecUrl -Destination $psExec -DisplayName "Downloading Sysinternals PsExec..." -Priority Foreground -Description "From $psExecUrl..." -ErrorVariable err
	            If ($err) {Write-Warning " - Could not download PsExec!"; Pause "exit"; break}
	            $sourceFile = $destinationFile
	        }
	        Write-Host -ForegroundColor White " - Pre-installing Windows Identity Foundation on `"$server`" via PsExec..."
	        Start-Process -FilePath "$psExec" `
	                      -ArgumentList "/acceptEula \\$server -u $username -p $password -h wusa.exe `"$env:SPbits\PrerequisiteInstallerFiles\$wifHotfix`" /quiet /norestart" `
	                      -Wait -NoNewWindow
	    }
	}
}

Function Start-RemoteInstaller ($server, $password, $inputFile)
{
    If ($password) {$credential = New-Object System.Management.Automation.PsCredential $env:USERDOMAIN\$env:USERNAME,$(ConvertTo-SecureString $password)}
    If (!$credential) {$credential = $host.ui.PromptForCredential("AutoSPInstaller - Remote Install", "Re-Enter Credentials for Remote Authentication:", "$env:USERDOMAIN\$env:USERNAME", "NetBiosUserName")}
    If ($session.Name -ne "AutoSPInstallerSession-$server")
    {
        Write-Host -ForegroundColor White " - Starting remote session to $server..."
        $session = New-PSSession -Name "AutoSPInstallerSession-$server" -Authentication Credssp -Credential $credential -ComputerName $server
    }
    # Create a hash table with major version to product year mappings
    $spYears = @{"14" = "2010"; "15" = "2013"}
    $spYear = $spYears.$env:spVer
    # Set some remote variables that we will need...
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name dp0 -Value $value} -ArgumentList $env:dp0 -Session $session
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name InputFile -Value $value} -ArgumentList $inputFile -Session $session
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name spVer -Value $value} -ArgumentList $env:spVer -Session $session
    # Crude way of checking if SharePoint is already installed
    $spInstalledOnRemote = Invoke-Command -ScriptBlock {Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\BIN\stsadm.exe"} -Session $session
    Write-Host -ForegroundColor Green " - SharePoint $spYear binaries are"($spInstalledOnRemote -replace "True","already" -replace "False","not yet") "installed on $server."
    Write-Host -ForegroundColor White " - Launching AutoSPInstaller..."
    Invoke-Command -ScriptBlock {& "$dp0\AutoSPInstallerMain.ps1" "$inputFile"} -Session $session
    Write-Host -ForegroundColor White " - Removing session `"$($session.Name)...`""
    Remove-PSSession $session
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
        # Added the line below to match what the SharePoint.ps1 file implements (normally called via the SharePoint Management Shell Start Menu shortcut)
        If (Confirm-LocalSession) {$Host.Runspace.ThreadOptions = "ReuseThread"}
        Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop | Out-Null
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
    # From http://www.microsoft.com/technet/scriptcenter/resources/pstips/jan08/pstip0118.mspx
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
        [String]$aliasName = "SharePointDB",
    
        [Parameter(Mandatory=$false, ParameterSetName="BuildPath+SetupInfo")][ValidateNotNullOrEmpty()]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [Parameter(Mandatory=$false, ParameterSetName="BuildPath+SetupInfo")][ValidateNotNullOrEmpty()]
        [String]$port = ""
    )

    $serverAliasConnection="DBMSSOCN,$SQLInstance"
    If ($port -ne "")
    {
         $serverAliasConnection += ",$port"
    }
    $notExist = $true
    $client = Get-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client' -ErrorAction SilentlyContinue
    # Create the key in case it doesn't yet exist
    If (!$client) {$client = New-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client' -Force}
    $client.GetSubKeyNames() | ForEach-Object -Process { If ( $_ -eq 'ConnectTo') { $notExist=$false }}
    If ($notExist)
    {
        $data = New-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo'
    }
    # Add Alias
    $data = New-ItemProperty HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo -Name $aliasName -Value $serverAliasConnection -PropertyType "String" -Force -ErrorAction SilentlyContinue
}

# ====================================================================================
# Func: CheckSQLAccess
# Desc: Checks if the install account has the correct SQL database access and permissions
# By:   Sameer Dhoot (http://sharemypoint.in/about/sameerdhoot/)
# From: http://sharemypoint.in/2011/04/18/powershell-script-to-check-sql-server-connectivity-version-custering-status-user-permissions/
# Adapted for use in AutoSPInstaller by @brianlala
# ====================================================================================
Function CheckSQLAccess
{
    WriteLine
    # Look for references to DB Servers, Aliases, etc. in the XML
    ForEach ($node in $xmlinput.SelectNodes("//*[DBServer]|//*[@DatabaseServer]|//*[@FailoverDatabaseServer]"))
    {
        $dbServer = (GetFromNode $node "DBServer")
        If ($node.DatabaseServer) {$dbServer = GetFromNode $node "DatabaseServer"}
        # If the DBServer has been specified, and we've asked to set up an alias, create one
        If (!([string]::IsNullOrEmpty($dbServer)) -and ($node.DBAlias.Create -eq $true))
        {
            $dbInstance = GetFromNode $node.DBAlias "DBInstance"
            $dbPort = GetFromNode $node.DBAlias "DBPort"
            # If no DBInstance has been specified, but Create="$true", set the Alias to the server value
            If (($dbInstance -eq $null) -and ($dbInstance -ne "")) {$dbInstance = $dbServer}
            If (($dbPort -ne $null) -and ($dbPort -ne "")) 
            {
                Write-Host -ForegroundColor White " - Creating SQL alias `"$dbServer,$dbPort`"..."
                Add-SQLAlias -AliasName $dbServer -SQLInstance $dbInstance -Port $dbPort
            }
            Else # Create the alias without specifying the port (use default)
            {
                Write-Host -ForegroundColor White " - Creating SQL alias `"$dbServer`"..."
                Add-SQLAlias -AliasName $dbServer -SQLInstance $dbInstance
            }
        }
        $dbServers += @($dbServer)
    }

    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    $serverRolesToCheck = "dbcreator","securityadmin"
    # If we are provisioning PerformancePoint but aren't running SharePoint 2010 Service Pack 1 yet, we need sysadmin in order to run the RenameDatabase function
    # We also evidently need sysadmin in order to configure MaxDOP on the SQL instance if we are installing SharePoint 2013
    If (($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -and (ShouldIProvision ($xmlinput.Configuration.EnterpriseServiceApps.PerformancePointService) -eq $true) -and (!(CheckForSP1)))  
    {
        $serverRolesToCheck += "sysadmin"    
    }

    ForEach ($sqlServer in ($dbServers | Select-Object -Unique))
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
                Write-Host -ForegroundColor Black -BackgroundColor Green "Success"
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
                        Write-Host -ForegroundColor Black -BackgroundColor Green "Pass"
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
                $errText = $error[0].ToString()
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
                    If (!([string]::IsNullOrEmpty($serverRole)))
                    {
                        Throw " - $currentUser does not have `'$serverRole`' role!"
                    }
                    Else {Throw " - $errText"}
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
    $healthJobs = Get-SPTimerJob | Where {$_.DisplayName -match "Health Analysis Job"}
    Write-Host -ForegroundColor White " - Running all Health Analyzer jobs..."
    ForEach ($job in $healthJobs)
    {
        $job.RunNow()
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
        $queryOS = Gwmi Win32_OperatingSystem
        $queryOS = $queryOS.Version
        If ($queryOS.Contains("6.0")) # Win2008
        {
            Start-Process -FilePath servermanagercmd.exe -ArgumentList "-install smtp-server" -Wait -NoNewWindow
        }
            Else # Win2008 or Win2012
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
    $taxonomyPicker = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\TEMPLATE\CONTROLTEMPLATES\TaxonomyPicker.ascx"
    If (Test-Path $taxonomyPicker) 
    {
        WriteLine
        Write-Host -ForegroundColor White " - Renaming TaxonomyPicker.ascx..."
        Move-Item -Path $taxonomyPicker -Destination $taxonomyPicker".buggy" -Force
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
        $build = (Get-SPFarm).BuildVersion.Build
        If (!($build)) # Get the ProductVersion of a SharePoint DLL instead, since the farm doesn't seem to exist yet
        {
            $spProdVer = (Get-Command $env:CommonProgramFiles'\Microsoft Shared\Web Server Extensions\$env:spVer\isapi\microsoft.sharepoint.portal.dll').FileVersionInfo.ProductVersion
            $null,$null,[int]$build,$null = $spProdVer -split "\."
        }
        If ($build -ge 6029 -or $env:spVer -eq "15") # SP2010 SP1, or SP2013
        {
            Return $true
        }
    }
    # SharePoint probably isn't installed yet, so try to see if we have slipstreamed SP1 in the \Updates folder at least...
    ElseIf (Get-Item "$env:SPbits\Updates\oserversp1-x-none.msp" -ErrorAction SilentlyContinue)
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
    $setupType = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$env:spVer.0\WSS\").GetValue("SetupType")
    If ($setupType -ne "CLEAN_INSTALL") # For example, if the value is "B2B_UPGRADE"
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
        If ($file.Contains($hostname))
        {Write-Host -ForegroundColor White " - HOSTS file entry for `"$hostname`" already exists - skipping."} 
        Else
        {
            Write-Host -ForegroundColor White " - Adding HOSTS file entry for `"$hostname`"..."
            Add-Content -Path $hostsfile -Value "`r"
            Add-Content -Path $hostsfile -value "127.0.0.1 `t $hostname"
            $keepHOSTSCopy = $true
        }
    }
    If (!$keepHOSTSCopy)
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
    If (($url -like "*.*") -and (($webApp.AddURLToLocalIntranetZone) -eq $true))
    {
        $url = $url -replace "https://",""
        $url = $url -replace "http://",""
        $splitURL = $url -split "\."
        $urlDomain = $splitURL[-2] + "." + $splitURL[-1]
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
Function CompressFolder ($folder)
{
    # Replace \ with \\ for WMI
    $wmiPath = $folder.Replace("\","\\")
    $wmiDirectory = Get-WmiObject -Class "Win32_Directory" -Namespace "root\cimv2" -ComputerName $env:COMPUTERNAME -Filter "Name='$wmiPath'"
    # Check if folder is already compressed
    If (!($wmiDirectory.Compressed))
    {
        Write-Host -ForegroundColor White " - Compressing $folder and subfolders..."
        $compress = $wmiDirectory.CompressEx("","True")
    }
    Else {Write-Host -ForegroundColor White " - $folder is already compressed."}
}

# ====================================================================================
# Func: EnsureFolder
# Desc: Checks for the existence and validity of a given path, and attempts to create if it doesn't exist.
# From: Modified from patch 9833 at http://autospinstaller.codeplex.com/SourceControl/list/patches by user timiun
# ====================================================================================
Function EnsureFolder ($path)
{
        If (!(Test-Path -Path $path -PathType Container))
        {
            Write-Host -ForegroundColor White " - $path doesn't exist; creating..."
            Try 
            {
                New-Item -Path $path -ItemType Directory | Out-Null
            }
            Catch
            {               
                Write-Warning " - $($_.Exception.Message)"
                Throw " - Could not create folder $path!"
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
    $queryOS = Gwmi Win32_OperatingSystem
    $queryOS = $queryOS.Version 
    Try
    {
        If ($queryOS.Contains("6.0")) # Win2008
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
        Else # Win2008R2 or Win2012
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
    # Crude way of checking if SharePoint is already installed
    If (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$env:spVer\BIN\stsadm.exe")
    {
        return $true
    }
    Else {return $false}
}

# ====================================================================================
# Func: Show-Progress
# Desc: Shows a row of dots to let us know that $process is still running
# From: Brian Lalancette, 2012
# ====================================================================================
Function Show-Progress ($process, $color, $interval)
{
    $indicators = @("/","-","\","|")
    While (Get-Process -Name $process -ErrorAction SilentlyContinue)
    {
        Write-Host -ForegroundColor $color "." -NoNewline
        Start-Sleep $interval
    }
    Write-Host -ForegroundColor $color "Done."
}

# ====================================================================================
# Func: Set-UserAccountControl
# Desc: Enables or disables User Account Control (UAC), using a 1 or a 0 (respectively) passed as a parameter
# From: Brian Lalancette, 2012
# ====================================================================================
Function Set-UserAccountControl ($flag)
{
    $regUAC = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system").GetValue("EnableLUA")
    if ($flag -eq $regUAC)
    {
        Write-Host -ForegroundColor White " - User Account Control is already" $($regUAC -replace "1","enabled." -replace "0","disabled.")
    }
    else
    {
        if ($regUAC -eq 1)
        {
            New-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue | Out-Null
			$regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\"
            $regKey | New-ItemProperty -Name "UACWasEnabled" -PropertyType String -Value "1" -Force | Out-Null
        }
        Write-Host -ForegroundColor White " - $($flag -replace "1","Re-enabling" -replace "0","Disabling") User Account Control (effective upon restart)..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" -Name EnableLUA -Value $flag
    }
}
#EndRegion