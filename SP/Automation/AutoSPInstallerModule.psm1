# ===================================================================================
# EXTERNAL FUNCTIONS
# ===================================================================================

# Check that the version of the script matches the Version (essentially the schema) of the input XML so we don't have any unexpected behavior
Function CheckXMLVersion ([xml]$xmlInput)
{
    $getXMLVersion = $xmlInput.Configuration.Version
    # The value below will increment whenever there is an update to the format of the AutoSPInstallerInput XML file
    $scriptCurrentVersion = "3.99.85"
    $scriptPreviousVersion = "3.99.60"
    if ($getXMLVersion -ne $scriptCurrentVersion)
    {
        if ($getXMLVersion -eq $scriptPreviousVersion)
        {
            Write-Host -ForegroundColor Yellow " - Warning! Your input XML version ($getXMLVersion) is one level behind the script's version."
            Write-Host -ForegroundColor Yellow " - Visit https://autospinstaller.com to update it to the current version before proceeding."
        }
        else
        {
            Write-Host -ForegroundColor Yellow " - Warning! Your versions of the XML ($getXMLVersion) and script ($scriptCurrentVersion) are mismatched."
            Write-Host -ForegroundColor Yellow " - You should compare against the latest AutoSPInstallerInput.XML for missing/updated elements."
            Write-Host -ForegroundColor Yellow " - Or, try to validate/update your XML input at https://autospinstaller.com"
        }
        Pause "proceed with running AutoSPInstaller if you are sure this is OK, or Ctrl-C to exit" "y"
    }
}

#region Validate Passphrase
Function ValidatePassphrase ([xml]$xmlInput)
{
    # Check if passphrase is supplied
    $farmPassphrase = $xmlInput.Configuration.Farm.Passphrase
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        Return
    }
    $groups=0
    If ($farmPassphrase -cmatch "[a-z]") { $groups = $groups + 1 }
    If ($farmPassphrase -cmatch "[A-Z]") { $groups = $groups + 1 }
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
#endregion

#region Validate Credentials
Function ValidateCredentials ([xml]$xmlInput)
{
    WriteLine
    Write-Host -ForegroundColor White " - Validating user accounts and passwords..."
    If ($env:COMPUTERNAME -eq $env:USERDOMAIN)
    {
        Throw " - You are running this script under a local machine user account. You must be a domain user"
    }

    ForEach($node in $xmlInput.SelectNodes("//*[@Password]|//*[@password]|//*[@ContentAccessAccountPassword]|//*[@UnattendedIDPassword]|//*[@SyncConnectionAccountPassword]|//*[Password]|//*[password]|//*[ContentAccessAccountPassword]|//*[UnattendedIDPassword]|//*[SyncConnectionAccountPassword]"))
    {
        $user = (GetFromNode $node "username")
        If ($user -eq "") { $user = (GetFromNode $node "Username") }
        If ($user -eq "") { $user = (GetFromNode $node "Account") }
        If ($user -eq "") { $user = (GetFromNode $node "ContentAccessAccount") }
        If ($user -eq "") { $user = (GetFromNode $node "UnattendedIDUser") }
        If ($user -eq "") { $user = (GetFromNode $node "SyncConnectionAccount") }

        $password = (GetFromNode $node "password")
        If ($password -eq "") { $password = (GetFromNode $node "Password") }
        If ($password -eq "") { $password = (GetFromNode $node "ContentAccessAccountPassword") }
        If ($password -eq "") { $password = (GetFromNode $node "UnattendedIDPassword") }
        If ($password -eq "") { $password = (GetFromNode $node "SyncConnectionAccountPassword") }

        If (($password -ne "") -and ($user -ne ""))
        {
            $currentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            Write-Host -ForegroundColor White " - Account `"$user`" ($($node.Name))..." -NoNewline
            $dom = New-Object System.DirectoryServices.DirectoryEntry($currentDomain,$user,$password)
            If ($null -eq $dom.Path)
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
    if ($xmlInput.Configuration.WebApplications)
    {
        # Get application pool accounts
        foreach ($webApp in $($xmlInput.Configuration.WebApplications.WebApplication))
        {
            $appPoolAccounts = @($appPoolAccounts+$webApp.applicationPoolAccount)
            # Get site collection owners #
            foreach ($siteCollection in $($webApp.SiteCollections.SiteCollection))
            {
                if (!([string]::IsNullOrEmpty($siteCollection.Owner)))
                {
                    $siteCollectionOwners = @($siteCollectionOwners+$siteCollection.Owner)
                }
            }
        }
    }
    $appPoolAccounts = $appPoolAccounts | Select-Object -Unique
    $siteCollectionOwners = $siteCollectionOwners | Select-Object -Unique
    # Check for the existence of object cache accounts and other ones for which we don't need to specify passwords
    $accountsToCheck = @($xmlInput.Configuration.Farm.ObjectCacheAccounts.SuperUser,$xmlInput.Configuration.Farm.ObjectCacheAccounts.SuperReader)+$appPoolAccounts+$siteCollectionOwners | Select-Object -Unique
    foreach ($account in $accountsToCheck)
    {
        $domain,$accountName = $account -split "\\"
        Write-Host -ForegroundColor White " - Account `"$account`"..." -NoNewline
        if (!(userExists $accountName))
        {
            Write-Host -BackgroundColor Red -ForegroundColor Black "Invalid!"
            $acctInvalid = $true
        }
        else
        {
            Write-Host -ForegroundColor Black -BackgroundColor Green "Verified."
        }
    }
    If ($acctInvalid) {Throw " - At least one set of credentials is invalid.`n - Check usernames and passwords in each place they are used."}
    WriteLine
}
#endregion

#region Unblock Files / Trust Source Path & Remove IE Enhanced Security
Function UnblockFiles ($path)
{
    # Ensure that if we're running from a UNC path, the host portion is added to the Local Intranet zone so we don't get the "Open File - Security Warning"
    If ($env:dp0 -like "\\*")
    {
        WriteLine
        if (Get-Command -Name "Unblock-File" -ErrorAction SilentlyContinue)
        {
            Write-Host -ForegroundColor White " - Unblocking executable files in $path to prevent security prompts..." -NoNewline
            # Leverage the Unblock-File cmdlet, if available to prevent security warnings when working with language packs, CUs etc.
            Get-ChildItem -Path $path -Recurse | Where-Object {($_.Name -like "*.exe") -or ($_.Name -like "*.ms*") -or ($_.Name -like "*.zip") -or ($_.Name -like "*.cab")} | Unblock-File -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host -ForegroundColor White "Done."
        }
        $safeHost = ($env:dp0 -split "\\")[2]
        Write-Host -ForegroundColor White " - Adding location `"$safeHost`" to local Intranet security zone to prevent security prompts..." -NoNewline
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Name $safeHost -ItemType Leaf -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$safeHost" -Name "file" -value "1" -PropertyType dword -Force | Out-Null
        Write-Host -ForegroundColor White "Done."
        WriteLine
    }
}

Function RemoveIEEnhancedSecurity ([xml]$xmlInput)
{
    WriteLine
    If ($xmlInput.Configuration.Install.Disable.IEEnhancedSecurity -eq "True")
    {
        Write-Host -ForegroundColor White " - Disabling IE Enhanced Security..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name isinstalled -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name isinstalled -Value 0 -ErrorAction SilentlyContinue
        # Stuff below doesn't work on Server Core as IE is not installed
        if (!(Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT/Currentversion").InstallationType -eq "Server Core")
        {
            Rundll32 iesetup.dll, IEHardenLMSettings,1,True
            Rundll32 iesetup.dll, IEHardenUser,1,True
            Rundll32 iesetup.dll, IEHardenAdmin,1,True
        }
        If (Test-Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -ErrorAction SilentlyContinue)
        {
            Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        }
        If (Test-Path "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -ErrorAction SilentlyContinue)
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
#endregion

#region Disable Certificate Revocation List checks
Function DisableCRLCheck ([xml]$xmlInput)
{
    WriteLine
    If ($xmlInput.Configuration.Install.Disable.CertificateRevocationListCheck -eq "True")
    {
        Write-Host -ForegroundColor White " - Disabling Certificate Revocation List (CRL) check..."
        Write-Host -ForegroundColor White "  - Registry..."
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        New-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name State -PropertyType DWord -Value 146944 -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name State -PropertyType DWord -Value 146944 -Force | Out-Null
        Write-Host -ForegroundColor White "  - Machine.config files..."
        [array]$frameworkVersions = "v2.0.50727","v4.0.30319" # For .Net 2.0 and .Net 4.0
        ForEach($bitsize in ("","64"))
        {
            foreach ($frameworkVersion in $frameworkVersions)
            {
                # Added a check below for $xml because on Windows Server 2012 machines, the path to $xml doesn't exist until the .Net Framework is installed, so the steps below were failing
                $xml = [xml](Get-Content "$env:windir\Microsoft.NET\Framework$bitsize\$frameworkVersion\CONFIG\Machine.config" -ErrorAction SilentlyContinue)
                if ($xml)
                {
                    if ($bitsize -eq "64") {Write-Host -ForegroundColor White "   - $frameworkVersion..." -NoNewline}
                    If (!$xml.DocumentElement.SelectSingleNode("runtime"))
                    {
                        $runtime = $xml.CreateElement("runtime")
                        $xml.DocumentElement.AppendChild($runtime) | Out-Null
                    }
                    If (!$xml.DocumentElement.SelectSingleNode("runtime/generatePublisherEvidence"))
                    {
                        $gpe = $xml.CreateElement("generatePublisherEvidence")
                        $xml.DocumentElement.SelectSingleNode("runtime").AppendChild($gpe) | Out-Null
                    }
                    $xml.DocumentElement.SelectSingleNode("runtime/generatePublisherEvidence").SetAttribute("enabled","false") | Out-Null
                    $xml.Save("$env:windir\Microsoft.NET\Framework$bitsize\$frameworkVersion\CONFIG\Machine.config")
                    if ($bitsize -eq "64") {Write-Host -ForegroundColor White "OK."}
                }
                else
                {
                    if ($bitsize -eq "") {$bitsize = "32"}
                    Write-Warning "$bitsize-bit machine.config not found - could not disable CRL check."
                }
            }
        }
        Write-Host -ForegroundColor White " - Done."
    }
    Else
    {
        Write-Host -ForegroundColor White " - Not changing CRL check behavior."
    }
    WriteLine
}
#endregion

#region Start logging to user's desktop
Function StartTracing ($server)
{
    If (!$isTracing)
    {
        # Look for an existing log file start time in the registry so we can re-use the same log file
        $regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue
        If ($regKey) {$script:Logtime = $regkey.GetValue("LogTime")}
        If ([string]::IsNullOrEmpty($logtime)) {$script:Logtime = Get-Date -Format yyyy-MM-dd_h-mm}
        If ($server) {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$server-$script:Logtime.log"}
        else {$script:LogFile = "$env:USERPROFILE\Desktop\AutoSPInstaller-$script:Logtime.log"}
        Start-Transcript -Path $logFile -Append -Force
        If ($?) {$script:isTracing = $true}
    }
}
#endregion

#region Check Input File
Function CheckInput ($inputFile)
{
    # Check that the config file exists.
    If (-not $(Test-Path -Path $inputFile -Type Leaf))
    {
        Write-Error -message (" - Input file '" + $inputFile + "' does not exist.")
    }
}
#endregion

#region Check For or Create Config Files
Function CheckConfigFiles ([xml]$xmlInput)
{
    #region SharePoint config file
    if (Test-Path -Path (Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.Install.ConfigFile)))
    {
        # Just use the existing config file we found
        $script:configFile = Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.Install.ConfigFile)
        Write-Host -ForegroundColor White " - Using existing config file:`n - $configFile"
    }
    else
    {
        $spYear = $xmlInput.Configuration.Install.SPVersion
        $spVer = Get-MajorVersionNumber $spYear
        # Write out a new config file based on defaults and the values provided in $inputFile
        $pidKey = $xmlInput.Configuration.Install.PIDKey
        # Do a rudimentary check on the presence and format of the product key, only if we're not installing Foundation
        if ($xmlInput.Configuration.Install.SKU -ne "Foundation" -and $pidKey -notlike "?????-?????-?????-?????-?????")
        {
            throw " - The Product ID (PIDKey) is missing or badly formatted.`n - Check the value of <PIDKey> in `"$(Split-Path -Path $inputFile -Leaf)`" and try again."
        }
        $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
        $installDir = $xmlInput.Configuration.Install.InstallDir
        # Set $installDir to the default value if it's not specified in $xmlInput
        if ([string]::IsNullOrEmpty($installDir)) {$installDir = "%PROGRAMFILES%\Microsoft Office Servers\"}
        $dataDir = $xmlInput.Configuration.Install.DataDir
        # Set $dataDir to the default value if it's not specified in $xmlInput
        if ([string]::IsNullOrEmpty($dataDir)) {$dataDir = "%PROGRAMFILES%\Microsoft Office Servers\$spVer.0\Data"}
        $dataDir = $dataDir.TrimEnd("\")
        $xmlConfig = @"
<Configuration>
  <Package Id="sts">
    <Setting Id="LAUNCHEDFROMSETUPSTS" Value="Yes"/>
  </Package>
  <Package Id="spswfe">
    <Setting Id="SETUPCALLED" Value="1"/>
    <Setting Id="OFFICESERVERPREMIUM" Value="$officeServerPremium" />
  </Package>
  <ARP ARPCOMMENTS="Installed with AutoSPInstaller (https://autospinstaller.com)" ARPCONTACT="brian@autospinstaller.com" />
  <Logging Type="verbose" Path="%temp%" Template="SharePoint Server Setup(*).log"/>
  <Display Level="basic" CompletionNotice="No" AcceptEula="Yes"/>
  <INSTALLLOCATION Value="$installDir"/>
  <DATADIR Value="$dataDir"/>
  <PIDKEY Value="$pidKey"/>
  <Setting Id="SERVERROLE" Value="APPLICATION"/>
  <Setting Id="USINGUIINSTALLMODE" Value="1"/>
  <Setting Id="SETUPTYPE" Value="CLEAN_INSTALL"/>
  <Setting Id="SETUP_REBOOT" Value="Never"/>
  <Setting Id="AllowWindowsClientInstall" Value="True"/>
</Configuration>
"@
        $script:configFile = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath $($xmlInput.Configuration.Install.ConfigFile)
        Write-Host -ForegroundColor White " - Writing $($xmlInput.Configuration.Install.ConfigFile) to $((Get-Item $env:TEMP).FullName)..."
        Set-Content -Path "$configFile" -Force -Value $xmlConfig
    }
    #endregion

    #region OWA config file
    if ($xmlInput.Configuration.OfficeWebApps.Install -eq $true)
    {
        if (Test-Path -Path (Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.OfficeWebApps.ConfigFile)))
        {
            # Just use the existing config file we found
            $script:configFileOWA = Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.OfficeWebApps.ConfigFile)
            Write-Host -ForegroundColor White " - Using existing OWA config file:`n - $configFileOWA"
        }
        else
        {
            # Write out a new config file based on defaults and the values provided in $inputFile
            $pidKeyOWA = $xmlInput.Configuration.OfficeWebApps.PIDKeyOWA
            # Do a rudimentary check on the presence and format of the product key
            if ($pidKeyOWA -notlike "?????-?????-?????-?????-?????")
            {
                throw " - The OWA Product ID (PIDKey) is missing or badly formatted.`n - Check the value of <PIDKeyOWA> in `"$(Split-Path -Path $inputFile -Leaf)`" and try again."
            }
            $xmlConfigOWA = @"
<Configuration>
    <Package Id="sts">
        <Setting Id="LAUNCHEDFROMSETUPSTS" Value="Yes"/>
    </Package>
    <ARP ARPCOMMENTS="Installed with AutoSPInstaller (http://autospinstaller.com)" ARPCONTACT="brian@autospinstaller.com" />
    <Logging Type="verbose" Path="%temp%" Template="Wac Server Setup(*).log"/>
    <Display Level="basic" CompletionNotice="no" />
    <Setting Id="SERVERROLE" Value="APPLICATION"/>
    <PIDKEY Value="$pidKeyOWA"/>
    <Setting Id="USINGUIINSTALLMODE" Value="1"/>
    <Setting Id="SETUPTYPE" Value="CLEAN_INSTALL"/>
    <Setting Id="SETUP_REBOOT" Value="Never"/>
    <Setting Id="AllowWindowsClientInstall" Value="True"/>
</Configuration>
"@
            $script:configFileOWA = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath $($xmlInput.Configuration.OfficeWebApps.ConfigFile)
            Write-Host -ForegroundColor White " - Writing $($xmlInput.Configuration.OfficeWebApps.ConfigFile) to $((Get-Item $env:TEMP).FullName)..."
            Set-Content -Path "$configFileOWA" -Force -Value $xmlConfigOWA
        }
    }
    #endregion

    #region Project Server config file
    if ($xmlInput.Configuration.ProjectServer.Install -eq $true)
    {
        $pidKeyProjectServer = $xmlInput.Configuration.ProjectServer.PIDKeyProjectServer
        # Do a rudimentary check on the presence and format of the product key
        if ($pidKeyProjectServer -notlike "?????-?????-?????-?????-?????")
        {
            throw " - The Project Server Product ID (PIDKey) is missing or badly formatted.`n - Check the value of <PIDKeyProjectServer> in `"$(Split-Path -Path $inputFile -Leaf)`" and try again."
        }
        if ($spYear -eq 2013) # We only need this config file for Project Server 2013 / SP2013
        {
            if (Test-Path -Path (Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.ProjectServer.ConfigFile)))
            {
                # Just use the existing config file we found
                $script:configFileProjectServer = Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.ProjectServer.ConfigFile)
                Write-Host -ForegroundColor White " - Using existing ProjectServer config file:`n - $configFileProjectServer"
            }
            else
            {
                # Write out a new config file based on defaults and the values provided in $inputFile
                $xmlConfigProjectServer = @"
<Configuration>
    <Package Id="sts">
      <Setting Id="LAUNCHEDFROMSETUPSTS" Value="Yes"/>
    </Package>
      <Package Id="PJSRVWFE">
        <Setting Id="PSERVER" Value="1"/>
      </Package>
    <ARP ARPCOMMENTS="Installed with AutoSPInstaller (http://autospinstaller.com)" ARPCONTACT="brian@autospinstaller.com" />
    <Logging Type="verbose" Path="%temp%" Template="Project Server Setup(*).log"/>
    <Display Level="basic" CompletionNotice="No" AcceptEula="Yes"/>
    <Setting Id="SERVERROLE" Value="APPLICATION"/>
    <PIDKEY Value="$pidKeyProjectServer"/>
    <Setting Id="USINGUIINSTALLMODE" Value="1"/>
    <Setting Id="SETUPTYPE" Value="CLEAN_INSTALL"/>
    <Setting Id="SETUP_REBOOT" Value="Never"/>
    <Setting Id="AllowWindowsClientInstall" Value="True"/>
</Configuration>
"@
                $script:configFileProjectServer = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath $($xmlInput.Configuration.ProjectServer.ConfigFile)
                Write-Host -ForegroundColor White " - Writing $($xmlInput.Configuration.ProjectServer.ConfigFile) to $((Get-Item $env:TEMP).FullName)..."
                Set-Content -Path "$configFileProjectServer" -Force -Value $xmlConfigProjectServer
            }
        }
    }
    #endregion

    #region ForeFront answer file
    if (ShouldIProvision $xmlInput.Configuration.ForeFront -eq $true)
    {
        if (Test-Path -Path (Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.ForeFront.ConfigFile)))
        {
            # Just use the existing answer file we found
            $script:configFileForeFront = Join-Path -Path $env:dp0 -ChildPath $($xmlInput.Configuration.ForeFront.ConfigFile)
            Write-Host -ForegroundColor White " - Using existing ForeFront answer file:`n - $configFileForeFront"
        }
        else
        {
            $farmAcct = $xmlInput.Configuration.Farm.Account.Username
            $farmAcctPWD = $xmlInput.Configuration.Farm.Account.Password
            # Write out a new answer file based on defaults and the values provided in $inputFile
            $xmlConfigForeFront = @"
<?xml version="1.0" encoding="utf-8"?>
<FSSAnswerFile>
  <AcceptLicense>true</AcceptLicense>
  <AcceptRestart>true</AcceptRestart>
  <AcceptReplacePreviousVS>true</AcceptReplacePreviousVS>
  <InstallType>Full</InstallType>
  <Folders>
    <!--Leave these empty to use the default values-->
    <ProgramFolder></ProgramFolder>
    <DataFolder></DataFolder>
  </Folders>
  <ProxyInformation>
    <UseProxy>false</UseProxy>
    <ServerName></ServerName>
    <Port>80</Port>
    <UserName></UserName>
    <Password></Password>
  </ProxyInformation>
  <SharePointInformation>
    <UserName>$farmAcct</UserName>
    <Password>$farmAcctPWD</Password>
  </SharePointInformation>
  <EnableAntiSpamNow>false</EnableAntiSpamNow>
  <EnableCustomerExperienceImprovementProgram>false</EnableCustomerExperienceImprovementProgram>
</FSSAnswerFile>
"@
            $script:configFileForeFront = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath $($xmlInput.Configuration.ForeFront.ConfigFile)
            Write-Host -ForegroundColor White " - Writing $($xmlInput.Configuration.ForeFront.ConfigFile) to $((Get-Item $env:TEMP).FullName)..."
            Set-Content -Path "$configFileForeFront" -Force -Value $xmlConfigForeFront
        }
    }
    #endregion
}
#endregion

#region Check Installation Account
# ===================================================================================
# Func: CheckInstallAccount
# Desc: Check the install account and
# ===================================================================================
Function CheckInstallAccount ([xml]$xmlInput)
{
    # Check if we are running under Farm Account credentials
    $farmAcct = $xmlInput.Configuration.Farm.Account.Username
    If ($env:USERDOMAIN+"\"+$env:USERNAME -eq $farmAcct)
    {
        Write-Host  -ForegroundColor Yellow " - WARNING: Running install using Farm Account: $farmAcct"
    }
}
#endregion

#region Disable Loopback Check and Services
# ===================================================================================
# Func: DisableLoopbackCheck
# Desc: Disable Loopback Check
# ===================================================================================
Function DisableLoopbackCheck ([xml]$xmlInput)
{
    # Disable the Loopback Check on stand alone demo servers.
    # This setting usually kicks out a 401 error when you try to navigate to sites that resolve to a loopback address e.g.  127.0.0.1
    If ($xmlInput.Configuration.Install.Disable.LoopbackCheck -eq $true)
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
Function DisableServices ([xml]$xmlInput)
{
    If ($xmlInput.Configuration.Install.Disable.UnusedServices -eq $true)
    {
        WriteLine
        Write-Host -ForegroundColor White " - Setting services Spooler and AudioSrv to Manual..."

        $servicesToSetManual = "Spooler", "AudioSrv"
        ForEach ($svcName in $servicesToSetManual)
        {
            $svc = Get-WmiObject win32_service | Where-Object {$_.Name -eq $svcName}
            $svcStartMode = $svc.StartMode
            $svcState = $svc.State
            If (($svcState -eq "Running") -and ($svcStartMode -eq "Auto"))
            {
                Stop-Service -Name $svcName
                Set-Service -Name $svcName -StartupType Manual
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
            $svc = Get-WmiObject win32_service | Where-Object {$_.Name -eq $svcName}
            $svcStartMode = $svc.StartMode
            $svcState = $svc.State
            If (($svcState -eq "Running") -and (($svcStartMode -eq "Auto") -or ($svcStartMode -eq "Manual")))
            {
                Stop-Service -Name $svcName
                Set-Service -Name $svcName -StartupType Disabled
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
#endregion

#region Install Prerequisites
# ===================================================================================
# Func: InstallPrerequisites
# Desc: If SharePoint is not already installed install the Prerequisites
# ===================================================================================
Function InstallPrerequisites ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    WriteLine
    # Remove any lingering post-reboot registry values first
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "RestartRequired" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "CancelRemoteInstall" -ErrorAction SilentlyContinue
    # Check for whether UAC was previously enabled and should therefore be re-enabled after an automatic restart
    $regKey = Get-Item -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -ErrorAction SilentlyContinue
    If ($regKey)
    {
        $UACWasEnabled = $regkey.GetValue("UACWasEnabled")
    }
    If ($UACWasEnabled -eq 1)
    {
        Set-UserAccountControl 1
    }
    # Now, remove the lingering registry UAC flag
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\AutoSPInstaller\" -Name "UACWasEnabled" -ErrorAction SilentlyContinue
    $spInstalled = Get-SharePointInstall
    If ($spInstalled)
    {
        Write-Host -ForegroundColor White " - SharePoint $spYear prerequisites appear be already installed - skipping install."
    }
    Else
    {
        Write-Host -ForegroundColor White " - Installing Prerequisite Software:"
        If ((Get-WmiObject Win32_OperatingSystem).Version -eq "6.1.7601") # Win2008 R2 SP1
        {
            # Due to the SharePoint 2010 issue described in http://support.microsoft.com/kb/2581903 (related to installing the KB976462 hotfix)
            # (and simply to speed things up for SharePoint 2013) we install the .Net 3.5.1 features prior to attempting the PrerequisiteInstaller on Win2008 R2 SP1
            Write-Host -ForegroundColor White "  - .Net Framework 3.5.1..." -NoNewline
            # Get the current progress preference
            $pref = $ProgressPreference
            # Hide the progress bar since it tends to not disappear
            $ProgressPreference = "SilentlyContinue"
            Import-Module ServerManager
            If (!(Get-WindowsFeature -Name NET-Framework).Installed)
            {
                Add-WindowsFeature -Name NET-Framework | Out-Null
                if (!$?)
                {
                    Write-Output "."
                    throw "An error occurred installing the .Net Framework."
                }
                Write-Host -ForegroundColor Green "Done."
            }
            else
            {
                Write-Host -ForegroundColor White "Already installed."
            }
            # Restore progress preference
            $ProgressPreference = $pref

        }
        Try
        {
            # Detect if we're installing SP2010 on Windows Server 2012 (R2)
            if ((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*")
            {
                $osName = "Windows Server 2012"
                $win2012 = $true
                $prereqInstallerRequiredBuild = "7009" # i.e. minimum required version of PrerequisiteInstaller.exe for Windows Server 2012 is 14.0.7009.1000
            }
            elseif ((Get-WmiObject Win32_OperatingSystem).Version -like "6.3*")
            {
                $osName = "Windows Server 2012 R2"
                $win2012 = $true
                $prereqInstallerRequiredBuild = "7104" # i.e. minimum required version of PrerequisiteInstaller.exe for Windows Server 2012 R2 is 14.0.7104.5000
            }
            else
            {
                $win2012 = $false
            }
            if ($win2012 -and ($spYear -eq 2010))
            {
                Write-Host -ForegroundColor White " - Checking for required version of PrerequisiteInstaller.exe..." -NoNewline
                $prereqInstallerVer = (Get-Command $env:SPbits\PrerequisiteInstaller.exe).FileVersionInfo.ProductVersion
                $null, $null, $prereqInstallerBuild, $null = $prereqInstallerVer -split "\."
                # Check that the version of PrerequisiteInstaller.exe included in the MS-provided SharePoint 2010 SP2-integrated package meets the minimum required version for the detected OS
                if ($prereqInstallerBuild -lt $prereqInstallerRequiredBuild)
                {
                    Write-Host -ForegroundColor White "."
                    Throw " - SharePoint 2010 is officially unsupported on $osName without an updated set of SP2-integrated binaries - see http://support.microsoft.com/kb/2724471"
                }
                else
                {
                    Write-Host -BackgroundColor Green -ForegroundColor Black "OK."
                }
            }
            # Install using PrerequisiteInstaller as usual
            If ($xmlInput.Configuration.Install.OfflineInstall -eq $true) # Install all prerequisites from local folder
            {
                # Try to pre-install .Net Framework 3.5.1 on Windows Server 2012, 2012 R2 or 2016
                if ((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.4*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "10.0*" -and $spYear -ne "SE")
                {
                    if (Test-Path -Path "$env:SPbits\PrerequisiteInstallerFiles\sxs")
                    {
                        Write-Host -ForegroundColor White "  - .Net Framework 3.5.1 from `"$env:SPbits\PrerequisiteInstallerFiles\sxs`"..." -NoNewline
                        # Get the current progress preference
                        $pref = $ProgressPreference
                        # Hide the progress bar since it tends to not disappear
                        $ProgressPreference = "SilentlyContinue"
                        Import-Module ServerManager
                        if (!(Get-WindowsFeature -Name NET-Framework-Core).Installed)
                        {
                            Start-Process -FilePath DISM.exe -ArgumentList "/Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:`"$env:SPbits\PrerequisiteInstallerFiles\sxs`"" -NoNewWindow -Wait
                            if (!$?)
                            {
                                Write-Output "."
                                throw "An error occurred installing the .Net Framework."
                            }
                            ##Install-WindowsFeature NET-Framework-Core -Source "$env:SPbits\PrerequisiteInstallerFiles\sxs" | Out-Null
                            Write-Host -ForegroundColor Green "Done."
                        }
                        else
                        {
                            Write-Host -ForegroundColor White "Already installed."
                        }
                        # Restore progress preference
                        $ProgressPreference = $pref
                    }
                    else
                    {
                        Write-Host -ForegroundColor White " - Could not locate source for .Net Framework 3.5.1`n - The PrerequisiteInstaller will attempt to download it."
                    }
                }
                if ($spYear -eq 2010) # SP2010
                {
                    Write-Host -ForegroundColor White "  - SQL Native Client..."
                    # Install SQL native client before running pre-requisite installer as newest versions require an IACCEPTSQLNCLILICENSETERMS=YES argument
                    Start-Process "$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi" -Wait -ArgumentList "/passive /norestart IACCEPTSQLNCLILICENSETERMS=YES"
                    Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (offline mode)..." -NoNewline
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
                    If (-not $?)
                    {
                        Throw
                    }
                }
                elseif ($spYear -eq 2013) #SP2013
                {
                    Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (offline mode)..." -NoNewline
                    $startTime = Get-Date
                    if (CheckFor2013SP1 -xmlInput $xmlInput) # Include WCFDataServices56 as required by updated SP1 prerequisiteinstaller.exe
                    {
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
                                                                                             /WCFDataServices:`"$env:SPbits\PrerequisiteInstallerFiles\WcfDataServices.exe`" `
                                                                                             /WCFDataServices56:`"$env:SPbits\PrerequisiteInstallerFiles\WcfDataServices56.exe`""
                        If (-not $?)
                        {
                            Throw
                        }
                    }
                    else # Just install the pre-SP1 set of prerequisites
                    {
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
                        If (-not $?)
                        {
                            Throw
                        }
                    }
                }
                elseif ($spYear -eq 2016) #SP2016
                {
                    Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (offline mode)..." -NoNewline
                    $startTime = Get-Date
                    Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended `
                                                                                         /SQLNCli:`"$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi`" `
                                                                                         /Sync:`"$env:SPbits\PrerequisiteInstallerFiles\Synchronization.msi`" `
                                                                                         /AppFabric:`"$env:SPbits\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe`" `
                                                                                         /IDFX11:`"$env:SPbits\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi`" `
                                                                                         /MSIPCClient:`"$env:SPbits\PrerequisiteInstallerFiles\setup_msipc_x64.exe`" `
                                                                                         /KB3092423:`"$env:SPbits\PrerequisiteInstallerFiles\AppFabric-KB3092423-x64-ENU.exe`" `
                                                                                         /WCFDataServices56:`"$env:SPbits\PrerequisiteInstallerFiles\WcfDataServices.exe`" `
                                                                                         /ODBC:`"$env:SPbits\PrerequisiteInstallerFiles\msodbcsql.msi`" `
                                                                                         /DotNetFx:`"$env:SPbits\PrerequisiteInstallerFiles\NDP46-KB3045557-x86-x64-AllOS-ENU.exe`" `
                                                                                         /MSVCRT11:`"$env:SPbits\PrerequisiteInstallerFiles\vcredist_x64.exe`" `
                                                                                         /MSVCRT14:`"$env:SPbits\PrerequisiteInstallerFiles\vc_redist.x64.exe`""
                    If (-not $?)
                    {
                        Throw
                    }
                }
                elseif ($spYear -eq 2019) #SP2019
                {
                    Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (offline mode)..." -NoNewline
                    $startTime = Get-Date
                    Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended `
                                                                                         /SQLNCli:`"$env:SPbits\PrerequisiteInstallerFiles\sqlncli.msi`" `
                                                                                         /Sync:`"$env:SPbits\PrerequisiteInstallerFiles\Synchronization.msi`" `
                                                                                         /AppFabric:`"$env:SPbits\PrerequisiteInstallerFiles\WindowsServerAppFabricSetup_x64.exe`" `
                                                                                         /IDFX11:`"$env:SPbits\PrerequisiteInstallerFiles\MicrosoftIdentityExtensions-64.msi`" `
                                                                                         /MSIPCClient:`"$env:SPbits\PrerequisiteInstallerFiles\setup_msipc_x64.exe`" `
                                                                                         /KB3092423:`"$env:SPbits\PrerequisiteInstallerFiles\AppFabric-KB3092423-x64-ENU.exe`" `
                                                                                         /WCFDataServices56:`"$env:SPbits\PrerequisiteInstallerFiles\WcfDataServices.exe`" `
                                                                                         /DotNet472:`"$env:SPbits\PrerequisiteInstallerFiles\NDP472-KB4054530-x86-x64-AllOS-ENU.exe`" `
                                                                                         /MSVCRT11:`"$env:SPbits\PrerequisiteInstallerFiles\vcredist_x64.exe`" `
                                                                                         /MSVCRT141:`"$env:SPbits\PrerequisiteInstallerFiles\vc_redist.x64.exe`" `
                                                                                        "
                    If (-not $?)
                    {
                        Throw
                    }
                }
                elseif ($spYear -eq "SE") # SharePoint Subscription Edition (SPSE)
                {
                    Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (offline mode)..." -NoNewline
                    $startTime = Get-Date
                    Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended `
                                                                                         /DotNet48:`"$env:SPbits\PrerequisiteInstallerFiles\ndp48-x86-x64-allos-enu.exe`" `
                                                                                         /MSVCRT142:`"$env:SPbits\PrerequisiteInstallerFiles\VC_redist.x64.exe`" `
                                                                                        "
                    If (-not $?)
                    {
                        Throw
                    }
                }
            }
            else # Regular prerequisite install - download required files
            {
                Write-Host -ForegroundColor Cyan "  - Running Prerequisite Installer (online mode)..." -NoNewline
                $startTime = Get-Date
                Start-Process "$env:SPbits\PrerequisiteInstaller.exe" -ArgumentList "/unattended" -WindowStyle Minimized
                If (-not $?)
                {
                    Throw
                }
            }
            Show-Progress -Process PrerequisiteInstaller -Color Cyan -Interval 5
            $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            Write-Host -ForegroundColor White "  - Prerequisite Installer completed in $delta."
            If ($spYear -eq 2013) # SP2013
            {
                # Install the "missing prerequisites" for SP2013 per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=349
                # Expand hotfix executable to $env:SPbits\PrerequisiteInstallerFiles\
                if ((Get-WmiObject Win32_OperatingSystem).Version -eq "6.1.7601") # Win2008 R2 SP1
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
                else {} # Reserved for Win2012 R2
                if ($missingHotfixes.Count -ge 1)
                {
                    Write-Host -ForegroundColor White "  - SharePoint 2013 `"missing hotfix`" prerequisites..."
                    $hotfixLocation = $env:SPbits + "\PrerequisiteInstallerFiles"
                }
                ForEach ($hotfixPatch in $missingHotfixes.Keys)
                {
                    $hotfixKB = $hotfixPatch.Split('-') | Where-Object {$_ -like "KB*"}
                    # Check if the hotfix is already installed
                    Write-Host -ForegroundColor White "   - Checking for $hotfixKB..." -NoNewline
                    If (!(Get-HotFix -Id $hotfixKB -ErrorAction SilentlyContinue))
                    {
                        Write-Host -ForegroundColor White "Missing; attempting to install..."
                        $hotfixUrl = $missingHotfixes.$hotfixPatch
                        $hotfixFile = $hotfixUrl.Split('/')[-1]
                        $hotfixFileZip = $hotfixFile + ".zip"
                        $hotfixZipPath = Join-Path -Path $hotfixLocation -ChildPath $hotfixFileZip
                        # Check if the .msu/.exe file is already present
                        If (Test-Path "$hotfixLocation\$hotfixPatch")
                        {
                            Write-Host -ForegroundColor White "    - Hotfix file `"$hotfixPatch`" found."
                        }
                        Else
                        {
                            # Check if the downloaded package exists with a .zip extension
                            If (!([string]::IsNullOrEmpty($hotfixFileZip)) -and (Test-Path "$hotfixLocation\$hotfixFileZip"))
                            {
                                Write-Host -ForegroundColor White "    - File $hotfixFile (zip) found."
                            }
                            Else
                            {
                                # Check if the downloaded package exists
                                If (Test-Path "$hotfixLocation\$hotfixFile")
                                {
                                    Write-Host -ForegroundColor White "    - File $hotfixFile found."
                                }
                                Else # Go ahead and download the missing package
                                {
                                    Try
                                    {
                                        # Begin download
                                        Write-Host -ForegroundColor White "    - Hotfix $hotfixPatch not found in $env:SPbits\PrerequisiteInstallerFiles"
                                        Write-Host -ForegroundColor White "    - Attempting to download..." -NoNewline
                                        Import-Module BitsTransfer | Out-Null
                                        Start-BitsTransfer -Source $hotfixUrl -Destination "$hotfixLocation\$hotfixFile" -DisplayName "Downloading `'$hotfixFile`' to $hotfixLocation" -Priority Foreground -Description "From $hotfixUrl..." -ErrorVariable err
                                        if ($err)
                                        {
                                            Write-Host "."; Throw "  - Could not download from $hotfixUrl!"
                                        }
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
                                    Write-Host -ForegroundColor White "    - Renaming $hotfixFile to $hotfixFileZip..."
                                    Rename-Item -Path "$hotfixLocation\$hotfixFile" -NewName $hotfixFileZip -Force -ErrorAction SilentlyContinue
                                }
                            }
                            If (Test-Path "$hotfixLocation\$hotfixFileZip") # The zipped hotfix exists, ands needs to be extracted
                            {
                                Write-Host -ForegroundColor White "    - Extracting `"$hotfixPatch`" from `"$hotfixFile`"..." -NoNewline
                                $shell = New-Object -ComObject Shell.Application
                                $hotfixFileZipNs = $shell.Namespace($hotfixZipPath)
                                $hotfixLocationNs = $shell.Namespace($hotfixLocation)
                                $hotfixLocationNs.Copyhere($hotfixFileZipNs.items())
                                Write-Host -ForegroundColor Green "Done."
                            }
                        }
                        # Install the hotfix
                        $extractedHotfixPath = Join-Path -Path $hotfixLocation -ChildPath $hotfixPatch
                        Write-Host -ForegroundColor White "    - Installing hotfix $hotfixPatch..." -NoNewline
                        if ($hotfixPatch -like "*.msu") # Treat as a Windows Update patch
                        {
                            Start-Process -FilePath "wusa.exe" -ArgumentList "`"$extractedHotfixPath`" /quiet /norestart" -Wait -NoNewWindow
                        }
                        else # Treat as an executable (.exe) patch
                        {
                            Start-Process -FilePath "$extractedHotfixPath" -ArgumentList "/passive /norestart" -Wait -NoNewWindow
                        }
                        Write-Host -ForegroundColor Green "Done."
                    }
                    Else
                    {
                        Write-Host -ForegroundColor White "Already installed."
                    }
                }
            }
        }
        Catch
        {
            Write-Host -ForegroundColor Cyan "."
            Write-Host -ForegroundColor Red " - Error: $_ $LASTEXITCODE"
            If ($LASTEXITCODE -eq "1") {Throw " - Another instance of this application is already running"}
            ElseIf ($LASTEXITCODE -eq "2") {Throw " - Invalid command line parameter(s)"}
            ElseIf ($LASTEXITCODE -eq "1001") {Throw " - A pending restart blocks installation"}
            ElseIf ($LASTEXITCODE -eq "3010") {Throw " - A restart is needed"}
            ElseIf ($LASTEXITCODE -eq "-2145124329") {Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites"; InstallPreRequisites ([xml]$xmlInput)}
            Else {Throw " - An unknown error occurred installing prerequisites"}
        }
        # Parsing most recent PreRequisiteInstaller log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
        $preReqLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "PrerequisiteInstaller.*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
        If ($null -eq $preReqLog)
        {
            Write-Warning "Could not find PrerequisiteInstaller log file"
        }
        Else
        {
            # Get error(s) from log but filter out false-positives
            $preReqLastError = $preReqLog | Select-String -SimpleMatch -Pattern "Error" -Encoding Unicode | Where-Object {($_.Line -notlike "*Startup task*") -and ($_.Line -notlike "*`$operation*")}
            If ($preReqLastError)
            {
                ForEach ($preReqError in ($preReqLastError | ForEach-Object {$_.Line}))
                {
                    Write-Warning $preReqError
                }
                $preReqLastReturncode = $preReqLog | Select-String -SimpleMatch -Pattern "Last return code" -Encoding Unicode | Select-Object -Last 1
                If ($preReqLastReturnCode)
                {
                    Write-Verbose $preReqLastReturncode.Line
                }
                If (!($preReqLastReturncode -like "*(0)"))
                {
                    Write-Warning $preReqLastReturncode.Line
                    If (($preReqLastReturncode -like "*-2145124329*") -or ($preReqLastReturncode -like "*2359302*") -or ($preReqLastReturncode -eq "5"))
                    {
                        Write-Host -ForegroundColor White " - A known issue occurred installing one of the prerequisites - retrying..."
                        InstallPreRequisites ([xml]$xmlInput)
                    }
                    ElseIf (($preReqLog | Select-String -SimpleMatch -Pattern "Error when enabling ASP.NET v4.0.30319" -Encoding Unicode) -or ($preReqLog | Select-String -SimpleMatch -Pattern "Error when enabling ASP.NET v4.5 with IIS" -Encoding Unicode))
                    {
                        # Account for new issue with Win2012 RC / R2 and SP2013
                        Write-Host -ForegroundColor White " - A known issue occurred configuring .NET 4 / IIS."
                        $preReqKnownIssueRestart = $true
                    }
                    ElseIf ($preReqLog | Select-String -SimpleMatch -Pattern "pending restart blocks the installation" -Encoding Unicode)
                    {
                        Write-Host -ForegroundColor White " - A pending restart blocks the installation."
                        $preReqKnownIssueRestart = $true
                    }
                    ElseIf ($preReqLog | Select-String -SimpleMatch -Pattern "Error: This tool supports Windows Server version 6.1 and version 6.2" -Encoding Unicode)
                    {
                        Write-Host -ForegroundColor White " - A known issue occurred (due to Win2012 R2), continuing."
                        ##$preReqKnownIssueRestart = $true
                    }
                    Else
                    {
                        Invoke-Item -Path "$((Get-Item $env:TEMP).FullName)\$preReqLog"
                        Throw " - Review the log file and try to correct any error conditions."
                    }
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
                # We now also want to disable remote installs, or else each server will attempt to remote install to every *other* server after it reboots!
                $regKey | New-ItemProperty -Name "CancelRemoteInstall" -PropertyType String -Value "1" -Force | Out-Null
                $regKey | New-ItemProperty -Name "LogTime" -PropertyType String -Value $script:Logtime -ErrorAction SilentlyContinue | Out-Null
                Throw " - One or more of the prerequisites requires a restart."
            }
            Write-Host -ForegroundColor White " - All Prerequisite Software installed successfully."
        }
    }
    WriteLine
}
#endregion

#region Install SharePoint
# ===================================================================================
# Func: InstallSharePoint
# Desc: Installs the SharePoint binaries in unattended mode
# ===================================================================================
Function InstallSharePoint ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spInstalled = Get-SharePointInstall
    If ($spInstalled)
    {
        Write-Host -ForegroundColor White " - SharePoint $spYear binaries appear to be already installed - skipping installation."
    }
    Else
    {
        # Install SharePoint Binaries
        If (Test-Path "$env:SPbits\setup.exe")
        {
            Write-Host -ForegroundColor Cyan " - Installing SharePoint $spYear binaries..." -NoNewline
            $startTime = Get-Date
            Start-Process "$env:SPbits\setup.exe" -ArgumentList "/config `"$configFile`"" -WindowStyle Minimized
            Show-Progress -Process setup -Color Cyan -Interval 5
            $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            Write-Host -ForegroundColor White " - SharePoint $spYear setup completed in $delta."
            If (-not $?)
            {
                Throw " - Error $LASTEXITCODE occurred running $env:SPbits\setup.exe"
            }

            # Parsing most recent SharePoint Server Setup log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
            $setupLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "*SharePoint * Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
            If ($null -eq $setupLog)
            {
                Throw " - Could not find SharePoint Server Setup log file!"
            }

            # Get error(s) from log
            $setupLastError = $setupLog | Select-String -SimpleMatch -Pattern "Error:" | Select-Object -Last 1
            $setupSuccess = $setupLog | Select-String -SimpleMatch -Pattern "Successfully installed package: oserver"
            # Look for a different success message if we are only installing Foundation
            if ($xmlInput.Configuration.Install.SKU -eq "Foundation")
            {
                $setupSuccess = $setupLog | Select-String -SimpleMatch -Pattern "Successfully installed package: wss"
            }
            If ($setupLastError -and !$setupSuccess)
            {
                Write-Warning $setupLastError.Line
                Invoke-Item -Path "$((Get-Item $env:TEMP).FullName)\$setupLog"
                Throw " - Review the log file and try to correct any error conditions."
            }
            # Look for restart requirement in log
            $setupRestartNotNeeded = $setupLog | Select-String -SimpleMatch -Pattern "System reboot is not pending."
            If (!($setupRestartNotNeeded))
            {
                Throw " - SharePoint setup requires a restart. Run the script again after restarting to continue."
            }
            # Now wait up to 30 seconds for PSConfigUI to launch
            Write-Host -ForegroundColor Cyan " - Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
            While ($null -eq (Get-Process | Where-Object {$_.ProcessName -like "psconfigui*"}) -and $counter -le 30)
            {
                Write-Host -ForegroundColor Cyan "." -NoNewline
                Start-Sleep 1
                $counter++
            }
            Write-Host -ForegroundColor Green "Done."
            Write-Host -ForegroundColor White " - Exiting Products and Technologies Wizard - using PowerShell instead!"
            Stop-Process -Name psconfigui -ErrorAction SilentlyContinue
        }
        Else
        {
            Throw " - Install path $env:SPbits not found!!"
        }
    }
    WriteLine
}
#endregion

#region Install AppFabric CU
# ===================================================================================
# Func: Install-AppFabricCU
# Desc: Attempts to install a recently-released cumulative update for AppFabric, if found in $env:SPbits\PrerequisiteInstallerFiles
# ===================================================================================
function Install-AppFabricCU
{
    WriteLine
    # Create a hash table with major version to product year mappings
    [hashtable]$updates = @{"CU7" = "AppFabric-KB3092423-x64-ENU.exe";
                            "CU6" = "AppFabric-KB3042099-x64-ENU.exe";
                            "CU5" = "AppFabric1.1-KB2932678-x64-ENU.exe";
                            "CU4" = "AppFabric1.1-RTM-KB2800726-x64-ENU.exe"}
    $installSucceeded = $false
    Write-Host -ForegroundColor White " - Checking for AppFabric CU4 or newer..."
    $appFabricKB = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates\AppFabric 1.1 for Windows Server\KB2800726" -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled -eq 1) -or `
                    ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates\AppFabric 1.1 for Windows Server\KB2932678" -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled -eq 1) -or
                    ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates\AppFabric 1.1 for Windows Server\KB3042099" -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled -eq 1) -or
                    ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates\AppFabric 1.1 for Windows Server\KB3092423" -Name "IsInstalled" -ErrorAction SilentlyContinue).IsInstalled -eq 1))
    if (!$appFabricKB) # Try to install the AppFabric update if it isn't detected
    {
        foreach ($CU in ($updates.Keys | Sort-Object -Descending))
        {
            try
            {
                $currentUpdate = $updates.$CU
                # Check that we haven't already succeded with one of the CUs
                if (!$installSucceeded)
                {
                    # Check if the current CU exists in the current path
                    Write-Host -ForegroundColor White "CU4 or newer was not found."
                    Write-Host -ForegroundColor White "  - Looking for update: `"$env:SPbits\PrerequisiteInstallerFiles\$currentUpdate`"..."
                    if (Test-Path -Path "$env:SPbits\PrerequisiteInstallerFiles\$currentUpdate" -ErrorAction SilentlyContinue)
                    {
                        Write-Host "  - Installing $currentUpdate..."
                        Start-Process -FilePath "$env:SPbits\PrerequisiteInstallerFiles\$currentUpdate" -ArgumentList "/passive /promptrestart" -Wait -NoNewWindow
                        if ($?)
                        {
                            $installSucceeded = $true
                            Write-Host " - Done."
                        }
                    }
                    else
                    {
                        Write-Host -ForegroundColor White "  - AppFabric CU $currentUpdate wasn't found, looking for other update files..."
                    }
                }
            }
            catch
            {
                $installSucceeded = $false
                Write-Warning "  - Something went wrong with the installation of $currentUpdate."
            }
        }
    }
    else
    {
        $installSucceeded = $true
        Write-Host -ForegroundColor White " - Already installed."
    }
    if (!$installSucceeded)
    {
        Write-Host -ForegroundColor White " - Either no required AppFabric updates were found in $env:SPbits\PrerequisiteInstallerFiles, or the installation failed."
    }
    WriteLine
}
#endregion

#region Install Office Web Apps 2010
# ===================================================================================
# Func: InstallOfficeWebApps2010
# Desc: Installs the OWA binaries in unattended mode
# From: Ported over by user http://www.codeplex.com/site/users/view/cygoh originally from the InstallSharePoint function, fixed up by brianlala
# Originally posted on: http://autospinstaller.codeplex.com/discussions/233530
# ===================================================================================
Function InstallOfficeWebApps2010 ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    If ($xmlInput.Configuration.OfficeWebApps.Install -eq $true -and $spYear -eq 2010) # Check for SP2010
    {
        WriteLine
        If (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml") # Crude way of checking if Office Web Apps is already installed
        {
            Write-Host -ForegroundColor White " - Office Web Apps binaries appear to be already installed - skipping install."
        }
        Else
        {
            # Install Office Web Apps Binaries
            If (Test-Path "$bits\$spYear\OfficeWebApps\setup.exe")
            {
                Write-Host -ForegroundColor Cyan " - Installing Office Web Apps binaries..." -NoNewline
                $startTime = Get-Date
                Start-Process "$env:bits\$spYear\OfficeWebApps\setup.exe" -ArgumentList "/config `"$configFileOWA`"" -WindowStyle Minimized
                Show-Progress -Process setup -Color Cyan -Interval 5
                $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White " - Office Web Apps setup completed in $delta."
                If (-not $?)
                {
                    Throw " - Error $LASTEXITCODE occurred running $env:bits\$spYear\OfficeWebApps\setup.exe"
                }
                # Parsing most recent Office Web Apps Setup log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
                $setupLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "Wac Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
                If ($null -eq $setupLog)
                {
                    Throw " - Could not find Office Web Apps Setup log file!"
                }
                # Get error(s) from log
                $setupLastError = $setupLog | Select-String -SimpleMatch -Pattern "Error:" | Select-Object -Last 1 #| Where-Object {$_.Line -notlike "*Startup task*"}
                If ($setupLastError)
                {
                    Write-Warning $setupLastError.Line
                    Invoke-Item -Path "$((Get-Item $env:TEMP).FullName)\$setupLog"
                    Throw " - Review the log file and try to correct any error conditions."
                }
                # Look for restart requirement in log
                $setupRestartNotNeeded = $setupLog | Select-String -SimpleMatch -Pattern "System reboot is not pending."
                If (!($setupRestartNotNeeded))
                {
                    Throw " - Office Webapps setup requires a restart. Run the script again after restarting to continue."
                }
                Write-Host -ForegroundColor Cyan " - Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
                While ($null -eq (Get-Process | Where-Object {$_.ProcessName -like "psconfigui*"}))
                {
                    Write-Host -ForegroundColor Green "." -NoNewline
                    Start-Sleep 1
                }
                # The Connect-SPConfigurationDatabase cmdlet throws an error about an "upgrade required" if we don't at least *launch* the Wizard, so we wait to let it launch, then kill it.
                Start-Sleep 10
                Write-Host -ForegroundColor White "OK."
                Write-Host -ForegroundColor White " - Exiting Products and Technologies Wizard - using PowerShell instead!"
                Stop-Process -Name psconfigui
            }
            Else
            {
                Throw " - Install path $env:bits\$spYear\OfficeWebApps not found!!"
            }
        }
        WriteLine
    }
}
#endregion

#region Install Project Server
# ===================================================================================
# Func: InstallProjectServer
# Desc: Installs the Project Server binaries in unattended mode
# ===================================================================================
Function InstallProjectServer ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    If ($xmlInput.Configuration.ProjectServer.Install -eq $true -and $spYear -eq 2013) # Check for SP2013 since we don't support installing Project Server 2010 at this point, and it's included with SP2016
    {
        WriteLine
        # There has to be a better way to check whether Project Server is installed...
        $projectServerInstalled = Test-Path -Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\CONFIG\BIN\Microsoft.ProjectServer.dll"
        If ($projectServerInstalled)
        {
            Write-Host -ForegroundColor White " - Project Server $spYear binaries appear to be already installed - skipping installation."
        }
        Else
        {
            # Install Project Server Binaries
            If (Test-Path "$env:bits\$spYear\ProjectServer\setup.exe")
            {
                Write-Host -ForegroundColor Cyan " - Installing Project Server $spYear binaries..." -NoNewline
                $startTime = Get-Date
                Start-Process "$env:bits\$spYear\ProjectServer\setup.exe" -ArgumentList "/config `"$configFileProjectServer`"" -WindowStyle Minimized
                Show-Progress -Process setup -Color Cyan -Interval 5
                $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White " - Project Server $spYear setup completed in $delta."
                If (-not $?)
                {
                    Throw " - Error $LASTEXITCODE occurred running $env:bits\$spYear\ProjectServer\setup.exe"
                }

                # Parsing most recent Project Server Setup log for errors or restart requirements, since $LASTEXITCODE doesn't seem to work...
                $setupLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "Project Server Setup*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
                If ($null -eq $setupLog)
                {
                    Throw " - Could not find Project Server Setup log file!"
                }

                # Get error(s) from log
                $setupLastError = $setupLog | Select-String -SimpleMatch -Pattern "Error:" | Select-Object -Last 1
                $setupSuccess = $setupLog | Select-String -SimpleMatch -Pattern "Successfully installed package: pserver"
                if (!$setupSuccess)
                {
                    $setupSuccess = $setupLog | Select-String -SimpleMatch -Pattern "Successfully configured package: pserver"
                } # In case we are just configuring pre-installed or partially-installed product
                If ($setupLastError -and !$setupSuccess)
                {
                    Write-Warning $setupLastError.Line
                    Invoke-Item -Path "$((Get-Item $env:TEMP).FullName)\$setupLog"
                    Throw " - Review the log file and try to correct any error conditions."
                }
                # Look for restart requirement in log, but only if we installed fresh vs. just configuring
                if ($setupSuccess -like "*installed*")
                {
                    $setupRestartNotNeeded = $setupLog | Select-String -SimpleMatch -Pattern "System reboot is not pending."
                    If (!$setupRestartNotNeeded)
                    {
                        Throw " - Project Server setup requires a restart. Run the script again after restarting to continue."
                    }
                }
                Write-Host -ForegroundColor Cyan " - Waiting for SharePoint Products and Technologies Wizard to launch..." -NoNewline
                While ($null -eq (Get-Process | Where-Object {$_.ProcessName -like "psconfigui*"}))
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                }
                Write-Host -ForegroundColor White "OK."
                Write-Host -ForegroundColor White " - Exiting Products and Technologies Wizard - using PowerShell instead!"
                Stop-Process -Name psconfigui
            }
            Else
            {
                Write-Warning "Project Server installation requested, but install path $env:bits\$spYear\ProjectServer not found!!"
                Pause "continue"
            }
        }
        WriteLine
    }
}
#endregion

#region Configure Office Web Apps 2010
Function ConfigureOfficeWebApps ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    If ($xmlInput.Configuration.OfficeWebApps.Install -eq $true -and $spYear -eq 2010) # Check for SP2010
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
            If (!$?)
            {
                Throw
            }
            # Install (all) features
            Write-Host -ForegroundColor White " - Installing Features..."
            Install-SPFeature -AllExistingFeatures | Out-Null
        }
        Catch
        {
            Write-Output $_
            Throw " - Error configuring Office Web Apps!"
        }
        Writeline
    }
}
#endregion

#region Install Language Packs
# ===================================================================================
# Func: Install Language Packs
# Desc: Install language packs and report on any languages installed
# ===================================================================================
Function InstallLanguagePacks ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    # Get installed languages from registry (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office Server\$spVer.0\InstalledLanguages)
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
    # Look for extracted language packs
    $extractedLanguagePacks = (Get-ChildItem -Path "$env:bits\$spYear\LanguagePacks" -Name -Include "??-??" -ErrorAction SilentlyContinue)
    $serverLanguagePacks = (Get-ChildItem -Path "$env:bits\$spYear\LanguagePacks" -Name -Include ServerLanguagePack_*.exe -ErrorAction SilentlyContinue)
    If ($extractedLanguagePacks -and (Get-ChildItem -Path "$env:bits\$spYear\LanguagePacks" -Name -Include "setup.exe" -Recurse -ErrorAction SilentlyContinue))
    {
        Write-Host -ForegroundColor White " - Installing SharePoint Language Packs:"
        ForEach ($languagePackFolder in $extractedLanguagePacks)
        {
            $language = $installedOfficeServerLanguages | Where-Object {$_ -eq $languagePackFolder}
            If (!$language)
            {
#                if (Test-Path -Path "$env:bits\$spYear\LanguagePacks\$languagePackFolder\setup.exe" -ErrorAction SilentlyContinue)
#                {
                Write-Host -ForegroundColor Cyan "  - Installing extracted language pack $languagePackFolder..." -NoNewline
                $startTime = Get-Date
                Start-Process -WorkingDirectory "$env:bits\$spYear\LanguagePacks\$languagePackFolder\" -FilePath "setup.exe" -ArgumentList "/config $env:bits\$spYear\LanguagePacks\$languagePackFolder\Files\SetupSilent\config.xml"
                Show-Progress -Process setup -Color Cyan -Interval 5
                $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White "  - Language pack $languagePackFolder setup completed in $delta."
#                }
#                else {Write-Host -ForegroundColor White " - None found."}
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
            $language = $installedOfficeServerLanguages | Where-Object {$_ -eq (($languagePack -replace "ServerLanguagePack_", "") -replace ".exe", "")}
            If (!$language)
            {
                Write-Host -ForegroundColor Cyan " - Installing $languagePack..." -NoNewline
                $startTime = Get-Date
                Start-Process -FilePath "$env:bits\$spYear\LanguagePacks\$languagePack" -ArgumentList "/quiet /norestart"
                Show-Progress -Process $($languagePack -replace ".exe", "") -Color Cyan -Interval 5
                $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
                Write-Host -ForegroundColor White " - Language pack $languagePack setup completed in $delta."
                $language = (($languagePack -replace "ServerLanguagePack_", "") -replace ".exe", "")
                # Install Foundation Language Pack SP1, then Server Language Pack SP1, if found
                If (Get-ChildItem -Path "$env:bits\$spYear\LanguagePacks" -Name -Include spflanguagepack2010sp1-kb2460059-x64-fullfile-$language.exe -ErrorAction SilentlyContinue)
                {
                    Write-Host -ForegroundColor Cyan " - Installing Foundation language pack SP1 for $language..." -NoNewline
                    Start-Process -WorkingDirectory "$env:bits\$spYear\LanguagePacks\" -FilePath "spflanguagepack2010sp1-kb2460059-x64-fullfile-$language.exe" -ArgumentList "/quiet /norestart"
                    Show-Progress -Process spflanguagepack2010sp1-kb2460059-x64-fullfile-$language -Color Cyan -Interval 5
                    # Install Server Language Pack SP1, if found
                    If (Get-ChildItem -Path "$env:bits\$spYear\LanguagePacks" -Name -Include serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language.exe -ErrorAction SilentlyContinue)
                    {
                        Write-Host -ForegroundColor Cyan " - Installing Server language pack SP1 for $language..." -NoNewline
                        Start-Process -WorkingDirectory "$env:bits\$spYear\LanguagePacks\" -FilePath "serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language.exe" -ArgumentList "/quiet /norestart"
                        Show-Progress -Process serverlanguagepack2010sp1-kb2460056-x64-fullfile-$language -Color Cyan -Interval 5
                    }
                    Else
                    {
                        Write-Warning "Server Language Pack SP1 not found for $language!"
                        Write-Warning "You must install it for the language service pack patching process to be complete."
                    }
                }
                Else
                {
                    Write-Host -ForegroundColor White " - No Language Pack service packs found."
                }
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
        Write-Host -ForegroundColor White " - No language pack installers found in $env:bits\$spYear\LanguagePacks, skipping."
    }

    # Get and note installed languages
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
    Write-Host -ForegroundColor White " - Currently installed languages:"
    ForEach ($language in $installedOfficeServerLanguages)
    {
        Write-Host "  -" ([System.Globalization.CultureInfo]::GetCultureInfo($language).DisplayName)
    }
    WriteLine
}
#endregion

#region Install Updates
# ===================================================================================
# Func: InstallUpdates
# Desc: Install SharePoint Updates (CUs and Service Packs) to work around slipstreaming issues
# ===================================================================================
Function InstallUpdates ([xml]$xmlInput)
{
    WriteLine
    Write-Host -ForegroundColor White " - Looking for SharePoint updates to install..."
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    # Result codes below are from http://technet.microsoft.com/en-us/library/cc179058(v=office.14).aspx
    $oPatchInstallResultCodes = @{"17301" = "Error: General Detection error";
                                  "17302" = "Error: Applying patch";
                                  "17303" = "Error: Extracting file";
                                  "17021" = "Error: Creating temp folder";
                                  "17022" = "Success: Reboot flag set";
                                  "17023" = "Error: User cancelled installation";
                                  "17024" = "Error: Creating folder failed";
                                  "17025" = "Patch already installed";
                                  "17026" = "Patch already installed to admin installation";
                                  "17027" = "Installation source requires full file update";
                                  "17028" = "No product installed for contained patch";
                                  "17029" = "Patch failed to install";
                                  "17030" = "Detection: Invalid CIF format";
                                  "17031" = "Detection: Invalid baseline";
                                  "17034" = "Error: Required patch does not apply to the machine";
                                  "17038" = "You do not have sufficient privileges to complete this installation for all users of the machine. Log on as administrator and then retry this installation";
                                  "17044" = "Installer was unable to run detection for this package"}
    if ($spYear -eq 2010)
    {
        $sp2010SP1 = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "officeserver2010sp1-kb2460045-x64-fullfile-en-us.exe" -Recurse -ErrorAction SilentlyContinue
        # In case we find more than one (e.g. in subfolders), grab the first one
        if ($sp2010SP1 -is [system.array])
        {
            $sp2010SP1 = $sp2010SP1[0]
        }
        $sp2010June2013CU = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "ubersrv2010-kb2817527-fullfile-x64-glb.exe" -Recurse -ErrorAction SilentlyContinue
        # In case we find more than one (e.g. in subfolders), grab the first one
        if ($sp2010June2013CU -is [system.array])
        {
            $sp2010June2013CU = $sp2010June2013CU[0]
        }
        $sp2010SP2 = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "oserversp2010-kb2687453-fullfile-x64-en-us.exe" -Recurse -ErrorAction SilentlyContinue
        # In case we find more than one (e.g. in subfolders), grab the first one
        if ($sp2010SP2 -is [system.array])
        {
            $sp2010SP2 = $sp2010SP2[0]
        }
        # Get installed SharePoint languages, so we can determine which language pack updates to apply
        $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
        # First & foremost, install SP2 if it's there
        if ($sp2010SP2)
        {
            InstallSpecifiedUpdate $sp2010SP2 "Service Pack 2"
        }
        # Otherwise, install SP1 as it is a required baseline for any post-June 2012 CUs
        elseif ($sp2010SP1)
        {
            InstallSpecifiedUpdate $sp2010SP1 "Service Pack 1"
        }
        # Next, install the June 2013 CU if it's found in \Updates
        if ($sp2010June2013CU)
        {
            InstallSpecifiedUpdate $sp2010June2013CU "June 2013 CU"
        }
        # Now find any language pack service packs, using the naming conventions for both SP1 and SP2
        $sp2010LPServicePacks = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include serverlanguagepack2010sp*.exe, oslpksp2010*.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object -Descending
        # Now install language pack service packs - only if they match a currently-installed SharePoint language
        foreach ($installedOfficeServerLanguage in $installedOfficeServerLanguages)
        {
            [array]$sp2010LPServicePacksToInstall += $sp2010LPServicePacks | Where-Object {$_ -like "*$installedOfficeServerLanguage*"}
        }
        if ($sp2010LPServicePacksToInstall)
        {
            foreach ($sp2010LPServicePack in $sp2010LPServicePacksToInstall)
            {
                InstallSpecifiedUpdate $sp2010LPServicePack "Language Pack Service Pack"
            }
        }
        if ($xmlInput.Configuration.OfficeWebApps.Install -eq $true)
        {
            $sp2010OWAUpdates = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include wac*.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object -Descending
            if ($sp2010OWAUpdates.Count -ge 1)
            {
                foreach ($sp2010OWAUpdate in $sp2010OWAUpdates)
                {
                    InstallSpecifiedUpdate $sp2010OWAUpdate "Office Web Apps Update"
                }
            }
        }
    }
    if ($spYear -eq 2013)
    {
        # Do SP1 first, if it's found
        $sp2013SP1 = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "officeserversp2013-kb2880552-fullfile-x64-en-us.exe" -Recurse -ErrorAction SilentlyContinue
        if ($sp2013SP1)
        {
            # In case we find more than one (e.g. in subfolders), grab the first one
            if ($sp2013SP1 -is [system.array])
            {
                $sp2013SP1 = $sp2013SP1[0]
            }
            InstallSpecifiedUpdate $sp2013SP1 "Service Pack 1"
        }
        if ($xmlInput.Configuration.ProjectServer.Install -eq $true)
        {
            if ($sp2013SP1)
            {
                # Look for Project Server 2013 SP1, since we have SharePoint Server SP1
                $sp2013ProjectSP1 = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "projectserversp2013-kb2817434-fullfile-x64-en-us.exe" -Recurse -ErrorAction SilentlyContinue
                if ($sp2013ProjectSP1)
                {
                    # In case we find more than one (e.g. in subfolders), grab the first one
                    if ($sp2013ProjectSP1 -is [system.array])
                    {
                        $sp2013ProjectSP1 = $sp2013ProjectSP1[0]
                    }
                    InstallSpecifiedUpdate $sp2013ProjectSP1 "Project Server Service Pack 1"
                }
                else
                {
                    Write-Warning "Project Server Service Pack 1 wasn't found. Since SharePoint itself will be updated to SP1, you should download and install Project Server 2013 SP1 for your server/farm to be completely patched."
                }
            }
            else
            {
                # Look for a Project Server March PU
                $marchPublicUpdate = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "ubersrvprjsp2013-kb2768001-fullfile-x64-glb.exe" -Recurse -ErrorAction SilentlyContinue
                if (!$marchPublicUpdate)
                {
                    # In case we forgot to include the Project Server March PU, just look for the SharePoint Server March PU
                    $marchPublicUpdate = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "ubersrvsp2013-kb2767999-fullfile-x64-glb.exe" -Recurse -ErrorAction SilentlyContinue
                    if ($marchPublicUpdate)
                    {
                        Write-Warning "The Project Server March PU wasn't found, but the regular SharePoint Server March PU was, and will be applied. However you should download and install the full Project Server March PU and any subsequent updates afterwards for your server/farm to be completely patched."
                    }
                }
            }
        }
        else
        {
            if (!$sp2013SP1)
            {
                # Look for the SharePoint Server March PU
                $marchPublicUpdate = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Name -Include "ubersrvsp2013-kb2767999-fullfile-x64-glb.exe" -Recurse -ErrorAction SilentlyContinue
            }
        }
        if ($marchPublicUpdate)
        {
            # In case we find more than one (e.g. in subfolders), grab the first one
            if ($marchPublicUpdate -is [system.array])
            {
                $marchPublicUpdate = $marchPublicUpdate[0]
            }
            InstallSpecifiedUpdate $marchPublicUpdate "March 2013 Public Update"
        }
    }
    # Get all CUs except the March 2013 PU for SharePoint / Project Server 2013 and the June 2013 CU for SharePoint 2010
    $cumulativeUpdates = Get-ChildItem -Path "$env:bits\$spYear\Updates" -Include office2010*.exe, ubersrv*.exe, uber-*.exe, ubersts*.exe, *pjsrv*.exe, sharepointsp2013*.exe, coreserver201*.exe, sts201*.exe, wssloc201*.exe, wssloc-*.exe, svrproofloc201*.exe -Recurse -ErrorAction SilentlyContinue | Where-Object {$_ -notlike "*ubersrvsp2013-kb2767999-fullfile-x64-glb.exe" -and $_ -notlike "*ubersrvprjsp2013-kb2768001-fullfile-x64-glb.exe" -and $_ -notlike "*ubersrv2010-kb2817527-fullfile-x64-glb.exe"} | Sort-Object -Descending
    # Filter out Project Server updates if we aren't installing Project Server
    if ($xmlInput.Configuration.ProjectServer.Install -ne $true)
    {
        $cumulativeUpdates = $cumulativeUpdates | Where-Object {($_ -notlike "*prj*.exe") -and ($_ -notlike "*pjsrv*.exe")}
    }
    # Look for Server Cumulative Update installers
    if ($cumulativeUpdates)
    {
        # Display warning about missing March 2013 PU only if we are actually installing SP2013 and SP1 isn't already installed and the SP1 installer isn't found
        if ($spYear -eq 2013 -and !($sp2013SP1 -or (CheckFor2013SP1 -xmlInput $xmlInput)) -and !$marchPublicUpdate)
        {
            Write-Host -ForegroundColor Yellow "  - Note: the March 2013 PU package wasn't found in ..\$spYear\Updates; it may need to be installed first if it wasn't slipstreamed."
        }
        # Now attempt to install any other CUs found in the \Updates folder
        Write-Host -ForegroundColor White "  - Installing SharePoint $(if ($spYear -ge 2016) {"Public"} else {"Cumulative"}) Updates:"
        ForEach ($cumulativeUpdate in $cumulativeUpdates)
        {
            # Get the file name only, in case $cumulativeUpdate includes part of a path (e.g. is in a subfolder)
            $splitCumulativeUpdate = Split-Path -Path $cumulativeUpdate -Leaf
            Write-Host -ForegroundColor Cyan "   - Installing $splitCumulativeUpdate from `"$($cumulativeUpdate.Directory.Name)`"..." -NoNewline
            $startTime = Get-Date
            Start-Process -FilePath "$cumulativeUpdate" -ArgumentList "/passive /norestart"
            Show-Progress -Process $($splitCumulativeUpdate -replace ".exe", "") -Color Cyan -Interval 5
            $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
            $oPatchInstallLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "opatchinstall*.log"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
            # Get install result from log
            $oPatchInstallResultMessage = $oPatchInstallLog | Select-String -SimpleMatch -Pattern "OPatchInstall: Property 'SYS.PROC.RESULT' value" | Select-Object -Last 1
            If (!($oPatchInstallResultMessage -like "*value '0'*")) # Anything other than 0 means unsuccessful but that's not necessarily a bad thing
            {
                $null, $oPatchInstallResultCode = $oPatchInstallResultMessage.Line -split "OPatchInstall: Property 'SYS.PROC.RESULT' value '"
                $oPatchInstallResultCode = $oPatchInstallResultCode.TrimEnd("'")
                # OPatchInstall: Property 'SYS.PROC.RESULT' value '17028' means the patch was not needed or installed product was newer
                if ($oPatchInstallResultCode -eq "17028")
                {
                    Write-Host -ForegroundColor White "   - Patch not required; installed product is same or newer."
                }
                elseif ($oPatchInstallResultCode -eq "17031")
                {
                    Write-Warning "Error 17031: Detection: Invalid baseline"
                    Write-Warning "A baseline patch (e.g. March 2013 PU for SP2013, SP1 for SP2010) is missing!"
                    Write-Host -ForegroundColor Yellow "   - Either slipstream the missing patch first, or include the patch package in the ..\$spYear\Updates folder."
                    Pause "continue"
                }
                else
                {
                    Write-Host "   - $($oPatchInstallResultCodes.$oPatchInstallResultCode)"
                }
            }
            Write-Host -ForegroundColor White "   - $splitCumulativeUpdate install completed in $delta."
        }
        Write-Host -ForegroundColor White "  - $(if ($spYear -ge 2016) {"Public"} else {"Cumulative"}) Update installation complete."
    }
    # Finally, install SP2 last in case we applied the June 2013 CU which would not have properly detected SP2...
    if ($sp2010SP2 -and $sp2010June2013CU -and $spYear -eq 2010)
    {
        InstallSpecifiedUpdate $sp2010SP2 "Service Pack 2"
    }
    if (!$marchPublicUpdate -and !$cumulativeUpdates)
    {
        Write-Host -ForegroundColor White " - No other updates found in $env:bits\$spYear\Updates, proceeding..."
    }
    else
    {
        Write-Host -ForegroundColor White " - Finished installing SharePoint updates."
    }
    WriteLine
}
# ===================================================================================
# Func: InstallSpecifiedUpdate
# Desc: Installs a specified SharePoint Updates (CU or Service Pack)
# ===================================================================================
Function InstallSpecifiedUpdate ($updateFile, $updateName)
{
    # Get the file name only, in case $updateFile includes part of a path (e.g. is in a subfolder)
    $splitUpdateFile = Split-Path -Path $updateFile -Leaf
    Write-Host -ForegroundColor Cyan "  - Installing SP$spYear $updateName $splitUpdateFile..." -NoNewline
    $startTime = Get-Date
    Start-Process -FilePath "$env:bits\$spYear\Updates\$updateFile" -ArgumentList "/passive /norestart"
    Show-Progress -Process $($splitUpdateFile -replace ".exe", "") -Color Cyan -Interval 5
    $delta, $null = (New-TimeSpan -Start $startTime -End (Get-Date)).ToString() -split "\."
    $oPatchInstallLog = Get-ChildItem -Path (Get-Item $env:TEMP).FullName | Where-Object {$_.Name -like "opatchinstall*.log"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
    # Get install result from log
    $oPatchInstallResultMessage = $oPatchInstallLog | Select-String -SimpleMatch -Pattern "OPatchInstall: Property 'SYS.PROC.RESULT' value" | Select-Object -Last 1
    If (!($oPatchInstallResultMessage -like "*value '0'*")) # Anything other than 0 means unsuccessful but that's not necessarily a bad thing
    {
        $null, $oPatchInstallResultCode = $oPatchInstallResultMessage.Line -split "OPatchInstall: Property 'SYS.PROC.RESULT' value '"
        $oPatchInstallResultCode = $oPatchInstallResultCode.TrimEnd("'")
        # OPatchInstall: Property 'SYS.PROC.RESULT' value '17028' means the patch was not needed or installed product was newer
        if ($oPatchInstallResultCode -eq "17028")
        {
            Write-Host -ForegroundColor White "   - Patch not required; installed product is same or newer."
        }
        elseif ($oPatchInstallResultCode -eq "17031")
        {
            Write-Warning "Error 17031: Detection: Invalid baseline"
            Write-Warning "A baseline patch (e.g. March 2013 PU for SP2013, SP1 for SP2010) is missing!"
            Write-Host -ForegroundColor Yellow "   - Either slipstream the missing patch first, or include the patch package in the ..\$spYear\Updates folder."
            Pause "continue"
        }
        else
        {
            Write-Host "  - $($oPatchInstallResultCodes.$oPatchInstallResultCode)"
        }
    }
    Write-Host -ForegroundColor White "  - $updateName install completed in $delta."
}
#endregion

#region Configure Farm Account
# ===================================================================================
# Func: ConfigureFarmAdmin
# Desc: Sets up the farm account and adds to Local admins if needed
# ===================================================================================
Function ConfigureFarmAdmin ([xml]$xmlInput)
{
    # Per Spencer Harbar, the farm account needs to be a local admin when provisioning distributed cache, so if it's being requested for provisioning we'll add it to Administrators here
    If (($xmlInput.Configuration.Farm.Account.AddToLocalAdminsDuringSetup -eq $true) -or (ShouldIProvision $xmlInput.Configuration.ServiceApps.UserProfileServiceApp -eq $true) -or (ShouldIProvision $xmlInput.Configuration.Farm.Services.DistributedCache -eq $true))
    {
        WriteLine
        # Add to Admins Group
        $farmAcct = $xmlInput.Configuration.Farm.Account.Username
        Write-Host -ForegroundColor White " - Adding $farmAcct to local Administrators" -NoNewline
        If ($xmlInput.Configuration.Farm.Account.LeaveInLocalAdmins -ne $true)
        {
            Write-Host -ForegroundColor White " (only for install)..."
        }
        Else
        {
            Write-Host -ForegroundColor White " ..."
        }
        $farmAcctDomain, $farmAcctUser = $farmAcct -Split "\\"
        Try
        {
            $builtinAdminGroup = Get-AdministratorsGroup
            ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$farmAcctDomain/$farmAcctUser")
            If (-not $?)
            {
                Throw
            }
            # Restart the SPTimerV4 service if it's running, so it will pick up the new credential
            If ((Get-Service -Name SPTimerV4).Status -eq "Running")
            {
                Write-Host -ForegroundColor White " - Restarting SharePoint Timer Service..."
                Restart-Service SPTimerV4
            }
        }
        Catch
        {
            Write-Host -ForegroundColor White " - $farmAcct is already a member of `"$builtinAdminGroup`"."
        }
        WriteLine
    }
}

# ===================================================================================
# Func: Get-SQLCredentials
# Desc: Return the credentials for the SQL server account, prompt the user if need more info
# ===================================================================================
Function Get-SQLCredentials ($SqlAccount, $SqlPass)
{
    If (([string]::IsNullOrEmpty($SqlAccount)) -or ([string]::IsNullOrEmpty($SqlPass)))
    {
        Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan " - Prompting for SQL Account:"
        $SqlCredential = $host.ui.PromptForCredential("SQL Authentication", "Enter SQL Account Credentials:", "$SqlAccount", "")
    }
    Else
    {
        $secSqlPassword = ConvertTo-SecureString "$SqlPass" -AsPlainText -Force
        $SqlCredential = New-Object System.Management.Automation.PsCredential $SqlAccount, $secSqlPassword
    }
    Return $SqlCredential
}

# ===================================================================================
# Func: GetFarmCredentials
# Desc: Return the credentials for the farm account, prompt the user if need more info
# ===================================================================================
Function GetFarmCredentials ([xml]$xmlInput)
{
    $farmAcct = $xmlInput.Configuration.Farm.Account.Username
    $farmAcctPWD = $xmlInput.Configuration.Farm.Account.Password
    If (!($farmAcct) -or $farmAcct -eq "" -or !($farmAcctPWD) -or $farmAcctPWD -eq "")
    {
        Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan " - Prompting for Farm Account:"
        $script:farmCredential = $host.ui.PromptForCredential("Farm Setup", "Enter Farm Account Credentials:", "$farmAcct", "NetBiosUserName")
    }
    Else
    {
        $secPassword = ConvertTo-SecureString "$farmAcctPWD" -AsPlainText -Force
        $script:farmCredential = New-Object System.Management.Automation.PsCredential $farmAcct, $secPassword
    }
    Return $farmCredential
}
#endregion

#region Get Farm Passphrase
Function GetFarmPassphrase ([xml]$xmlInput)
{
    $farmPassphrase = $xmlInput.Configuration.Farm.Passphrase
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        $farmPassphrase = Read-Host -Prompt " - Please enter the farm passphrase now" -AsSecureString
        If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
        {
            Throw " - Farm passphrase is required!"
        }
    }
    Return $farmPassphrase
}
#endregion

#region Get Secure Farm Passphrase
# ===================================================================================
# Func: GetSecureFarmPassphrase
# Desc: Return the Farm Phrase as a secure string
# ===================================================================================
Function GetSecureFarmPassphrase ([xml]$xmlInput)
{
    If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
    {
        $farmPassphrase = GetFarmPassPhrase $xmlInput
    }
    If ($farmPassPhrase.GetType().Name -ne "SecureString")
    {
        $secPhrase = ConvertTo-SecureString $farmPassphrase -AsPlainText -Force
    }
    Else
    {
        $secPhrase = $farmPassphrase
    }
    Return $secPhrase
}
#endregion

#region Update Service Process Identity

# ====================================================================================
# Func: UpdateProcessIdentity
# Desc: Updates the account a specified service runs under to the general app pool account
# ====================================================================================
Function UpdateProcessIdentity ($serviceToUpdate)
{
    $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
    # Managed Account
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    if ($null -eq $managedAccountGen)
    {
        Throw " - Managed Account $($spservice.username) not found"
    }
    if ($serviceToUpdate.Service)
    {
        $serviceToUpdate = $serviceToUpdate.Service
    }
    if ($serviceToUpdate.ProcessIdentity.Username -ne $managedAccountGen.UserName)
    {
        Write-Host -ForegroundColor White " - Updating $($serviceToUpdate.TypeName) to run as $($managedAccountGen.UserName)..." -NoNewline
        # Set the Process Identity to our general App Pool Account; otherwise it's set by default to the Farm Account and gives warnings in the Health Analyzer
        $serviceToUpdate.ProcessIdentity.CurrentIdentityType = "SpecificUser"
        $serviceToUpdate.ProcessIdentity.ManagedAccount = $managedAccountGen
        $serviceToUpdate.ProcessIdentity.Update()
        $serviceToUpdate.ProcessIdentity.Deploy()
        Write-Host -ForegroundColor Green "Done."
    }
    else
    {
        Write-Host -ForegroundColor White " - $($serviceToUpdate.TypeName) is already configured to run as $($managedAccountGen.UserName)."
    }
}
#endregion

#region Create or Join Farm
# ===================================================================================
# Func: CreateOrJoinFarm
# Desc: Check if the farm is created
# ===================================================================================
Function CreateOrJoinFarm ([xml]$xmlInput, [System.Security.SecureString]$secPhrase, [System.Management.Automation.PsCredential]$farmCredential)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $dbPrefix = Get-DBPrefix $xmlInput
    $configDB = $dbPrefix + $xmlInput.Configuration.Farm.Database.ConfigDB

    # Look for an existing farm and join the farm if not already joined, or create a new farm
    Try
    {
        Write-Host -ForegroundColor White " - Checking farm membership for $env:COMPUTERNAME in `"$configDB`"..." -NoNewline
        $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB} -ErrorAction SilentlyContinue
        Write-Host "."
    }
    Catch
    {
        Write-Host "Not joined yet."
    }
    If ($null -eq $spFarm)
    {
        $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
        $centralAdminContentDB = $dbPrefix + $xmlInput.Configuration.Farm.CentralAdmin.Database
        # If the SharePoint version is newer than 2010, set the new -SkipRegisterAsDistributedCacheHost parameter when creating/joining the farm if we aren't requesting it for the current server
        if (($spVer -ge 15) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.DistributedCache -eq $true))
        {
            $distCacheSwitch = @{SkipRegisterAsDistributedCacheHost = $true}
            Write-Host -ForegroundColor White " - This server ($env:COMPUTERNAME) has been requested to be excluded from the Distributed Cache cluster."
        }
        else
        {
            $distCacheSwitch = @{}
        }
        if ($spVer -ge 16)
        {
            if (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Custom)) {$serverRole = "Custom"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEnd)) {$serverRole = "WebFrontEnd"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Search)) {$serverRole = "Search"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Application)) {$serverRole = "Application"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.DistributedCache)) {$serverRole = "DistributedCache"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServerFarm)) {$serverRole = "SingleServerFarm"}
            elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServer)) {$serverRole = "SingleServerFarm"}
            # Only process this stuff if we are running SP2016 with Feature Pack 1
            if (CheckForSP2016FeaturePack1 -xmlInput $xmlInput)
            {
                if (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.ApplicationWithSearch))
                {
                    $serverRole = "ApplicationWithSearch"
                }
                elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEndWithDistributedCache))
                {
                    $serverRole = "WebFrontEndWithDistributedCache"
                }
            }
            if ($serverRole) # If the role has been specified, let's apply it
            {
                $serverRoleSwitch = @{LocalServerRole = $serverRole}
                $serverRoleOptionalSwitch = @{}
                Write-Host -ForegroundColor Green " - This server ($env:COMPUTERNAME) has been requested to have the `"$serverRole`" LocalServerRole."
            }
            else # Otherwise we'll just go with Custom/SpecialLoad
            {
                $serverRoleSwitch = @{}
                $serverRoleOptionalSwitch = @{ServerRoleOptional = $true}
                Write-Host -ForegroundColor Green " - ServerRole was not specified (or an invalid role was given); assuming `"Custom`"."
            }
        }
        else
        {
            $serverRoleSwitch = @{}
            $serverRoleOptionalSwitch = @{}
        }
        # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
        $usingSQLAuthenticationForFarm = $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true"
        if ($usingSQLAuthenticationForFarm)
        {
            Write-Host -ForegroundColor White " - Creating SQL credential object..."
            $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
            $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
        }
        else # Otherwise assume Windows integrated and no database credentials provided
        {
            $databaseCredentialsParameter = @{}
        }

        Write-Host -ForegroundColor White " - Attempting to join farm on `"$configDB`"..."
        Connect-SPConfigurationDatabase -DatabaseName "$configDB" -Passphrase $secPhrase -DatabaseServer "$dbServer" @distCacheSwitch @serverRoleSwitch @databaseCredentialsParameter -ErrorAction SilentlyContinue
        If (-not $?)
        {
            Write-Host -ForegroundColor White " - No existing farm found.`n - Creating config database `"$configDB`"..."
            # Waiting a few seconds seems to help with the Connect-SPConfigurationDatabase barging in on the New-SPConfigurationDatabase command; not sure why...
            Start-Sleep 5
            New-SPConfigurationDatabase -DatabaseName "$configDB" -DatabaseServer "$dbServer" -AdministrationContentDatabaseName "$centralAdminContentDB" -Passphrase $secPhrase -FarmCredentials $farmCredential @distCacheSwitch @serverRoleSwitch @serverRoleOptionalSwitch @databaseCredentialsParameter
            If (-not $?)
            {
                Throw " - Error creating new farm configuration database"
            }
            Else
            {
                $farmMessage = " - Done creating configuration database for farm."
            }
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
#endregion

#region PSConfig
Function Invoke-PSConfig ($spVer)
{

    $PSConfig = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\BIN\psconfig.exe"
    Start-Process -FilePath $PSConfig -ArgumentList "-cmd upgrade -inplace b2b -force -cmd applicationcontent -install -cmd installfeatures -cmd secureresources" -NoNewWindow -Wait
}
Function Confirm-PSConfig
{
    $PSConfigLogLocation = $((Get-SPDiagnosticConfig).LogLocation) -replace "%CommonProgramFiles%", "$env:CommonProgramFiles"
    $PSConfigLog = Get-ChildItem -Path $PSConfigLogLocation | Where-Object {$_.Name -like "PSCDiagnostics*"} | Sort-Object -Descending -Property "LastWriteTime" | Select-Object -First 1
    If ($null -eq $PSConfigLog)
    {
        Throw " - Could not find PSConfig log file!"
    }
    Else
    {
        # Get error(s) from log
        $PSConfigLastError = $PSConfigLog | Select-String -SimpleMatch -CaseSensitive -Pattern "ERR" | Select-Object -Last 1
        return $PSConfigLastError
    }
}
#endregion

#region Configure Farm
# ===================================================================================
# Func: CreateCentralAdmin
# Desc: Setup Central Admin Web Site, Check the topology of an existing farm, and configure the farm as required.
# ===================================================================================
Function CreateCentralAdmin ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    # Get all Central Admin service instances in the farm
    $centralAdminServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPWebServiceInstance" -and $_.Name -eq "WSS_Administration"}
    # Get those Central Admin services that are Online
    $centralAdminServicesOnline = $centralAdminServices | Where-Object {$_.Status -eq "Online"}
    # Get the local Central Admin service
    $localCentralAdminService = $centralAdminServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
    If ((ShouldIProvision $xmlInput.Configuration.Farm.CentralAdmin -eq $true) -and ($localCentralAdminService.Status -ne "Online"))
    {
        Try
        {
            # Check if there is already a Central Admin provisioned in the farm; if not, create one
            If (!(Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication}) -or $centralAdminServicesOnline.Count -lt 1)
            {
                # Create Central Admin for farm
                Write-Host -ForegroundColor White " - Creating Central Admin site..."
                $centralAdminPort = $xmlInput.Configuration.Farm.CentralAdmin.Port
                if (($spVer -ge 16) -and ($xmlInput.Configuration.Farm.CentralAdmin.UseSSL -eq $true)) # Use updated cmdlet switch for SP2016 for SSL in Central Admin
                {
                    $centralAdminSSLSwitch = @{SecureSocketsLayer = $true}
                }
                else
                {
                    $centralAdminSSLSwitch = @{}
                }
                New-SPCentralAdministration -Port $centralAdminPort -WindowsAuthProvider "NTLM" @centralAdminSSLSwitch
                If (-not $?)
                {
                    Throw " - Error creating central administration application"
                }
                Write-Host -ForegroundColor Cyan " - Waiting for Central Admin site..." -NoNewline
                While ($localCentralAdminService.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $centralAdminServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPWebServiceInstance" -and $_.Name -eq "WSS_Administration"}
                    $localCentralAdminService = $centralAdminServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black $($localCentralAdminService.Status)
                If ($xmlInput.Configuration.Farm.CentralAdmin.UseSSL -eq $true)
                {
                    Write-Host -ForegroundColor White " - Enabling SSL for Central Admin..."
                    $centralAdmin = Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication}
                    $SSLHostHeader = $env:COMPUTERNAME
                    $SSLPort = $centralAdminPort
                    $SSLSiteName = $centralAdmin.DisplayName
                    if ($spYear -le 2013) # Use the old pre-2016 way to enable SSL for Central Admin
                    {
                        New-SPAlternateURL -Url "https://$($env:COMPUTERNAME):$centralAdminPort" -Zone Default -WebApplication $centralAdmin | Out-Null
                    }
                    if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
                    {
                        Write-Host -ForegroundColor White " - Assigning certificate(s) in a separate PowerShell window..."
                        Start-Process -FilePath "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "-Command `"Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; AssignCert $SSLHostHeader $SSLPort $SSLSiteName; Start-Sleep 10`"" -Wait
                    }
                    else
                    {
                        AssignCert $SSLHostHeader $SSLPort $SSLSiteName
                    }
                }
            }
            # Otherwise create a Central Admin site locally, with an AAM to the existing Central Admin
            Else
            {
                Write-Host -ForegroundColor White " - Creating local Central Admin site..."
                New-SPCentralAdministration
            }
        }
        Catch
        {
            If ($err -like "*update conflict*")
            {
                Write-Warning "A concurrency error occured, trying again."
                CreateCentralAdmin $xmlInput
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
Function CheckFarmTopology ([xml]$xmlInput)
{
    $dbPrefix = Get-DBPrefix $xmlInput
    $configDB = $dbPrefix + $xmlInput.Configuration.Farm.Database.ConfigDB
    $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
    $spFarm = Get-SPFarm | Where-Object {$_.Name -eq $configDB}
    ForEach ($srv in $spFarm.Servers)
    {
        If (($srv -like "*$dbServer*") -and ($dbServer -ne $env:COMPUTERNAME))
        {
            [bool]$dbLocal = $false
        }
    }
    If (($($spFarm.Servers.Count) -gt 1) -and ($dbLocal -eq $false))
    {
        [bool]$script:FirstServer = $false
    }
    Else
    {
        [bool]$script:FirstServer = $true
    }
}

# ===================================================================================
# Func: WaitForHelpInstallToFinish
# Desc: Waits for the Help Collection timer job to complete before proceeding, in order to avoid concurrency errors
# From: Adapted from a function submitted by CodePlex user jwthompson98
# ===================================================================================
Function WaitForHelpInstallToFinish
{
    Write-Host -ForegroundColor Cyan "  - Waiting for Help Collection Installation timer job..." -NoNewline
    # Wait for the timer job to start
    Do
    {
        Write-Host -ForegroundColor Cyan "." -NoNewline
        Start-Sleep -Seconds 1
    }
    Until
    (
        (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"}
    )
    Write-Host -ForegroundColor Green "Started."
    Write-Host -ForegroundColor Cyan "  - Waiting for Help Collection Installation timer job to complete: " -NoNewline
    # Monitor the timer job and display progress
    $helpJob = (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"} | Sort-Object StartTime | Select-Object -Last 1
    While ($null -ne $helpJob)
    {
        Write-Host -ForegroundColor White "$($helpJob.PercentageDone)%" -NoNewline
        Start-Sleep -Milliseconds 250
        for ($i = 0; $i -lt 3; $i++)
        {
            Write-Host -ForegroundColor Cyan "." -NoNewline
            Start-Sleep -Milliseconds 250
        }
        $backspaceCount = (($helpJob.PercentageDone).ToString()).Length + 3
        for ($count = 0; $count -le $backspaceCount; $count++)
        {
            Write-Host "`b `b" -NoNewline
        }
        $helpJob = (Get-SPFarm).TimerService.RunningJobs | Where-Object {$_.JobDefinition.TypeName -eq "Microsoft.SharePoint.Help.HelpCollectionInstallerJob"} | Sort-Object StartTime | Select-Object -Last 1
    }
    Write-Host -ForegroundColor White "OK."
}

# ===================================================================================
# Func: ConfigureFarm
# Desc: Setup Central Admin Web Site, Check the topology of an existing farm, and configure the farm as required.
# ===================================================================================
Function ConfigureFarm ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    Write-Host -ForegroundColor White " - Configuring the SharePoint farm/server..."
    # Force a full configuration if this is the first web/app server in the farm
    If ((!($farmExists)) -or ($firstServer -eq $true) -or ((CheckIfUpgradeNeeded -xmlInput $xmlInput) -eq $true))
    {
        [bool]$doFullConfig = $true
    }
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
            Install-SPFeature -AllExistingFeatures | Out-Null
        }
        CreateCentralAdmin $xmlInput
        # Update Central Admin branding text for SharePoint 2013 based on the XML input Environment attribute
        if ($spVer -ge 15 -and !([string]::IsNullOrEmpty($xmlInput.Configuration.Environment)))
        {
            # From http://www.wictorwilen.se/sharepoint-2013-central-administration-productivity-tip
            Write-Host -ForegroundColor White " - Updating Central Admin branding text to `"$($xmlInput.Configuration.Environment)`"..."
            $suiteBarBrandingText = "SharePoint - " + $xmlInput.Configuration.Environment
            $ca = Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication}
            if ($spVer -ge 16) # Updated for SharePoint 2016 - thanks Mark Kordelski (@delsk) for the tip!
            {
                $ca.SuiteNavBrandingText = $suiteBarBrandingText
            }
            else # Assume SharePoint 2013 method
            {
                $ca.SuiteBarBrandingElementHtml = "<div class='ms-core-brandingText'>$suiteBarBrandingText</div>"
            }
            $ca.Update()
        }
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
            Write-Warning "A concurrency error occured, trying again."
            CreateCentralAdmin $xmlInput
        }
        Else
        {
            Throw $_
        }
    }
    # Check again if we need to run PSConfig, in case a CU was installed on a subsequent pass of AutoSPInstaller
    if ((CheckIfUpgradeNeeded -xmlInput $xmlInput) -eq $true)
    {
        $retryNum = 1
        Invoke-PSConfig -spVer $spVer
        $PSConfigLastError = Confirm-PSConfig
        while (!([string]::IsNullOrEmpty($PSConfigLastError)) -and $retryNum -le 4)
        {
            Write-Warning $PSConfigLastError.Line
            Write-Host -ForegroundColor White " - An error occurred running PSConfig, trying again ($retryNum)..."
            Start-Sleep -Seconds 5
            $retryNum += 1
            Invoke-PSConfig -spVer $spVer
            $PSConfigLastError = Confirm-PSConfig
        }
        If ($retryNum -ge 5)
        {
            Write-Host -ForegroundColor White " - After $retryNum retries to run PSConfig, trying GUI-based..."
            Start-Process -FilePath $PSConfigUI -NoNewWindow -Wait
        }
        Clear-Variable -Name PSConfigLastError -ErrorAction SilentlyContinue
        Clear-Variable -Name PSConfigLog -ErrorAction SilentlyContinue
        Clear-Variable -Name retryNum -ErrorAction SilentlyContinue
    }
    $spRegVersion = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\").GetValue("Version")
    If (!($spRegVersion))
    {
        Write-Host -ForegroundColor White " - Creating Version registry value (workaround for bug in PS-based install)"
        Write-Host -ForegroundColor White -NoNewline " - Getting version number... "
        $spBuild = "$($(Get-SPFarm).BuildVersion.Major).0.0.$($(Get-SPFarm).BuildVersion.Build)"
        Write-Host -ForegroundColor White "$spBuild"
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\" -Name Version -Value $spBuild -ErrorAction SilentlyContinue | Out-Null
    }
    # Set an environment variable for the 14/15 hive (SharePoint root)
    [Environment]::SetEnvironmentVariable($spVer, "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer", "Machine")

    # Let's make sure the SharePoint Timer Service (SPTimerV4) is running
    # Per workaround in http://www.paulgrimley.com/2010/11/side-effects-of-attaching-additional.html
    If ((Get-Service SPTimerV4).Status -eq "Stopped")
    {
        Write-Host -ForegroundColor White " - Starting $((Get-Service SPTimerV4).DisplayName) Service..."
        Start-Service SPTimerV4
        If (!$?)
        {
            Throw " - Could not start Timer service!"
        }
    }
    if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
    {
        Write-Host -ForegroundColor White " - Stopping Default Web Site in a separate PowerShell window..."
        Start-Process -FilePath "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "-Command `"Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; Stop-DefaultWebsite; Start-Sleep 10`"" -Wait
    }
    else
    {
        Stop-DefaultWebsite
    }
    Write-Host -ForegroundColor White " - Done initial farm/server config."
    WriteLine
}

#endregion

#region Configure Language Packs
Function ConfigureLanguagePacks ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
    $languagePackInstalled = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS\").GetValue("LanguagePackInstalled")
    # If there were language packs installed we need to run psconfig to configure them
    If (($languagePackInstalled -eq "1") -and ($installedOfficeServerLanguages.Count -gt 1))
    {
        WriteLine
        Write-Host -ForegroundColor White " - Configuring language packs..."
        # Let's sleep for a while to let the farm config catch up...
        Start-Sleep 20
        $retryNum += 1
        # Run PSConfig.exe per http://sharepoint.stackexchange.com/questions/9927/sp2010-psconfig-fails-trying-to-configure-farm-after-installing-language-packs
        # Note this was changed from v2v to b2b as suggested by CodePlex user jwthompson98
        Invoke-PSConfig -spVer $spVer
        $PSConfigLastError = Confirm-PSConfig
        while (!([string]::IsNullOrEmpty($PSConfigLastError)) -and $retryNum -le 4)
        {
            Write-Warning $PSConfigLastError.Line
            Write-Host -ForegroundColor White " - An error occurred running PSConfig, trying again ($retryNum)..."
            Start-Sleep -Seconds 5
            $retryNum += 1
            Invoke-PSConfig -spVer $spVer
            $PSConfigLastError = Confirm-PSConfig
        }
        If ($retryNum -ge 5)
        {
            Write-Host -ForegroundColor White " - After $retryNum retries to run PSConfig, trying GUI-based..."
            Start-Process -FilePath $PSConfigUI -NoNewWindow -Wait
        }
        Clear-Variable -Name PSConfigLastError -ErrorAction SilentlyContinue
        Clear-Variable -Name PSConfigLog -ErrorAction SilentlyContinue
        Clear-Variable -Name retryNum -ErrorAction SilentlyContinue
        WriteLine
    }
}
#endregion

#region Add Managed Accounts
# ===================================================================================
# FUNC: AddManagedAccounts
# DESC: Adds existing accounts to SharePoint managed accounts and creates local profiles for each
# TODO: Make this more robust, prompt for blank values etc.
# ===================================================================================
Function AddManagedAccounts ([xml]$xmlInput)
{
    WriteLine
    Write-Host -ForegroundColor White " - Adding Managed Accounts..."
    If ($xmlInput.Configuration.Farm.ManagedAccounts)
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

        ForEach ($account in $xmlInput.Configuration.Farm.ManagedAccounts.ManagedAccount)
        {
            $username = $account.username

            if([string]::IsNullOrEmpty($account.Password)) {
                $password = (Get-Credential -Message "Enter Password for Managed Account" -UserName $account.username).Password
            }
            else {
                $password = $account.Password
                $password = ConvertTo-SecureString "$password" -AsPlaintext -Force
            }
            $alreadyAdmin = $false
            # The following was suggested by Matthias Einig (http://www.codeplex.com/site/users/view/matein78)
            # And inspired by http://toddcarter.net/post/2010/05/03/give-your-application-pool-accounts-a-profile/ & http://blog.brainlitter.com/archive/2010/06/08/how-to-revolve-event-id-1511-windows-cannot-find-the-local-profile-on-windows-server-2008.aspx
            Try
            {
                $credAccount = New-Object System.Management.Automation.PsCredential $username,$password
                $managedAccountDomain,$managedAccountUser = $username -Split "\\"
                Write-Host -ForegroundColor White "  - Account `"$managedAccountDomain\$managedAccountUser`:"
                Write-Host -ForegroundColor White "   - Creating local profile for $username..."
                # Add managed account to local admins (very) temporarily so it can log in and create its profile
                If (!($localAdmins -contains $managedAccountUser))
                {
                    $builtinAdminGroup = Get-AdministratorsGroup
                    Write-Host -ForegroundColor White "   - Adding to local Admins (*temporarily*)..." -NoNewline
                    ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$managedAccountDomain/$managedAccountUser")
                    Write-Host -ForegroundColor White "OK."
                }
                Else
                {
                    $alreadyAdmin = $true
                }
                # Spawn a command window using the managed account's credentials, create the profile, and exit immediately
                Start-Process -WorkingDirectory "$env:SYSTEMROOT\System32\" -FilePath "cmd.exe" -ArgumentList "/C" -LoadUserProfile -NoNewWindow -Credential $credAccount
                # Remove managed account from local admins unless it was already there
                $builtinAdminGroup = Get-AdministratorsGroup
                If (-not $alreadyAdmin)
                {
                    Write-Host -ForegroundColor White "   - Removing from local Admins..." -NoNewline
                    ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Remove("WinNT://$managedAccountDomain/$managedAccountUser")
                    if (!$?)
                    {
                        Write-Host -ForegroundColor White "."
                        Write-Host -ForegroundColor Yellow "   - Could not remove `"$managedAccountDomain\$managedAccountUser`" from local Admins."
                        Write-Host -ForegroundColor Yellow "   - Please remove it manually."
                    }
                    else
                    {
                        Write-Host -ForegroundColor White "OK."
                    }
                }
                Write-Host -ForegroundColor Green "  - Done."
            }
            Catch
            {
                $_
                Write-Host -ForegroundColor White "."
                Write-Warning "Could not create local user profile for $username"
                break
            }
            $managedAccount = Get-SPManagedAccount | Where-Object {$_.UserName -eq $username}
            If ($null -eq $managedAccount)
            {
                Write-Host -ForegroundColor White "   - Registering managed account $username..."
                If ($null -eq $username -or $null -eq $password)
                {
                    Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan "   - Prompting for Account: "
                    $credAccount = $host.ui.PromptForCredential("Managed Account", "Enter Account Credentials:", "", "NetBiosUserName" )
                }
                Else
                {
                    $credAccount = New-Object System.Management.Automation.PsCredential $username, $password
                }
                New-SPManagedAccount -Credential $credAccount | Out-Null
                If (-not $?)
                {
                    Throw "   - Failed to create managed account"
                }
            }
            Else
            {
                Write-Host -ForegroundColor White "   - Managed account $username already exists."
            }
        }
    }
    Write-Host -ForegroundColor White " - Done Adding Managed Accounts."
    WriteLine
}
#endregion

#region Return SP Managed Account
Function Get-SPManagedAccountXML ([xml]$xmlInput, $commonName)
{
    $managedAccountXML = $xmlInput.Configuration.Farm.ManagedAccounts.ManagedAccount | Where-Object { $_.CommonName -eq $commonName }
    Return $managedAccountXML
}
#endregion

#region Get or Create Hosted Services Application Pool
# ====================================================================================
# Func: Get-HostedServicesAppPool
# Desc: Creates and/or returns the Hosted Services Application Pool
# ====================================================================================
Function Get-HostedServicesAppPool ([xml]$xmlInput)
{
    $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
    # Managed Account
    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
    If ($null -eq $managedAccountGen)
    {
        Throw " - Managed Account $($spservice.username) not found"
    }
    # App Pool
    $applicationPool = Get-SPServiceApplicationPool "SharePoint Hosted Services" -ea SilentlyContinue
    If ($null -eq $applicationPool)
    {
        Write-Host -ForegroundColor White " - Creating SharePoint Hosted Services Application Pool..."
        $applicationPool = New-SPServiceApplicationPool -Name "SharePoint Hosted Services" -account $managedAccountGen
        If (-not $?)
        {
            Throw "Failed to create the application pool"
        }
    }
    Return $applicationPool
}
#endregion

#region Create Generic Service Application
# ===================================================================================
# Func: CreateGenericServiceApplication
# Desc: General function that creates a broad range of service applications
# ===================================================================================
Function CreateGenericServiceApplication()
{
    param
    (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [String]$serviceConfig,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [String]$serviceInstanceType,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [String]$serviceName,
        [Parameter(Mandatory = $false)]
        [String]$serviceProxyName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [String]$serviceGetCmdlet,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyGetCmdlet,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [String]$serviceNewCmdlet,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewCmdlet,
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()]
        [String]$serviceProxyNewParams
    )

    Try
    {
        $applicationPool = Get-HostedServicesAppPool $xmlInput
        Write-Host -ForegroundColor White " - Provisioning $serviceName..."
        # get the service instance
        $serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $serviceInstanceType}
        $serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
        If (!$serviceInstance)
        {
            Throw " - Failed to get service instance - check product version (Standard vs. Enterprise)"
        }
        # Start Service instance
        Write-Host -ForegroundColor White " - Checking $($serviceInstance.TypeName) instance..."
        If (($serviceInstance.Status -eq "Disabled") -or ($serviceInstance.Status -ne "Online"))
        {
            Write-Host -ForegroundColor White " - Starting $($serviceInstance.TypeName) instance..."
            $serviceInstance.Provision()
            If (-not $?)
            {
                Throw " - Failed to start $($serviceInstance.TypeName) instance"
            }
            # Wait
            Write-Host -ForegroundColor Cyan " - Waiting for $($serviceInstance.TypeName) instance..." -NoNewline
            While ($serviceInstance.Status -ne "Online")
            {
                Write-Host -ForegroundColor Cyan "." -NoNewline
                Start-Sleep 1
                $serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $serviceInstanceType}
                $serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Green -ForegroundColor Black $($serviceInstance.Status)
        }
        Else
        {
            Write-Host -ForegroundColor White " - $($serviceInstance.TypeName) instance already started."
        }
        # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin in versions 2019 and older
        If (!(Get-Command $serviceGetCmdlet -ErrorAction SilentlyContinue) -and $spyear -le 2019)
        {
            Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
            Remove-PSSnapin Microsoft.SharePoint.PowerShell
            Add-SharePointPSSnapin
        }
        $getServiceApplication = Invoke-Expression "$serviceGetCmdlet | Where-Object {`$_.Name -eq `"$serviceName`"}"
        If ($null -eq $getServiceApplication)
        {
            Write-Host -ForegroundColor White " - Creating $serviceName..."
            # A bit kludgey to accomodate the new PerformancePoint cmdlet in Service Pack 1, and some new SP2010 service apps (and still be able to use the CreateGenericServiceApplication function)
            If ((CheckFor2010SP1 -xmlinput $xmlInput) -and ($serviceInstanceType -eq "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"))
            {
                $newServiceApplication = Invoke-Expression "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool -DatabaseServer `$dbServer -DatabaseName `$serviceDB @databaseCredentialsParameter"
            }
            Else # Just do the regular non-database-bound service app creation
            {
                $newServiceApplication = Invoke-Expression "$serviceNewCmdlet -Name `"$serviceName`" -ApplicationPool `$applicationPool"
            }
            $getServiceApplication = Invoke-Expression "$serviceGetCmdlet | Where-Object {`$_.Name -eq `"$serviceName`"}"
            if ($getServiceApplication)
            {
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
                    "Microsoft.Office.Server.WorkManagement.WorkManagementServiceInstance" {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -DefaultProxyGroup | Out-Null}
                    "Microsoft.Office.TranslationServices.TranslationServiceInstance" {} # Do nothing because the service app cmdlet automatically creates a proxy with the default name
                    "Microsoft.Office.Access.Services.MossHost.AccessServicesWebServiceInstance" {& $serviceProxyNewCmdlet -application $newServiceApplication | Out-Null}
                    "Microsoft.Office.Server.PowerPoint.Administration.PowerPointConversionServiceInstance" {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication -AddToDefaultGroup | Out-Null}
                    "Microsoft.Office.Project.Server.Administration.PsiServiceInstance" {} # Do nothing because the service app cmdlet automatically creates a proxy with the default name
                    Default {& $serviceProxyNewCmdlet -Name "$serviceProxyName" -ServiceApplication $newServiceApplication | Out-Null}
                }
                Write-Host -ForegroundColor White " - Done provisioning $serviceName. "
            }
            else
            {
                Write-Warning "An error occurred provisioning $serviceName! Check the log for any details, then try again."
            }
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
#endregion

#region Sandboxed Code Service
# ===================================================================================
# Func: ConfigureSandboxedCodeService
# Desc: Configures the SharePoint Foundation Sandboxed (User) Code Service
# ===================================================================================
Function ConfigureSandboxedCodeService ([xml]$xmlInput)
{
    If (ShouldIProvision $xmlInput.Configuration.Farm.Services.SandboxedCodeService -eq $true)
    {
        WriteLine
        Write-Host -ForegroundColor White " - Starting Sandboxed Code Service"
        $sandboxedCodeServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
        $sandboxedCodeService = $sandboxedCodeServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
        If ($sandboxedCodeService.Status -ne "Online")
        {
            Try
            {
                Write-Host -ForegroundColor White " - Starting Microsoft SharePoint Foundation Sandboxed Code Service..."
                UpdateProcessIdentity $sandboxedCodeService
                $sandboxedCodeService.Update()
                $sandboxedCodeService.Provision()
                If (-not $?)
                {
                    Throw " - Failed to start Sandboxed Code Service"
                }
            }
            Catch
            {
                Throw " - An error occurred starting the Microsoft SharePoint Foundation Sandboxed Code Service"
            }
            #Wait
            Write-Host -ForegroundColor Cyan " - Waiting for Sandboxed Code service..." -NoNewline
            While ($sandboxedCodeService.Status -ne "Online")
            {
                Write-Host -ForegroundColor Cyan "." -NoNewline
                Start-Sleep 1
                $sandboxedCodeServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.SPUserCodeServiceInstance"}
                $sandboxedCodeService = $sandboxedCodeServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Green -ForegroundColor Black $($sandboxedCodeService.Status)
        }
        Else
        {
            Write-Host -ForegroundColor White " - Sandboxed Code Service already started."
        }
        WriteLine
    }
}
#endregion

#region Create Metadata Service Application
# ===================================================================================
# Func: CreateMetadataServiceApp
# Desc: Managed Metadata Service Application
# ===================================================================================
Function CreateMetadataServiceApp ([xml]$xmlInput)
{
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.ManagedMetadataServiceApp -eq $true) -and (Get-Command -Name New-SPMetadataServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        Try
        {
            $spYear = $xmlInput.Configuration.Install.SPVersion
            $serviceConfig = $xmlInput.Configuration.ServiceApps.ManagedMetadataServiceApp
            $dbPrefix = Get-DBPrefix $xmlInput
            $metaDataDB = $dbPrefix + $serviceConfig.Database.Name
            $dbServer = $serviceConfig.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
            if ($usingSQLAuthentication)
            {
                Write-Host -ForegroundColor White " - Creating SQL credential object..."
                $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseCredentialsParameter = @{}
            }
            $metadataServiceName = $serviceConfig.Name
            $metadataServiceProxyName = $serviceConfig.ProxyName
            If ($null -eq $metadataServiceName)
            {
                $metadataServiceName = "Metadata Service Application"
            }
            If ($null -eq $metadataServiceProxyName)
            {
                $metadataServiceProxyName = $metadataServiceName
            }
            Write-Host -ForegroundColor White " - Provisioning Managed Metadata Service Application"
            $applicationPool = Get-HostedServicesAppPool $xmlInput
            Write-Host -ForegroundColor White " - Starting Managed Metadata Service:"
            # Get the service instance
            $metadataServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
            $metadataServiceInstance = $metadataServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find Metadata service instance"
            }
            # Start Service instances
            If ($metadataServiceInstance.Status -eq "Disabled")
            {
                Write-Host -ForegroundColor White " - Starting Metadata Service Instance..."
                $metadataServiceInstance.Provision()
                If (-not $?)
                {
                    Throw " - Failed to start Metadata service instance"
                }
                # Wait
                Write-Host -ForegroundColor Cyan " - Waiting for Metadata service..." -NoNewline
                While ($metadataServiceInstance.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $metadataServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceInstance"}
                    $metadataServiceInstance = $metadataServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black ($metadataServiceInstance.Status)
            }
            Else
            {
                Write-Host -ForegroundColor White " - Managed Metadata Service already started."
            }

            $metaDataServiceApp = Get-SPServiceApplication | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
            # Create a Metadata Service Application if we don't already have one
            If ($null -eq $metaDataServiceApp)
            {
                # Create Service App
                Write-Host -ForegroundColor White " - Creating Metadata Service Application..."
                $metaDataServiceApp = New-SPMetadataServiceApplication -Name $metadataServiceName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $metaDataDB @databaseCredentialsParameter
                If (-not $?)
                {
                    Throw " - Failed to create Metadata Service Application"
                }
            }
            Else
            {
                Write-Host -ForegroundColor White " - Managed Metadata Service Application already provisioned."
            }
            $metaDataServiceAppProxy = Get-SPServiceApplicationProxy | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplicationProxy"}
            if ($null -eq $metaDataServiceAppProxy)
            {
                # create proxy
                Write-Host -ForegroundColor White " - Creating Metadata Service Application Proxy..."
                $metaDataServiceAppProxy = New-SPMetadataServiceApplicationProxy -Name $metadataServiceProxyName -ServiceApplication $metaDataServiceApp -DefaultProxyGroup -ContentTypePushdownEnabled -DefaultKeywordTaxonomy -DefaultSiteCollectionTaxonomy
                If (-not $?)
                {
                    Throw " - Failed to create Metadata Service Application Proxy"
                }
            }
            else
            {
                Write-Host -ForegroundColor White " - Managed Metadata Service Application Proxy already provisioned."
            }
            if ($metaDataServiceApp -or $metaDataServiceAppProxy)
            {
                # Added to enable Metadata Service Navigation for SP2013, per http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=354
                If ($spYear -eq 2013)
                {
                    If ($metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy -ne $true)
                    {
                        Write-Host -ForegroundColor White " - Configuring Metadata Service Application Proxy..."
                        $metaDataServiceAppProxy.Properties.IsDefaultSiteCollectionTaxonomy = $true
                        $metaDataServiceAppProxy.Update()
                    }
                }
                Write-Host -ForegroundColor White " - Granting rights to Metadata Service Application:"
                # Get ID of "Managed Metadata Service"
                $metadataServiceAppToSecure = Get-SPServiceApplication | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Taxonomy.MetadataWebServiceApplication"}
                $metadataServiceAppIDToSecure = $metadataServiceAppToSecure.Id
                # Create a variable that contains the list of administrators for the service application
                $metadataServiceAppSecurity = Get-SPServiceApplicationSecurity $metadataServiceAppIDToSecure
                ForEach ($account in ($xmlInput.Configuration.Farm.ManagedAccounts.ManagedAccount))
                {
                    # Create a variable that contains the claims principal for the service accounts
                    Write-Host -ForegroundColor White "  - $($account.username)..."
                    $accountPrincipal = New-SPClaimsPrincipal -Identity $account.username -IdentityType WindowsSamAccountName
                    # Give permissions to the claims principal you just created
                    Grant-SPObjectSecurity $metadataServiceAppSecurity -Principal $accountPrincipal -Rights "Full Access to Term Store"
                }
                # Apply the changes to the Metadata Service application
                Set-SPServiceApplicationSecurity $metadataServiceAppIDToSecure -objectSecurity $metadataServiceAppSecurity
                Write-Host -ForegroundColor White " - Done granting rights."
                Write-Host -ForegroundColor White " - Done creating Managed Metadata Service Application."
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
#endregion

#region Assign Certificate
# ===================================================================================
# Func: AssignCert
# Desc: Create and assign SSL Certificate
# ===================================================================================
Function AssignCert ($SSLHostHeader, $SSLPort, $SSLSiteName)
{
    ImportWebAdministration
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    Write-Host -ForegroundColor White " - Assigning certificate to site `"https://$SSLHostHeader`:$SSLPort`""
    # If our SSL host header is a FQDN (contains a dot), look for an existing wildcard cert
    If ($SSLHostHeader -like "*.*")
    {
        # Remove the host portion of the URL and the leading dot
        $splitSSLHostHeader = $SSLHostHeader -split "\."
        $topDomain = $SSLHostHeader.Substring($splitSSLHostHeader[0].Length + 1)
        # Create a new wildcard cert so we can potentially use it on other sites too
        if ($SSLHostHeader -like "*.$env:USERDNSDOMAIN")
        {
            $certCommonName = "*.$env:USERDNSDOMAIN"
        }
        elseif ($SSLHostHeader -like "*.$topDomain")
        {
            $certCommonName = "*.$topDomain"
        }
        Write-Host -ForegroundColor White " - Looking for existing `"$certCommonName`" wildcard certificate..."
    }
    Else
    {
        # Just create a cert that matches the SSL host header
        $certCommonName = $SSLHostHeader
        Write-Host -ForegroundColor White " - Looking for existing `"$certCommonName`" certificate..."
    }
    $cert = Get-ChildItem cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$certCommonName"}
    If (!$cert)
    {
        Write-Host -ForegroundColor White " - None found."
        if (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue) # SP2016 no longer seems to ship with makecert.exe, but we should be able to use PowerShell native commands instead in Windows 2012 R2 / PowerShell 4.0 and higher
        {
            # New PowerShelly way to create self-signed certs, so we don't need makecert.exe
            # From http://windowsitpro.com/blog/creating-self-signed-certificates-powershell
            Write-Host -ForegroundColor White " - Creating new self-signed certificate $certCommonName..."
            $cert = New-SelfSignedCertificate -CertStoreLocation cert:\localmachine\my -DnsName $certCommonName
            ##$cert = Get-ChildItem cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=``*$certCommonName"}
        }
        else # Try to create the cert using makecert.exe instead
        {
            # Get the actual location of makecert.exe in case we installed SharePoint in the non-default location
            $spInstallPath = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Office Server\$spVer.0").GetValue("InstallPath")
            $makeCert = "$spInstallPath\Tools\makecert.exe"
            If (Test-Path "$makeCert")
            {
                Write-Host -ForegroundColor White " - Creating new self-signed certificate $certCommonName..."
                Start-Process -NoNewWindow -Wait -FilePath "$makeCert" -ArgumentList "-r -pe -n `"CN=$certCommonName`" -eku 1.3.6.1.5.5.7.3.1 -ss My -sr localMachine -sky exchange -sp `"Microsoft RSA SChannel Cryptographic Provider`" -sy 12"
                $cert = Get-ChildItem cert:\LocalMachine\My | Where-Object {$_.Subject -like "CN=``*$certCommonName"}
                if (!$cert)
                {
                    $cert = Get-ChildItem cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$SSLHostHeader"}
                }
            }
            Else
            {
                Write-Host -ForegroundColor Yellow " - `"$makeCert`" not found."
                Write-Host -ForegroundColor White " - Looking for any machine-named certificates we can use..."
                # Select the first certificate with the most recent valid date
                $cert = Get-ChildItem cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$env:COMPUTERNAME"} | Sort-Object NotBefore -Desc | Select-Object -First 1
                If (!$cert)
                {
                    Write-Host -ForegroundColor Yellow " - None found, skipping certificate creation."
                }
            }
        }
    }
    If ($cert)
    {
        $certSubject = $cert.Subject
        Write-Host -ForegroundColor White " - Certificate `"$certSubject`" found."
        # Fix up the cert subject name to a file-friendly format
        $certSubjectName = $certSubject.Split(",")[0] -replace "CN=","" -replace "\*","wildcard"
        $certsubjectname = $certsubjectname.TrimEnd("/")
        # Export our certificate to a file, then import it to the Trusted Root Certification Authorites store so we don't get nasty browser warnings
        # This will actually only work if the Subject and the host part of the URL are the same
        # Borrowed from https://www.orcsweb.com/blog/james/powershell-ing-on-windows-server-how-to-import-certificates-using-powershell/
        Write-Host -ForegroundColor White " - Exporting `"$certSubject`" to `"$certSubjectName.cer`"..."
        $cert.Export("Cert") | Set-Content -Path "$((Get-Item $env:TEMP).FullName)\$certSubjectName.cer" -Encoding byte
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        Write-Host -ForegroundColor White " - Importing `"$certSubjectName.cer`" to Local Machine\Root..."
        $pfx.Import("$((Get-Item $env:TEMP).FullName)\$certSubjectName.cer")
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
        $store.Open("MaxAllowed")
        $store.Add($pfx)
        $store.Close()
        Write-Host -ForegroundColor White " - Assigning certificate `"$certSubject`" to SSL-enabled site..."
        if ($spYear -eq "SE") # SharePoint Subscription Edition (SPSE) way using native cmdlets
        {
            Write-Host -ForegroundColor White "  - Using SPSE native cmdlets..."
            # First export the cert again to a pfx that SharePoint SE can use
            Write-Host -ForegroundColor White "  - Exporting the cert as a pfx to '$((Get-Item $env:TEMP).FullName)\$certSubjectName.pfx'..."
            Export-PfxCertificate -Cert $cert -FilePath "$((Get-Item $env:TEMP).FullName)\$certSubjectName.pfx" -ProtectTo "$env:USERDOMAIN\$env:USERNAME" -Force | Out-Null
            Write-Host -ForegroundColor White "  - Importing the certificate to SharePoint..."
            Import-SPCertificate -Path "$((Get-Item $env:TEMP).FullName)\$certSubjectName.pfx" -Exportable -Replace | Out-Null
            $seCert = Get-SPCertificate | Where-Object {$_.Subject -eq $certSubject}
            Write-Host -ForegroundColor White "  - Binding certificate to web app '$SSLSiteName'..."
            if ((Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication -eq $true} | Select-Object DisplayName).DisplayName -eq $SSLSiteName)
            {
                # Since this is central admin, use Set-SPCentralAdministration instead
                Set-SPCentralAdministration -Port $SSLPort -SecureSocketsLayer -Certificate $seCert -Confirm:$false
            }
            else # Use method for a regular web app
            {
                Set-SPWebApplication -Identity $SSLSiteName -Zone Default -Port $SSLPort -SecureSocketsLayer -HostHeader $SSLHostHeader -Certificate $seCert
            }
        }
        else # Classic way
        {
            Write-Host -ForegroundColor White "  - Using classic method..."
            if (!(Get-Item IIS:\SslBindings\0.0.0.0!$SSLPort -ErrorAction SilentlyContinue))
            {
                $cert | New-Item IIS:\SslBindings\0.0.0.0!$SSLPort -ErrorAction SilentlyContinue | Out-Null
            }
            # Check if we have specified no host header
            if (!([string]::IsNullOrEmpty($webApp.UseHostHeader)) -and $webApp.UseHostHeader -eq $false)
            {
                Set-ItemProperty IIS:\Sites\$SSLSiteName -Name bindings -Value @{protocol="https";bindingInformation="*:$($SSLPort):"} -ErrorAction SilentlyContinue
            }
            else # Set the binding to the host header
            {
                Set-ItemProperty IIS:\Sites\$SSLSiteName -Name bindings -Value @{protocol="https";bindingInformation="*:$($SSLPort):$($SSLHostHeader)"} -ErrorAction SilentlyContinue
            }
        }
        ## Set-WebBinding -Name $SSLSiteName -BindingInformation ":$($SSLPort):" -PropertyName Port -Value $SSLPort -PropertyName Protocol -Value https
        Write-Host -ForegroundColor White " - Certificate has been assigned to site `"https://$SSLHostHeader`:$SSLPort`""
    }
    else
    {
        Write-Host -ForegroundColor White " - No certificates were found, and none could be created."
    }
    $cert = $null
}
#endregion

#region Create Web Applications
# ===================================================================================
# Func: CreateWebApplications
# Desc: Create and  configure the required web applications
# ===================================================================================
Function CreateWebApplications ([xml]$xmlInput)
{
    WriteLine
    If ($xmlInput.Configuration.WebApplications)
    {
        Write-Host -ForegroundColor White " - Creating web applications..."
        ForEach ($webApp in $xmlInput.Configuration.WebApplications.WebApplication)
        {
            CreateWebApp $webApp
            ConfigureOnlineWebPartCatalog $webApp
            Add-LocalIntranetURL ($webApp.URL).TrimEnd("/")
            WriteLine
        }
        # Updated so that we don't add URLs to the local hosts file of a server that's not been specified to run the Foundation Web Application service, or the Search MinRole
        If ($xmlInput.Configuration.WebApplications.AddURLsToHOSTS -eq $true -and !(ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Search)) -and !(($xmlInput.Configuration.Farm.Services.SelectSingleNode("FoundationWebApplication")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.FoundationWebApplication -eq $true)))
        {
            AddToHOSTS
        }
    }
    WriteLine
}
# ===================================================================================
# Func: CreateWebApp
# Desc: Create the web application
# ===================================================================================
Function CreateWebApp ([System.Xml.XmlElement]$webApp)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    # Look for a managed account that matches the web app type, e.g. "Portal" or "MySiteHost"
    $webAppPoolAccount = Get-SPManagedAccountXML $xmlInput $webApp.Type
    # If no managed account is found matching the web app type, just use the Portal managed account
    if (!$webAppPoolAccount)
    {
        $webAppPoolAccount = Get-SPManagedAccountXML $xmlInput -CommonName "Portal"
        if ([string]::IsNullOrEmpty($webAppPoolAccount.username))
        {
            throw " - `"Portal`" managed account not found! Check your XML."
        }
    }
    $webAppName = $webApp.name
    $appPool = $webApp.applicationPool
    $dbPrefix = Get-DBPrefix $xmlInput
    $database = $dbPrefix + $webApp.Database.Name
    $dbServer = $webApp.Database.DBServer
    # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
    $usingSQLAuthentication = (($webApp.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($webApp.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($webApp.Database.SQLAuthentication.SQLUserName)))
    if ($usingSQLAuthentication)
    {
        Write-Host -ForegroundColor White " - Creating SQL credential object..."
        $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
        $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
    }
    else # Otherwise assume Windows integrated and no database credentials provided
    {
        $databaseCredentialsParameter = @{}
    }

    # Check for an existing App Pool
    $existingWebApp = Get-SPWebApplication | Where-Object { ($_.ApplicationPool).Name -eq $appPool }
    $appPoolExists = ($null -ne $existingWebApp)
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
    }
    $url = ($webApp.url).TrimEnd("/")
    $port = $webApp.port
    $fullUrl = $url + ":" + $port
    $useSSL = $false
    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
    # Strip out any protocol value
    If ($fullUrl -like "https://*")
    {
        $useSSL = $true
    }
    $hostHeader = $url -replace "http://","" -replace "https://",""
    if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
    {
        Write-Host -ForegroundColor White " - Skipping setting the web app directory path name (not currently working on Windows 2012 w/SP2010)..."
        $pathSwitch = @{}
    }
    else
    {
        # Set the directory path for the web app to something a bit more friendly
        ImportWebAdministration
        # Get the default root location for web apps (first from IIS itself, then failing that, from the registry)
        $iisWebDir = (Get-ItemProperty "IIS:\Sites\Default Web Site\" -Name physicalPath -ErrorAction SilentlyContinue) -replace ("%SystemDrive%","$env:SystemDrive")
        if ([string]::IsNullOrEmpty($iisWebDir))
        {
            $iisWebDir = (Get-Item -Path HKLM:\SOFTWARE\Microsoft\InetStp).GetValue("PathWWWRoot") -replace ("%SystemDrive%","$env:SystemDrive")
        }
        if (!([string]::IsNullOrEmpty($iisWebDir)))
        {
            $pathSwitch = @{Path = "$iisWebDir\wss\VirtualDirectories\$webAppName-$port"}
        }
        else
        {
            $pathSwitch = @{}
        }
    }
    # Only set $hostHeaderSwitch to blank if the UseHostHeader value exists has explicitly been set to false
    if (!([string]::IsNullOrEmpty($webApp.UseHostHeader)) -and $webApp.UseHostHeader -eq $false)
    {
        $hostHeaderSwitch = @{}
    }
    else
    {
        $hostHeaderSwitch = @{HostHeader = $hostHeader}
    }
    if (!([string]::IsNullOrEmpty($webApp.useClaims)) -and $webApp.useClaims -eq $false)
    {
        # Create the web app using Classic mode authentication
        $authProviderSwitch = @{}
    }
    else # Configure new web app to use Claims-based authentication
    {
        If ($($webApp.useBasicAuthentication) -eq $true)
        {
            $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication -UseBasicAuthentication
        }
        Else
        {
            $authProvider = New-SPAuthenticationProvider -UseWindowsIntegratedAuthentication
        }
        $authProviderSwitch = @{AuthenticationProvider = $authProvider}
        If ((Get-WmiObject Win32_OperatingSystem).Version -like "6.0*") # If we are running Win2008 (non-R2), we may need the claims hotfix
        {
            [bool]$claimsHotfixRequired = $true
            Write-Host -ForegroundColor Yellow " - Web Applications using Claims authentication require an update"
            Write-Host -ForegroundColor Yellow " - Apply the http://go.microsoft.com/fwlink/?LinkID=184705 update after setup."
        }
    }
    if ($appPoolExists)
    {
        $appPoolAccountSwitch = @{}
    }
    else
    {
        $appPoolAccountSwitch = @{ApplicationPoolAccount = $($webAppPoolAccount.username)}
    }
    $getSPWebApplication = Get-SPWebApplication -Identity $fullUrl -ErrorAction SilentlyContinue
    If ($null -eq $getSPWebApplication)
    {
        Write-Host -ForegroundColor White " - Creating Web App `"$webAppName`""
        New-SPWebApplication -Name $webAppName -ApplicationPool $appPool -DatabaseServer $dbServer -DatabaseName $database -Url $url -Port $port -SecureSocketsLayer:$useSSL @hostHeaderSwitch @appPoolAccountSwitch @authProviderSwitch @pathSwitch @databaseCredentialsParameter | Out-Null
        If (-not $?)
        {
            Throw " - Failed to create web application"
        }
    }
    Else
    {
        Write-Host -ForegroundColor White " - Web app '$fullUrl' already provisioned."
    }
    SetupManagedPaths $webApp
    If ($useSSL)
    {
        $SSLHostHeader = $hostHeader
        $SSLPort = $port
        $SSLSiteName = $webAppName
        if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
        {
            Write-Host -ForegroundColor White " - Assigning certificate(s) in a separate PowerShell window..."
            Start-Process -FilePath "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "-Command `"Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; AssignCert $SSLHostHeader $SSLPort $SSLSiteName; Start-Sleep 10`"" -Wait
        }
        else
        {
            AssignCert $SSLHostHeader $SSLPort $SSLSiteName
        }
    }

    # If we are provisioning any Office Web Apps, Visio, Excel, Access or PerformancePoint services, we need to grant the generic app pool account access to the newly-created content database
    # Per http://technet.microsoft.com/en-us/library/ff829837.aspx and http://autospinstaller.codeplex.com/workitem/16224 (thanks oceanfly!)
    If ((ShouldIProvision $xmlInput.Configuration.OfficeWebApps.ExcelService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.OfficeWebApps.PowerPointService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.OfficeWebApps.WordViewingService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.VisioService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.AccessService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.AccessServices -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService -eq $true))
    {
        $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
        Write-Host -ForegroundColor White " - Granting $($spservice.username) rights to `"$webAppName`"..." -NoNewline
        $wa = Get-SPWebApplication -Identity $fullUrl
        $wa.GrantAccessToProcessIdentity("$($spservice.username)")
        Write-Host -ForegroundColor White "OK."
    }
    if ($webApp.GrantCurrentUserFullControl -eq $true)
    {
        $currentUser = "$env:USERDOMAIN\$env:USERNAME"
        $wa = Get-SPWebApplication -Identity $fullUrl
        if ($wa.UseClaimsAuthentication -eq $true)
        {
            $currentUser = 'i:0#.w|' + $currentUser
        }
        Set-WebAppUserPolicy $wa $currentUser "$env:USERNAME" "Full Control"
    }
    WriteLine
    ConfigureObjectCache $webApp

    if ($webApp.SiteCollections.SelectSingleNode("SiteCollection")) # Only go through these steps if we actually have a site collection to create
    {
        ForEach ($siteCollection in $webApp.SiteCollections.SiteCollection)
        {
            $dbPrefix = Get-DBPrefix $xmlInput
            $getSPSiteCollection = $null
            $siteCollectionName = $siteCollection.Name
            $siteURL = ($siteCollection.siteURL).TrimEnd("/")
            $CompatibilityLevel = $siteCollection.CompatibilityLevel
            if (!([string]::IsNullOrEmpty($CompatibilityLevel))) # Check the Compatibility Level if it's been specified
            {
                $CompatibilityLevelSwitch = @{CompatibilityLevel = $CompatibilityLevel}
            }
            else
            {
                $CompatibilityLevelSwitch = @{}
            }
            if (!([string]::IsNullOrEmpty($($siteCollection.CustomDatabase)))) # Check if we have specified a non-default content database for this site collection
            {
                $siteDatabase = $dbPrefix + $siteCollection.CustomDatabase
            }
            else # Just use the first, default content database for the web application
            {
                $siteDatabase = $database
            }
            # If an OwnerAlias has been specified, make it the primary, and the currently logged-in account the secondary. Otherwise, make the app pool account for the web app the primary owner
            if (!([string]::IsNullOrEmpty($($siteCollection.Owner))))
            {
                $ownerAlias = $siteCollection.Owner
            }
            else
            {
                $ownerAlias = $webAppPoolAccount.username
            }
            $LCID = $siteCollection.LCID
            $siteCollectionLocale = $siteCollection.Locale
            $siteCollectionTime24 = $siteCollection.Time24
            # If a template has been pre-specified, use it when creating the Portal site collection; otherwise, leave it blank so we can select one when the portal first loads
            $template = $siteCollection.template
            If (($null -ne $template) -and ($template -ne ""))
            {
                $templateSwitch = @{Template = $template}
            }
            else
            {
                $templateSwitch = @{}
            }
            if ($siteCollection.HostNamedSiteCollection -eq $true)
            {
                $hostHeaderWebAppSwitch = @{HostHeaderWebApplication = $(($webApp.url).TrimEnd("/")) + ":" + $($webApp.port)}
            }
            else
            {
                $hostHeaderWebAppSwitch = @{}
            }
            Write-Host -ForegroundColor White " - Checking for Site Collection `"$siteURL`"..."
            $getSPSiteCollection = Get-SPSite -Identity $siteURL -ErrorAction SilentlyContinue
            If (($null -eq $getSPSiteCollection) -and ($null -ne $siteURL))
            {
                # Verify that the Language we're trying to create the site in is currently installed on the server
                $culture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($LCID)))
                $cultureDisplayName = $culture.DisplayName
                If (!($installedOfficeServerLanguages | Where-Object {$_ -eq $culture.Name}))
                {
                    Write-Warning "You must install the `"$culture ($cultureDisplayName)`" Language Pack before you can create a site using LCID $LCID"
                }
                Else
                {
                    $siteDatabaseExists = Get-SPContentDatabase -Identity $siteDatabase -ErrorAction SilentlyContinue
                    if (!$siteDatabaseExists)
                    {
                        Write-Host -ForegroundColor White " - Creating/attaching/upgrading content database `"$siteDatabase`"..."
                        New-SPContentDatabase -Name $siteDatabase -WebApplication (Get-SPWebApplication -Identity $fullUrl) @databaseCredentialsParameter | Out-Null
                    }
                    Write-Host -ForegroundColor White " - Creating Site Collection `"$siteURL`"..."
                    $site = New-SPSite -Url $siteURL -OwnerAlias $ownerAlias -SecondaryOwner $env:USERDOMAIN\$env:USERNAME -ContentDatabase $siteDatabase -Description $siteCollectionName -Name $siteCollectionName -Language $LCID @templateSwitch @hostHeaderWebAppSwitch @CompatibilityLevelSwitch -ErrorAction Stop

                    # JDM Not all Web Templates greate the default SharePoint Croups that are made by the UI
                    # JDM These lines will insure that the the approproprate SharePoint Groups, Owners, Members, Visitors are created
                    $primaryUser = $site.RootWeb.EnsureUser($ownerAlias)
                    $secondaryUser = $site.RootWeb.EnsureUser("$env:USERDOMAIN\$env:USERNAME")
                    $title = $site.RootWeb.title
                    if ($spYear -ne 2019) # This seems to cause an "access denied" error with SP2019, at least on the first attempt
                    {
                        Write-Host -ForegroundColor White " - Ensuring default groups are created..."
                        $site.RootWeb.CreateDefaultAssociatedGroups($primaryUser, $secondaryUser, $title)
                    }
                    # Add the Portal Site Connection to the web app, unless of course the current web app *is* the portal
                    # Inspired by http://www.toddklindt.com/blog/Lists/Posts/Post.aspx?ID=264
                    $portalWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "Portal"} | Select-Object -First 1
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
            Else
            {
                Write-Host -ForegroundColor White " - Skipping creation of site `"$siteCollectionName`" - already provisioned."
            }
            if ($siteCollection.HostNamedSiteCollection -eq $true)
            {
                Add-LocalIntranetURL ($siteURL)
                # Updated so that we don't add URLs to the local hosts file of a server that's not been specified to run the Foundation Web Application service, or the Search MinRole
                if ($xmlInput.Configuration.WebApplications.AddURLsToHOSTS -eq $true -and !(ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Search)) -and !(($xmlInput.Configuration.Farm.Services.SelectSingleNode("FoundationWebApplication")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.FoundationWebApplication -eq $true)))
                {
                    # Add the hostname of this host header-based site collection to the local HOSTS so it's immediately resolvable locally
                    # Strip out any protocol and/or port values
                    $hostname,$null = $siteURL -replace "http://","" -replace "https://","" -split ":"
                    AddToHOSTS $hostname
                }
            }
            WriteLine
        }
    }
    else
    {
        Write-Host -ForegroundColor Yellow " - No site collections specified for $($webapp.url) - skipping."
    }
}

# ===================================================================================
# Func: Set-WebAppUserPolicy
# AMW 1.7.2
# Desc: Set the web application user policy
# Refer to http://technet.microsoft.com/en-us/library/ff758656.aspx
# Updated based on Gary Lapointe example script to include Policy settings 18/10/2010
# ===================================================================================
Function Set-WebAppUserPolicy ($wa, $userName, $displayName, $perm)
{
    [Microsoft.SharePoint.Administration.SPPolicyCollection]$policies = $wa.Policies
    [Microsoft.SharePoint.Administration.SPPolicy]$policy = $policies.Add($userName, $displayName)
    [Microsoft.SharePoint.Administration.SPPolicyRole]$policyRole = $wa.PolicyRoles | Where-Object {$_.Name -eq $perm}
    If ($null -ne $policyRole)
    {
        Write-Host -ForegroundColor White " - Granting $userName $perm to $($wa.Url)..."
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
        $url = ($webApp.Url).TrimEnd("/") + ":" + $webApp.Port
        $wa = Get-SPWebApplication -Identity $url
        $superUserAcc = $xmlInput.Configuration.Farm.ObjectCacheAccounts.SuperUser
        $superReaderAcc = $xmlInput.Configuration.Farm.ObjectCacheAccounts.SuperReader
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
        Write-Warning "An error occurred applying object cache to `"$url`""
        Pause "exit"
    }
}

# ===================================================================================
# Func: ConfigureOnlineWebPartCatalog
# Desc: Enables / Disables access to the online web parts catalog for each web application
# ===================================================================================
Function ConfigureOnlineWebPartCatalog ([System.Xml.XmlElement]$webApp)
{
    If ($webapp.UseOnlineWebPartCatalog -ne "")
    {
        $url = ($webApp.Url).TrimEnd("/") + ":" + $webApp.Port
        If ($url -like "*localhost*")
        {
            $url = $url -replace "localhost", "$env:COMPUTERNAME"
        }
        Write-Host -ForegroundColor White " - Setting online webpart catalog access for `"$url`""

        $wa = Get-SPWebApplication -Identity $url
        If ($webapp.UseOnlineWebPartCatalog -eq "True")
        {
            $wa.AllowAccessToWebpartCatalog = $true
        }
        Else
        {
            $wa.AllowAccessToWebpartCatalog = $false
        }
        $wa.Update()
    }
}

# ===================================================================================
# Func: SetupManagedPaths
# Desc: Sets up managed paths for a given web application
# ===================================================================================
Function SetupManagedPaths ([System.Xml.XmlElement]$webApp)
{
    $url = ($webApp.Url).TrimEnd("/") + ":" + $webApp.Port
    If ($url -like "*localhost*")
    {
        $url = $url -replace "localhost", "$env:COMPUTERNAME"
    }
    Write-Host -ForegroundColor White " - Setting up managed paths for `"$url`""

    If ($webApp.ManagedPaths)
    {
        ForEach ($managedPath in $webApp.ManagedPaths.ManagedPath)
        {
            If ($managedPath.Delete -eq "true")
            {
                Write-Host -ForegroundColor White "  - Deleting managed path `"$($managedPath.RelativeUrl)`" at `"$url`""
                Remove-SPManagedPath -Identity $managedPath.RelativeUrl -WebApplication $url -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
            Else
            {
                If ($managedPath.Explicit -eq "true")
                {
                    Write-Host -ForegroundColor White "  - Setting up explicit managed path `"$($managedPath.RelativeUrl)`" at `"$url`" and HNSCs..."
                    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -WebApplication $url -Explicit -ErrorAction SilentlyContinue | Out-Null
                    # Let's create it for host-named site collections too, in case we have any
                    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -HostHeader -Explicit -ErrorAction SilentlyContinue | Out-Null
                }
                Else
                {
                    Write-Host -ForegroundColor White "  - Setting up managed path `"$($managedPath.RelativeUrl)`" at `"$url`" and HNSCs..."
                    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -WebApplication $url -ErrorAction SilentlyContinue | Out-Null
                    # Let's create it for host-named site collections too, in case we have any
                    New-SPManagedPath -RelativeUrl $managedPath.RelativeUrl -HostHeader -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }

    Write-Host -ForegroundColor White " - Done setting up managed paths at `"$url`""
}
#endregion

#region Create User Profile Service Application
# ===================================================================================
# Func: CreateUserProfileServiceApplication
# Desc: Create the User Profile Service Application
# ===================================================================================
Function CreateUserProfileServiceApplication ([xml]$xmlInput)
{
    # Based on http://sharepoint.microsoft.com/blogs/zach/Lists/Posts/Post.aspx?ID=50
    Try
    {
        $spYear = $xmlInput.Configuration.Install.SPVersion
        $spVer = Get-MajorVersionNumber $spYear
        $userProfile = $xmlInput.Configuration.ServiceApps.UserProfileServiceApp
        $mySiteWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "MySiteHost"}
        $dbPrefix = Get-DBPrefix $xmlInput
        # If we have asked to create a MySite Host web app, use that as the MySite host location
        if ($mySiteWebApp)
        {
            $mySiteName = $mySiteWebApp.name
            $mySiteURL = ($mySiteWebApp.url).TrimEnd("/")
            $mySitePort = $mySiteWebApp.port
            $mySiteDBServer = $mySiteWebApp.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($mySiteDBServer))
            {
                $mySiteDBServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $mySiteDB = $dbPrefix + $mySiteWebApp.Database.Name
            $mySiteAppPoolAcct = Get-SPManagedAccountXML $xmlInput -CommonName "MySiteHost"
            if ([string]::IsNullOrEmpty($mySiteAppPoolAcct.username))
            {
                throw " - `"MySiteHost`" managed account not found! Check your XML."
            }
        }
        $portalAppPoolAcct = Get-SPManagedAccountXML $xmlInput -CommonName "Portal"
        if ([string]::IsNullOrEmpty($portalAppPoolAcct.username))
        {
            throw " - `"Portal`" managed account not found! Check your XML."
        }
        $farmAcct = $xmlInput.Configuration.Farm.Account.Username
        $farmAcctPWD = $xmlInput.Configuration.Farm.Account.Password
        # Get the content access accounts of each Search Service Application in the XML (in case there are multiple)
        foreach ($searchServiceApplication in $xmlInput.Configuration.ServiceApps.EnterpriseSearchService.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication)
        {
            [array]$contentAccessAccounts += $searchServiceApplication.ContentAccessAccount
        }
        If (($farmAcctPWD -ne "") -and ($null -ne $farmAcctPWD))
        {
            $farmAcctPWD = (ConvertTo-SecureString $farmAcctPWD -AsPlainText -Force)
        }
        $mySiteTemplate = $mySiteWebApp.SiteCollections.SiteCollection.Template
        $mySiteLCID = $mySiteWebApp.SiteCollections.SiteCollection.LCID
        $userProfileServiceName = $userProfile.Name
        $userProfileServiceProxyName = $userProfile.ProxyName
        $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
        If ($null -eq $userProfileServiceName)
        {
            $userProfileServiceName = "User Profile Service Application"
        }
        If ($null -eq $userProfileServiceProxyName)
        {
            $userProfileServiceProxyName = $userProfileServiceName
        }
        If (!$farmCredential)
        {
            [System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlInput
        }
        if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
        {
            Write-Host -ForegroundColor White " - Skipping setting the web app directory path name (not currently working on Windows 2012 w/SP2010)..."
            $pathSwitch = @{}
        }
        else
        {
            # Set the directory path for the web app to something a bit more friendly
            ImportWebAdministration
            # Get the default root location for web apps (first from IIS itself, then failing that, from the registry)
            $iisWebDir = (Get-ItemProperty "IIS:\Sites\Default Web Site\" -Name physicalPath -ErrorAction SilentlyContinue) -replace ("%SystemDrive%","$env:SystemDrive")
            if ([string]::IsNullOrEmpty($iisWebDir))
            {
                $iisWebDir = (Get-Item -Path HKLM:\SOFTWARE\Microsoft\InetStp).GetValue("PathWWWRoot") -replace ("%SystemDrive%","$env:SystemDrive")
            }
            If (!([string]::IsNullOrEmpty($iisWebDir)))
            {
                $pathSwitch = @{Path = "$iisWebDir\wss\VirtualDirectories\$webAppName-$port"}
            }
            else
            {
                $pathSwitch = @{}
            }
        }
        # Only set $hostHeaderSwitch to blank if the UseHostHeader value exists has explicitly been set to false
        if (!([string]::IsNullOrEmpty($webApp.UseHostHeader)) -and $webApp.UseHostHeader -eq $false)
        {
            $hostHeaderSwitch = @{}
        }
        else
        {
            $hostHeaderSwitch = @{HostHeader = $hostHeader}
        }

        If ((ShouldIProvision $userProfile -eq $true) -and (Get-Command -Name New-SPProfileServiceApplication -ErrorAction SilentlyContinue))
        {
            WriteLine
            Write-Host -ForegroundColor White " - Provisioning $($userProfile.Name)"
            # get the service instance
            $profileServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
            $profileServiceInstance = $profileServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find User Profile Service instance"
            }
            # Start Service instance
            Write-Host -ForegroundColor White " - Starting User Profile Service instance..."
            If (($profileServiceInstance.Status -eq "Disabled") -or ($profileServiceInstance.Status -ne "Online"))
            {
                $profileServiceInstance.Provision()
                If (-not $?)
                {
                    Throw " - Failed to start User Profile Service instance"
                }
                # Wait
                Write-Host -ForegroundColor Cyan " - Waiting for User Profile Service..." -NoNewline
                While ($profileServiceInstance.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $profileServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileServiceInstance"}
                    $profileServiceInstance = $profileServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black $($profileServiceInstance.Status)
            }
            # Create a Profile Service Application
            If ($null -eq (Get-SPServiceApplication | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.UserProfileApplication"}))
            {
                # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
                $usingSQLAuthentication = (($userProfile.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($userProfile.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($userProfile.Database.SQLAuthentication.SQLUserName)))
                if ($usingSQLAuthentication)
                {
                    Write-Host -ForegroundColor White " - Creating SQL credential object..."
                    $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                    $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
                }
                else # Otherwise assume Windows integrated and no database credentials provided
                {
                    $databaseCredentialsParameter = @{}
                }
                # Create MySites Web Application if it doesn't already exist, and we've specified to create one
                $getSPWebApplication = Get-SPWebApplication -Identity $mySiteURL -ErrorAction SilentlyContinue
                If ($null -eq $getSPWebApplication -and ($mySiteWebApp))
                {
                    Write-Host -ForegroundColor White " - Creating Web App `"$mySiteName`"..."
                    New-SPWebApplication -Name $mySiteName -ApplicationPoolAccount $($mySiteAppPoolAcct.username) -ApplicationPool $mySiteAppPool -DatabaseServer $mySiteDBServer -DatabaseName $mySiteDB -Url $mySiteURL -Port $mySitePort -SecureSocketsLayer:$mySiteUseSSL @hostHeaderSwitch @pathSwitch @databaseCredentialsParameter | Out-Null
                }
                Else
                {
                    Write-Host -ForegroundColor White " - My Site host already provisioned."
                }

                # Create MySites Site Collection
                If ($null -eq (Get-SPContentDatabase | Where-Object {$_.Name -eq $mySiteDB}) -and ($mySiteWebApp))
                {
                    Write-Host -ForegroundColor White " - Creating My Sites content DB..."
                    New-SPContentDatabase -DatabaseServer $mySiteDBServer -Name $mySiteDB -WebApplication "$mySiteURL`:$mySitePort" @databaseCredentialsParameter | Out-Null
                    If (-not $?)
                    {
                        Throw " - Failed to create My Sites content DB"
                    }
                }
                If (!(Get-SPSite -Limit ALL | Where-Object {(($_.Url -like "$mySiteURL*") -and ($_.Port -eq "$mySitePort"))}) -and ($mySiteWebApp))
                {
                    Write-Host -ForegroundColor White " - Creating My Sites site collection $mySiteURL`:$mySitePort..."
                    # Verify that the Language we're trying to create the site in is currently installed on the server
                    $mySiteCulture = [System.Globalization.CultureInfo]::GetCultureInfo(([convert]::ToInt32($mySiteLCID)))
                    $mySiteCultureDisplayName = $mySiteCulture.DisplayName
                    $installedOfficeServerLanguages = (Get-Item "HKLM:\Software\Microsoft\Office Server\$spVer.0\InstalledLanguages").GetValueNames() | Where-Object {$_ -ne ""}
                    If (!($installedOfficeServerLanguages | Where-Object {$_ -eq $mySiteCulture.Name}))
                    {
                        Throw " - You must install the `"$mySiteCulture ($mySiteCultureDisplayName)`" Language Pack before you can create a site using LCID $mySiteLCID"
                    }
                    Else
                    {
                        New-SPSite -Url "$mySiteURL`:$mySitePort" -OwnerAlias $farmAcct -SecondaryOwnerAlias $env:USERDOMAIN\$env:USERNAME -ContentDatabase $mySiteDB -Description $mySiteName -Name $mySiteName -Template $mySiteTemplate -Language $mySiteLCID | Out-Null
                        If (-not $?)
                        {
                            Throw " - Failed to create My Sites site collection"
                        }
                        # Assign SSL certificate, if required
                        If ($mySiteUseSSL)
                        {
                            # Strip out any protocol and/or port values
                            $SSLHostHeader,$null = $mySiteHostLocation -replace "http://","" -replace "https://","" -split ":"
                            $SSLPort = $mySitePort
                            $SSLSiteName = $mySiteName
                            if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
                            {
                                Write-Host -ForegroundColor White " - Assigning certificate(s) in a separate PowerShell window..."
                                Start-Process -FilePath "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "-Command `"Import-Module -Name $env:dp0\AutoSPInstallerModule.psm1 -Force; AssignCert $SSLHostHeader $SSLPort $SSLSiteName; Start-Sleep 10`"" -Wait
                            }
                            else
                            {
                                AssignCert $SSLHostHeader $SSLPort $SSLSiteName
                            }
                        }
                    }
                }

                # Create Service App
                Write-Host -ForegroundColor White " - Creating $userProfileServiceName..."
                CreateUPSAsAdmin $xmlInput
                Write-Host -ForegroundColor Cyan " - Waiting for $userProfileServiceName..." -NoNewline
                $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
                While ($profileServiceApp.Status -ne "Online")
                {
                    [int]$UPSWaitTime = 0
                    # Wait 2 minutes for either the UPS to be created, or the UAC prompt to time out
                    While (($UPSWaitTime -lt 120) -and ($profileServiceApp.Status -ne "Online"))
                    {
                        Write-Host -ForegroundColor Cyan "." -NoNewline
                        Start-Sleep 1
                        $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
                        [int]$UPSWaitTime += 1
                    }
                    # If it still isn't Online after 2 minutes, prompt to try again
                    If (!($profileServiceApp))
                    {
                        Write-Host -ForegroundColor Cyan "."
                        Write-Warning "Timed out waiting for service creation (maybe a UAC prompt?)"
                        Write-Host "`a`a`a" # System beeps
                        Pause "try again"
                        CreateUPSAsAdmin $xmlInput
                        Write-Host -ForegroundColor Cyan " - Waiting for $userProfileServiceName..." -NoNewline
                        $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
                    }
                    Else
                    {
                        break
                    }
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black $($profileServiceApp.Status)
                # Wait a few seconds for the CreateUPSAsAdmin function to complete
                Start-Sleep 30

                # Get our new Profile Service App
                $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
                If (!($profileServiceApp))
                {
                    Throw " - Could not get $userProfileServiceName!";
                }

                # Create Proxy
                Write-Host -ForegroundColor White " - Creating $userProfileServiceName Proxy..."
                New-SPProfileServiceApplicationProxy -Name "$userProfileServiceProxyName" -ServiceApplication $profileServiceApp -DefaultProxyGroup | Out-Null
                If (-not $?)
                {
                    Throw " - Failed to create $userProfileServiceName Proxy"
                }

                Write-Host -ForegroundColor White " - Granting rights to ($userProfileServiceName):"
                # Create a variable that contains the guid for the User Profile service for which you want to delegate permissions
                $serviceAppIDToSecure = Get-SPServiceApplication $($profileServiceApp.Id)

                # Create a variable that contains the list of administrators for the service application
                $profileServiceAppSecurity = Get-SPServiceApplicationSecurity $serviceAppIDToSecure -Admin
                # Create a variable that contains the permissions for the service application
                $profileServiceAppPermissions = Get-SPServiceApplicationSecurity $serviceAppIDToSecure

                # Create variables that contains the claims principals for current (Setup) user, genral service account, MySite App Pool, Portal App Pool and Content Access accounts
                # Then give 'Full Control' permissions to the current (Setup) user, general service account, MySite App Pool, Portal App Pool account and content access account claims principals
                $currentUserAcctPrincipal = New-SPClaimsPrincipal -Identity $env:USERDOMAIN\$env:USERNAME -IdentityType WindowsSamAccountName
                $spServiceAcctPrincipal = New-SPClaimsPrincipal -Identity $($spservice.username) -IdentityType WindowsSamAccountName
                Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $currentUserAcctPrincipal -Rights "Full Control"
                Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $currentUserAcctPrincipal -Rights "Full Control"
                Grant-SPObjectSecurity $profileServiceAppPermissions -Principal $spServiceAcctPrincipal -Rights "Full Control"
                If ($mySiteAppPoolAcct)
                {
                    Write-Host -ForegroundColor White "  - $($mySiteAppPoolAcct.username)..."
                    $mySiteAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $($mySiteAppPoolAcct.username) -IdentityType WindowsSamAccountName
                    Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $mySiteAppPoolAcctPrincipal -Rights "Full Control"
                }
                If ($portalAppPoolAcct)
                {
                    Write-Host -ForegroundColor White "  - $($portalAppPoolAcct.username)..."
                    $portalAppPoolAcctPrincipal = New-SPClaimsPrincipal -Identity $($portalAppPoolAcct.username) -IdentityType WindowsSamAccountName
                    Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $portalAppPoolAcctPrincipal -Rights "Full Control"
                }
                If ($contentAccessAccounts)
                {
                    foreach ($contentAccessAcct in $contentAccessAccounts)
                    {
                        # Give 'Retrieve People Data for Search Crawlers' permissions to the Content Access claims principal
                        Write-Host -ForegroundColor White "  - $contentAccessAcct..."
                        $contentAccessAcctPrincipal = New-SPClaimsPrincipal -Identity $contentAccessAcct -IdentityType WindowsSamAccountName
                        Grant-SPObjectSecurity $profileServiceAppSecurity -Principal $contentAccessAcctPrincipal -Rights "Retrieve People Data for Search Crawlers"
                    }
                }

                # Apply the changes to the User Profile service application
                Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppSecurity -Admin
                Set-SPServiceApplicationSecurity $serviceAppIDToSecure -objectSecurity $profileServiceAppPermissions
                Write-Host -ForegroundColor White " - Done granting rights."

                # Add link to resources list
                AddResourcesLink "User Profile Administration" ("_layouts/ManageUserProfileServiceApplication.aspx?ApplicationID=" + $profileServiceApp.Id)

                If ($portalAppPoolAcct -and !$usingSQLAuthentication)
                {
                    # Grant the Portal App Pool account rights to the Profile and Social DBs
                    $profileDB = $dbPrefix + $userProfile.Database.ProfileDB
                    $socialDB = $dbPrefix + $userProfile.Database.SocialDB
                    Write-Host -ForegroundColor White " - Granting $($portalAppPoolAcct.username) rights to $mySiteDB..."
                    Get-SPDatabase | Where-Object {$_.Name -eq $mySiteDB} | Add-SPShellAdmin -UserName $($portalAppPoolAcct.username)
                    Write-Host -ForegroundColor White " - Granting $($portalAppPoolAcct.username) rights to $profileDB..."
                    Get-SPDatabase | Where-Object {$_.Name -eq $profileDB} | Add-SPShellAdmin -UserName $($portalAppPoolAcct.username)
                    Write-Host -ForegroundColor White " - Granting $($portalAppPoolAcct.username) rights to $socialDB..."
                    Get-SPDatabase | Where-Object {$_.Name -eq $socialDB} | Add-SPShellAdmin -UserName $($portalAppPoolAcct.username)
                }
                Write-Host -ForegroundColor White " - Enabling the Activity Feed Timer Job.."
                If ($profileServiceApp)
                {
                    Get-SPTimerJob | Where-Object {$_.TypeName -eq "Microsoft.Office.Server.ActivityFeed.ActivityFeedUPAJob"} | Enable-SPTimerJob
                }

                Write-Host -ForegroundColor White " - Done creating $userProfileServiceName."
            }
            # Start User Profile Synchronization Service
            # Get User Profile Service
            $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
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
                if ($spVer -lt "16") # Since User Profile Sync seems to only apply to SP2010/2013
                {
                    $profileSyncServices = @(Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"})
                    $profileSyncService = $profileSyncServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                    # Attempt to start only if there are no online Profile Sync Service instances in the farm as we don't want to start multiple Sync instances (running against the same Profile Service at least)
                    If (!($profileSyncServices | Where-Object {$_.Status -eq "Online"}))
                    {
                        # Inspired by http://technet.microsoft.com/en-us/library/ee721049.aspx
                        If (!($farmAcct))
                        {
                            $farmAcct = (Get-SPFarm).DefaultServiceAccount
                        }
                        If (!($farmAcctPWD))
                        {
                            Write-Host -ForegroundColor White "`n"
                            $farmAcctPWD = Read-Host -Prompt " - Please (re-)enter the Farm Account Password" -AsSecureString
                        }
                        Write-Host -ForegroundColor White "`n"
                        # Check for an existing UPS credentials timer job (e.g. from a prior provisioning attempt), and delete it
                        $UPSCredentialsJob = Get-SPTimerJob | Where-Object {$_.Name -eq "windows-service-credentials-FIMSynchronizationService"}
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
                        If (($profileSyncService.Status -ne "Provisioning") -and ($profileSyncService.Status -ne "Online"))
                        {
                            Write-Host -ForegroundColor Cyan "`n - Waiting for User Profile Synchronization Service to start..." -NoNewline
                        }
                        # Monitor User Profile Sync service status
                        While ($profileSyncService.Status -ne "Online")
                        {
                            While ($profileSyncService.Status -ne "Provisioning")
                            {
                                Write-Host -ForegroundColor Cyan "." -NoNewline
                                Start-Sleep 1
                                $profileSyncService = @(Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | Where-Object {$_.Parent.Address -eq $env:COMPUTERNAME}
                            }
                            If ($profileSyncService.Status -eq "Provisioning")
                            {
                                Write-Host -BackgroundColor Green -ForegroundColor Black $($profileSyncService.Status)
                                Write-Host -ForegroundColor Cyan " - Provisioning User Profile Sync Service, please wait..." -NoNewline
                            }
                            While ($profileSyncService.Status -eq "Provisioning" -and $profileSyncService.Status -ne "Disabled")
                            {
                                Write-Host -ForegroundColor Cyan "." -NoNewline
                                Start-Sleep 1
                                $profileSyncService = @(Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"}) | Where-Object {$_.Parent.Address -eq $env:COMPUTERNAME}
                            }
                            If ($profileSyncService.Status -ne "Online")
                            {
                                Write-Host -ForegroundColor Red ".`a`a"
                                Write-Host -BackgroundColor Red -ForegroundColor Black " - User Profile Synchronization Service could not be started!"
                                break
                            }
                            Else
                            {
                                Write-Host -BackgroundColor Green -ForegroundColor Black $($profileSyncService.Status)
                                # Need to recycle the Central Admin app pool before we can do anything with the User Profile Sync Service
                                Write-Host -ForegroundColor White " - Recycling Central Admin app pool..."
                                # From http://sharepoint.nauplius.net/2011/09/iisreset-not-required-after-starting.html
                                $appPool = Get-WmiObject -Namespace "root\MicrosoftIISv2" -Class "IIsApplicationPool" | Where-Object {$_.Name -eq "W3SVC/APPPOOLS/SharePoint Central Administration v4"}
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
                        If ((CheckFor2010SP1 -xmlinput $xmlInput) -and ($userProfile.CreateDefaultSyncConnection -eq $true) -and ($newlyProvisionedSync -eq $true))
                        {
                            Write-Host -ForegroundColor White " - Creating a default Profile Sync connection..."
                            $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
                            # Thanks to Codeplex user Reshetkov for this ingenious one-liner to build the default domain OU
                            $connectionSyncOU = "DC=" + $env:USERDNSDOMAIN -replace "\.",",DC="
                            $syncConnectionDomain,$syncConnectionAcct = ($userProfile.SyncConnectionAccount) -split "\\"
                            $addProfileSyncCmd = @"
Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
Write-Host -ForegroundColor White " - Creating default Sync connection..."
`$syncConnectionAcctPWD = (ConvertTo-SecureString -String `'$($userProfile.SyncConnectionAccountPassword)`' -AsPlainText -Force)
Add-SPProfileSyncConnection -ProfileServiceApplication $($profileServiceApp.Id) -ConnectionForestName $env:USERDNSDOMAIN -ConnectionDomain $syncConnectionDomain -ConnectionUserName "$syncConnectionAcct" -ConnectionSynchronizationOU "$connectionSyncOU" -ConnectionPassword `$syncConnectionAcctPWD
If (!`$?)
{
Write-Host "Press any key to exit..."
`$null = `$host.UI.RawUI.ReadKey(`"NoEcho,IncludeKeyDown`")
}
Else {Write-Host -ForegroundColor White " - Done.";Start-Sleep 15}
"@
                            $addProfileScriptFile = "$((Get-Item $env:TEMP).FullName)\AutoSPInstaller-AddProfileSyncCmd.ps1"
                            $addProfileSyncCmd | Out-File $addProfileScriptFile
                            if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
                            {
                                $versionSwitch = "-Version 2"
                            }
                            else
                            {
                                $versionSwitch = ""
                            }
                            # Run our Add-SPProfileSyncConnection script as the Farm Account - doesn't seem to work otherwise
                            Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-ExecutionPolicy Bypass -Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$versionSwitch -ExecutionPolicy Bypass $addProfileScriptFile'`" -Verb Runas" -Wait
                            # Give Add-SPProfileSyncConnection time to complete before continuing
                            Start-Sleep 120
                            Remove-Item -LiteralPath $addProfileScriptFile -Force -ErrorAction SilentlyContinue
                        }
                    }
                    Else
                    {
                        Write-Host -ForegroundColor White "Already started."
                    }
                    # Make the FIM services dependent on the SQL Server service if we are provisioning User Profile Sync and SQL is co-located with SharePoint on this machine
                    $dbServerUPSA = $xmlInput.Configuration.ServiceApps.UserProfileServiceApp.Database.DBServer
                    if ([string]::IsNullOrEmpty($dbServerUPSA))
                    {
                        $dbServerUPSA = $xmlInput.Configuration.Farm.Database.DBServer
                    }
                    $upAlias = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo" -Name $dbServerUPSA -ErrorAction SilentlyContinue
                    # Grab the values for the SQL alias, if one exists
                    $upDBInstance = $upAlias.$dbServerUPSA
                    if ([string]::IsNullOrEmpty($upDBInstance)) # Alias not found; maybe we are using an actual machine name
                    {
                        $upDBInstance = $dbServerUPSA
                    }
                    # Proceed if the database instance specified for the UPSA maps to the local machine name and the service was provisioned successfully
                    $profileSyncServices = @(Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Administration.ProfileSynchronizationServiceInstance"})
                    if ($upDBInstance -like "*$env:COMPUTERNAME*" -and ($profileSyncServices | Where-Object {$_.Status -eq "Online"}))
                    {
                        # Sets the Forefront Identity Manager Services to depend on the SQL Server service
                        # For all-in-one environments where FIM may not start automatically, e.g. Development VMs
                        Write-Host -ForegroundColor White " - Setting Forefront Identity Manager services to depend on SQL Server."
                        Write-Host -ForegroundColor White " - This is helpful when the SQL instance for the User Profile Service is co-located."
                        & "$env:windir\System32\sc.exe" config FIMService depend= MSSQLSERVER
                        & "$env:windir\System32\sc.exe" config FIMService start= delayed-auto
                        & "$env:windir\System32\sc.exe" config FIMSynchronizationService depend= Winmgmt/FIMService
                        & "$env:windir\System32\sc.exe" config FIMSynchronizationService start= delayed-auto
                    }
                }
                else
                {
                    Write-Host -ForegroundColor White "Not applicable to SharePoint $spYear."
                }
            }
            Else
            {
                Write-Host -ForegroundColor White " - Could not get User Profile Service, or StartProfileSync is False."
            }
            WriteLine
        }
    }
    Catch
    {
        Write-Output $_
        Throw " - Error Provisioning the User Profile Service Application"
    }
}
# ===================================================================================
# Func: CreateUPSAsAdmin
# Desc: Create the User Profile Service Application itself as the Farm Admin account, in a session with elevated privileges
#       This incorporates the workaround by @harbars & @glapointe http://www.harbar.net/archive/2010/10/30/avoiding-the-default-schema-issue-when-creating-the-user-profile.aspx
#       Modified to work within AutoSPInstaller (to pass our script variables to the Farm Account credential's PowerShell session)
# ===================================================================================

Function CreateUPSAsAdmin ([xml]$xmlInput)
{
    Try
    {
        $mySiteWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "MySiteHost"}
        $mySiteManagedPath = $userProfile.MySiteManagedPath
        # If we have asked to create a MySite Host web app, use that as the MySite host location
        if ($mySiteWebApp)
        {
            $mySiteURL = ($mySiteWebApp.url).TrimEnd("/")
            $mySitePort = $mySiteWebApp.port
            $mySiteHostLocation = $mySiteURL + ":" + $mySitePort
        }
        else # Use the value provided in the $userProfile node
        {
            $mySiteHostLocation = $userProfile.MySiteHostLocation
        }
        if ([string]::IsNullOrEmpty($mySiteHostLocation))
        {
            $mySiteHostLocationSwitch = ""
        }
        else
        {
            $mySiteHostLocationSwitch = "-MySiteHostLocation `"$mySiteHostLocation`"" # This format required to parse properly in the script block below
        }
        if ([string]::IsNullOrEmpty($mySiteManagedPath))
        {
            # Don't specify the MySiteManagedPath switch if it was left blank. This will effectively use the default path of "personal/sites"
            # Note that an empty hashtable doesn't seem to work here so we just put an empty string
            $mySiteManagedPathSwitch = ""
        }
        else
        {
            # Attempt to use the path we specified in the XML
            $mySiteManagedPathSwitch = "-MySiteManagedPath `"$mySiteManagedPath`"" # This format required to parse properly in the script block below
        }
        $farmAcct = $xmlInput.Configuration.Farm.Account.Username
        $userProfileServiceName = $userProfile.Name
        $dbServer = $userProfile.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($dbServer))
        {
            $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
        }
        # Set the ProfileDBServer, SyncDBServer and SocialDBServer to the same value ($dbServer). Maybe in the future we'll want to get more granular...?
        $profileDBServer = $dbServer
        $syncDBServer = $dbServer
        $socialDBServer = $dbServer
        $dbPrefix = Get-DBPrefix $xmlInput
        $profileDB = $dbPrefix + $userProfile.Database.ProfileDB
        $syncDB = $dbPrefix + $userProfile.Database.SyncDB
        $socialDB = $dbPrefix + $userProfile.Database.SocialDB
        $applicationPool = Get-HostedServicesAppPool $xmlInput
        If (!$farmCredential)
        {
            [System.Management.Automation.PsCredential]$farmCredential = GetFarmCredentials $xmlInput
        }
        $scriptFile = "$((Get-Item $env:TEMP).FullName)\AutoSPInstaller-ScriptBlock.ps1"
        # Write the script block, with expanded variables to a temporary script file that the Farm Account can get at
        Write-Output "Write-Host -ForegroundColor White `"Creating $userProfileServiceName as $farmAcct...`"" | Out-File $scriptFile -Width 400
        Write-Output "Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue" | Out-File $scriptFile -Width 400 -Append
        # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
        if ($usingSQLAuthentication)
        {
            Write-Output "`$SqlCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $($xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName),(ConvertTo-SecureString -String '$($xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword)' -AsPlainText -Force)" | Out-File $scriptFile -Width 400 -Append
            Write-Output "`$ProfileDBCredentialsParameter = @{ProfileDBCredentials = `$SqlCredential}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "`$SocialDBCredentialsParameter = @{SocialDBCredentials = `$SqlCredential}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "`$ProfileSyncDBCredentialsParameter = @{ProfileSyncDBCredentials = `$SqlCredential}" | Out-File $scriptFile -Width 400 -Append
        }
        else
        {
            Write-Output "`$ProfileDBCredentialsParameter = @{}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "`$SocialDBCredentialsParameter = @{}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "`$ProfileSyncDBCredentialsParameter = @{}" | Out-File $scriptFile -Width 400 -Append
        }
        Write-Output "`$newProfileServiceApp = New-SPProfileServiceApplication -Name `"$userProfileServiceName`" -ApplicationPool `"$($applicationPool.Name)`" -ProfileDBServer $profileDBServer -ProfileDBName $profileDB @ProfileDBCredentialsParameter -ProfileSyncDBServer $syncDBServer -ProfileSyncDBName $syncDB @ProfileSyncDBCredentialsParameter -SocialDBServer $socialDBServer -SocialDBName $socialDB @SocialDBCredentialsParameter $mySiteHostLocationSwitch $mySiteManagedPathSwitch" | Out-File $scriptFile -Width 400 -Append
        Write-Output "If (-not `$?) {Write-Error `" - Failed to create $userProfileServiceName`"; Write-Host `"Press any key to exit...`"; `$null = `$host.UI.RawUI.ReadKey`(`"NoEcho,IncludeKeyDown`"`)}" | Out-File $scriptFile -Width 400 -Append
        # Need a better way to determine if we're not requesting SQL auth for the service application
        if (!$usingSQLAuthentication)
        {
            # Grant the current install account rights to the newly-created Profile DB - needed since it's going to be running PowerShell commands against it
            Write-Output "`$profileDBId = Get-SPDatabase | Where-Object {`$_.Name -eq `"$profileDB`"}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$profileDBId" | Out-File $scriptFile -Width 400 -Append
            # Grant the current install account rights to the newly-created Social DB as well
            Write-Output "`$socialDBId = Get-SPDatabase | Where-Object {`$_.Name -eq `"$socialDB`"}" | Out-File $scriptFile -Width 400 -Append
            Write-Output "Add-SPShellAdmin -UserName `"$env:USERDOMAIN\$env:USERNAME`" -database `$socialDBId" | Out-File $scriptFile -Width 400 -Append
        }
        # Add the -Version 2 switch in case we are installing SP2010 on Windows Server 2012 or 2012 R2
        if (((Get-WmiObject Win32_OperatingSystem).Version -like "6.2*" -or (Get-WmiObject Win32_OperatingSystem).Version -like "6.3*") -and ($spYear -eq 2010))
        {
            $versionSwitch = "-Version 2"
        }
        else
        {
            $versionSwitch = ""
        }
        If (Confirm-LocalSession) # Create the UPA as usual if this isn't a remote session
        {
            # Start a process under the Farm Account's credentials, then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Start-Process -WorkingDirectory $PSHOME -FilePath "powershell.exe" -Credential $farmCredential -ArgumentList "-ExecutionPolicy Bypass -Command Start-Process -WorkingDirectory `"'$PSHOME'`" -FilePath `"'powershell.exe'`" -ArgumentList `"'$versionSwitch -ExecutionPolicy Bypass $scriptFile'`" -Verb Runas" -Wait
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
                Write-Warning "Couldn't create remote session to $env:COMPUTERNAME; trying again..."
                CreateUPSAsAdmin $xmlInput
            }
            # Pass the value of $scriptFile to the new session
            Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name ScriptFile -Value $value} -ArgumentList $scriptFile -Session $UPSession
            Write-Host -ForegroundColor White " - Creating $userProfileServiceName under `"remote`" session..."
            # Start a (local) process (on our "remote" session), then spawn an elevated process within to finally execute the script file that actually creates the UPS
            Invoke-Command -ScriptBlock {Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-ExecutionPolicy Bypass $scriptFile" -Verb Runas} -Session $UPSession
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
        $profileServiceApp = Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $userProfileServiceName}
        If ($profileServiceApp)
        {
            Remove-Item -LiteralPath $scriptFile -Force
        }
    }
}
#endregion

#region Create State Service Application
Function CreateStateServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.StateService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.AccessService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.VisioService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.AccessServices -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.ServiceApps.WebAnalyticsService -eq $true -and $spVer -eq 2010))
    {
        WriteLine
        Try
        {
            $serviceConfig = $xmlInput.Configuration.ServiceApps.StateService
            $dbServer = $serviceConfig.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $dbPrefix = Get-DBPrefix $xmlInput
            $stateServiceDB = $dbPrefix + $serviceConfig.Database.Name
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
            if ($usingSQLAuthentication)
            {
                Write-Host -ForegroundColor White " - Creating SQL credential object..."
                $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseCredentialsParameter = @{}
            }
            $stateServiceName = $serviceConfig.Name
            $stateServiceProxyName = $serviceConfig.ProxyName
            If ($null -eq $stateServiceName)
            {
                $stateServiceName = "State Service Application"
            }
            If ($null -eq $stateServiceProxyName)
            {
                $stateServiceProxyName = $stateServiceName
            }
            $getSPStateServiceApplication = Get-SPStateServiceApplication
            If ($null -eq $getSPStateServiceApplication)
            {
                Write-Host -ForegroundColor White " - Provisioning State Service Application..."
                New-SPStateServiceDatabase -DatabaseServer $dbServer -Name $stateServiceDB @databaseCredentialsParameter | Out-Null
                New-SPStateServiceApplication -Name $stateServiceName -Database $stateServiceDB | Out-Null
                Get-SPStateServiceDatabase | Initialize-SPStateServiceDatabase | Out-Null
                Write-Host -ForegroundColor White " - Creating State Service Application Proxy..."
                Get-SPStateServiceApplication | New-SPStateServiceApplicationProxy -Name $stateServiceProxyName -DefaultProxyGroup | Out-Null
                Write-Host -ForegroundColor White " - Done creating State Service Application."
            }
            Else
            {
                Write-Host -ForegroundColor White " - State Service Application already provisioned."
            }
        }
        Catch
        {
            Write-Output $_
            Throw " - Error provisioning the state service application"
        }
        WriteLine
    }
}
#endregion

#region Create SP Usage Application
# ===================================================================================
# Func: CreateSPUsageApp
# Desc: Creates the Usage and Health Data Collection service application
# ===================================================================================
Function CreateSPUsageApp ([xml]$xmlInput)
{
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.SPUsageService -eq $true) -and (Get-Command -Name New-SPUsageApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        Try
        {
            $dbServer = $xmlInput.Configuration.ServiceApps.SPUsageService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $spUsageApplicationName = $xmlInput.Configuration.ServiceApps.SPUsageService.Name
            $dbPrefix = Get-DBPrefix $xmlInput
            $spUsageDB = $dbPrefix + $xmlInput.Configuration.ServiceApps.SPUsageService.Database.Name
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            if ($xmlInput.Configuration.ServiceApps.SPUsageService.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true")
            {
                $databaseUsernameParameter = @{DatabaseUsername = $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName}
                $databasePasswordParameter = @{DatabasePassword = ConvertTo-SecureString -String $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword -AsPlainText -Force}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseUsernameParameter = @{}
                $databasePasswordParameter = @{}
            }
            $getSPUsageApplication = Get-SPUsageApplication
            If ($null -eq $getSPUsageApplication)
            {
                Write-Host -ForegroundColor White " - Provisioning SP Usage Application..."
                New-SPUsageApplication -Name $spUsageApplicationName -DatabaseServer $dbServer -DatabaseName $spUsageDB @databaseUsernameParameter @databasePasswordParameter | Out-Null
                # Need this to resolve a known issue with the Usage Application Proxy not automatically starting/provisioning
                # Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 !
                Write-Host -ForegroundColor White " - Fixing Usage and Health Data Collection Proxy..."
                $spUsageApplicationProxy = Get-SPServiceApplicationProxy | Where-Object {$_.DisplayName -eq $spUsageApplicationName}
                $spUsageApplicationProxy.Provision()
                # End Usage Proxy Fix
                Write-Host -ForegroundColor White " - Enabling usage processing timer job..."
                $usageProcessingJob = Get-SPTimerJob | Where-Object {$_.TypeName -eq "Microsoft.SharePoint.Administration.SPUsageProcessingJobDefinition"}
                $usageProcessingJob.IsDisabled = $false
                $usageProcessingJob.Update()
                Write-Host -ForegroundColor White " - Done provisioning SP Usage Application."
            }
            Else
            {
                Write-Host -ForegroundColor White " - SP Usage Application already provisioned."
            }
        }
        Catch
        {
            Write-Output $_
            Throw " - Error provisioning the SP Usage Application"
        }
        WriteLine
    }
}
#endregion

#region Configure Logging

# ===================================================================================
# Func: ConfigureIISLogging
# Desc: Configures IIS Logging for the local server
# ===================================================================================
Function ConfigureIISLogging ([xml]$xmlInput)
{
    WriteLine
    $IISLogConfig = $xmlInput.Configuration.Farm.Logging.IISLogs
    Write-Host -ForegroundColor White " - Configuring IIS logging..."
    # New: Check for PowerShell version > 2 in case this is being run on Windows Server 2012
    If (!([string]::IsNullOrEmpty($IISLogConfig.Path)) -and $host.Version.Major -gt 2)
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
            # TODO: Fix this so it actually moves all files within subfolders
            If (Test-Path -Path $oldIISLogDir)
            {
                Write-Host -ForegroundColor White " - Moving any contents in old location $oldIISLogDir to $IISLogDir..."
                ForEach ($item in $(Get-ChildItem -Path $oldIISLogDir))
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
Function ConfigureDiagnosticLogging ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $ULSLogConfig = $xmlInput.Configuration.Farm.Logging.ULSLogs
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
        $ULSLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\LOGS"
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
    {
        $doConfig = $true
    }
    Else # Assume default value if none was specified in the XML input file
    {
        $ULSLogRetention = 14
    }
    If (!([string]::IsNullOrEmpty($ULSLogCutInterval)))
    {
        $doConfig = $true
    }
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
            ForEach ($item in $(Get-ChildItem -Path $oldULSLogDir) | Where-Object {$_.Name -like "*.log"})
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
Function ConfigureUsageLogging ([xml]$xmlInput)
{
    WriteLine
    If (Get-SPUsageService)
    {
        $spYear = $xmlInput.Configuration.Install.SPVersion
        $spVer = Get-MajorVersionNumber $spYear
        $usageLogConfig = $xmlInput.Configuration.Farm.Logging.UsageLogs
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
                $usageLogDir = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\LOGS"
            }
            # UsageLogMaxSpaceGB must be between 1 and 20.
            If (($usageLogMaxSpaceGB -lt 1) -or ([string]::IsNullOrEmpty($usageLogMaxSpaceGB)))
            {
                $usageLogMaxSpaceGB = 5
            } # Default value
            If ($usageLogMaxSpaceGB -gt 20)
            {
                $usageLogMaxSpaceGB = 20
            } # Maximum value
            # UsageLogCutTime must be between 1 and 1440
            If (($usageLogCutTime -lt 1) -or ([string]::IsNullOrEmpty($usageLogCutTime)))
            {
                $usageLogCutTime = 30
            } # Default value
            If ($usageLogCutTime -gt 1440)
            {
                $usageLogCutTime = 1440
            } # Maximum value
            # Set-SPUsageService's LoggingEnabled is 0 for disabled, and 1 for enabled
            $loggingEnabled = 1
            Set-SPUsageService -LoggingEnabled $loggingEnabled -UsageLogLocation "$usageLogDir" -UsageLogMaxSpaceGB $usageLogMaxSpaceGB -UsageLogCutTime $usageLogCutTime | Out-Null
            # Only move log files if the old & new locations are different, and if the old location actually had a value
            If (($usageLogDir -ne $oldUsageLogDir) -and (!([string]::IsNullOrEmpty($oldUsageLogDir))))
            {
                Write-Host -ForegroundColor White " - Moving any contents in old location $oldUsageLogDir to $usageLogDir..."
                ForEach ($item in $(Get-ChildItem -Path $oldUsageLogDir) | Where-Object {$_.Name -like "*.usage"})
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

#endregion

#region Create Web Analytics Service Application
# Thanks and credit to Jesper Nygaard Schi?tt (jesper@schioett.dk) per http://autospinstaller.codeplex.com/Thread/View.aspx?ThreadId=237578 !

Function CreateWebAnalyticsApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.WebAnalyticsService -eq $true) -and ($spYear -eq 2010))
    {
        WriteLine
        Try
        {
            $dbServer = $xmlInput.Configuration.ServiceApps.WebAnalyticsService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $applicationPool = Get-HostedServicesAppPool $xmlInput
            $dbPrefix = Get-DBPrefix $xmlInput
            $webAnalyticsReportingDB = $dbPrefix + $xmlInput.Configuration.ServiceApps.WebAnalyticsService.Database.ReportingDB
            $webAnalyticsStagingDB = $dbPrefix + $xmlInput.Configuration.ServiceApps.WebAnalyticsService.Database.StagingDB
            $webAnalyticsServiceName = $xmlInput.Configuration.ServiceApps.WebAnalyticsService.Name
            $getWebAnalyticsServiceApplication = Get-SPWebAnalyticsServiceApplication $webAnalyticsServiceName -ea SilentlyContinue
            Write-Host -ForegroundColor White " - Provisioning $webAnalyticsServiceName..."
            # Start Analytics service instances
            Write-Host -ForegroundColor White " - Checking Analytics Service instances..."
            $analyticsWebServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsWebServiceInstance"}
            $analyticsWebServiceInstance = $analyticsWebServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find Analytics Web Service instance"
            }
            Write-Host -ForegroundColor White " - Starting local Analytics Web Service instance..."
            $analyticsWebServiceInstance.Provision()
            $analyticsDataProcessingInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.WebAnalytics.Administration.WebAnalyticsServiceInstance"}
            $analyticsDataProcessingInstance = $analyticsDataProcessingInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find Analytics Data Processing Service instance"
            }
            UpdateProcessIdentity $analyticsDataProcessingInstance
            $analyticsDataProcessingInstance.Update()
            Write-Host -ForegroundColor White " - Starting local Analytics Data Processing Service instance..."
            $analyticsDataProcessingInstance.Provision()
            If ($null -eq $getWebAnalyticsServiceApplication)
            {
                $stagerSubscription = "<StagingDatabases><StagingDatabase ServerName='$dbServer' DatabaseName='$webAnalyticsStagingDB'/></StagingDatabases>"
                $warehouseSubscription = "<ReportingDatabases><ReportingDatabase ServerName='$dbServer' DatabaseName='$webAnalyticsReportingDB'/></ReportingDatabases>"
                Write-Host -ForegroundColor White " - Creating $webAnalyticsServiceName..."
                $serviceApplication = New-SPWebAnalyticsServiceApplication -Name $webAnalyticsServiceName -ReportingDataRetention 20 -SamplingRate 100 -ListOfReportingDatabases $warehouseSubscription -ListOfStagingDatabases $stagerSubscription -ApplicationPool $applicationPool
                # Create Web Analytics Service Application Proxy
                Write-Host -ForegroundColor White " - Creating $webAnalyticsServiceName Proxy..."
                New-SPWebAnalyticsServiceApplicationProxy  -Name $webAnalyticsServiceName -ServiceApplication $serviceApplication.Name | Out-Null
            }
            Else
            {
                Write-Host -ForegroundColor White " - Web Analytics Service Application already provisioned."
            }
        }
        Catch
        {
            Write-Output $_
            Throw " - Error Provisioning Web Analytics Service Application"
        }
        WriteLine
    }
}
#endregion

#region Create Secure Store Service Application
Function CreateSecureStoreServiceApp ($xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    # Secure Store Service Application will be provisioned even if it's been marked false, if any of these service apps have been requested (and for the correct version of SharePoint), as it's a dependency.
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.SecureStoreService -eq $true) -or `
        ((ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices -eq $true) -and ($spYear -le 2013)) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.VisioService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.ServiceApps.BusinessDataConnectivity -eq $true) -or `
        ((ShouldIProvision $xmlInput.Configuration.OfficeWebApps.ExcelService -eq $true) -and ($xmlInput.Configuration.OfficeWebApps.Install -eq $true)) `
       )
    {
        WriteLine
        Try
        {
            $serviceConfig = $xmlInput.Configuration.ServiceApps.SecureStoreService
            If (!($farmPassphrase) -or ($farmPassphrase -eq ""))
            {
                $farmPassphrase = GetFarmPassPhrase $xmlInput
            }
            $secureStoreServiceAppName = $xmlInput.Configuration.ServiceApps.SecureStoreService.Name
            $secureStoreServiceAppProxyName = $xmlInput.Configuration.ServiceApps.SecureStoreService.ProxyName
            If ($null -eq $secureStoreServiceAppName)
            {
                $secureStoreServiceAppName = "Secure Store Service"
            }
            If ($null -eq $secureStoreServiceAppProxyName)
            {
                $secureStoreServiceAppProxyName = $secureStoreServiceAppName
            }
            $dbServer = $xmlInput.Configuration.ServiceApps.SecureStoreService.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $dbPrefix = Get-DBPrefix $xmlInput
            $secureStoreDB = $dbPrefix + $xmlInput.Configuration.ServiceApps.SecureStoreService.Database.Name
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
            if ($usingSQLAuthentication)
            {
                Write-Host -ForegroundColor White " - Creating SQL credential object..."
                $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseCredentialsParameter = @{}
            }
            Write-Host -ForegroundColor White " - Provisioning Secure Store Service Application..."
            $applicationPool = Get-HostedServicesAppPool $xmlInput
            # Get the service instance
            $secureStoreServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance])}
            $secureStoreServiceInstance = $secureStoreServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find Secure Store service instance"
            }
            # Start Service instance
            If ($secureStoreServiceInstance.Status -eq "Disabled")
            {
                Write-Host -ForegroundColor White " - Starting Secure Store Service Instance..."
                $secureStoreServiceInstance.Provision()
                If (-not $?)
                {
                    Throw " - Failed to start Secure Store service instance"
                }
                # Wait
                Write-Host -ForegroundColor Cyan " - Waiting for Secure Store service..." -NoNewline
                While ($secureStoreServiceInstance.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $secureStoreServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.SecureStoreService.Server.SecureStoreServiceInstance"}
                    $secureStoreServiceInstance = $secureStoreServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black $($secureStoreServiceInstance.Status)
            }
            # Create Service Application
            $getSPSecureStoreServiceApplication = Get-SPServiceApplication | Where-Object {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])}
            If ($null -eq $getSPSecureStoreServiceApplication)
            {
                Write-Host -ForegroundColor White " - Creating Secure Store Service Application..."
                New-SPSecureStoreServiceApplication -Name $secureStoreServiceAppName -PartitionMode:$false -Sharing:$false -DatabaseServer $dbServer -DatabaseName $secureStoreDB -ApplicationPool $($applicationPool.Name) -AuditingEnabled:$true -AuditLogMaxSize 30 @databaseCredentialsParameter | Out-Null
                Write-Host -ForegroundColor White " - Creating Secure Store Service Application Proxy..."
                Get-SPServiceApplication | Where-Object {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplication])} | New-SPSecureStoreServiceApplicationProxy -Name $secureStoreServiceAppProxyName -DefaultProxyGroup | Out-Null
                Write-Host -ForegroundColor White " - Done creating Secure Store Service Application."
            }
            Else
            {
                Write-Host -ForegroundColor White " - Secure Store Service Application already provisioned."
            }

            $secureStore = Get-SPServiceApplicationProxy | Where-Object {$_.GetType().Equals([Microsoft.Office.SecureStoreService.Server.SecureStoreServiceApplicationProxy])}
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Master Key..."
            Update-SPSecureStoreMasterKey -ServiceApplicationProxy $secureStore.Id -Passphrase $farmPassphrase
            Start-Sleep 5
            Write-Host -ForegroundColor White " - Creating the Application Key..."
            Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase $farmPassphrase -ErrorAction SilentlyContinue
            Start-Sleep 5
            If (!$?)
            {
                # Try again...
                Write-Host -ForegroundColor White " - Creating the Application Key (2nd attempt)..."
                Update-SPSecureStoreApplicationServerKey -ServiceApplicationProxy $secureStore.Id -Passphrase $farmPassphrase
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
#endregion

#region Start Search Query and Site Settings Service
Function StartSearchQueryAndSiteSettingsService ([xml]$xmlInput)
{
    If (ShouldIProvision $xmlInput.Configuration.Farm.Services.SearchQueryAndSiteSettingsService -eq $true)
    {
        WriteLine
        Try
        {
            # Get the service instance
            $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
            $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?)
            {
                Throw " - Failed to find Search Query and Site Settings service instance"
            }
            # Start Service instance
            Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
            If ($searchQueryAndSiteSettingsService.Status -eq "Disabled")
            {
                $searchQueryAndSiteSettingsService.Provision()
                If (-not $?)
                {
                    Throw " - Failed to start Search Query and Site Settings service instance"
                }
                # Wait
                Write-Host -ForegroundColor Cyan " - Waiting for Search Query and Site Settings service..." -NoNewline
                While ($searchQueryAndSiteSettingsService.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                    $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black $($searchQueryAndSiteSettingsService.Status)
            }
            Else
            {
                Write-Host -ForegroundColor White " - Search Query and Site Settings Service already started."
            }
        }
        Catch
        {
            Write-Output $_
            Throw " - Error provisioning Search Query and Site Settings Service"
        }
        WriteLine
    }
}
#endregion

#region Configure Claims to Windows Token Service
Function ConfigureClaimsToWindowsTokenService ([xml]$xmlInput)
{
    # C2WTS is required by Excel Services, Visio Services and PerformancePoint Services; if any of these are being provisioned we should start it.
    If ((ShouldIProvision $xmlInput.Configuration.Farm.Services.ClaimsToWindowsTokenService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.VisioService -eq $true) -or `
        (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService -eq $true) -or `
        ((ShouldIProvision $xmlInput.Configuration.OfficeWebApps.ExcelService -eq $true) -and ($xmlInput.Configuration.OfficeWebApps.Install -eq $true)))
    {
        WriteLine
        # Ensure Claims to Windows Token Service is started
        $claimsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
        $claimsService = $claimsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
        If ($claimsService.Status -ne "Online")
        {
            Try
            {
                Write-Host -ForegroundColor White " - Starting $($claimsService.DisplayName)..."
                if ($xmlInput.Configuration.Farm.Services.ClaimsToWindowsTokenService.UpdateAccount -eq $true)
                {
                    UpdateProcessIdentity $claimsService
                    $claimsService.Update()
                    # Add C2WTS account (currently the generic service account) to local admins
                    $builtinAdminGroup = Get-AdministratorsGroup
                    $adminGroup = ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group")
                    # This syntax comes from Ying Li (http://myitforum.com/cs2/blogs/yli628/archive/2007/08/30/powershell-script-to-add-remove-a-domain-user-to-the-local-administrators-group-on-a-remote-machine.aspx)
                    $localAdmins = $adminGroup.psbase.invoke("Members") | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
                    $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
                    $managedAccountGen = Get-SPManagedAccount | Where-Object {$_.UserName -eq $($spservice.username)}
                    $managedAccountDomain,$managedAccountUser = $managedAccountGen.UserName -split "\\"
                    If (!($localAdmins -contains $managedAccountUser))
                    {
                        Write-Host -ForegroundColor White " - Adding $($managedAccountGen.Username) to local Administrators..."
                        ([ADSI]"WinNT://$env:COMPUTERNAME/$builtinAdminGroup,group").Add("WinNT://$managedAccountDomain/$managedAccountUser")
                    }
                }
                $claimsService.Provision()
                $claimsService | Start-SPServiceInstance
                If (-not $?)
                {
                    throw " - Failed to start $($claimsService.DisplayName)"
                }
            }
            Catch
            {
                Throw " - An error occurred starting $($claimsService.DisplayName)"
            }
            #Wait
            Write-Host -ForegroundColor Cyan " - Waiting for $($claimsService.DisplayName)..." -NoNewline
            While ($claimsService.Status -ne "Online")
            {
                Write-Host -ForegroundColor Cyan "." -NoNewline
                Start-Sleep -Seconds 1
                $claimsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.Administration.Claims.SPWindowsTokenServiceInstance"}
                $claimsService = $claimsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            }
            Write-Host -BackgroundColor Green -ForegroundColor Black $($claimsService.Status)
        }
        Else
        {
            Write-Host -ForegroundColor White " - $($claimsService.DisplayName) already started."
        }
        Write-Host -ForegroundColor White " - Setting C2WTS to depend on Cryptographic Services..."
        Start-Process -FilePath "$env:windir\System32\sc.exe" -ArgumentList "config c2wts depend= CryptSvc" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        WriteLine
    }
}
#endregion

#region Stop Specified Service Instance
# ===================================================================================
# Func: StopServiceInstance
# Desc: Disables a specified service instance (e.g. on dedicated App servers or WFEs)
# ===================================================================================
Function StopServiceInstance ($service)
{
    WriteLine
    $serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $service -and $_.Name -ne "WSS_Administration"} # Need to filter out WSS_Administration because the Central Administration service instance shares the same Type as the Foundation Web Application Service
    $serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
    Write-Host -ForegroundColor White " - Stopping $($serviceInstance.TypeName)..."
    if ($serviceInstance.Status -eq "Online")
    {
        $serviceInstance.Unprovision()
        If (-not $?)
        {
            Throw " - Failed to stop $($serviceInstance.TypeName)"
        }
        # Wait
        Write-Host -ForegroundColor Cyan " - Waiting for $($serviceInstance.TypeName) to stop..." -NoNewline
        While ($serviceInstance.Status -ne "Disabled")
        {
            Write-Host -ForegroundColor Cyan "." -NoNewline
            Start-Sleep 1
            $serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $service}
            $serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
        }
        Write-Host -BackgroundColor Green -ForegroundColor Black $($serviceInstance.Status -replace "Disabled","Stopped")
    }
    Else
    {
        Write-Host -ForegroundColor White " - Already stopped."
    }
    WriteLine
}
#endregion

#region Configure Workflow Timer Service
# ===================================================================================
# Func: ConfigureWorkflowTimerService
# Desc: Configures the Microsoft SharePoint Foundation Workflow Timer Service
# ===================================================================================
Function ConfigureWorkflowTimerService ([xml]$xmlInput)
{
    # Ensure the node exists in the XML first as we don't want to inadvertently disable the service if it wasn't explicitly specified
    if (($xmlInput.Configuration.Farm.Services.SelectSingleNode("WorkflowTimer")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.WorkflowTimer -eq $true))
    {
        StopServiceInstance "Microsoft.SharePoint.Workflow.SPWorkflowTimerServiceInstance"
    }
}
#endregion

#region Configure Foundation Search
# ====================================================================================
# Func: ConfigureFoundationSearch
# Desc: Updates the service account for SPSearch4 (SharePoint Foundation (Help) Search)
# ====================================================================================

Function ConfigureFoundationSearch ([xml]$xmlInput)
# Does not actually provision Foundation Search as of yet, just updates the service account it would run under to mitigate Health Analyzer warnings
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    # Make sure a credential deployment job doesn't already exist, and that we are running SP2010
    if ((!(Get-SPTimerJob -Identity "windows-service-credentials-SPSearch4")) -and ($spYear -eq 2010))
    {
        WriteLine
        Try
        {
            $foundationSearchService = (Get-SPFarm).Services | Where-Object {$_.Name -eq "SPSearch4"}
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
#endregion

#region Configure SPTraceV4 (Logging)
# ====================================================================================
# Func: ConfigureTracing
# Desc: Updates the service account for SPTraceV4 (SharePoint Foundation (Help) Search)
# ====================================================================================

Function ConfigureTracing ([xml]$xmlInput)
{
    # Make sure a credential deployment job doesn't already exist
    if (!(Get-SPTimerJob -Identity "windows-service-credentials-SPTraceV4"))
    {
        WriteLine
        $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
        $spTraceV4 = (Get-SPFarm).Services | Where-Object {$_.Name -eq "SPTraceV4"}
        $appPoolAcctDomain,$appPoolAcctUser = $spservice.username -Split "\\"
        Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service SPTraceV4..."
        #Add to Performance Monitor Users group
        Write-Host -ForegroundColor White " - Adding $($spservice.username) to local Performance Monitor Users group..."
        Try
        {
            ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Monitor Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
            If (-not $?)
            {
                Throw
            }
        }
        Catch
        {
            Write-Host -ForegroundColor White " - $($spservice.username) is already a member of Performance Monitor Users."
        }
        #Add all managed accounts to Performance Log Users group
        foreach ($managedAccount in (Get-SPManagedAccount))
        {
            $appPoolAcctDomain,$appPoolAcctUser = $managedAccount.UserName -Split "\\"
            Write-Host -ForegroundColor White " - Adding $($managedAccount.UserName) to local Performance Log Users group..."
            Try
            {
                ([ADSI]"WinNT://$env:COMPUTERNAME/Performance Log Users,group").Add("WinNT://$appPoolAcctDomain/$appPoolAcctUser")
                If (-not $?)
                {
                    Throw
                }
            }
            Catch
            {
                Write-Host -ForegroundColor White "  - $($managedAccount.UserName) is already a member of Performance Log Users."
            }
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
        # Restart SPTraceV4 service so changes to group memberships above can take effect
        Write-Host -ForegroundColor White " - Restarting service SPTraceV4..."
        Restart-Service -Name "SPTraceV4" -Force
        WriteLine
    }
    else
    {
        Write-Warning "Timer job `"windows-service-credentials-SPTraceV4`" already exists."
        Write-Host -ForegroundColor Yellow "Check that $($spservice.username) is a member of the Performance Log Users and Performance Monitor Users local groups once install completes."
    }
}
#endregion

#region Configure Distributed Cache Service
# ====================================================================================
# Func: ConfigureDistributedCacheService
# Desc: Updates the service account for AppFabricCachingService AKA Distributed Caching Service AKA SPCache
# Info: http://technet.microsoft.com/en-us/library/jj219613.aspx
# ====================================================================================

Function ConfigureDistributedCacheService ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    if ($spYear -eq "SE") # SharePoint Subscription Edition (SPSE)
    {
        $cacheServiceName = "SPCache"
    }
    else # Just use the old name
    {
        $cacheServiceName = "AppFabricCachingService"
    }
    # Make sure a credential deployment job doesn't already exist, and that we are running SP2013 at minimum
    if ((!(Get-SPTimerJob -Identity "windows-service-credentials-AppFabricCachingService")) -and ($spVer -ge 15))
    {
        WriteLine
        $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
        $distributedCachingSvc = (Get-SPFarm).Services | Where-Object {$_.Name -eq "$cacheServiceName"}
        if ($null -eq $distributedCachingSvc)
        {
            $distributedCachingSvc = (Get-SPFarm).Services | Where-Object {$_.Name -eq "SPCache"}
        }
        # Check if we should disable the Distributed Cache service on the local server
        # Ensure the node exists in the XML first as we don't want to inadvertently disable the service if it wasn't explicitly specified
        $serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.DistributedCaching.Utilities.SPDistributedCacheServiceInstance"}
        $serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
        # Check if we are installing SharePoint 2016 and have requested a MinRole that requires (or complies with) Distributed Cache
        if ($spVer -ge 16)
        {
            # DistributedCache and SingleServerFarm Minroles require Distributed Cache to be provisioned locally
            if ((ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.DistributedCache)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServerFarm)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServer)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEndWithDistributedCache)))
            {
                $distributedCache2016Stop = $false
            }
            # Check if we have requested both Custom Minrole and local Distributed Cache provisioning in the XML
            elseif (($xmlInput.Configuration.Farm.Services.SelectSingleNode("DistributedCache")) -and (ShouldIProvision $xmlInput.Configuration.Farm.Services.DistributedCache -eq $true) -and (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Custom)))
            {
                $distributedCache2016Stop = $false
            }
            # Otherwise we should be stopping the Distributed Cache
            else
            {
                $distributedCache2016Stop = $true
            }
            # Check if Feature Pack 1 (November 2106 PU) for SharePoint 2016 is installed
            if (CheckForSP2016FeaturePack1 -xmlInput $xmlInput)
            {
                # Check if we are requesting a Single Server Farm
                if ((ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServerFarm)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServer)))
                {
                    $distributedCacheSingleServerFarmSwitch = @{Role = "SingleServerFarm"}
                }
                elseif (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEndWithDistributedCache))
                {
                    $distributedCacheSingleServerFarmSwitch = @{Role = "WebFrontEndWithDistributedCache"}
                }
            }
            else
            {
                $distributedCacheSingleServerFarmSwitch = @{}
            }
        }
        else
        {
            if (($xmlInput.Configuration.Farm.Services.SelectSingleNode("DistributedCache")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.DistributedCache -eq $true))
            {
                $distributedCache2013Stop = $true
            }
        }
        # New additional check for $distributedCache2016Stop flag - because we will need to ensure DC doesn't get stopped if we are running certain MinRoles in SP2016
        if ($distributedCache2013Stop -or $distributedCache2016Stop)
        {
            Write-Host -ForegroundColor White " - Stopping the Distributed Cache service..." -NoNewline
            if ($serviceInstance.Status -eq "Online")
            {
                Stop-SPDistributedCacheServiceInstance -Graceful
                Remove-SPDistributedCacheServiceInstance
                Write-Host -ForegroundColor Green "Done."
            }
            else
            {
                Write-Host -ForegroundColor White "Already stopped."
            }
        }
        # Otherwise, make sure it's started, and set it to run under a different account
        else
        {
            # Ensure the local Distributed Cache service is actually running
            if ($serviceInstance.Status -ne "Online")
            {
                Write-Host -ForegroundColor White " - Starting the Distributed Cache service..." -NoNewline
                Add-SPDistributedCacheServiceInstance @distributedCacheSingleServerFarmSwitch
                Write-Host -ForegroundColor Green "Done."
            }
            $appPoolAcctDomain,$appPoolAcctUser = $spservice.username -Split "\\"
            Write-Host -ForegroundColor White " - Applying service account $($spservice.username) to service $cacheServiceName..."
            Try
            {
                UpdateProcessIdentity $distributedCachingSvc
            }
            Catch
            {
                Write-Output $_
                Write-Warning "An error occurred updating the service account for service $cacheServiceName."
            }
        }
        WriteLine
    }
}
#endregion

#region Provision Enterprise Search
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

function CreateEnterpriseSearchServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $searchServiceAccount = Get-SPManagedAccountXML $xmlInput -CommonName "SearchService"
    # Check if the Search Service account username has been specified before we try to convert its password to a secure string
    if (!([string]::IsNullOrEmpty($searchServiceAccount.Username)))
    {
        $secSearchServicePassword = ConvertTo-SecureString -String $searchServiceAccount.Password -AsPlainText -Force
    }
    else
    {
        Write-Host -ForegroundColor White " - Managed account credentials for Search Service have not been specified."
    }
    # We now do a check that both Search is being requested for provisioning and that we are not running the Foundation SKU
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.EnterpriseSearchService -eq $true) -and (Get-Command -Name New-SPEnterpriseSearchServiceApplication -ErrorAction SilentlyContinue) -and ($xmlInput.Configuration.Install.SKU -ne "Foundation"))
    {
        WriteLine
        Write-Host -ForegroundColor White " - Provisioning Enterprise Search..."
        # SLN: Added support for local host
        $svcConfig = $xmlInput.Configuration.ServiceApps.EnterpriseSearchService
        if ($xmlInput.Configuration.ServiceApps.UserProfileServiceApp.Provision -ne $false) # We didn't use ShouldIProvision here as we want to know if UPS is being provisioned in this farm, not just on this server
        {
            $mySiteWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "MySiteHost"}
            # If we have asked to create a MySite Host web app, use that as the MySite host location
            if ($mySiteWebApp)
            {
                $mySiteURL = ($mySiteWebApp.URL).TrimEnd("/")
                $mySitePort = $mySiteWebApp.Port
                $mySiteHostLocation = $mySiteURL+":"+$mySitePort
            }
            else # Use the value provided in the $userProfile node
            {
                $mySiteHostLocation = $xmlInput.Configuration.ServiceApps.UserProfileServiceApp.MySiteHostLocation
            }
            # Strip out any protocol values
            $mySiteHostHeaderAndPort,$null = $mySiteHostLocation -replace "http://","" -replace "https://","" -split "/"
        }

        $dataDir = $xmlInput.Configuration.Install.DataDir
        $dataDir = $dataDir.TrimEnd("\")
        # Set it to the default value if it's not specified in $xmlInput
        if ([string]::IsNullOrEmpty($dataDir)) {$dataDir = "$env:ProgramFiles\Microsoft Office Servers\$spVer.0\Data"}

        $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
        If ($null -eq $searchSvc)
        {
            Throw "  - Unable to retrieve search service."
        }
        if ([string]::IsNullOrEmpty($svcConfig.CustomIndexLocation))
        {
            # Use the default location
            $indexLocation = "$dataDir\Office Server\Applications"
        }
        else
        {
            $indexLocation = $svcConfig.CustomIndexLocation
            $indexLocation = $indexLocation.TrimEnd("\")
            # If the requested index location is not the default, make sure the new location exists so we can use it later in the script
            if ($indexLocation -ne "$dataDir\Office Server\Applications")
            {
                Write-Host -ForegroundColor White " - Checking requested IndexLocation path..."
                EnsureFolder $svcConfig.CustomIndexLocation
            }
        }
        Write-Host -ForegroundColor White "  - Configuring search service..." -NoNewline
        Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService  `
          -ContactEmail $svcConfig.ContactEmail -ConnectionTimeout $svcConfig.ConnectionTimeout `
          -AcknowledgementTimeout $svcConfig.AcknowledgementTimeout -ProxyType $svcConfig.ProxyType `
          -IgnoreSSLWarnings $svcConfig.IgnoreSSLWarnings -InternetIdentity $svcConfig.InternetIdentity -PerformanceLevel $svcConfig.PerformanceLevel `
          -ServiceAccount $searchServiceAccount.Username -ServicePassword $secSearchServicePassword
        If ($?) {Write-Host -ForegroundColor Green "Done."}


        If ($spYear -eq 2010) # SharePoint 2010 steps
        {
            $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication | ForEach-Object {
                $appConfig = $_
                $dbPrefix = Get-DBPrefix $xmlInput
                If (!([string]::IsNullOrEmpty($appConfig.Database.DBServer)))
                {
                    $dbServer = $appConfig.Database.DBServer
                }
                Else
                {
                    $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
                }
                # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
                if ($appConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true")
                {
                    $databaseUsernameParameter = @{DatabaseUsername = $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName}
                    $databasePasswordParameter = @{DatabasePassword = ConvertTo-SecureString -String $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword -AsPlainText -Force}
                }
                else # Otherwise assume Windows integrated and no database credentials provided
                {
                    $databaseUsernameParameter = @{}
                    $databasePasswordParameter = @{}
                }
                $secContentAccessAcctPWD = ConvertTo-SecureString -String $appConfig.ContentAccessAccountPassword -AsPlainText -Force
                # Try and get the application pool if it already exists
                $pool = Get-ApplicationPool $appConfig.ApplicationPool
                $adminPool = Get-ApplicationPool $appConfig.AdminComponent.ApplicationPool
                $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name -ErrorAction SilentlyContinue
                If ($null -eq $searchApp)
                {
                    Write-Host -ForegroundColor White " - Creating $($appConfig.Name)..."
                    $searchApp = New-SPEnterpriseSearchServiceApplication -Name $appConfig.Name `
                        -DatabaseServer $dbServer `
                        -DatabaseName $($dbPrefix+$appConfig.Database.Name) `
                        -FailoverDatabaseServer $appConfig.FailoverDatabaseServer `
                        -ApplicationPool $pool `
                        -AdminApplicationPool $adminPool `
                        -Partitioned:([bool]::Parse($appConfig.Partitioned)) `
                        -SearchApplicationType $appConfig.SearchServiceApplicationType `
                        @databaseUsernameParameter `
                        @databasePasswordParameter
                }
                Else
                {
                    Write-Host -ForegroundColor White " - Enterprise search service application already exists, skipping creation."
                }

                # Add link to resources list
                AddResourcesLink "Search Administration" ("searchadministration.aspx?appid=" +  $searchApp.Id)

                # If the index location isn't already set to either the default location or our custom-specified location, set the default location for the search service instance
                if ($indexLocation -ne "$dataDir\Office Server\Applications" -or $indexLocation -ne $searchSvc.DefaultIndexLocation)
                {
                    Write-Host -ForegroundColor White "  - Setting default index location on search service instance..." -NoNewline
                    $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $indexLocation -ErrorAction SilentlyContinue
                    if ($?) {Write-Host -ForegroundColor White "OK."}
                }

                # Finally using ShouldIProvision here like everywhere else in the script...
                $installCrawlSvc = ShouldIProvision $appConfig.CrawlComponent
                $installQuerySvc = ShouldIProvision $appConfig.QueryComponent
                $installAdminComponent = ShouldIProvision $appConfig.AdminComponent
                $installSyncSvc = ShouldIProvision $appConfig.SearchQueryAndSiteSettingsComponent

                If ($searchSvc.Status -ne "Online" -and ($installCrawlSvc -or $installQuerySvc)) {
                    $searchSvc | Start-SPEnterpriseSearchServiceInstance
                }

                If ($installAdminComponent) {
                    Write-Host -ForegroundColor White " - Setting administration component..."
                    Set-SPEnterpriseSearchAdministrationComponent -SearchApplication $searchApp -SearchServiceInstance $searchSvc

                    $adminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
                    If ($adminCmpnt.Initialized -eq $false)
                    {
                        Write-Host -ForegroundColor Cyan " - Waiting for administration component initialization..." -NoNewline
                        While ($adminCmpnt.Initialized -ne $true)
                        {
                            Write-Host -ForegroundColor Cyan "." -NoNewline
                            Start-Sleep 1
                            $adminCmpnt = $searchApp | Get-SPEnterpriseSearchAdministrationComponent
                        }
                        Write-Host -BackgroundColor Green -ForegroundColor Black $($adminCmpnt.Initialized -replace "True","Done.")
                    }
                    Else {Write-Host -ForegroundColor White " - Administration component already initialized."}
                }
                # Update the default Content Access Account
                Update-SearchContentAccessAccount $($appconfig.Name) $searchApp $($appConfig.ContentAccessAccount) $secContentAccessAcctPWD


                $crawlTopology = Get-SPEnterpriseSearchCrawlTopology -SearchApplication $searchApp | Where-Object {$_.CrawlComponents.Count -gt 0 -or $_.State -eq "Inactive"}

                If ($null -eq $crawlTopology)
                {
                    Write-Host -ForegroundColor White " - Creating new crawl topology..."
                    $crawlTopology = $searchApp | New-SPEnterpriseSearchCrawlTopology
                } Else {
                    Write-Host -ForegroundColor White " - A crawl topology with crawl components already exists, skipping crawl topology creation."
                }

                If ($installCrawlSvc)
                {
                    $crawlComponent = $crawlTopology.CrawlComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    If ($crawlTopology.CrawlComponents.Count -eq 0 -or $null -eq $crawlComponent) {
                        $crawlStore = $searchApp.CrawlStores | Where-Object {$_.Name -eq "$($dbPrefix+$appConfig.Database.Name)_CrawlStore"}
                        Write-Host -ForegroundColor White " - Creating new crawl component..."
                        $crawlComponent = New-SPEnterpriseSearchCrawlComponent -SearchServiceInstance $searchSvc -SearchApplication $searchApp -CrawlTopology $crawlTopology -CrawlDatabase $crawlStore.Id.ToString() -IndexLocation $indexLocation
                    } Else {
                        Write-Host -ForegroundColor White " - Crawl component already exist, skipping crawl component creation."
                    }
                }

                $queryTopologies = Get-SPEnterpriseSearchQueryTopology -SearchApplication $searchApp | Where-Object {$_.QueryComponents.Count -gt 0 -or $_.State -eq "Inactive"}
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
                    $queryComponent = $queryTopology.QueryComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    If ($null -eq $queryComponent) {
                        $partition = ($queryTopology | Get-SPEnterpriseSearchIndexPartition)
                        Write-Host -ForegroundColor White " - Creating new query component..."
                        $queryComponent = New-SPEnterpriseSearchQueryComponent -IndexPartition $partition -QueryTopology $queryTopology -SearchServiceInstance $searchSvc -ShareName $svcConfig.ShareName -IndexLocation $indexLocation
                        Write-Host -ForegroundColor White " - Setting index partition and property store database..."
                        $propertyStore = $searchApp.PropertyStores | Where-Object {$_.Name -eq "$($dbPrefix+$appConfig.Database.Name)_PropertyStore"}
                        $partition | Set-SPEnterpriseSearchIndexPartition -PropertyDatabase $propertyStore.Id.ToString()
                    } Else {
                        Write-Host -ForegroundColor White " - Query component already exists, skipping query component creation."
                    }
                }

                If ($installSyncSvc) {
                    # SLN: Updated to new syntax
                    $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                    $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                    If (-not $?) { Throw " - Failed to find Search Query and Site Settings service instance" }
                    # Start Service instance
                    Write-Host -ForegroundColor White " - Starting Search Query and Site Settings Service Instance..."
                    If ($searchQueryAndSiteSettingsService.Status -eq "Disabled")
                    {
                        $searchQueryAndSiteSettingsService.Provision()
                        If (-not $?) { Throw " - Failed to start Search Query and Site Settings service instance" }
                        # Wait
                        Write-Host -ForegroundColor Cyan " - Waiting for Search Query and Site Settings service..." -NoNewline
                        While ($searchQueryAndSiteSettingsService.Status -ne "Online")
                        {
                            Write-Host -ForegroundColor Cyan "." -NoNewline
                            Start-Sleep 1
                            $searchQueryAndSiteSettingsServices = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.Search.Administration.SearchQueryAndSiteSettingsServiceInstance"}
                            $searchQueryAndSiteSettingsService = $searchQueryAndSiteSettingsServices | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                        }
                        Write-Host -BackgroundColor Green -ForegroundColor Black $($searchQueryAndSiteSettingsService.Status)
                    }
                    Else {Write-Host -ForegroundColor White " - Search Query and Site Settings Service already started."}
                    }

                # Don't activate until we've added all components
                $allCrawlServersDone = $true
                # Put any comma- or space-delimited servers we find in the "Provision" attribute into an array
                [array]$crawlServersToProvision = $appConfig.CrawlComponent.Provision -split "," -split " "
                $crawlServersToProvision | ForEach-Object {
                    $crawlServer = $_
                    $top = $crawlTopology.CrawlComponents | Where-Object {$_.ServerName -eq $crawlServer}
                    If ($null -eq $top)
                    {
                        $allCrawlServersDone = $false
                    }
                }

                If ($allCrawlServersDone -and $crawlTopology.State -ne "Active") {
                    Write-Host -ForegroundColor White " - Setting new crawl topology to active..."
                    $crawlTopology | Set-SPEnterpriseSearchCrawlTopology -Active -Confirm:$false
                    Write-Host -ForegroundColor Cyan " - Waiting for Crawl Components..." -NoNewLine
                    while ($true)
                    {
                        $ct = Get-SPEnterpriseSearchCrawlTopology -Identity $crawlTopology -SearchApplication $searchApp
                        $state = $ct.CrawlComponents | Where-Object {$_.State -ne "Ready"}
                        If ($ct.State -eq "Active" -and $null -eq $state)
                        {
                            break
                        }
                        Write-Host -ForegroundColor Cyan "." -NoNewLine
                        Start-Sleep 1
                    }
                    Write-Host -BackgroundColor Green -ForegroundColor Black $($crawlTopology.State)

                    # Need to delete the original crawl topology that was created by default
                    $searchApp | Get-SPEnterpriseSearchCrawlTopology | Where-Object {$_.State -eq "Inactive"} | Remove-SPEnterpriseSearchCrawlTopology -Confirm:$false
                }

                $allQueryServersDone = $true
                # Put any comma- or space-delimited servers we find in the "Provision" attribute into an array
                [array]$queryServersToProvision = $appConfig.QueryComponent.Provision -split "," -split " "
                $queryServersToProvision | ForEach-Object {
                    $queryServer = $_
                    $top = $queryTopology.QueryComponents | Where-Object {$_.ServerName -eq $queryServer}
                    If ($null -eq $top) { $allQueryServersDone = $false }
                }

                # Make sure we have a crawl component added and started before trying to enable the query component
                If ($allCrawlServersDone -and $allQueryServersDone -and $queryTopology.State -ne "Active") {
                    Write-Host -ForegroundColor White " - Setting query topology as active..."
                    $queryTopology | Set-SPEnterpriseSearchQueryTopology -Active -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable err
                    Write-Host -ForegroundColor Cyan " - Waiting for Query Components..." -NoNewLine
                    while ($true)
                    {
                        $qt = Get-SPEnterpriseSearchQueryTopology -Identity $queryTopology -SearchApplication $searchApp
                        $state = $qt.QueryComponents | Where-Object {$_.State -ne "Ready"}
                        If ($qt.State -eq "Active" -and $null -eq $state)
                        {
                            break
                        }
                        Write-Host -ForegroundColor Cyan "." -NoNewLine
                        Start-Sleep 1
                    }
                    Write-Host -BackgroundColor Green -ForegroundColor Black $($queryTopology.State)

                    # Need to delete the original query topology that was created by default
                    $origQueryTopology = $searchApp | Get-SPEnterpriseSearchQueryTopology | Where-Object {$_.QueryComponents.Count -eq 0}
                    If ($origQueryTopology.State -eq "Inactive")
                    {
                        Write-Host -ForegroundColor White " - Removing original (default) query topology..."
                        $origQueryTopology | Remove-SPEnterpriseSearchQueryTopology -Confirm:$false
                    }
                }

                $proxy = Get-SPEnterpriseSearchServiceApplicationProxy -Identity $appConfig.Proxy.Name -ErrorAction SilentlyContinue
                If ($null -eq $proxy) {
                    Write-Host -ForegroundColor White " - Creating enterprise search service application proxy..."
                    $proxy = New-SPEnterpriseSearchServiceApplicationProxy -Name $appConfig.Proxy.Name -SearchApplication $searchApp -Partitioned:([bool]::Parse($appConfig.Proxy.Partitioned))
                } Else {
                    Write-Host -ForegroundColor White " - Enterprise search service application proxy already exists, skipping creation."
                }
                If ($proxy.Status -ne "Online") {
                    $proxy.Status = "Online"
                    $proxy.Update()
                }
                Write-Host -ForegroundColor White " - Setting proxy group membership..."
                $proxy | Set-ProxyGroupsMembership $appConfig.Proxy
            }
            WriteLine
        }
        ElseIf ($spVer -ge 15) # SharePoint 2013+ steps
        {
            $svcConfig.EnterpriseSearchServiceApplications.EnterpriseSearchServiceApplication | ForEach-Object {
                $appConfig = $_
                $dbPrefix = Get-DBPrefix $xmlInput
                If (!([string]::IsNullOrEmpty($appConfig.Database.DBServer)))
                {
                    $dbServer = $appConfig.Database.DBServer
                }
                Else
                {
                    $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
                }
                # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
                if ($appConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true")
                {
                    $databaseUsernameParameter = @{DatabaseUsername = $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName}
                    $databasePasswordParameter = @{DatabasePassword = ConvertTo-SecureString -String $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword -AsPlainText -Force}
                }
                else # Otherwise assume Windows integrated and no database credentials provided
                {
                    $databaseUsernameParameter = @{}
                    $databasePasswordParameter = @{}
                }
                $secContentAccessAcctPWD = ConvertTo-SecureString -String $appConfig.ContentAccessAccountPassword -AsPlainText -Force

                # Finally using ShouldIProvision here like everywhere else in the script...
                $installCrawlComponent = ShouldIProvision $appConfig.CrawlComponent
                $installQueryComponent = ShouldIProvision $appConfig.QueryComponent
                $installAdminComponent = ShouldIProvision $appConfig.AdminComponent
                $installSyncSvc = ShouldIProvision $appConfig.SearchQueryAndSiteSettingsComponent
                $installAnalyticsProcessingComponent = ShouldIProvision $appConfig.AnalyticsProcessingComponent
                $installContentProcessingComponent = ShouldIProvision $appConfig.ContentProcessingComponent
                $installIndexComponent = ShouldIProvision $appConfig.IndexComponent

                $pool = Get-ApplicationPool $appConfig.ApplicationPool
                $adminPool = Get-ApplicationPool $appConfig.AdminComponent.ApplicationPool
                $appPoolUserName = $searchServiceAccount.Username

                $saAppPool = Get-SPServiceApplicationPool -Identity $pool -ErrorAction SilentlyContinue
                if ($null -eq $saAppPool)
                {
                    Write-Host -ForegroundColor White "  - Creating Service Application Pool..."

                    $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -ErrorAction SilentlyContinue
                    if ($null -eq $appPoolAccount)
                    {
                        Write-Host -ForegroundColor White "  - Please supply the password for the Service Account..."
                        $appPoolCred = Get-Credential $appPoolUserName
                        $appPoolAccount = New-SPManagedAccount -Credential $appPoolCred -ErrorAction SilentlyContinue
                    }

                    $appPoolAccount = Get-SPManagedAccount -Identity $appPoolUserName -ErrorAction SilentlyContinue

                    if ($null -eq $appPoolAccount)
                    {
                        Throw "  - Cannot create or find the managed account $appPoolUserName, please ensure the account exists."
                    }

                    New-SPServiceApplicationPool -Name $pool -Account $appPoolAccount -ErrorAction SilentlyContinue | Out-Null
                }

                # From http://mmman.itgroove.net/2012/12/search-host-controller-service-in-starting-state-sharepoint-2013-8/
                # And http://blog.thewulph.com/?p=374
                Write-Host -ForegroundColor White "  - Fixing registry permissions for Search Host Controller Service..." -NoNewline
                $acl = Get-Acl HKLM:\System\CurrentControlSet\Control\ComputerName
                $person = [System.Security.Principal.NTAccount] "WSS_WPG" # Trimmed down from the original "Users"
                $access = [System.Security.AccessControl.RegistryRights]::FullControl
                $inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
                $propagation = [System.Security.AccessControl.PropagationFlags]::None
                $type = [System.Security.AccessControl.AccessControlType]::Allow
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule($person, $access, $inheritance, $propagation, $type)
                $acl.AddAccessRule($rule)
                Set-Acl HKLM:\System\CurrentControlSet\Control\ComputerName $acl
                Write-Host -ForegroundColor White "OK."

                Write-Host -ForegroundColor White "  - Checking Search Service Instance..." -NoNewline
                If ($searchSvc.Status -eq "Disabled")
                {
                    Write-Host -ForegroundColor White "Starting..." -NoNewline
                    $searchSvc | Start-SPEnterpriseSearchServiceInstance
                    If (!$?) {Throw "  - Could not start the Search Service Instance."}
                    # Wait
                    $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
                    While ($searchSvc.Status -ne "Online")
                    {
                        Write-Host -ForegroundColor Cyan "." -NoNewline
                        Start-Sleep 1
                        $searchSvc = Get-SPEnterpriseSearchServiceInstance -Local
                    }
                    Write-Host -BackgroundColor Green -ForegroundColor Black $($searchSvc.Status)
                }
                Else {Write-Host -ForegroundColor White "Already $($searchSvc.Status)."}

                if ($installSyncSvc)
                {
                    Write-Host -ForegroundColor White "  - Checking Search Query and Site Settings Service Instance..." -NoNewline
                    $searchQueryAndSiteSettingsService = Get-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance -Local
                    If ($searchQueryAndSiteSettingsService.Status -eq "Disabled")
                    {
                        Write-Host -ForegroundColor White "Starting..." -NoNewline
                        $searchQueryAndSiteSettingsService | Start-SPEnterpriseSearchQueryAndSiteSettingsServiceInstance
                        If (!$?) {Throw "  - Could not start the Search Query and Site Settings Service Instance."}
                        Write-Host -ForegroundColor Green $($searchQueryAndSiteSettingsService.Status)
                    }
                    Else {Write-Host -ForegroundColor White "Already $($searchQueryAndSiteSettingsService.Status)."}
                }

                Write-Host -ForegroundColor White "  - Checking Search Service Application..." -NoNewline
                $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name -ErrorAction SilentlyContinue
                If ($null -eq $searchApp)
                {
                    Write-Host -ForegroundColor White "Creating $($appConfig.Name)..." -NoNewline
                    $searchApp = New-SPEnterpriseSearchServiceApplication -Name $appConfig.Name `
                        -DatabaseServer $dbServer `
                        -DatabaseName $($dbPrefix+$appConfig.Database.Name) `
                        -FailoverDatabaseServer $appConfig.FailoverDatabaseServer `
                        -ApplicationPool $pool `
                        -AdminApplicationPool $adminPool `
                        -Partitioned:([bool]::Parse($appConfig.Partitioned)) `
                        @databaseUsernameParameter `
                        @databasePasswordParameter
                    If (!$?) {Throw "  - An error occurred creating the $($appConfig.Name) application."}
                    Write-Host -ForegroundColor Green "Done."
                }
                Else {Write-Host -ForegroundColor White "Already exists."}

                # Update the default Content Access Account
                Update-SearchContentAccessAccount $($appConfig.Name) $searchApp $($appConfig.ContentAccessAccount) $secContentAccessAcctPWD

                # If the index location isn't already set to either the default location or our custom-specified location, set the default location for the search service instance
                if ($indexLocation -ne "$dataDir\Office Server\Applications" -or $indexLocation -ne $searchSvc.DefaultIndexLocation)
                {
                    Write-Host -ForegroundColor White "  - Setting default index location on search service instance..." -NoNewline
                    $searchSvc | Set-SPEnterpriseSearchServiceInstance -DefaultIndexLocation $indexLocation -ErrorAction SilentlyContinue
                    if ($?) {Write-Host -ForegroundColor White "OK."}
                }

                # Look for a topology that has components, or is still Inactive, because that's probably our $clone
                $clone = $searchApp.Topologies | Where-Object {$_.ComponentCount -gt 0 -and $_.State -eq "Inactive"} | Select-Object -First 1
                if (!$clone)
                {
                    # Clone the active topology
                    Write-Host -ForegroundColor White "  - Cloning the active search topology..." -NoNewline
                    $activeTopology = Get-SPEnterpriseSearchTopology -SearchApplication $searchApp -Active
                    $clone = New-SPEnterpriseSearchTopology -SearchApplication $searchApp -Clone -SearchTopology $activeTopology
                    Write-Host -ForegroundColor White "OK."
                }
                else
                {
                    Write-Host -ForegroundColor White "  - Using existing cloned search topology."
                    # Since this clone probably doesn't have all its components added yet, we probably want to keep it if it isn't activated after this pass
                    $keepClone = $true
                }
                $activateTopology = $false
                # Check if each search component is already assigned to the current server, then check that it's actually being requested for the current server, then create it as required.
                Write-Host -ForegroundColor White "  - Checking admin component..." -NoNewline
                $adminComponents = $clone.GetComponents() | Where-Object {$_.Name -like "AdminComponent*"}
                If ($installAdminComponent)
                {
                    if (!($adminComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        New-SPEnterpriseSearchAdminComponent -SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $adminComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $adminComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($adminComponents) {Write-Host -ForegroundColor White "  - Admin component(s) already exist(s) in the farm."; $adminComponentReady = $true}

                Write-Host -ForegroundColor White "  - Checking content processing component..." -NoNewline
                $contentProcessingComponents = $clone.GetComponents() | Where-Object {$_.Name -like "ContentProcessingComponent*"}
                if ($installContentProcessingComponent)
                {
                    if (!($contentProcessingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        New-SPEnterpriseSearchContentProcessingComponent -SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $contentProcessingComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $contentProcessingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($contentProcessingComponents) {Write-Host -ForegroundColor White "  - Content processing component(s) already exist(s) in the farm."; $contentProcessingComponentReady = $true}

                Write-Host -ForegroundColor White "  - Checking analytics processing component..." -NoNewline
                $analyticsProcessingComponents = $clone.GetComponents() | Where-Object {$_.Name -like "AnalyticsProcessingComponent*"}
                if ($installAnalyticsProcessingComponent)
                {
                    if (!($analyticsProcessingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        New-SPEnterpriseSearchAnalyticsProcessingComponent -SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $analyticsProcessingComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $analyticsProcessingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($analyticsProcessingComponents) {Write-Host -ForegroundColor White "  - Analytics processing component(s) already exist(s) in the farm."; $analyticsProcessingComponentReady = $true}

                Write-Host -ForegroundColor White "  - Checking crawl component..." -NoNewline
                $crawlComponents = $clone.GetComponents() | Where-Object {$_.Name -like "CrawlComponent*"}
                if ($installCrawlComponent)
                {
                    if (!($crawlComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        New-SPEnterpriseSearchCrawlComponent -SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $crawlComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $crawlComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($crawlComponents) {Write-Host -ForegroundColor White "  - Crawl component(s) already exist(s) in the farm."; $crawlComponentReady = $true}

                Write-Host -ForegroundColor White "  - Checking index component..." -NoNewline
                $indexingComponents = $clone.GetComponents() | Where-Object {$_.Name -like "IndexComponent*"}
                if ($installIndexComponent)
                {
                    if (!($indexingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        # Specify the RootDirectory parameter only if it's different than the default path
                        if ($indexLocation -ne "$dataDir\Office Server\Applications")
                        {$rootDirectorySwitch = @{RootDirectory = $indexLocation}}
                        else {$rootDirectorySwitch = @{}}
                        New-SPEnterpriseSearchIndexComponent -SearchTopology $clone -SearchServiceInstance $searchSvc @rootDirectorySwitch | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $indexComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $indexingComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($indexingComponents) {Write-Host -ForegroundColor White "  - Index component(s) already exist(s) in the farm."; $indexComponentReady = $true}

                Write-Host -ForegroundColor White "  - Checking query processing component..." -NoNewline
                $queryComponents = $clone.GetComponents() | Where-Object {$_.Name -like "QueryProcessingComponent*"}
                if ($installQueryComponent)
                {
                    if (!($queryComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}))
                    {
                        Write-Host -ForegroundColor White "Creating..." -NoNewline
                        New-SPEnterpriseSearchQueryProcessingComponent -SearchTopology $clone -SearchServiceInstance $searchSvc | Out-Null
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            $componentsModified = $true
                        }
                    }
                    else {Write-Host -ForegroundColor White "Already exists on this server."}
                    $queryComponentReady = $true
                }
                else
                {
                    Write-Host -ForegroundColor White "Not requested for this server."
                    [array]$componentsToRemove = $queryComponents | Where-Object {$_.ServerName -eq $env:COMPUTERNAME}
                    if ($componentsToRemove)
                    {
                        foreach ($componentToRemove in $componentsToRemove)
                        {
                            Write-Host -ForegroundColor White "   - Removing component $($componentToRemove.ComponentId)..." -NoNewline
                            $componentToRemove | Remove-SPEnterpriseSearchComponent -SearchTopology $clone -Confirm:$false
                            If ($?)
                            {
                                Write-Host -ForegroundColor White "OK."
                                $componentsModified = $true
                            }
                        }
                    }
                    $componentsToRemove = $null
                }
                if ($queryComponents) {Write-Host -ForegroundColor White "  - Query component(s) already exist(s) in the farm."; $queryComponentReady = $true}

                $searchApp | Get-SPEnterpriseSearchAdministrationComponent | Set-SPEnterpriseSearchAdministrationComponent -SearchServiceInstance $searchSvc

                if ($adminComponentReady -and $contentProcessingComponentReady -and $analyticsProcessingComponentReady -and $indexComponentReady -and $crawlComponentReady -and $queryComponentReady) {$activateTopology = $true}
                # Check if any new search components were added (or if we have a clone with more components than the current active topology) and if we're ready to activate the topology
                if ($componentsModified -or ($clone.ComponentCount -gt $searchApp.ActiveTopology.ComponentCount))
                {
                    if ($activateTopology)
                    {
                        Write-Host -ForegroundColor White "  - Activating Search Topology..." -NoNewline
                        $clone.Activate()
                        If ($?)
                        {
                            Write-Host -ForegroundColor White "OK."
                            # Clean up original or previous unsuccessfully-provisioned search topologies
                            $inactiveTopologies = $searchApp.Topologies | Where-Object {$_.State -eq "Inactive"}
                            if ($null -ne $inactiveTopologies)
                            {
                                Write-Host -ForegroundColor White "  - Removing old, inactive search topologies:"
                                foreach ($inactiveTopology in $inactiveTopologies)
                                {
                                    Write-Host -ForegroundColor White "   -"$inactiveTopology.TopologyId.ToString()
                                    $inactiveTopology.Delete()
                                }
                            }
                        }
                    }
                    else
                    {
                        Write-Host -ForegroundColor White "  - Not activating topology yet as there seem to be components still pending."
                    }
                }
                elseif ($keepClone -ne $true) # Delete the newly-cloned topology since nothing was done
                # TODO: Check that the search topology is truly complete and there are no more servers to install
                {
                    Write-Host -ForegroundColor White "  - Deleting unneeded cloned topology..."
                    $clone.Delete()
                }
                # Clean up any empty, inactive topologies
                $emptyTopologies = $searchApp.Topologies | Where-Object {$_.ComponentCount -eq 0 -and $_.State -eq "Inactive"}
                if ($null -ne $emptyTopologies)
                {
                    Write-Host -ForegroundColor White "  - Removing empty and inactive search topologies:"
                    foreach ($emptyTopology in $emptyTopologies)
                    {
                        Write-Host -ForegroundColor White "  -"$emptyTopology.TopologyId.ToString()
                        $emptyTopology.Delete()
                    }
                }
                Write-Host -ForegroundColor White "  - Checking search service application proxy..." -NoNewline
                If (!(Get-SPEnterpriseSearchServiceApplicationProxy -Identity $appConfig.Proxy.Name -ErrorAction SilentlyContinue))
                {
                    Write-Host -ForegroundColor White "Creating..." -NoNewline
                    New-SPEnterpriseSearchServiceApplicationProxy -Name $appConfig.Proxy.Name -SearchApplication $appConfig.Name | Out-Null
                    If ($?) {Write-Host -ForegroundColor White "OK."}
                }
                Else {Write-Host -ForegroundColor White "Already exists."}

                # Check the Search Host Controller Service for a known issue ("stuck on starting")
                Write-Host -ForegroundColor White "  - Checking for stuck Search Host Controller Service (known issue)..."
                $searchHostServices = Get-SPServiceInstance | Where-Object {$_.TypeName -eq "Search Host Controller Service"}
                foreach ($sh in $searchHostServices)
                {
                    Write-Host -ForegroundColor White "   - Server: $($sh.Parent.Address)..." -NoNewline
                    if ($sh.Status -eq "Provisioning")
                    {
                        Write-Host -ForegroundColor White "Re-provisioning..." -NoNewline
                        $sh.Unprovision()
                        $sh.Provision($true)
                        Write-Host -ForegroundColor Green "Done."
                    }
                    else {Write-Host -ForegroundColor White "OK."}
                }

                # Add link to resources list
                AddResourcesLink $appConfig.Name ("searchadministration.aspx?appid=" +  $searchApp.Id)

                function SetSearchCenterUrl ($searchCenterURL, $searchApp)
                {
                    Start-Sleep 10 # Wait for stuff to catch up so we don't get a concurrency error
                    $searchApp.SearchCenterUrl = $searchCenterURL
                    $searchApp.Update()
                }

                If (!([string]::IsNullOrEmpty($appConfig.SearchCenterUrl)))
                {
                    # Set the SP2013+ Search Center URL per http://blogs.technet.com/b/speschka/archive/2012/10/29/how-to-configure-the-global-search-center-url-for-sharepoint-2013-using-powershell.aspx
                    Write-Host -ForegroundColor White "  - Setting the Global Search Center URL to $($appConfig.SearchCenterURL)..." -NoNewline
                    while ($done -ne $true)
                    {
                        try
                        {
                            # Get the #searchApp object again to prevent conflicts
                            $searchApp = Get-SPEnterpriseSearchServiceApplication -Identity $appConfig.Name
                            SetSearchCenterUrl $appConfig.SearchCenterURL.TrimEnd("/") $searchApp
                            if ($?)
                            {
                                $done = $true
                                Write-Host -ForegroundColor White "OK."
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
                Else {Write-Host -ForegroundColor Yellow "  - SearchCenterUrl was not specified, skipping."}
                Write-Host -ForegroundColor White " - Search Service Application successfully provisioned."

                WriteLine
            }
        }

        # SLN: Create the network share (will report an error if exist)
        # default to primitives
        $pathToShare = """" + $svcConfig.ShareName + "=" + $indexLocation + """"
        # The path to be shared should exist if the Enterprise Search App creation succeeded earlier
        EnsureFolder $indexLocation
        Write-Host -ForegroundColor White " - Creating network share $pathToShare"
        Start-Process -FilePath net.exe -ArgumentList "share $pathToShare `"/GRANT:WSS_WPG,CHANGE`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue

        # Set the crawl start addresses (including the elusive sps3:// URL required for People Search, if My Sites are provisioned)
        # Updated to include all web apps and host-named site collections, not just main Portal and MySites host
        ForEach ($webAppConfig in $xmlInput.Configuration.WebApplications.WebApplication)
        {
            if ([string]::IsNullOrEmpty($crawlStartAddresses))
            {
                $crawlStartAddresses = $(($webAppConfig.url).TrimEnd("/"))+":"+$($webAppConfig.Port)
            }
            else
            {
                $crawlStartAddresses += ","+$(($webAppConfig.url).TrimEnd("/"))+":"+$($webAppConfig.Port)
            }
        }

        If ($mySiteHostHeaderAndPort)
        {
            # Need to set the correct sps (People Search) URL protocol in case the web app that hosts My Sites is SSL-bound
            If ($mySiteHostLocation -like "https*") {$peopleSearchProtocol = "sps3s://"}
            Else {$peopleSearchProtocol = "sps3://"}
            $crawlStartAddresses += ","+$peopleSearchProtocol+$mySiteHostHeaderAndPort
        }
        Write-Host -ForegroundColor White " - Setting up crawl addresses for default content source..." -NoNewline
        Get-SPEnterpriseSearchServiceApplication | Get-SPEnterpriseSearchCrawlContentSource | Set-SPEnterpriseSearchCrawlContentSource -StartAddresses $crawlStartAddresses
        If ($?) {Write-Host -ForegroundColor White "OK."}
        if ($spVer -ge 15) # Invoke-WebRequest requires PowerShell 3.0 but if we're installing SP2013 and we've gotten this far, we must have v3.0
        {
            # Issue a request to the Farm Search Administration page to avoid a Health Analyzer warning about 'Missing Server Side Dependencies'
            $ca = Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication}
            $centralAdminUrl = $ca.Url
            if ($ca.Url -like "http://*" -or $ca.Url -like "*$($env:COMPUTERNAME)*") # If Central Admin uses SSL, only attempt the web request if we're on the same server as Central Admin, otherwise it may throw a certificate error due to our self-signed cert
            {
                try
                {
                    Write-Host -ForegroundColor White " - Requesting searchfarmdashboard.aspx (resolves Health Analyzer error)..."
                    $null = Invoke-WebRequest -Uri $centralAdminUrl"searchfarmdashboard.aspx" -UseDefaultCredentials -DisableKeepAlive -UseBasicParsing -ErrorAction SilentlyContinue
                }
                catch {}
            }
        }
        WriteLine
    }
    Else
    {
        WriteLine
        # Set the service account to something other than Local System to avoid Health Analyzer warnings
        If (!([string]::IsNullOrEmpty($searchServiceAccount.Username)) -and !([string]::IsNullOrEmpty($secSearchServicePassword)))
        {
            # Use the values for Search Service account and password, if they've been defined
            $username = $searchServiceAccount.Username
            $password = $secSearchServicePassword
        }
        Else
        {
            $spservice = Get-SPManagedAccountXML $xmlInput -CommonName "spservice"
            $username = $spservice.username
            $password = ConvertTo-SecureString "$($spservice.password)" -AsPlaintext -Force
        }
        Write-Host -ForegroundColor White " - Applying service account $username to Search Service..."
        Get-SPEnterpriseSearchService | Set-SPEnterpriseSearchService -ServiceAccount $username -ServicePassword $password
        If (!$?) {Write-Error " - An error occurred setting the Search Service account!"}
        WriteLine
    }
}

function Update-SearchContentAccessAccount ($saName, $sa, $caa, $caapwd)
{
    try
    {
        Write-Host -ForegroundColor White "  - Setting content access account for $saName..."
        $sa | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $caa -DefaultContentAccessAccountPassword $caapwd -ErrorVariable err
    }
    catch
    {
        if ($err -like "*update conflict*")
        {
            Write-Warning "An update conflict error occured, trying again."
            Update-SearchContentAccessAccount $saName, $sa, $caa, $caapwd
            $sa | Set-SPEnterpriseSearchServiceApplication -DefaultContentAccessAccountName $caa -DefaultContentAccessAccountPassword $caapwd -ErrorVariable err
        }
        else
        {
            throw $_
        }
    }
    finally {Clear-Variable err}
}

function Set-ProxyGroupsMembership ([System.Xml.XmlElement[]]$groups, [Microsoft.SharePoint.Administration.SPServiceApplicationProxy[]]$inputObject)
{
    begin {}
    process {
        $proxy = $_
        # Clear any existing proxy group assignments
        Get-SPServiceApplicationProxyGroup | Where-Object {$_.Proxies -contains $proxy} | ForEach-Object {
            $proxyGroupName = $_.Name
            If ([string]::IsNullOrEmpty($proxyGroupName)) { $proxyGroupName = "Default" }
            $group = $null
            [bool]$matchFound = $false
            ForEach ($g in $groups) {
                $group = $g.ProxyGroup
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
            $group = $g.ProxyGroup
            $pg = $null
            If ($group -eq "Default" -or [string]::IsNullOrEmpty($group)) {
                $pg = [Microsoft.SharePoint.Administration.SPServiceApplicationProxyGroup]::Default
            } Else {
                $pg = Get-SPServiceApplicationProxyGroup $group -ErrorAction SilentlyContinue -ErrorVariable err
                If ($null -eq $pg) {
                    $pg = New-SPServiceApplicationProxyGroup -Name $name
                }
            }
            $pg = $pg | Where-Object {$_.Proxies -notcontains $proxy}
            If ($null -ne $pg) {
                Write-Host -ForegroundColor White " - Adding ""$($proxy.DisplayName)"" to ""$($pg.DisplayName)"""
                $pg | Add-SPServiceApplicationProxyGroupMember -Member $proxy | Out-Null
            }
        }
    }
    end {}
}

Function Get-ApplicationPool ([System.Xml.XmlElement]$appPoolConfig) {
    # Try and get the application pool if it already exists
    # SLN: Updated names
    $pool = Get-SPServiceApplicationPool -Identity $appPoolConfig.Name -ErrorVariable err -ErrorAction SilentlyContinue
    If ($err) {
        # The application pool does not exist so create.
        Write-Host -ForegroundColor White "  - Getting $($searchServiceAccount.Username) account for application pool..."
        $managedAccountSearch = (Get-SPManagedAccount -Identity $searchServiceAccount.Username -ErrorVariable err -ErrorAction SilentlyContinue)
        If ($err) {
            If (!([string]::IsNullOrEmpty($searchServiceAccount.Password)))
            {
                $appPoolConfigPWD = (ConvertTo-SecureString $searchServiceAccount.Password -AsPlainText -force)
                $accountCred = New-Object System.Management.Automation.PsCredential $searchServiceAccount.Username,$appPoolConfigPWD
            }
            Else
            {
                $accountCred = Get-Credential $searchServiceAccount.Username
            }
            $managedAccountSearch = New-SPManagedAccount -Credential $accountCred
        }
        Write-Host -ForegroundColor White "  - Creating $($appPoolConfig.Name)..."
        $pool = New-SPServiceApplicationPool -Name $($appPoolConfig.Name) -Account $managedAccountSearch
    }
    Return $pool
}

#endregion

#region Create Business Data Catalog Service Application
# ===================================================================================
# Func: CreateBusinessDataConnectivityServiceApp
# Desc: Business Data Catalog Service Application
# From: http://autospinstaller.codeplex.com/discussions/246532 (user bunbunaz)
# ===================================================================================
Function CreateBusinessDataConnectivityServiceApp ([xml]$xmlInput)
{
    If ((ShouldIProvision $xmlInput.Configuration.ServiceApps.BusinessDataConnectivity -eq $true) -and (Get-Command -Name New-SPBusinessDataCatalogServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        Try
        {
            $serviceConfig = $xmlInput.Configuration.ServiceApps.BusinessDataConnectivity
            $dbServer = $xmlInput.Configuration.ServiceApps.BusinessDataConnectivity.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $bdcAppName = $xmlInput.Configuration.ServiceApps.BusinessDataConnectivity.Name
            $dbPrefix = Get-DBPrefix $xmlInput
            $bdcDataDB = $dbPrefix+$($xmlInput.Configuration.ServiceApps.BusinessDataConnectivity.Database.Name)
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
            if ($usingSQLAuthentication)
            {
                Write-Host -ForegroundColor White " - Creating SQL credential object..."
                $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseCredentialsParameter = @{}
            }
            Write-Host -ForegroundColor White " - Provisioning $bdcAppName"
            $applicationPool = Get-HostedServicesAppPool $xmlInput
            Write-Host -ForegroundColor White " - Checking local service instance..."
            # Get the service instance
            $bdcServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
            $bdcServiceInstance = $bdcServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
            If (-not $?) { Throw " - Failed to find the service instance" }
            # Start Service instances
            If($bdcServiceInstance.Status -eq "Disabled")
            {
                Write-Host -ForegroundColor White " - Starting $($bdcServiceInstance.TypeName)..."
                $bdcServiceInstance.Provision()
                If (-not $?) { Throw " - Failed to start $($bdcServiceInstance.TypeName)" }
                # Wait
                Write-Host -ForegroundColor Cyan " - Waiting for $($bdcServiceInstance.TypeName)..." -NoNewline
                While ($bdcServiceInstance.Status -ne "Online")
                {
                    Write-Host -ForegroundColor Cyan "." -NoNewline
                    Start-Sleep 1
                    $bdcServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceInstance"}
                    $bdcServiceInstance = $bdcServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                }
                Write-Host -BackgroundColor Green -ForegroundColor Black ($bdcServiceInstance.Status)
            }
            Else
            {
                Write-Host -ForegroundColor White " - $($bdcServiceInstance.TypeName) already started."
            }
            # Create a Business Data Catalog Service Application
            If ($null -eq (Get-SPServiceApplication | Where-Object {$_.GetType().ToString() -eq "Microsoft.SharePoint.BusinessData.SharedService.BdcServiceApplication"}))
            {
                # Create Service App
                Write-Host -ForegroundColor White " - Creating $bdcAppName..."
                New-SPBusinessDataCatalogServiceApplication -Name $bdcAppName -ApplicationPool $applicationPool -DatabaseServer $dbServer -DatabaseName $bdcDataDB @databaseCredentialsParameter | Out-Null
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
#endregion

#region Create Word Automation Service
Function CreateWordAutomationServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.WordAutomationService
    $dbServer = $serviceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
    }
    $dbPrefix = Get-DBPrefix $xmlInput
    $serviceDB = $dbPrefix+$($serviceConfig.Database.Name)
    # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
    $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
    if ($usingSQLAuthentication)
    {
        Write-Host -ForegroundColor White " - Creating SQL credential object..."
        $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
        $databaseCredentialsParameter = @{DatabaseCredential = $SqlCredential}
    }
    else # Otherwise assume Windows integrated and no database credentials provided
    {
        $databaseCredentialsParameter = @{}
    }
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPWordConversionServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Word.Server.Service.WordServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPWordConversionServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB -Default @databaseCredentialsParameter" `
                                        -ServiceProxyNewCmdlet "New-SPWordConversionServiceApplicationProxy" # Fake cmdlet, but the CreateGenericServiceApplication function expects something
        # Run the Word Automation Timer Job immediately; otherwise we will have a Health Analyzer error condition until the job runs as scheduled
        If (Get-SPServiceApplication | Where-Object {$_.DisplayName -eq $($serviceConfig.Name)})
        {
            Get-SPTimerJob | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Word.Server.Service.QueueJob"} | ForEach-Object {$_.RunNow()}
        }
        WriteLine
    }
}
#endregion

#region Enterprise Service Apps

#region Create Excel Service
Function CreateExcelServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
    If ((ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices -eq $true) -and ($spYear -le 2013))
    {
        WriteLine
        if ($officeServerPremium -eq "1")
        {
            Try
            {
                $excelAppName = $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices.Name
                $portalWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "Portal"} | Select-Object -First 1
                $portalURL = ($portalWebApp.URL).TrimEnd("/")
                $portalPort = $portalWebApp.Port
                Write-Host -ForegroundColor White " - Provisioning $excelAppName..."
                $applicationPool = Get-HostedServicesAppPool $xmlInput
                Write-Host -ForegroundColor White " - Checking local service instance..."
                # Get the service instance
                $excelServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
                $excelServiceInstance = $excelServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                If (-not $?) { Throw " - Failed to find the service instance" }
                # Start Service instances
                If($excelServiceInstance.Status -eq "Disabled")
                {
                    Write-Host -ForegroundColor White " - Starting $($excelServiceInstance.TypeName)..."
                    $excelServiceInstance.Provision()
                    If (-not $?) { Throw " - Failed to start $($excelServiceInstance.TypeName) instance" }
                    # Wait
                    Write-Host -ForegroundColor Cyan " - Waiting for $($excelServiceInstance.TypeName)..." -NoNewline
                    While ($excelServiceInstance.Status -ne "Online")
                    {
                        Write-Host -ForegroundColor Cyan "." -NoNewline
                        Start-Sleep 1
                        $excelServiceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"}
                        $excelServiceInstance = $excelServiceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
                    }
                    Write-Host -BackgroundColor Green -ForegroundColor Black ($excelServiceInstance.Status)
                }
                Else
                {
                    Write-Host -ForegroundColor White " - $($excelServiceInstance.TypeName) already started."
                }
                # Create an Excel Service Application
                If ($null -eq (Get-SPServiceApplication | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceApplication"}))
                {
                    # Create Service App
                    Write-Host -ForegroundColor White " - Creating $excelAppName..."
                    # Check if our new cmdlets are available yet,  if not, re-load the SharePoint PS Snapin
                    If (!(Get-Command New-SPExcelServiceApplication -ErrorAction SilentlyContinue) -and $spyear -le 2019)
                    {
                        Write-Host -ForegroundColor White " - Re-importing SP PowerShell Snapin to enable new cmdlets..."
                        Remove-PSSnapin Microsoft.SharePoint.PowerShell
                        Add-SharePointPSSnapin
                    }
                    $excelServiceApp = New-SPExcelServiceApplication -name $excelAppName -ApplicationPool $($applicationPool.Name) -Default
                    If (-not $?) { Throw " - Failed to create $excelAppName" }
                    Write-Host -ForegroundColor White " - Configuring service app settings..."
                    Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $portalURL`:$portalPort -ExcelServiceApplication $excelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10 | Out-Null
                    $caUrl = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS").GetValue("CentralAdministrationURL")
                    New-SPExcelFileLocation -LocationType SharePoint -IncludeChildren -Address $caUrl -ExcelServiceApplication $excelAppName -ExternalDataAllowed 2 -WorkbookSizeMax 10 | Out-Null

                    # Configure unattended accounts, based on:
                    # http://blog.falchionconsulting.com/index.php/2010/10/service-accounts-and-managed-service-accounts-in-sharepoint-2010/
                    If (($xmlInput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser) -and ($xmlInput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword))
                    {
                        Write-Host -ForegroundColor White " - Setting unattended account credentials..."

                        # Reget application to prevent update conflict error message
                        $excelServiceApp = Get-SPExcelServiceApplication

                        # Get account credentials
                        $excelAcct = $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDUser
                        $excelAcctPWD = $xmlInput.Configuration.EnterpriseServiceApps.ExcelServices.UnattendedIDPassword
                        If (!($excelAcct) -or $excelAcct -eq "" -or !($excelAcctPWD) -or $excelAcctPWD -eq "")
                        {
                            Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan " - Prompting for Excel Unattended Account:"
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
                        If ($null -eq $secureStoreApp) {
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
    }
        else
        {
            Write-Warning "You have specified a non-Enterprise SKU in `"$(Split-Path -Path $inputFile -Leaf)`". However, SharePoint requires the Enterprise SKU and corresponding PIDKey to provision Excel Services."
        }
        WriteLine
    }
}
#endregion

#region Create Visio Graphics Service
Function CreateVisioServiceApp ([xml]$xmlInput)
{
    $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
    $serviceConfig = $xmlInput.Configuration.EnterpriseServiceApps.VisioService
    If (ShouldIProvision $serviceConfig -eq $true)
    {
        WriteLine
        if ($officeServerPremium -eq "1")
        {
            $serviceInstanceType = "Microsoft.Office.Visio.Server.Administration.VisioGraphicsServiceInstance"
            CreateGenericServiceApplication -ServiceConfig $serviceConfig `
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
                    $visioAcct = $xmlInput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDUser
                    $visioAcctPWD = $xmlInput.Configuration.EnterpriseServiceApps.VisioService.UnattendedIDPassword
                    If (!($visioAcct) -or $visioAcct -eq "" -or !($visioAcctPWD) -or $visioAcctPWD -eq "")
                    {
                        Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan " - Prompting for Visio Unattended Account:"
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
        }
        else
        {
            Write-Warning "You have specified a non-Enterprise SKU in `"$(Split-Path -Path $inputFile -Leaf)`". However, SharePoint requires the Enterprise SKU and corresponding PIDKey to provision Visio Services."
        }
        WriteLine
    }

}
#endregion

#region Create PerformancePoint Service
Function CreatePerformancePointServiceApp ([xml]$xmlInput)
{
    $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
    $serviceConfig = $xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService
    If (ShouldIProvision $serviceConfig -eq $true)
    {
        WriteLine
        if ($officeServerPremium -eq "1")
        {
            $dbServer = $serviceConfig.Database.DBServer
            # If we haven't specified a DB Server then just use the default used by the Farm
            If ([string]::IsNullOrEmpty($dbServer))
            {
                $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
            }
            $dbPrefix = Get-DBPrefix $xmlInput
            $serviceDB = $dbPrefix+$serviceConfig.Database.Name
            # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
            $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
            if ($usingSQLAuthentication)
            {
                Write-Host -ForegroundColor White " - Creating SQL credential object..."
                $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
                $databaseCredentialsParameter = @{DatabaseSQLAuthenticationCredential = $SqlCredential}
            }
            else # Otherwise assume Windows integrated and no database credentials provided
            {
                $databaseCredentialsParameter = @{}
            }
            $serviceInstanceType = "Microsoft.PerformancePoint.Scorecards.BIMonitoringServiceInstance"
            CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                            -ServiceInstanceType $serviceInstanceType `
                                            -ServiceName $serviceConfig.Name `
                                            -ServiceProxyName $serviceConfig.ProxyName `
                                            -ServiceGetCmdlet "Get-SPPerformancePointServiceApplication" `
                                            -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                            -ServiceNewCmdlet "New-SPPerformancePointServiceApplication" `
                                            -ServiceProxyNewCmdlet "New-SPPerformancePointServiceApplicationProxy"

            $application = Get-SPPerformancePointServiceApplication | Where-Object {$_.Name -eq $serviceConfig.Name}
            If ($application)
            {
                # Need a better way to determine if we're not requesting SQL auth for the service application
                # Only run Add-SPShellAdmin if we are using Windows integrated auth to connect to SQL
                if (!$usingSQLAuthentication)
                {
                    $farmAcct = $xmlInput.Configuration.Farm.Account.Username
                    Write-Host -ForegroundColor White " - Granting $farmAcct rights to database $serviceDB..."
                    Get-SPDatabase | Where-Object {$_.Name -eq $serviceDB} | Add-SPShellAdmin -UserName $farmAcct
                }
                Write-Host -ForegroundColor White " - Setting PerformancePoint Data Source Unattended Service Account..."
                $performancePointAcct = $serviceConfig.UnattendedIDUser
                $performancePointAcctPWD = $serviceConfig.UnattendedIDPassword
                If (!($performancePointAcct) -or $performancePointAcct -eq "" -or !($performancePointAcctPWD) -or $performancePointAcctPWD -eq "")
                {
                    Write-Host -BackgroundColor Gray -ForegroundColor DarkCyan " - Prompting for PerformancePoint Unattended Service Account:"
                    $performancePointCredential = $host.ui.PromptForCredential("PerformancePoint Setup", "Enter PerformancePoint Unattended Account Credentials:", "$performancePointAcct", "NetBiosUserName" )
                }
                Else
                {
                    $secPassword = ConvertTo-SecureString "$performancePointAcctPWD" -AsPlaintext -Force
                    $performancePointCredential = New-Object System.Management.Automation.PsCredential $performancePointAcct,$secPassword
                }
                $application | Set-SPPerformancePointSecureDataValues -DataSourceUnattendedServiceAccount $performancePointCredential

                If (!(CheckFor2010SP1 -xmlinput $xmlInput)) # Only need this if our environment isn't up to Service Pack 1 for SharePoint 2010
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
        }
        else
        {
            Write-Warning " You have specified a non-Enterprise SKU in `"$(Split-Path -Path $inputFile -Leaf)`". However, SharePoint requires the Enterprise SKU and corresponding PIDKey to provision PerformancePoint Services."
        }
        WriteLine
    }
}
#endregion

#region Create Access 2010 Service
Function CreateAccess2010ServiceApp ([xml]$xmlInput)
{
    $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
    $serviceConfig = $xmlInput.Configuration.EnterpriseServiceApps.AccessService
    If (ShouldIProvision $serviceConfig -eq $true)
    {
        WriteLine
        if ($officeServerPremium -eq "1")
        {
            $serviceInstanceType = "Microsoft.Office.Access.Server.MossHost.AccessServerWebServiceInstance"
            CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                            -ServiceInstanceType $serviceInstanceType `
                                            -ServiceName $serviceConfig.Name `
                                            -ServiceProxyName $serviceConfig.ProxyName `
                                            -ServiceGetCmdlet "Get-SPAccessServiceApplication" `
                                            -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                            -ServiceNewCmdlet "New-SPAccessServiceApplication -Default" `
                                            -ServiceProxyNewCmdlet "New-SPAccessServiceApplicationProxy" # Fake cmdlet (and not needed for Access Services), but the CreateGenericServiceApplication function expects something
        }
        else
        {
            Write-Warning "You have specified a non-Enterprise SKU in `"$(Split-Path -Path $inputFile -Leaf)`". However, SharePoint requires the Enterprise SKU and corresponding PIDKey to provision Access Services 2010."
        }
        WriteLine
    }
}
#endregion

#endregion

#region Create Office Web Apps
Function CreateExcelOWAServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $serviceConfig = $xmlInput.Configuration.OfficeWebApps.ExcelService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        $portalWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "Portal"} | Select-Object -First 1
        $portalURL = ($portalWebApp.URL).TrimEnd("/")
        $portalPort = $portalWebApp.Port
        $serviceInstanceType = "Microsoft.Office.Excel.Server.MossHost.ExcelServerWebServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPExcelServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPExcelServiceApplication -Default" `
                                        -ServiceProxyNewCmdlet "New-SPExcelServiceApplicationProxy" # Fake cmdlet (and not needed for Excel Services), but the CreateGenericServiceApplication function expects something

        If (Get-SPExcelServiceApplication)
        {
            Write-Host -ForegroundColor White " - Setting Excel Services Trusted File Location..."
            Set-SPExcelFileLocation -Identity "http://" -LocationType SharePoint -IncludeChildren -Address $portalURL`:$portalPort -ExcelServiceApplication $($serviceConfig.Name) -ExternalDataAllowed 2 -WorkbookSizeMax 10
        }
        WriteLine
    }
}

Function CreatePowerPointOWAServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $serviceConfig = $xmlInput.Configuration.OfficeWebApps.PowerPointService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        If ($spYear -eq 2010) {$serviceInstanceType = "Microsoft.Office.Server.PowerPoint.SharePoint.Administration.PowerPointWebServiceInstance"}
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
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

Function CreateWordViewingOWAServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    Get-MajorVersionNumber $spYear
    $serviceConfig = $xmlInput.Configuration.OfficeWebApps.WordViewingService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Test-Path "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\TEMPLATE\FEATURES\OfficeWebApps\feature.xml"))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Web.Environment.Sharepoint.ConversionServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
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
#endregion

#region SharePoint 2013 Service Apps
#region Create App Domain
Function CreateAppManagementServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.AppManagementService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPAppManagementServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        $dbPrefix = Get-DBPrefix $xmlInput
        $serviceDB = $dbPrefix+$serviceConfig.Database.Name
        $dbServer = $serviceConfig.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($dbServer))
        {
            $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
        }
        # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
        $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
        if ($usingSQLAuthentication)
        {
            Write-Host -ForegroundColor White " - Creating SQL credential object..."
            $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
            $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
        }
        else # Otherwise assume Windows integrated and no database credentials provided
        {
            $databaseCredentialsParameter = @{}
        }
        $serviceInstanceType = "Microsoft.SharePoint.AppManagement.AppManagementServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPAppManagementServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB @databaseCredentialsParameter" `
                                        -ServiceProxyNewCmdlet "New-SPAppManagementServiceApplicationProxy"

        # Configure your app domain and location
        Write-Host -ForegroundColor White " - Setting App Domain `"$($serviceConfig.AppDomain)`"..."
        Set-SPAppDomain -AppDomain $serviceConfig.AppDomain
        WriteLine
    }
}

Function CreateSubscriptionSettingsServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.SubscriptionSettingsService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPSubscriptionSettingsServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        $dbPrefix = Get-DBPrefix $xmlInput
        $serviceDB = $dbPrefix+$serviceConfig.Database.Name
        $dbServer = $serviceConfig.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($dbServer))
        {
            $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
        }
        # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
        $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
        if ($usingSQLAuthentication)
        {
            Write-Host -ForegroundColor White " - Creating SQL credential object..."
            $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
            $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
        }
        else # Otherwise assume Windows integrated and no database credentials provided
        {
            $databaseCredentialsParameter = @{}
        }
        $serviceInstanceType = "Microsoft.SharePoint.SPSubscriptionSettingsServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPSubscriptionSettingsServiceApplication -DatabaseServer $dbServer -DatabaseName $serviceDB @databaseCredentialsParameter" `
                                        -ServiceProxyNewCmdlet "New-SPSubscriptionSettingsServiceApplicationProxy"

        Write-Host -ForegroundColor White " - Setting Site Subscription name `"$($serviceConfig.AppSiteSubscriptionName)`"..."
        Set-SPAppSiteSubscriptionName -Name "$($serviceConfig.AppSiteSubscriptionName)" -Confirm:$false
        WriteLine
    }
}
#endregion

#region Create Access Services (2013)
Function CreateAccessServicesApp ([xml]$xmlInput)
{
    $officeServerPremium = $xmlInput.Configuration.Install.SKU -replace "Enterprise","1" -replace "Standard","0"
    $serviceConfig = $xmlInput.Configuration.EnterpriseServiceApps.AccessServices
    $dbServer = $serviceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
    }
    ##$dbPrefix = Get-DBPrefix $xmlInput
    ##$serviceDB = $dbPrefix+$($serviceConfig.Database.Name)
    # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
    $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
    if ($usingSQLAuthentication)
    {
        Write-Host -ForegroundColor White " - Creating SQL credential object..."
        $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
        $databaseCredentialsParameter = @{DatabaseServerCredentials = $SqlCredential}
    }
    else # Otherwise assume Windows integrated and no database credentials provided
    {
        $databaseCredentialsParameter = @{}
    }
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPAccessServicesApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        if ($officeServerPremium -eq "1")
        {
            $serviceInstanceType = "Microsoft.Office.Access.Services.MossHost.AccessServicesWebServiceInstance"
            CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                            -ServiceInstanceType $serviceInstanceType `
                                            -ServiceName $serviceConfig.Name `
                                            -ServiceProxyName $serviceConfig.ProxyName `
                                            -ServiceGetCmdlet "Get-SPAccessServicesApplication" `
                                            -ServiceProxyGetCmdlet "Get-SPServicesApplicationProxy" `
                                            -ServiceNewCmdlet "New-SPAccessServicesApplication -DatabaseServer $dbServer -Default @databaseCredentialsParameter" `
                                            -ServiceProxyNewCmdlet "New-SPAccessServicesApplicationProxy"
        }
        else
        {
            Write-Warning "You have specified a non-Enterprise SKU in `"$(Split-Path -Path $inputFile -Leaf)`". However, SharePoint requires the Enterprise SKU and corresponding PIDKey to provision Access Services 2010."
        }
        WriteLine
    }
}

#endregion

#region PowerPoint Conversion Service
Function CreatePowerPointConversionServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.PowerPointConversionService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPPowerPointConversionServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Server.PowerPoint.Administration.PowerPointConversionServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPPowerPointConversionServiceApplication" `
                                        -ServiceProxyNewCmdlet "New-SPPowerPointConversionServiceApplicationProxy"
        WriteLine
    }
}
#endregion

#region Create Machine Translation Service
Function CreateMachineTranslationServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.MachineTranslationService
    $dbServer = $serviceConfig.Database.DBServer
    # If we haven't specified a DB Server then just use the default used by the Farm
    If ([string]::IsNullOrEmpty($dbServer))
    {
        $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
    }
    $dbPrefix = Get-DBPrefix $xmlInput
    $translationDatabase = $dbPrefix+$($serviceConfig.Database.Name)
    # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
    $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
    if ($usingSQLAuthentication)
    {
        Write-Host -ForegroundColor White " - Creating SQL credential object..."
        $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
        $databaseCredentialsParameter = @{DatabaseCredential = $SqlCredential}
    }
    else # Otherwise assume Windows integrated and no database credentials provided
    {
        $databaseCredentialsParameter = @{}
    }
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPTranslationServiceApplication -ErrorAction SilentlyContinue))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.TranslationServices.TranslationServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPTranslationServiceApplication -DatabaseServer $dbServer -DatabaseName $translationDatabase -Default @databaseCredentialsParameter" `
                                        -ServiceProxyNewCmdlet "New-SPTranslationServiceApplicationProxy"
        WriteLine
    }
}
#endregion

#region Create Work Management Service
Function CreateWorkManagementServiceApp ([xml]$xmlInput)
{
    $serviceConfig = $xmlInput.Configuration.ServiceApps.WorkManagementService
    If ((ShouldIProvision $serviceConfig -eq $true) -and (Get-Command -Name New-SPWorkManagementServiceApplication -ErrorAction SilentlyContinue) -and (Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq "Microsoft.Office.Server.WorkManagement.WorkManagementServiceInstance"}))
    {
        WriteLine
        $serviceInstanceType = "Microsoft.Office.Server.WorkManagement.WorkManagementServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPWorkManagementServiceApplication" `
                                        -ServiceProxyNewCmdlet "New-SPWorkManagementServiceApplicationProxy"
        WriteLine
    }
}
#endregion
#endregion

#region Create Project Server Service Application & Instance
Function CreateProjectServerServiceApp ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $serviceConfig = $xmlInput.Configuration.ProjectServer.ServiceApp
    If ((ShouldIProvision $serviceConfig -eq $true) -and ($xmlInput.Configuration.ProjectServer.Install -eq $true) -and (Get-Command -Name New-SPProjectServiceApplication -ErrorAction SilentlyContinue)) # We need to check that Project Server has been requested for install, not just if the service app should be provisioned
    {
        WriteLine
        $dbPrefix = Get-DBPrefix $xmlInput
        $serviceDB = $dbPrefix+$serviceConfig.Database.Name
        $dbServer = $serviceConfig.Database.DBServer
        # If we haven't specified a DB Server then just use the default used by the Farm
        If ([string]::IsNullOrEmpty($dbServer))
        {
            $dbServer = $xmlInput.Configuration.Farm.Database.DBServer
        }
        # Check if we've specified SQL authentication instead of the default Windows integrated authentication, and prepare the credentials
        $usingSQLAuthentication = (($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "true" -and $xmlInput.Configuration.Farm.Database.SQLAuthentication.Enable -eq "true") -or ($serviceConfig.Database.SQLAuthentication.UseFarmSetting -eq "false" -and ![string]::IsNullOrEmpty($serviceConfig.Database.SQLAuthentication.SQLUserName)))
        if ($usingSQLAuthentication)
        {
            Write-Host -ForegroundColor White " - Creating SQL credential object..."
            $SqlCredential = Get-SQLCredentials -SqlAccount $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLUserName -SqlPass $xmlInput.Configuration.Farm.Database.SQLAuthentication.SQLPassword
            $databaseCredentialsParameter = @{DatabaseCredentials = $SqlCredential}
        }
        else # Otherwise assume Windows integrated and no database credentials provided
        {
            $databaseCredentialsParameter = @{}
        }
        $serviceInstanceType = "Microsoft.Office.Project.Server.Administration.PsiServiceInstance"
        CreateGenericServiceApplication -ServiceConfig $serviceConfig `
                                        -ServiceInstanceType $serviceInstanceType `
                                        -ServiceName $serviceConfig.Name `
                                        -ServiceProxyName $serviceConfig.ProxyName `
                                        -ServiceGetCmdlet "Get-SPServiceApplication" `
                                        -ServiceProxyGetCmdlet "Get-SPServiceApplicationProxy" `
                                        -ServiceNewCmdlet "New-SPProjectServiceApplication -Proxy:`$true" `
                                        -ServiceProxyNewCmdlet "New-SPProjectServiceApplicationProxy" # We won't be using the proxy cmdlet though for Project Server

        # Update process account for Project services
        $projectServices = @("Microsoft.Office.Project.Server.Administration.ProjectEventService", "Microsoft.Office.Project.Server.Administration.ProjectCalcService", "Microsoft.Office.Project.Server.Administration.ProjectQueueService")
        foreach ($projectService in $projectServices)
        {
            $projectServiceInstances = (Get-SPFarm).Services | Where-Object {$_.GetType().ToString() -eq $projectService}
            foreach ($projectServiceInstance in $projectServiceInstances)
            {
                UpdateProcessIdentity $projectServiceInstance
            }
        }
        # Create a Project Server DB (2013 only)
        $portalWebApp = $xmlInput.Configuration.WebApplications.WebApplication | Where-Object {$_.Type -eq "Portal"} | Select-Object -First 1
        if (!(Get-SPDatabase | Where-Object {$_.Name -eq $serviceDB}))
        {
            if (Get-Command -Name New-SPProjectDatabase -ErrorAction SilentlyContinue) # Check for this since it no longer exists in SP2016+
            {
               Write-Host -ForegroundColor White " - Creating Project Server database `"$serviceDB`"..." -NoNewline
               New-SPProjectDatabase -Name $serviceDB -ServiceApplication (Get-SPServiceApplication | Where-Object {$_.Name -eq $serviceConfig.Name}) -DatabaseServer $dbServer @databaseCredentialsParameter | Out-Null
                if ($?) {Write-Host -ForegroundColor Black -BackgroundColor Cyan "Done."}
                else
                {
                    Write-Host -ForegroundColor White "."
                    throw {"Error creating the Project Server database."}
                }
            }
        }
        else
        {
            Write-Host -ForegroundColor Black -BackgroundColor Cyan "Already exists."
        }
        # Create a Project Server Web Instance
        $projectManagedPath = $xmlInput.Configuration.ProjectServer.ServiceApp.ManagedPath
        New-SPManagedPath -RelativeURL $xmlInput.Configuration.ProjectServer.ServiceApp.ManagedPath -WebApplication (Get-SPWebApplication | Where-Object {$_.Name -eq $portalWebApp.Name}) -Explicit:$true -ErrorAction SilentlyContinue | Out-Null
        Write-Host -ForegroundColor White " - Creating Project Server site collection at `"$projectManagedPath`"..." -NoNewline
        $projectSiteUrl = ($portalWebApp.Url).TrimEnd("/")+":"+$portalWebApp.Port+"/"+$projectManagedPath
        if (!(Get-SPSite -Identity $projectSiteUrl -ErrorAction SilentlyContinue))
        {
            $projectSite = New-SPSite -Url $projectSiteUrl  -OwnerAlias $env:USERDOMAIN\$env:USERNAME -Template "PROJECTSITE#0"
            if ($?) {Write-Host -ForegroundColor Black -BackgroundColor Green "Done."}
            else
            {
                Write-Host -ForegroundColor White "."
                throw {"Error creating the Project Server site collection."}
            }
        }
        else
        {
            Write-Host -ForegroundColor Black -BackgroundColor Cyan "Already exists."
        }
        Write-Host -ForegroundColor White " - Checking for Project Server web instance at `"$projectSiteUrl`"..." -NoNewline
        if (!(Get-SPProjectWebInstance -Url $projectSiteUrl -ErrorAction SilentlyContinue))
        {
            Write-Host -ForegroundColor White "."
            if ((Get-Command -Name Mount-SPProjectWebInstance -ErrorAction SilentlyContinue) -and ($spYear -le 2013)) # Check for this since the command no longer exists in SP2016+
            {
                Write-Host -ForegroundColor White " - Creating Project Server web instance at `"$projectSiteUrl`"..." -NoNewline
                Mount-SPProjectWebInstance -DatabaseName $serviceDB -SiteCollection $projectSite
                if ($?) {Write-Host -ForegroundColor Black -BackgroundColor Green "Done."}
                else
                {
                    Write-Host -ForegroundColor White "."
                    throw {"Error creating the Project Server web instance."}
                }
            }
            elseif ($spVer -ge 16)
            {
                $pidKeyProjectServer = $xmlInput.Configuration.ProjectServer.PIDKeyProjectServer
                Write-Host -ForegroundColor White " - Enabling Project Server license key..."
                Enable-ProjectServerLicense -Key $pidKeyProjectServer
                Write-Host -ForegroundColor White " - Creating Project Web Instance by enabling PWA feature on `"$projectSiteUrl`"..." -NoNewline
                Enable-SPFeature -Identity pwasite -Url $projectSiteUrl
                if ($?) {Write-Host -ForegroundColor Black -BackgroundColor Green "Done."}
                else
                {
                    Write-Host -ForegroundColor White "."
                    throw {"Error creating the Project Server web instance."}
                }
            }
        }
        else
        {
            Write-Host -ForegroundColor Black -BackgroundColor Cyan "Already exists."
        }
        WriteLine
    }
}
#endregion

#region Configure Outgoing Email
# This is from http://autospinstaller.codeplex.com/discussions/228507?ProjectName=autospinstaller courtesy of rybocf
Function ConfigureOutgoingEmail ([xml]$xmlInput)
{
    If ($($xmlInput.Configuration.Farm.Services.OutgoingEmail.Configure) -eq $true)
    {
        WriteLine
        Try
        {
            $SMTPServer = $xmlInput.Configuration.Farm.Services.OutgoingEmail.SMTPServer
            $emailAddress = $xmlInput.Configuration.Farm.Services.OutgoingEmail.EmailAddress
            $replyToEmail = $xmlInput.Configuration.Farm.Services.OutgoingEmail.ReplyToEmail
            Write-Host -ForegroundColor White " - Configuring Outgoing Email..."
            $null = [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint")
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
#endregion

#region Configure Incoming Email
Function ConfigureIncomingEmail ([xml]$xmlInput)
{
    # Ensure the node exists in the XML first as we don't want to inadvertently disable the service if it wasn't explicitly specified
    if (($xmlInput.Configuration.Farm.Services.SelectSingleNode("IncomingEmail")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.IncomingEmail -eq $true))
    {
        StopServiceInstance "Microsoft.SharePoint.Administration.SPIncomingEmailServiceInstance"
    }
}
#endregion

#region Configure Foundation Web Application Service
Function ConfigureFoundationWebApplicationService ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $minRoleRequiresFoundationWebAppService = $false
    # Check if we are installing SharePoint 2016+ and we're requesting a MinRole that requires the Foundation Web Application Service
    if ($spVer -ge 16)
    {
        if ((ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.Application)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.DistributedCache)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServerFarm)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.SingleServer)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEnd)) -or (ShouldIProvision ($xmlInput.Configuration.Farm.ServerRoles.WebFrontEndWithDistributedCache)))
        {
            $minRoleRequiresFoundationWebAppService = $true
        }
    }
    # Ensure the node exists in the XML first as we don't want to inadvertently stop/disable the service if it wasn't explicitly specified
    if (($xmlInput.Configuration.Farm.Services.SelectSingleNode("FoundationWebApplication")) -and !(ShouldIProvision $xmlInput.Configuration.Farm.Services.FoundationWebApplication -eq $true) -and !($minRoleRequiresFoundationWebAppService))
    {
        StopServiceInstance "Microsoft.SharePoint.Administration.SPWebServiceInstance"
    }
    else
    {
		if(ShouldIProvision $xmlInput.Configuration.Farm.Services.FoundationWebApplication -eq $true) {
			# Start the service, if it isn't already running
			$serviceInstanceType = "Microsoft.SharePoint.Administration.SPWebServiceInstance"
			# Get all occurrences of the Foundation Web App Service except those which are actually Central Administration instances
			$serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $serviceInstanceType -and $_.Name -ne "WSS_Administration"}
			$serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
			If (!$serviceInstance) { Throw " - Failed to get service instance - check product version (Standard vs. Enterprise)" }
			Write-Host -ForegroundColor White " - Checking $($serviceInstance.TypeName) instance..."
			If (($serviceInstance.Status -eq "Disabled") -or ($serviceInstance.Status -ne "Online"))
			{
				Write-Host -ForegroundColor White " - Starting $($serviceInstance.TypeName) instance..."
				$serviceInstance.Provision()
				If (-not $?) { Throw " - Failed to start $($serviceInstance.TypeName) instance" }
				# Wait
				Write-Host -ForegroundColor Cyan " - Waiting for $($serviceInstance.TypeName) instance..." -NoNewline
				While ($serviceInstance.Status -ne "Online")
				{
					Write-Host -ForegroundColor Cyan "." -NoNewline
					Start-Sleep 1
					$serviceInstances = Get-SPServiceInstance | Where-Object {$_.GetType().ToString() -eq $serviceInstanceType}
					$serviceInstance = $serviceInstances | Where-Object {$_.Server.Address -eq $env:COMPUTERNAME}
				}
					Write-Host -BackgroundColor Green -ForegroundColor Black $($serviceInstance.Status)
			}
			Else
			{
				Write-Host -ForegroundColor White " - $($serviceInstance.TypeName) instance already started."
			}
		}
    }
    WriteLine
}
#endregion

#region Configure Adobe PDF Indexing and Display
# ====================================================================================
# Func: Set-PDFSearchAndIcon
# Desc: Downloads and installs the PDF iFilter, registers the PDF search file type and document icon for display in SharePoint
# From: Adapted/combined from @brianlala's additions, @tonifrankola's http://www.sharepointusecases.com/index.php/2011/02/automate-pdf-configuration-for-sharepoint-2010-via-powershell/
# And : Paul Hickman's Patch 9609 at http://autospinstaller.codeplex.com/SourceControl/list/patches
# ====================================================================================

Function Set-PDFSearchAndIcon ([xml]$xmlInput)
{
    WriteLine
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    Write-Host -ForegroundColor White " - Configuring PDF file search, display and handling..."
    $sharePointRoot = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer"
    $sourceFileLocations = @("$env:bits\$spYear\PDF\","$env:bits\PDF\","$env:bits\AdobePDF\","$((Get-Item $env:TEMP).FullName)\")
    # Only install/configure iFilter if specified, and we are running SP2010 (as SP2013 includes one)
    If ((ShouldIProvision $xmlInput.Configuration.AdobePDF.iFilter -eq $true) -and ($spYear -eq 2010))
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
                    $zipLocation = (Get-Item $env:TEMP).FullName
                    $destinationFile = $zipLocation+"\PDFiFilter64installer.zip"
                    Import-Module BitsTransfer | Out-Null
                    Start-BitsTransfer -Source $pdfIfilterUrl -Destination $destinationFile -DisplayName "Downloading Adobe PDF iFilter..." -Priority Foreground -Description "From $pdfIfilterUrl..." -ErrorVariable err
                    If ($err) {Write-Warning "Could not download Adobe PDF iFilter!"; Pause "exit"; break}
                    $sourceFile = $destinationFile
                }
                Else {Write-Warning "The remote use of BITS is not supported. Please pre-download the PDF install files and try again."}
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
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$iFilterInstaller`" /passive /norestart" -NoNewWindow -Wait
        }
        Catch {$_}
        If ($null -eq (Get-PsSnapin | Where-Object {$_.Name -eq "Microsoft.SharePoint.PowerShell"}))
        {
            Write-Host -ForegroundColor White " - Loading SharePoint PowerShell Snapin..."
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
        Else {Write-Warning "No search applications found."}
        Write-Host -ForegroundColor White " - Updating registry..."
        If ($null -eq (Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$spVer.0\Search\Setup\Filters\.pdf" -ErrorAction SilentlyContinue))
        {
            $item = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$spVer.0\Search\Setup\Filters\.pdf"
            $item | New-ItemProperty -Name Extension -PropertyType String -Value "pdf" | Out-Null
            $item | New-ItemProperty -Name FileTypeBucket -PropertyType DWord -Value 1 | Out-Null
            $item | New-ItemProperty -Name MimeTypes -PropertyType String -Value "application/pdf" | Out-Null
        }
        If ($null -eq (Get-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$spVer.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf" -ErrorAction SilentlyContinue))
        {
            $registryItem = New-Item -Path Registry::"HKLM\SOFTWARE\Microsoft\Office Server\$spVer.0\Search\Setup\ContentIndexCommon\Filters\Extension\.pdf"
            $registryItem | New-ItemProperty -Name "(default)" -PropertyType String -Value "{E8978DA6-047F-4E3D-9C78-CDBE46041603}" | Out-Null
        }
        $spSearchService = "OSearch"+$spVer # Substitute the correct SharePoint version into the service name so we can handle SP2013 as well as SP2010
        If ((Get-Service $spSearchService).Status -eq "Running")
        {
            Write-Host -ForegroundColor White " - Restarting SharePoint Search Service..."
            Restart-Service $spSearchService
        }
        Write-Host -ForegroundColor White " - Done configuring PDF iFilter and indexing."
    }
    If ($xmlInput.Configuration.AdobePDF.Icon.Configure -eq $true)
    {
        $docIconFolderPath = "$sharePointRoot\TEMPLATE\XML"
        $docIconFilePath = "$docIconFolderPath\DOCICON.XML"
        $xml = New-Object XML
        $xml.Load($docIconFilePath)
        # Only configure PDF icon if we are running SP2010 (as SP2013 includes one)
        if ($spYear -eq 2010)
        {
            $pdfIconUrl = "http://www.adobe.com/images/pdficon_small.png"
            Write-Host -ForegroundColor White " - Configuring PDF Icon..."
            $pdfIcon = "pdficon_small.png"
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
                        If ($err) {Write-Warning "Could not download PDF Icon!"; Pause "exit"; break}
                    }
                    Else {Write-Warning "The remote use of BITS is not supported. Please pre-download the PDF icon and try again."}
                }
                If (Get-Item $sharePointRoot\Template\Images\$pdfIcon) {Write-Host -ForegroundColor White " - PDF icon copied successfully."}
                Else {Throw}
            }
            If ($null -eq $xml.SelectSingleNode("//Mapping[@Key='pdf']"))
            {
                Try
                {
                    $pdf = $xml.CreateElement("Mapping")
                    $pdf.SetAttribute("Key","pdf")
                    $pdf.SetAttribute("Value",$pdfIcon)
                }
                Catch {$_; Pause "exit"; Break}
            }
        }
        # Perform the rest of the DOCICON.XML modifications to allow PDF edit etc., and write out the new DOCICON.XML file
        Try
        {
            $date = Get-Date -UFormat "%y%m%d%H%M%S"
            Write-Host -ForegroundColor White " - Creating backup of DOCICON.XML file..."
            $backupFile = "$docIconFolderPath\DOCICON_Backup_$date.xml"
            Copy-Item $docIconFilePath $backupFile
            Write-Host -ForegroundColor White " - Writing new DOCICON.XML..."
            if (!$pdf) {$pdf = $xml.SelectSingleNode("//Mapping[@Key='pdf']")}
            if (!$pdf) {$pdf = $xml.CreateElement("Mapping")}
            $pdf.SetAttribute("EditText","Adobe Acrobat or Reader X")
            $pdf.SetAttribute("OpenControl","AdobeAcrobat.OpenDocuments")
            $xml.DocIcons.ByExtension.AppendChild($pdf) | Out-Null
            $xml.Save($docIconFilePath)
            Write-Host -ForegroundColor White " - Restarting IIS..."
            iisreset
        }
        Catch {$_; Pause "exit"; Break}
    }
    If ($xmlInput.Configuration.AdobePDF.MIMEType.Configure -eq $true)
    {
        # Add the PDF MIME type to each web app so PDFs can be directly viewed/opened without saving locally first
        # More granular and generally preferable to setting the whole web app to "Permissive" file handling
        $mimeType = "application/pdf"
        Write-Host -ForegroundColor White " - Adding PDF MIME type `"$mimeType`" web apps..."
        Add-SharePointPSSnapin
        ForEach ($webAppConfig in $xmlInput.Configuration.WebApplications.WebApplication)
        {
            $webAppUrl = $(($webAppConfig.url).TrimEnd("/"))+":"+$($webAppConfig.Port)
            $webApp = Get-SPWebApplication -Identity $webAppUrl
            If ($webApp.AllowedInlineDownloadedMimeTypes -notcontains $mimeType)
            {
                Write-Host -ForegroundColor White "  - "$webAppUrl": Adding "`"$mimeType"`"..." -NoNewline
                $webApp.AllowedInlineDownloadedMimeTypes.Add($mimeType)
                $webApp.Update()
                Write-Host -ForegroundColor White "OK."
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
#endregion

#region Install Forefront
# ====================================================================================
# Func: InstallForeFront
# Desc: Installs ForeFront Protection 2010 for SharePoint Sites
# ====================================================================================
Function InstallForeFront ([xml]$xmlInput)
{
    If (ShouldIProvision $xmlInput.Configuration.ForeFront -eq $true)
    {
        WriteLine
        If (Test-Path "$env:PROGRAMFILES\Microsoft ForeFront Protection for SharePoint\Launcher.exe")
        {
            Write-Host -ForegroundColor White " - ForeFront binaries appear to be already installed - skipping install."
        }
        Else
        {
            # Install ForeFront
            If (Test-Path "$env:bits\$spYear\Forefront\setup.exe")
            {
                Write-Host -ForegroundColor White " - Installing ForeFront binaries..."
                Try
                {
                    Start-Process "$bits\$spYear\Forefront\setup.exe" -ArgumentList "/a `"$configFileForeFront`" /p" -Wait
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
#endregion

#region Remote Functions
Function Get-FarmServers ([xml]$xmlInput)
{
    $servers = $null
    $farmServers = @()
    # Look for server name references in the XML
    ForEach ($node in $xmlInput.SelectNodes("//*[@Provision]|//*[@Install]|//*[CrawlComponent]|//*[QueryComponent]|//*[SearchQueryAndSiteSettingsComponent]|//*[AdminComponent]|//*[IndexComponent]|//*[ContentProcessingComponent]|//*[AnalyticsProcessingComponent]|//*[@Start]"))
    {
        # Try to set the server name from the various elements/attributes
        $servers = @(GetFromNode $node "Provision")
        If ([string]::IsNullOrEmpty($servers)) { $servers = @(GetFromNode $node "Install") }
        If ([string]::IsNullOrEmpty($servers)) { $servers = @(GetFromNode $node "Start") }
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
    If (!$?) {Pause "exit"; throw $_}
}

Function Test-ServerConnection ($server)
{
    Write-Host -ForegroundColor White " - Testing connection (via Ping) to `"$server`"..." -NoNewline
    $canConnect = Test-Connection -ComputerName $server -Count 1 -Quiet
    If ($canConnect) {Write-Host -ForegroundColor Cyan -BackgroundColor Black $($canConnect.ToString() -replace "True","Success.")}
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
        If ($err) {Write-Warning "Could not download PsExec!"; Pause "exit"; break}
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
    If (!($remoteQueryOS.Version.Contains("6.2")) -and !($remoteQueryOS.Version.Contains("6.3")) -and !($remoteQueryOS.Version.StartsWith("10"))) # Only perform the stuff below if we aren't on Windows 2012 or 2012 R2 OR 2016
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
    If (!($remoteQueryOS.Version.Contains("6.2")) -and !($remoteQueryOS.Version.Contains("6.3")) -and !($remoteQueryOS.Version.StartsWith("10"))) # Only perform the stuff below if we aren't on Windows 2012 or 2012 R2 OR 2016
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
            Else {Write-Warning "Could not detect OS of `"$server`", or unsupported OS."}
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
                If ($err) {Write-Warning "Could not download PsExec!"; Pause "exit"; break}
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
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spver = Get-MajorVersionNumber $spYear
    # Set some remote variables that we will need...
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name dp0 -Value $value} -ArgumentList $env:dp0 -Session $session
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name InputFile -Value $value} -ArgumentList $inputFile -Session $session
    Invoke-Command -ScriptBlock {param ($value) Set-Variable -Name spVer -Value $value} -ArgumentList $spVer -Session $session
    # Check if SharePoint is already installed
    $spInstalledOnRemote = Invoke-Command -ScriptBlock {(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*) | Where-Object {$_.DisplayName -like "Microsoft SharePoint Server*"}} -Session $session
    Write-Host -ForegroundColor Green " - SharePoint $spYear binaries are"($spInstalledOnRemote -replace "True","already" -replace "False","not yet") "installed on $server."
    Write-Host -ForegroundColor White " - Launching AutoSPInstaller..."
    Invoke-Command -ScriptBlock {& "$dp0\AutoSPInstallerMain.ps1" "$inputFile"} -Session $session
    Write-Host -ForegroundColor White " - Removing session `"$($session.Name)...`""
    Remove-PSSession $session
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

#endregion

#region Miscellaneous/Utility Functions
#region Load Snapins
# ===================================================================================
# Func: Load SharePoint PowerShell Snapin
# Desc: Load SharePoint PowerShell Snapin
# ===================================================================================
Function Add-SharePointPSSnapin
{
    If ($null -eq (Get-PsSnapin | Where-Object {$_.Name -eq "Microsoft.SharePoint.PowerShell"}))
    {
        WriteLine
        Write-Host -ForegroundColor White " - Loading SharePoint PowerShell Snapin..."
        # Added the line below to match what the SharePoint.ps1 file implements (normally called via the SharePoint Management Shell Start Menu shortcut)
        If (Confirm-LocalSession) {$Host.Runspace.ThreadOptions = "ReuseThread"}
        Add-PsSnapin Microsoft.SharePoint.PowerShell -ErrorAction Inquire | Out-Null
        WriteLine
    }
}
# ====================================================================================
# Func: ImportWebAdministration
# Desc: Load IIS WebAdministration Snapin/Module
# From: Inspired by http://stackoverflow.com/questions/1924217/powershell-load-webadministration-in-ps1-script-on-both-iis-7-and-iis-7-5
# ====================================================================================
Function ImportWebAdministration
{
    $queryOS = Get-WmiObject Win32_OperatingSystem
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
#endregion

#region ConvertTo-PlainText
# ===================================================================================
# Func: ConvertTo-PlainText
# Desc: Convert string to secure phrase
#       Used (for example) to get the Farm Account password into plain text as input to provision the User Profile Sync Service
#       From http://www.vistax64.com/powershell/159190-read-host-assecurestring-problem.html
# ===================================================================================
Function ConvertTo-PlainText ([security.securestring]$secure)
{
    $marshal = [Runtime.InteropServices.Marshal]
    $marshal::PtrToStringAuto( $marshal::SecureStringToBSTR($secure) )
}
#endregion

#region ShouldIProvision
# ===================================================================================
# Func: ShouldIProvision
# Desc: Returns TRUE if the item whose configuration node is passed in should be provisioned.
#       on this machine.
#       This function supports wildcard computernames.   Computernames specified in the
#       AutoSpInstallerInput.xml may contain either a single * character
#       to do a wildcard match or may contain one or more # characters to match an integer.
#       Using wildcard computer names is not compatible with remote installation.
#
#   Examples:   WFE* would match computers named WFE-foo, WFEbar, etc.
#               WFE## would match WFE01, WFE02, but not WFE1
# ===================================================================================
Function ShouldIProvision ([System.Xml.XmlNode] $node)
{
    If (!$node) {Return $false} # In case the node doesn't exist in the XML file
    # Allow for comma- or space-delimited list of server names in Provision or Start attribute
    If ($node.GetAttribute("Provision")) {$v = $node.GetAttribute("Provision").Replace(","," ")}
    ElseIf ($node.GetAttribute("Start")) {$v = $node.GetAttribute("Start").Replace(","," ")}
    ElseIf ($node.GetAttribute("Install")) {$v = $node.GetAttribute("Install").Replace(","," ")}
    If ($v -eq $true) { Return $true; }
	Return MatchComputerName $v $env:COMPUTERNAME
}
#endregion

#region SQL Stuff
# ====================================================================================
# Func: Add-SQLAlias
# Desc: Creates a local SQL alias (like using cliconfg.exe) so the real SQL server/name doesn't get hard-coded in SharePoint
#       if local database server is being used, then use Shared Memory protocol
# From: Bill Brockbank, SharePoint MVP (billb@navantis.com)
# ====================================================================================

Function Add-SQLAlias ()
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

    If ((MatchComputerName $SQLInstance $env:COMPUTERNAME) -or ($SQLInstance.StartsWith($env:ComputerName +"\"))) {
        $protocol = "dbmslpcn" # Shared Memory
        }
    else {
        $protocol = "DBMSSOCN" # TCP/IP
    }

    $serverAliasConnection="$protocol,$SQLInstance"
    If ($port -ne "")
    {
         $serverAliasConnection += ",$port"
    }
    $notExist = $true
    $client = Get-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client' -ErrorAction SilentlyContinue
    # Create the key in case it doesn't yet exist
    If (!$client) {$client = New-Item 'HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client' -Force}
    $client.GetSubKeyNames() | ForEach-Object -Process { If ( $_ -eq 'ConnectTo') {$notExist = $false}}
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
Function CheckSQLAccess ([xml]$xmlInput, $SqlAccount, $SqlPass)
{
    WriteLine
    # Look for references to DB Servers, Aliases, etc. in the XML
    ForEach ($node in $xmlInput.SelectNodes("//*[DBServer]|//*[@DatabaseServer]|//*[@FailoverDatabaseServer]"))
    {
        $dbServer = (GetFromNode $node "DBServer")
        If ($node.DatabaseServer) {$dbServer = GetFromNode $node "DatabaseServer"}
        # If the DBServer has been specified, and we've asked to set up an alias, create one
        If (!([string]::IsNullOrEmpty($dbServer)) -and ($node.DBAlias.Create -eq $true))
        {
            $dbInstance = GetFromNode $node.DBAlias "DBInstance"
            $dbPort = GetFromNode $node.DBAlias "DBPort"
            # If no DBInstance has been specified, but Create="$true", set the Alias to the server value
            If (($null -eq $dbInstance) -and ($dbInstance -ne "")) {$dbInstance = $dbServer}
            If (($null -ne $dbPort) -and ($dbPort -ne ""))
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

    $serverRolesToCheck = "dbcreator","securityadmin"
    # If we are provisioning PerformancePoint but aren't running SharePoint 2010 Service Pack 1 yet, we need sysadmin in order to run the RenameDatabase function
    # We also evidently need sysadmin in order to configure MaxDOP on the SQL instance if we are installing SharePoint 2013
    If (($xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService) -and (ShouldIProvision $xmlInput.Configuration.EnterpriseServiceApps.PerformancePointService -eq $true) -and (!(CheckFor2010SP1 -xmlinput $xmlInput)))
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
                # If a SQL username and password were provided then check access using those, otherwise use Windows integrated authentication
                if (!([string]::IsNullOrEmpty($SqlAccount)) -and !([string]::IsNullOrEmpty($SqlPass)))
                {
                    $currentUser = $SqlAccount
                    $objSQLConnection.ConnectionString = "Server=$sqlServer;Persist Security Info=False;User ID=$SqlAccount;Password=$SqlPass;"
                }
                else
                {
                    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
                    $objSQLConnection.ConnectionString = "Server=$sqlServer;Integrated Security=SSPI;"
                }
                Write-Host -ForegroundColor White " - Testing access to SQL server/instance/alias:" $sqlServer
                Write-Host -ForegroundColor White "  - Trying to connect to '$sqlServer'"
                Write-Host -ForegroundColor White "  - Using connection string '$($objSQLConnection.ConnectionString)'..." -NoNewline
                $objSQLConnection.Open() | Out-Null
                Write-Host -ForegroundColor Black -BackgroundColor Green "Success"
                $strCmdSvrDetails = "SELECT SERVERPROPERTY('productversion') as Version"
                $strCmdSvrDetails += ",SERVERPROPERTY('IsClustered') as Clustering"
                $objSQLCommand.CommandText = $strCmdSvrDetails
                $objSQLCommand.Connection = $objSQLConnection
                $objSQLDataReader = $objSQLCommand.ExecuteReader()
                If ($objSQLDataReader.Read())
                {
                    Write-Host -ForegroundColor White ("  - SQL Server version is: {0}" -f $objSQLDataReader.GetValue(0))
                    $SQLVersion = $objSQLDataReader.GetValue(0)
                    [int]$SQLMajorVersion,[int]$SQLMinorVersion,[int]$SQLBuild,$null = $SQLVersion -split "\."
                    # SharePoint needs minimum SQL 2008 10.0.2714.0 or SQL 2005 9.0.4220.0 per http://support.microsoft.com/kb/976215
                    If ((($SQLMajorVersion -eq 10) -and ($SQLMinorVersion -lt 5) -and ($SQLBuild -lt 2714)) -or (($SQLMajorVersion -eq 9) -and ($SQLBuild -lt 4220)))
                    {
                        Throw "  - Unsupported SQL version!"
                    }
                    If ($objSQLDataReader.GetValue(1) -eq 1)
                    {
                        Write-Host -ForegroundColor White "  - This instance of SQL Server is clustered"
                    }
                    Else
                    {
                        Write-Host -ForegroundColor White "  - This instance of SQL Server is not clustered"
                    }
                }
                $objSQLDataReader.Close()
                ForEach($serverRole in $serverRolesToCheck)
                {
                    $objSQLCommand.CommandText = "SELECT IS_SRVROLEMEMBER('$serverRole')"
                    $objSQLCommand.Connection = $objSQLConnection
                    Write-Host -ForegroundColor White "  - Check if $currentUser has $serverRole server role..." -NoNewline
                    $objSQLDataReader = $objSQLCommand.ExecuteReader()
                    If ($objSQLDataReader.Read() -and $objSQLDataReader.GetValue(0) -eq 1)
                    {
                        Write-Host -ForegroundColor Black -BackgroundColor Green "Passed"
                    }
                    ElseIf($objSQLDataReader.GetValue(0) -eq 0)
                    {
                        Throw "  - $currentUser does not have `'$serverRole`' role!"
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
                Write-Host -ForegroundColor Red "Failed"
                $errText = $_
                If ($errText -like "*network-related*")
                {
                    Write-Warning "Connection Error. Check server name, port, firewall."
                    Write-Host -ForegroundColor White "  - This may be expected if e.g. SQL server isn't installed yet, and you are just installing SharePoint binaries for now."
                    Pause "continue without checking SQL Server connection, or Ctrl-C to exit" "y"
                }
                ElseIf ($errText -like "*login failed*")
                {
                    Throw "  - Not able to login. SQL Server login not created."
                }
                ElseIf ($errText -like "*Unsupported SQL version*")
                {
                    Throw "  - SharePoint 2010 requires SQL 2005 SP3+CU3, SQL 2008 SP1+CU2, or SQL 2008 R2."
                }
                Else
                {
                    If (!([string]::IsNullOrEmpty($serverRole)))
                    {
                        Throw "  - $currentUser does not have `'$serverRole`' role!"
                    }
                    Else {Throw "  - $errText"}
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
Function RenameDatabase ([string]$sqlServer,[string]$oldName,[string]$newName)
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
#endregion

#region Invoke-HealthAnalyzerJobs
# ====================================================================================
# Func: Invoke-HealthAnalyzerJobs
# Desc: Runs all Health Analyzer Timer Jobs Immediately
# From: http://www.sharepointconfig.com/2011/01/instant-sharepoint-health-analysis/
# ====================================================================================
Function Invoke-HealthAnalyzerJobs
{
    $healthJobs = Get-SPTimerJob | Where-Object {$_.Name -match "health-analysis-job"}
    Write-Host -ForegroundColor White " - Running all Health Analyzer jobs..."
    ForEach ($job in $healthJobs)
    {
        $job.RunNow()
    }
}
#endregion

#region InstallSMTP
# ====================================================================================
# Func: InstallSMTP
# Desc: Installs the SMTP Server Windows feature
# ====================================================================================
Function InstallSMTP([xml]$xmlInput)
{
    If (ShouldIProvision $xmlInput.Configuration.Farm.Services.SMTP -eq $true)
    {
        WriteLine
        Write-Host -ForegroundColor White " - Installing SMTP Server feature..."
        $queryOS = Get-WmiObject Win32_OperatingSystem
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
            If (!$?) {Throw " - Failed to install SMTP Server!"}
            else
            {
                # Need to set the newly-installed service to Automatic since it is set to Manual by default (per https://autospinstaller.codeplex.com/workitem/19744)
                Write-Host -ForegroundColor White "  - Setting SMTP service startup type to Automatic..."
                Set-Service SMTPSVC -StartupType Automatic -ErrorAction SilentlyContinue
            }
        }
        Write-Host -ForegroundColor White " - Done."
        WriteLine
    }
}
#endregion

#region FixTaxonomyPickerBug
# ====================================================================================
# Func: FixTaxonomyPickerBug
# Desc: Renames the TaxonomyPicker.ascx file which doesn't seem to be used anyhow
# Desc: Goes one step further than the fix suggested in http://support.microsoft.com/kb/2481844 (which doesn't work at all)
# ====================================================================================
Function FixTaxonomyPickerBug ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spver = Get-MajorVersionNumber $spYear
    $taxonomyPicker = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\$spVer\TEMPLATE\CONTROLTEMPLATES\TaxonomyPicker.ascx"
    If (Test-Path $taxonomyPicker)
    {
        WriteLine
        Write-Host -ForegroundColor White " - Renaming TaxonomyPicker.ascx..."
        Move-Item -Path $taxonomyPicker -Destination $taxonomyPicker".buggy" -Force
        Write-Host -ForegroundColor White " - Done."
        WriteLine
    }
}
#endregion

#region Miscellaneous Checks
# ====================================================================================
# Func: CheckForSP2016FeaturePack1
# Desc: Returns $true if the SharePoint 2016 farm build number or SharePoint DLL indicates that Feature Pack 1 or greater is installed: otherwise returns $false
# Desc: Helps to determine whether certain new/updated cmdlets and MinRoles are available
# ====================================================================================
function CheckForSP2016FeaturePack1 ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spver = Get-MajorVersionNumber $spYear
    # Try to get the version of the farm first
    try
    {
        # Get-SPFarm lately seems to ignore -ErrorAction SilentlyContinue so we have to put it in a try-catch block
        $farm = Get-SPFarm -ErrorAction SilentlyContinue
    }
    catch
    {
        # Set $farm to null
        $farm = $null
    }
    $build = $farm.BuildVersion.Build
    If (!($build)) # Get the ProductVersion of a SharePoint DLL instead, since the farm doesn't seem to exist yet
    {
        $spProdVer = (Get-Command $env:CommonProgramFiles"\Microsoft Shared\Web Server Extensions\$spVer\isapi\microsoft.sharepoint.portal.dll" -ErrorAction SilentlyContinue).FileVersionInfo.ProductVersion
        $null,$null,[int]$build,$null = $spProdVer -split "\."
    }
    If ($build -ge 4453) # SP2016 FP1
    {
        return $true
    }
}
# ====================================================================================
# Func: CheckFor2010SP1
# Desc: Returns $true if the SharePoint 2010 farm build number or SharePoint DLL is at Service Pack 1 (6029) or greater (or if slipstreamed SP1 is detected); otherwise returns $false
# Desc: Helps to determine whether certain new/updated cmdlets are available
# ====================================================================================
Function CheckFor2010SP1 ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spver = Get-MajorVersionNumber $spYear
    # First off, if this is SP2013 or higher, we're good
    if ($spVer -ge 15)
    {
        return $true
    }
    # Otherwise, if it's 2010, run some additional checks
    elseif (Get-Command Get-SPFarm -ErrorAction SilentlyContinue)
    {
        # Try to get the version of the farm first
        $build = (Get-SPFarm).BuildVersion.Build
        If (!($build)) # Get the ProductVersion of a SharePoint DLL instead, since the farm doesn't seem to exist yet
        {
            $spProdVer = (Get-Command $env:CommonProgramFiles"\Microsoft Shared\Web Server Extensions\$spVer\isapi\microsoft.sharepoint.portal.dll" -ErrorAction SilentlyContinue).FileVersionInfo.ProductVersion
            $null,$null,[int]$build,$null = $spProdVer -split "\."
        }
        If ($build -ge 6029) # SP2010 SP1
        {
            return $true
        }
    }
    # SharePoint probably isn't installed yet, so try to see if we have slipstreamed SP1 in the \Updates folder at least...
    elseIf (Get-Item "$env:SPbits\Updates\oserversp1-x-none.msp" -ErrorAction SilentlyContinue)
    {
        return $true
    }
    else
    {
        return $false
    }
}

# ====================================================================================
# Func: CheckFor2013SP1
# Desc: Returns $true if the SharePoint 2013 farm build number or SharePoint prerequisiteinstaller.exe is at Service Pack 1 (4569 or 4567, respectively) or greater; otherwise returns $false
# ====================================================================================
Function CheckFor2013SP1 ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    if ($spYear -eq 2013)
    {
        If (Get-Command Get-SPFarm -ErrorAction SilentlyContinue)
        {
            # Try to get the version of the farm first
            $build = (Get-SPFarm -ErrorAction SilentlyContinue).BuildVersion.Build
            If (!($build)) # Get the ProductVersion of a SharePoint DLL instead, since the farm doesn't seem to exist yet
            {
                $spProdVer = (Get-Command $env:CommonProgramFiles"\Microsoft Shared\Web Server Extensions\$spVer\isapi\microsoft.sharepoint.portal.dll").FileVersionInfo.ProductVersion
                $null,$null,[int]$build,$null = $spProdVer -split "\."
            }
            If ($build -ge 4569) # SP2013 SP1
            {
                Return $true
            }
        }
        # SharePoint probably isn't installed yet, so try to determine version of prerequisiteinstaller.exe...
        ElseIf (Get-Item "$env:SPbits\prerequisiteinstaller.exe" -ErrorAction SilentlyContinue)
        {
            $preReqInstallerVer = (Get-Command "$env:SPbits\prerequisiteinstaller.exe").FileVersionInfo.ProductVersion
            $null,$null,[int]$build,$null = $preReqInstallerVer -split "\."
            If ($build -ge 4567) # SP2013 SP1
            {
                Return $true
            }
        }
        Else
        {
            Return $false
        }
    }
    elseif ($spVer -ge 16)
        {
            Return $true
        }
    else
    {
        Return $false
    }
}

# ====================================================================================
# Func: CheckIfUpgradeNeeded
# Desc: Returns $true if the server or farm requires an upgrade (i.e. requires PSConfig or the corresponding PowerShell commands to be run)
# ====================================================================================
Function CheckIfUpgradeNeeded ([xml]$xmlInput)
{
    $spYear = $xmlInput.Configuration.Install.SPVersion
    $spVer = Get-MajorVersionNumber $spYear
    $setupType = (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\$spVer.0\WSS\").GetValue("SetupType")
    If ($setupType -ne "CLEAN_INSTALL") # For example, if the value is "B2B_UPGRADE"
    {
        Return $true
    }
    Else
    {
        Return $false
    }
}

Function Get-SharePointInstall
{
    # New(er), faster way courtesy of SPRambler (https://www.codeplex.com/site/users/view/SpRambler)
    if ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*) | Where-Object {$_.DisplayName -like "Microsoft SharePoint Server*" -or $_.DisplayName -like "Microsoft SharePoint Foundation*"})
    {
        return $true
    }
    else {return $false}
}

# ===================================================================================
# Func: MatchComputerName
# Desc: Returns TRUE if the $computerName specified matches one of the items in $computersList.
#       Supports wildcard matching (# for a a number, * for any non whitepace character)
# ===================================================================================
Function MatchComputerName ($computersList, $computerName)
{
    foreach ($v in $computersList) {
		foreach ($item in -split $v) {
			If ($v.Contains("*") -or $v.Contains("#")) {
				# wildcard processing
                $item = $item -replace "#", "[\d]"
                $item = $item -replace "\*", "[\S]*"
                if ($computerName -match $item) {
					return $true;
				}
            }
			else {
				if ($computerName -eq $item) {
					return $true;
				}
			}
        }
    }

	return $false;
}
Function GetFromNode ([System.Xml.XmlElement]$node, [string] $item)
{
    $value = $node.GetAttribute($item)
    If ($value -eq "")
    {
        $child = $node.SelectSingleNode($item);
        If ($null -ne $child)
        {
            Return $child.InnerText;
        }
    }
    Return $value;
}

#endregion

#region Manage HOSTS & URLs
# ====================================================================================
# Func: AddToHOSTS
# Desc: This writes URLs to the server's local hosts file and points them to the server itself
# From: Check http://toddklindt.com/loopback for more information
# Copyright Todd Klindt 2011
# Originally published to http://www.toddklindt.com/blog
# ====================================================================================
Function AddToHOSTS ($hosts)
{
    Write-Host -ForegroundColor White " - Adding HOSTS file entries for local resolution..."
    # Make backup copy of the Hosts file with today's date
    $hostsfile = "$env:windir\System32\drivers\etc\HOSTS"
    $date = Get-Date -UFormat "%y%m%d%H%M%S"
    $filecopy = $hostsfile + '.' + $date + '.copy'
    Write-Host -ForegroundColor White "  - Backing up HOSTS file to:"
    Write-Host -ForegroundColor White "  - $filecopy"
    Copy-Item $hostsfile -Destination $filecopy

    if (!$hosts) # No hosts were passed as arguments, so look at the AAMs in the farm
    {
        # Get a list of the AAMs and weed out the duplicates
        $hosts = Get-SPAlternateURL | ForEach-Object {$_.incomingurl.replace("https://","").replace("http://","")} | where-Object { $_.tostring() -notlike "*:*" } | Select-Object -Unique
    }

    # Get the contents of the Hosts file
    $file = Get-Content $hostsfile
    $file = $file | Out-String

    # Write the AAMs to the hosts file, UNLESS they already exist, are "localhost" or happen to match the local computer name.
    ForEach ($hostname in $hosts)
    {
        # Get rid of any path information that may have snuck in here
        $hostname,$null = $hostname -split "/" -replace ("localhost", $env:COMPUTERNAME)
        if (($file -match " $hostname") -or ($file -match "`t$hostname")) # Added check for a space or tab character before the hostname for better exact matching, also used -match for case-insensitivity
        {Write-Host -ForegroundColor White "  - HOSTS file entry for `"$hostname`" already exists - skipping."}
        elseif ($hostname -eq "$env:Computername" -or $hostname -eq "$env:Computername.$env:USERDNSDOMAIN")
        {Write-Host -ForegroundColor Yellow "  - HOSTS file entry for `"$hostname`" matches local computer name - skipping."}
        else
        {
            Write-Host -ForegroundColor White "  - Adding HOSTS file entry for `"$hostname`"..."
            Add-Content -Path $hostsfile -Value "`r"
            Add-Content -Path $hostsfile -value "127.0.0.1 `t $hostname`t# Added by AutoSPInstaller to locally resolve SharePoint URLs back to this server"
            $keepHOSTSCopy = $true
        }
    }
    If (!$keepHOSTSCopy)
    {
        Write-Host -ForegroundColor White "  - Deleting HOSTS backup file since no changes were made..."
        Remove-Item $filecopy
    }
    Write-Host -ForegroundColor White " - Done with HOSTS file."
}
# ====================================================================================
# Func: Add-LocalIntranetURL
# Desc: Adds a URL to the local Intranet zone (Internet Control Panel) to allow pass-through authentication in Internet Explorer (avoid prompts)
# ====================================================================================
Function Add-LocalIntranetURL ($url)
{
    If (($url -like "*.*") -and (($webApp.AddURLToLocalIntranetZone) -eq $true))
    {
        # Strip out any protocol value
        $url = $url -replace "http://","" -replace "https://",""
        $splitURL = $url -split "\."
        # Thanks to CodePlex user Eulenspiegel for the updates $urlDomain syntax (https://autospinstaller.codeplex.com/workitem/20486)
        $urlDomain = $url.Substring($splitURL[0].Length + 1)
        Write-Host -ForegroundColor White " - Adding *.$urlDomain to local Intranet security zone..."
        if ($splitUrl.Count -gt 3) # To handle subdomains
        {
            $subDomainString,$null = $urlDomain -split "\."
            $urlDomain = $urlDomain -replace "$subDomainString\.",""
            $wildCardHost = "*." + $subDomainString
            $targetKey = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$urlDomain" -Name $wildCardHost -ItemType Leaf -Force
        }
        else
        {
            $targetKey = New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" -Name $urlDomain -ItemType Leaf -Force
        }
        $targetKeyPath = $targetKey.Name -replace "HKEY_CURRENT_USER","HKCU:"
        New-ItemProperty -Path $targetKeyPath -Name '*' -value "1" -PropertyType dword -Force | Out-Null
    }
}
#endregion

#region File System Functions
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
        $null = $wmiDirectory.CompressEx("","True")
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
                Write-Warning "$($_.Exception.Message)"
                Throw " - Could not create folder $path!"
            }
        }
}
#endregion

#region Trivial Functions
# ===================================================================================
# Func: Pause
# Desc: Wait for user to press a key - normally used after an error has occured or input is required
# ===================================================================================
Function Pause ($action, $key)
{
    # From http://www.microsoft.com/technet/scriptcenter/resources/pstips/jan08/pstip0118.mspx
    if ($key -eq "any" -or ([string]::IsNullOrEmpty($key)))
    {
        $actionString = "Press any key to $action..."
        if (-not $unattended)
        {
            Write-Host $actionString
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        else
        {
            Write-Host "Skipping pause due to -unattended switch: $actionString"
        }
    }
    else
    {
        $actionString = "Enter `"$key`" to $action"
        $continue = Read-Host -Prompt $actionString
        if ($continue -ne $key) {pause $action $key}

    }
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
# Func: Show-Progress
# Desc: Shows a row of dots to let us know that $process is still running
# From: Brian Lalancette, 2012
# ====================================================================================
Function Show-Progress ($process, $color, $interval)
{
    While (Get-Process -Name $process -ErrorAction SilentlyContinue)
    {
        Write-Host -ForegroundColor $color "." -NoNewline
        Start-Sleep $interval
    }
    Write-Host -ForegroundColor Green "Done."
}

# ====================================================================================
# Func: Get-DBPrefix
# Desc: Returns the database prefix for the farm
# From: Brian Lalancette, 2014
# ====================================================================================
Function Get-DBPrefix ([xml]$xmlInput)
{
    $dbPrefix = $xmlInput.Configuration.Farm.Database.DBPrefix
    If (($dbPrefix -ne "") -and ($null -ne $dbPrefix)) {$dbPrefix += "_"}
    If ($dbPrefix -like "*localhost*") {$dbPrefix = $dbPrefix -replace "localhost","$env:COMPUTERNAME"}
    return $dbPrefix
}
#endregion

#region Security-Related
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

# ====================================================================================
# Func: userExists
# Desc: "Here is a little powershell function I made to see check if specific active directory users exists or not."
# From: http://oyvindnilsen.com/powershell-function-to-check-if-active-directory-users-exists/
# ====================================================================================
function userExists ([string]$name)
{
    #written by: Øyvind Nilsen (oyvindnilsen.com)
    [bool]$ret = $false #return variable
    $domainRoot = [ADSI]''
    $dirSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainRoot)
    $dirSearcher.filter = "(&(objectClass=user)(sAMAccountName=$name))"
    $results = $dirSearcher.findall()
    if ($results.Count -gt 0) #if a user object is found, that means the user exists.
    {
        $ret = $true
    }
    return $ret
}

#endregion

#region Shortcuts
# ====================================================================================
# Func: AddResourcesLink
# Desc: Adds an item to the Resources list shown on the Central Admin homepage
#       $url should be relative to the central admin home page and should not include the leading /
# ====================================================================================
Function AddResourcesLink ([string]$title,[string]$url)
{
    $centraladminapp = Get-SPWebApplication -IncludeCentralAdministration | Where-Object {$_.IsAdministrationWebApplication}
    $centraladminurl = $centraladminapp.Url
    $centraladmin = (Get-SPSite $centraladminurl)

    $item = $centraladmin.RootWeb.Lists["Resources"].Items | Where-Object { $_["URL"] -match ".*, $title" }
    If ($null -eq $item)
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
Function PinToTaskbar ([string]$application)
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
#endregion

#region Stop Default Web Site
Function Stop-DefaultWebsite ()
{
    # Added to avoid conflicts with web apps that do not use a host header
    # Thanks to Paul Stork per http://autospinstaller.codeplex.com/workitem/19318 for confirming the Stop-Website cmdlet
    ImportWebAdministration
    $defaultWebsite = Get-Website | Where-Object {$_.Name -eq "Default Web Site" -or $_.ID -eq 1 -or $_.physicalPath -eq "%SystemDrive%\inetpub\wwwroot"} # Try different ways of identifying the Default Web Site, in case it has a different name (e.g. localized installs)
    Write-Host -ForegroundColor White " - Checking $($defaultWebsite.Name)..." -NoNewline
    if ($defaultWebsite.State -ne "Stopped")
    {
        Write-Host -ForegroundColor White "Stopping..." -NoNewline
        $defaultWebsite | Stop-Website
        if ($?) {Write-Host -ForegroundColor White "OK."}
    }
    else {Write-Host -ForegroundColor White "Already stopped."}
}
#endregion

#region Get SP Major Version Number
function Get-MajorVersionNumber ($spYear)
{
    # Create hash tables with major version to product year mappings & vice-versa
    $spVersions = @{"2010" = "14"; "2013" = "15"; "2016" = "16"; "2019" = "16"; "SE" = "16"} # SharePoint 2019 and SPSE still use major build 16
    $spVer = $spVersions.$spYear
    return $spVer
}
#endregion

#region Set SP Management Shell Shortcut to Run As Administrator
# From http://stackoverflow.com/questions/28997799/how-to-create-a-run-as-administrator-shortcut-using-powershell
function Set-ShortcutRunAsAdmin ($shortcutFile)
{
    Write-Host -ForegroundColor White " - Setting SharePoint Management Shell to run as Administrator..." -NoNewline
    $bytes = [System.IO.File]::ReadAllBytes($ShortcutFile)
    $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
    [System.IO.File]::WriteAllBytes($ShortcutFile, $bytes)
    Write-Host -ForegroundColor White "Done."
}
#endregion
#endregion
