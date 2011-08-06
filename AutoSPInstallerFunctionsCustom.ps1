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

#Region Configure Adobe PDF Indexing and Display
# ====================================================================================
# Func: Configure-PDFSearchAndIcon
# Desc: Downloads and installs the PDF iFilter, registers the PDF search file type and document icon for display in SharePoint
# From: Adapted/combined from @brianlala's additions, @tonifrankola's http://www.sharepointusecases.com/index.php/2011/02/automate-pdf-configuration-for-sharepoint-2010-via-powershell/
# And : Paul Hickman's Patch 9609 at http://autospinstaller.codeplex.com/SourceControl/list/patches
# ====================================================================================

Function Configure-PDFSearchAndIcon
{
	If ($xmlinput.Configuration.AdobePDFIndexingAndIcon.Configure -eq $true)
	{
		WriteLine
		$PDFiFilterUrl = "http://download.adobe.com/pub/adobe/acrobat/win/9.x/PDFiFilter64installer.zip"
		$PDFIconUrl = "http://www.adobe.com/images/pdficon_small.gif"
		$SharePointRoot = "$env:CommonProgramFiles\Microsoft Shared\Web Server Extensions\14"
		$DocIconFolderPath = "$SharePointRoot\TEMPLATE\XML"
		$DocIconFilePath = "$DocIconFolderPath\DOCICON.XML"

		Write-Host -ForegroundColor White " - Configuring PDF file indexing..."
		$SourceFileLocations = @("$bits\PDF\","$bits\AdobePDF\",$env:TEMP)
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
				If ($err) {Write-Warning " - Could not download Adobe PDF iFilter!"; Pause; break}
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
		Write-Host -ForegroundColor White " - Done configuring PDF search."

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
				If ($err) {Write-Warning " - Could not download PDF Icon!"; Pause; break}
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
			}
			Catch {$_; Pause; Break}
		}
		Write-Host -ForegroundColor White " - Restarting IIS..."
		iisreset
		Write-Host -ForegroundColor White " - Done configuring PDF indexing and icon display."
		WriteLine
	}
}
#EndRegion

#Region Forefront Installer
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
			$config = $dp0 + "\" + $xmlinput.Configuration.ForeFront.ConfigFile
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