# Configures the server for WinRM and WSManCredSSP
Write-Host "Configuring PowerShell remoting..."
$winRM = Get-Service -Name WinRM
If ($winRM.Status -ne "Running") {Start-Service -Name WinRM}
Set-ExecutionPolicy Bypass -Force
Enable-PSRemoting -Force
Enable-WSManCredSSP -Role Server -Force > $null

# Increase the local memory limit to 1 GB
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024

#Get out of this PowerShell process
Stop-Process -Id $PID -Force