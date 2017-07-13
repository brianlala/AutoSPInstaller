# Configures the server for WinRM and WSManCredSSP
Write-Host "Configuring PowerShell remoting..."
$winRM = Get-Service -Name winrm
If ($winRM.Status -ne "Running") {Start-Service -Name winrm}
Set-ExecutionPolicy Bypass -Force
Enable-PSRemoting -Force
Enable-WSManCredSSP -Role Server -Force | Out-Null
# Increase the local memory limit to 1 GB
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 1024

#Get out of this PowerShell process
Stop-Process -Id $PID -Force




