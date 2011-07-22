@ECHO OFF
SETLOCAL
cls
@TITLE -- AutoSPInstaller --
FOR /F "tokens=2-4 delims=/ " %%i IN ('date /t') DO SET SHORTDATE=%%i-%%j-%%k
FOR /F "tokens=1-3 delims=: " %%i IN ('time /t') DO SET SHORTTIME=%%i-%%j%%k
SET LaunchedFromBAT=1
IF EXIST "%~dp0\AutoSPInstallerInput-%COMPUTERNAME%.xml" (
	Set InputFile="%~dp0\AutoSPInstallerInput-%COMPUTERNAME%.xml"
	ECHO - Using %COMPUTERNAME%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\AutoSPInstallerInput-%USERDOMAIN%.xml" (
	Set InputFile="%~dp0\AutoSPInstallerInput-%USERDOMAIN%.xml"
	ECHO - Using %USERDOMAIN%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\AutoSPInstallerInput.xml" (
	Set InputFile="%~dp0\AutoSPInstallerInput.xml"
	ECHO - Using standard Input File.
	GOTO START
	)
ECHO - Input File not found! Please check for AutoSPInstallerInput.xml, AutoSPInstallerInput-%USERDOMAIN%.xml, or AutoSPInstallerInput-%COMPUTERNAME%.xml
GOTO END
:START
:: Check for Powershell
IF NOT EXIST "%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" (
	COLOR 0C
	ECHO - "powershell.exe" not found!
	ECHO - This script requires PowerShell - install v2.0, then re-run this script.
	COLOR
	pause
	EXIT
	)
:: Check for Powershell v2.0
ECHO - Checking for Powershell 2.0...
"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" $host.Version.Major | find "2" >nul
IF ERRORLEVEL 1 (
	COLOR 0C
	ECHO - This script requires PowerShell version 2.0!
	ECHO - Please uninstall v1.0, install v2.0, then re-run this script.
	COLOR
	pause
	EXIT
	)
ECHO - OK.
:: Get existing Powershell ExecutionPolicy
FOR /F "tokens=*" %%x in ('"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" Get-ExecutionPolicy') do (set ExecutionPolicy=%%x)
:: Set Bypass, in case we are running over a net share or UNC
IF NOT "%ExecutionPolicy%"=="Bypass" IF NOT "%ExecutionPolicy%"=="Unrestricted" (
    SET RestoreExecutionPolicy=1
	ECHO - PS ExecutionPolicy is %ExecutionPolicy%, setting ExecutionPolicy to Bypass.
	"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" -Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-Command Set-ExecutionPolicy Bypass'"
	)
GOTO LAUNCHSCRIPT
:LAUNCHSCRIPT
"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" -Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'%~dp0\AutoSPInstallerMain.ps1 %InputFile%'"
GOTO END
:END
:: Set the ExecutionPolicy to RemoteSigned
IF "%RestoreExecutionPolicy%"=="1" (
	ECHO - 
	ECHO - Running AutoSPInstaller PowerShell script...
	ECHO - 
	ECHO - You can safely close this window if you want your PowerShell
	ECHO - Execution Policy to remain as "Bypass". 
	ECHO - Otherwise, wait for the AutoSPInstaller script to complete,
	ECHO - then press a key, and it will be set to "RemoteSigned".
	ECHO - 
	ECHO - If you press a key before the script finishes it may not complete as expected
	ECHO - in which case simply re-run this batch file to continue AutoSPInstaller
	ECHO - 
	pause
    ECHO - Setting PS ExecutionPolicy to "RemoteSigned".
    "%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" -Command Start-Process "$PSHOME\powershell.exe" -Verb RunAs -ArgumentList "'-Command Set-ExecutionPolicy RemoteSigned'"
    )
timeout 5
ENDLOCAL