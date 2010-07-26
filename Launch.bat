@ECHO OFF
SETLOCAL
cls
@TITLE -- AutoSPInstaller --
FOR /F "tokens=2-4 delims=/ " %%i IN ('date /t') DO SET SHORTDATE=%%i-%%j-%%k
FOR /F "tokens=1-3 delims=: " %%i IN ('time /t') DO SET SHORTTIME=%%i-%%j%%k
SET LaunchedFromBAT=1
IF EXIST "%~dp0\SetInputs-%COMPUTERNAME%.xml" (
	Set InputFile="%~dp0\SetInputs-%COMPUTERNAME%.xml"
	ECHO - Using %COMPUTERNAME%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\SetInputs-%USERDOMAIN%.xml" (
	Set InputFile="%~dp0\SetInputs-%USERDOMAIN%.xml"
	ECHO - Using %USERDOMAIN%-specific Input File.
	GOTO START
	)
IF EXIST "%~dp0\SetInputs.xml" (
	Set InputFile="%~dp0\SetInputs.xml"
	ECHO - Using standard Input File.
	GOTO START
	)
ECHO - Input File not found! Please check for SetInputs.xml, SetInputs-%USERDOMAIN%.xml, or SetInputs-%COMPUTERNAME%.xml
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
	ECHO - PS ExecutionPolicy is %ExecutionPolicy%, setting ExecutionPolicy to Bypass.
	"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" Set-ExecutionPolicy Bypass
	)
GOTO LAUNCHSCRIPT
:LAUNCHSCRIPT
"%SYSTEMROOT%\system32\windowspowershell\v1.0\powershell.exe" -command "& '%~dp0\AutoSPInstaller.ps1' '%InputFile%'"
GOTO END
:END
ENDLOCAL