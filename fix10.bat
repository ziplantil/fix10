@echo off & setlocal & rem https://github.com/ziplantil/fix10
                       rem Fix10 v1.3.1
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Config
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=

rem Unless otherwise noted, 0 disables and 1 enables, 0 is default
rem              | change only this column under this section!

rem Enable disabling Windows Defender (default = 1)!
call :setdefault 1 fix10nodefender
rem Enable dropping under %SYSTEMROOT%\System32 (for Run & cmd):
rem   xqacl.bat: opens an elevated command prompt at given location
rem   xqgod.bat: opens the All Tasks directory
call :setdefault 0 fix10dropbatchutils
rem Enable removing Mixed Reality
call :setdefault 0 fix10removemixed
rem Enable deleting Cortana
call :setdefault 0 fix10delcortana
rem Enable disabling Smart Screen
call :setdefault 0 fix10disablesmartscreen
rem Enable installing the Linux Subsystem (will also enable Developer Mode!!)
call :setdefault 0 fix10installbash
rem Enable disabling Fast Startup (Hiberboot)
call :setdefault 0 fix10disablehiberboot

rem Command line flags:
rem /q - quiet mode, will not ask for a key press to confirm or at exit

rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Intro
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo ===============================
echo  FFFFF IIIII X   X   1    000
echo  F       I    X X   11   0   0
echo  FFF     I     X     1   0 0 0
echo  F       I    X X    1   0   0
echo  F     IIIII X   X  111   000
echo.
echo v1.3.1                     .bat
echo ===============================
echo         ziplantil  2021
echo ===============================
echo.
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Initialize flags
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
set silent=0
for %%a in (%*) do if /i "%%a" equ "/q" set silent=1
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Admin check
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
net session >nul 2>&1
if %errorlevel% == 0 goto adminok
if "%silent%" == "1" goto adminquiet
echo.
echo This batch file requires administrator rights.
echo A dialog should open up.
echo Please choose the affirmative option.
echo.
timeout 5
:adminquiet
echo %* > %TEMP%\fix10args.tmp
for /f %%a in ('powershell -Command "$ErrorActionPreference = \"SilentlyContinue\"; Start-Process \"%~f0\" -Verb Runas -ErrorAction SilentlyContinue -ErrorVariable ElevatedError -ArgumentList $(Get-Content \"%TEMP%\fix10args.tmp\") ; echo $ElevatedError.Count"') do set adminfailed=%%a
if %adminfailed% == 0 goto adminok_endscript
echo.
echo Could not elevate the script.
echo Try right-clicking the batch file and
echo choosing "Run as Administrator".
echo.
if "%silent%" == "0" pause
goto endscriptnokey
:adminok_endscript
if "%silent%" == "1" goto endscriptnokey
echo.
echo A new window has been opened for the
echo elevated script.
echo.
pause
goto endscriptnokey
:adminok
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// OS version check
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
if "%version%" == "10.0" goto win10ok
echo.
echo.
echo It seems you are not running Windows 10.
echo Running this batch file in other versions of Windows
echo may cause unpredictable results and is not advised.
echo.
:win10choice
set /P contanyway=Continue anyway [Y/N]?
if /I "%contanyway%" == "Y" goto win10okforce
if /I "%contanyway%" == "N" goto endscript
goto win10choice
:win10okforce
echo.
:win10ok
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// List
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if "%silent%" == "1" goto nofix10intro
echo This batch file will:
echo.
echo * Disable diagnostics and tracking services
echo * Disable advertisements and "tips"
echo * Try to set Updates to Ask before Download
echo * Disable Windows Update automatic restarts
echo * Uninstall and disable OneDrive
echo * Disable Feedback notifications
echo * Disable Bing Search
echo * Disable Application Telemetry
echo * Disable Steps Recorder
echo * Disable "Delivery Optimization"
echo * Disable Wi-Fi Sense
echo * Turn off advertising ID
echo * Disable Suggested app download
echo   (you will still need to uninstall those already downloaded yourself)
echo * Disable Windows Spotlight
echo * Disable keylogger ("improve typing")
echo * Disable "Getting to know you"
echo * Opt out from CEIP
echo * Disable Cortana
echo * Leave Microsoft MAPS
echo * Restore Windows Photo Viewer
echo * Re-enable Task Manager, Registry Editor and Command Interpreter
echo * Make Ultimate Performance power mode visible (not selected by default)
echo * Win+X: PowerShell to CMD
echo * Re-add CMD to Context menu (if Shift down)
echo * Enable seconds in the tray
echo * Show file extensions, hidden files and all drives
echo * Disable Data Collection Publishing Service
echo * Enables Legacy Boot Loader + F8 Safe Mode (!!!)
echo.
echo Modify the batch file to disable (enabled by default):
echo * Disable Windows Defender
echo.
echo Modify the batch file to enable (disabled by default):
echo * Drops batch utilities
echo * Remove Mixed Reality
echo * Delete Cortana
echo * Disable Smart Screen
echo * Install the Linux Subsystem
echo * Disable Fast Startup
echo.
echo The list is long - scroll all the way through!
echo Some changes may require a reboot afterwards,
echo and some of them may not work on 10 Home/Pro!
echo.
echo Hit Ctrl-C and Y or close the window to cancel
echo        Cancel if you are not 100%% sure!
echo.
pause
:nofix10intro
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable services
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem These two are disabled by default; see DOCUMENT.md
rem sc config dmwappushsvc start= disabled
rem sc config Dmwappushservice start= disabled
sc config "Diagnostics Tracking Service" start= disabled
sc config "Connected User Experiences and Telemetry" start= disabled
sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config DoSvc start= demand
sc config DcpSvc start= demand
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable scheduled tasks
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Search UI firewall
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
powershell -Command New-NetFirewallRule -DisplayName "Search" -Direction Outbound -Action Block -Profile "Domain, Private, Public" -Program "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Telemetry stuff
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
pushd %ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger
echo. > AutoLogger-Diagtrack-Listener.etl
echo Y | cacls AutoLogger-Diagtrack-Listener.etl /d SYSTEM
popd
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Ultimate Performance
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
powercfg /L | find /c /i "Ultimate Performance" >nul || powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// taskmgr, regedit, cmd
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCMD /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableTaskMgr /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableRegistryTools /t REG_DWORD /d 0 /f
reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 0 /f
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry header
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo Windows Registry Editor Version 5.00 > %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry HKLM
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU] >> %TEMP%\fix10bat.reg
echo "AUOptions"=dword:00000002 >> %TEMP%\fix10bat.reg
echo "AUPowerManagement"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "NoAutoRebootWithLoggedOnUsers"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "NoAutoUpdate"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RebootRelaunchTimeout"=dword:000005a0 >> %TEMP%\fix10bat.reg
echo "RebootRelaunchTimeoutEnabled"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU] >> %TEMP%\fix10bat.reg
echo "AUOptions"=dword:00000002 >> %TEMP%\fix10bat.reg
echo "AUPowerManagement"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "NoAutoRebootWithLoggedOnUsers"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "NoAutoUpdate"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RebootRelaunchTimeout"=dword:000005a0 >> %TEMP%\fix10bat.reg
echo "RebootRelaunchTimeoutEnabled"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update] >> %TEMP%\fix10bat.reg
echo "AUOptions"=dword:00000002 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows] >> %TEMP%\fix10bat.reg
echo "DisableFileSync"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config] >> %TEMP%\fix10bat.reg
echo "DownloadMode"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DODownloadMode"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection] >> %TEMP%\fix10bat.reg
echo "AllowTelemetry"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DoNotShowFeedbackNotifications"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\CurrentVersion\DataCollection] >> %TEMP%\fix10bat.reg
echo "AllowTelemetry"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DoNotShowFeedbackNotifications"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Siuf\Rules] >> %TEMP%\fix10bat.reg
echo "NumberOfSIUFInPeriod"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "PeriodInNanoSeconds"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection] >> %TEMP%\fix10bat.reg
echo "AllowTelemetry"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata] >> %TEMP%\fix10bat.reg
echo "PreventDeviceMetadataFromNetwork"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent] >> %TEMP%\fix10bat.reg
echo "DisableSoftLanding"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "DisableWindowsConsumerFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "DisableWindowsSpotlightFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo] >> %TEMP%\fix10bat.reg
echo "Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo] >> %TEMP%\fix10bat.reg
echo "DisabledByGroupPolicy"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Microsoft\SQMClient\Windows] >> %TEMP%\fix10bat.reg
echo "CEIPEnable"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat] >> %TEMP%\fix10bat.reg
echo "AITEnable"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DisableUAR"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search] >> %TEMP%\fix10bat.reg
echo "AllowCortana"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DisableWebSearch"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "ConnectedSearchUseWeb"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "ConnectedSearchPrivacy"=dword:00000003 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive] >> %TEMP%\fix10bat.reg
echo "DisableFileSyncNGSC"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive] >> %TEMP%\fix10bat.reg
echo "PreventNetworkTrafficPreUserSignIn"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization] >> %TEMP%\fix10bat.reg
echo "AllowInputPersonalization"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RestrictImplicitInkCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "RestrictImplicitTextCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config] >> %TEMP%\fix10bat.reg
echo "AutoConnectAllowedOEM"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting] >> %TEMP%\fix10bat.reg
echo "value"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots] >> %TEMP%\fix10bat.reg
echo "value"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet] >> %TEMP%\fix10bat.reg
echo "SpyNetReporting"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubmitSamplesConsent"=dword:00000002 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry HKCU for current user
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced] >> %TEMP%\fix10bat.reg
echo "DontUsePowerShellOnWinX"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "Hidden"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "HideFileExt"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "HideDrivesWithNoMedia"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "ShowSyncProviderNotifications"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent] >> %TEMP%\fix10bat.reg
echo "DisableWindowsConsumerFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "DisableWindowsSpotlightFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace] >> %TEMP%\fix10bat.reg
echo "PenWorkspaceAppSuggestionsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager] >> %TEMP%\fix10bat.reg
echo "ContentDeliveryAllowed"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RotatingLockScreenEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RotatingLockScreenOverlayEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SilentInstalledAppsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SoftLandingEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-310093Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338387Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338388Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338389Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338393Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-353694Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-353696Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SystemPaneSuggestionsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC] >> %TEMP%\fix10bat.reg
echo "Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search] >> %TEMP%\fix10bat.reg
echo "CortanaEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "BingSearchEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "HistoryViewEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DeviceHistoryEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "CortanaConsent"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "AllowSearchToUseLocation"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings] >> %TEMP%\fix10bat.reg
echo "AcceptedPrivacyPolicy"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore] >> %TEMP%\fix10bat.reg
echo "HarvestContacts"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings] >> %TEMP%\fix10bat.reg
echo "UxOption"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization] >> %TEMP%\fix10bat.reg
echo "SystemSettingsDownloadMode"=dword:00000003 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language] >> %TEMP%\fix10bat.reg
echo "Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization] >> %TEMP%\fix10bat.reg
echo "RestrictImplicitInkCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "RestrictImplicitTextCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy] >> %TEMP%\fix10bat.reg
echo "TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry HKCU for default user
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced] >> %TEMP%\fix10bat.reg
echo "DontUsePowerShellOnWinX"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "Hidden"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "HideFileExt"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "ShowSyncProviderNotifications"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent] >> %TEMP%\fix10bat.reg
echo "DisableWindowsConsumerFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "DisableWindowsSpotlightFeatures"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\PenWorkspace] >> %TEMP%\fix10bat.reg
echo "PenWorkspaceAppSuggestionsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager] >> %TEMP%\fix10bat.reg
echo "ContentDeliveryAllowed"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RotatingLockScreenEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "RotatingLockScreenOverlayEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SilentInstalledAppsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SoftLandingEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-310093Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338387Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338388Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338389Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SubscribedContent-338393Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "SystemPaneSuggestionsEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Input\TIPC] >> %TEMP%\fix10bat.reg
echo "Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search] >> %TEMP%\fix10bat.reg
echo "CortanaEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "BingSearchEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "HistoryViewEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo "DeviceHistoryEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Personalization\Settings] >> %TEMP%\fix10bat.reg
echo "AcceptedPrivacyPolicy"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore] >> %TEMP%\fix10bat.reg
echo "HarvestContacts"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings] >> %TEMP%\fix10bat.reg
echo "UxOption"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization] >> %TEMP%\fix10bat.reg
echo "SystemSettingsDownloadMode"=dword:00000003 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language] >> %TEMP%\fix10bat.reg
echo "Enabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\InputPersonalization] >> %TEMP%\fix10bat.reg
echo "RestrictImplicitInkCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "RestrictImplicitTextCollection"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy] >> %TEMP%\fix10bat.reg
echo "TailoredExperiencesWithDiagnosticDataEnabled"=dword:00000000 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry HKCR
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Drive\shell\cmd2] >> %TEMP%\fix10bat.reg
echo @="@shell32.dll,-8506" >> %TEMP%\fix10bat.reg
echo "Extended"="" >> %TEMP%\fix10bat.reg
echo "Icon"="imageres.dll,-5323" >> %TEMP%\fix10bat.reg
echo "Nodefault"="" >> %TEMP%\fix10bat.reg
echo "NoWorkingDirectory"="" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Drive\shell\cmd2\command] >> %TEMP%\fix10bat.reg
echo @="cmd.exe /s /k pushd \"%%V\"" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Directory\shell\cmd2] >> %TEMP%\fix10bat.reg
echo @="@shell32.dll,-8506" >> %TEMP%\fix10bat.reg
echo "Extended"="" >> %TEMP%\fix10bat.reg
echo "Icon"="imageres.dll,-5323" >> %TEMP%\fix10bat.reg
echo "Nodefault"="" >> %TEMP%\fix10bat.reg
echo "NoWorkingDirectory"="" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Directory\shell\cmd2\command] >> %TEMP%\fix10bat.reg
echo @="cmd.exe /s /k pushd \"%%V\"" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Directory\Background\shell\cmd2] >> %TEMP%\fix10bat.reg
echo @="@shell32.dll,-8506" >> %TEMP%\fix10bat.reg
echo "Extended"="" >> %TEMP%\fix10bat.reg
echo "Icon"="imageres.dll,-5323" >> %TEMP%\fix10bat.reg
echo "Nodefault"="" >> %TEMP%\fix10bat.reg
echo "NoWorkingDirectory"="" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Directory\Background\shell\cmd2\command] >> %TEMP%\fix10bat.reg
echo @="cmd.exe /s /k pushd \"%%V\"" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Registry: Photo Viewer
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
echo. >> %TEMP%\fix10bat.reg
echo ; ======================================================================================== >> %TEMP%\fix10bat.reg
echo ; https://www.tenforums.com/tutorials/14312-restore-windows-photo-viewer-windows-10-a.html >> %TEMP%\fix10bat.reg
echo ; ======================================================================================== >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\jpegfile\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\pngfile\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open] >> %TEMP%\fix10bat.reg
echo "MuiVerb"="@photoviewer.dll,-3043" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\Applications\photoviewer.dll\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Bitmap] >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "FriendlyTypeName"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,\ >> %TEMP%\fix10bat.reg
echo   00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,\ >> %TEMP%\fix10bat.reg
echo   77,00,73,00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,\ >> %TEMP%\fix10bat.reg
echo   00,65,00,72,00,5c,00,50,00,68,00,6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   65,00,72,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,35,00,36,00,00,\ >> %TEMP%\fix10bat.reg
echo   00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Bitmap\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\imageres.dll,-70" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Bitmap\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF] >> %TEMP%\fix10bat.reg
echo "EditFlags"=dword:00010000 >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "FriendlyTypeName"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,\ >> %TEMP%\fix10bat.reg
echo   00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,\ >> %TEMP%\fix10bat.reg
echo   77,00,73,00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,\ >> %TEMP%\fix10bat.reg
echo   00,65,00,72,00,5c,00,50,00,68,00,6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   65,00,72,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,35,00,35,00,00,\ >> %TEMP%\fix10bat.reg
echo   00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\imageres.dll,-72" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF\shell\open] >> %TEMP%\fix10bat.reg
echo "MuiVerb"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,\ >> %TEMP%\fix10bat.reg
echo   69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,\ >> %TEMP%\fix10bat.reg
echo   00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,\ >> %TEMP%\fix10bat.reg
echo   72,00,5c,00,70,00,68,00,6f,00,74,00,6f,00,76,00,69,00,65,00,77,00,65,00,72,\ >> %TEMP%\fix10bat.reg
echo   00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,34,00,33,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg] >> %TEMP%\fix10bat.reg
echo "EditFlags"=dword:00010000 >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "FriendlyTypeName"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,\ >> %TEMP%\fix10bat.reg
echo   00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,\ >> %TEMP%\fix10bat.reg
echo   77,00,73,00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,\ >> %TEMP%\fix10bat.reg
echo   00,65,00,72,00,5c,00,50,00,68,00,6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   65,00,72,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,35,00,35,00,00,\ >> %TEMP%\fix10bat.reg
echo   00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\imageres.dll,-72" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg\shell\open] >> %TEMP%\fix10bat.reg
echo "MuiVerb"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,\ >> %TEMP%\fix10bat.reg
echo   69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,\ >> %TEMP%\fix10bat.reg
echo   00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,\ >> %TEMP%\fix10bat.reg
echo   72,00,5c,00,70,00,68,00,6f,00,74,00,6f,00,76,00,69,00,65,00,77,00,65,00,72,\ >> %TEMP%\fix10bat.reg
echo   00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,34,00,33,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Gif] >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "FriendlyTypeName"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,\ >> %TEMP%\fix10bat.reg
echo   00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,\ >> %TEMP%\fix10bat.reg
echo   77,00,73,00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,\ >> %TEMP%\fix10bat.reg
echo   00,65,00,72,00,5c,00,50,00,68,00,6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   65,00,72,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,35,00,37,00,00,\ >> %TEMP%\fix10bat.reg
echo   00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Gif\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\imageres.dll,-83" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Gif\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Png] >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo "FriendlyTypeName"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,\ >> %TEMP%\fix10bat.reg
echo   00,46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,\ >> %TEMP%\fix10bat.reg
echo   77,00,73,00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,\ >> %TEMP%\fix10bat.reg
echo   00,65,00,72,00,5c,00,50,00,68,00,6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   65,00,72,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,35,00,37,00,00,\ >> %TEMP%\fix10bat.reg
echo   00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Png\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\imageres.dll,-71" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Png\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Png\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp] >> %TEMP%\fix10bat.reg
echo "EditFlags"=dword:00010000 >> %TEMP%\fix10bat.reg
echo "ImageOptionFlags"=dword:00000001 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp\DefaultIcon] >> %TEMP%\fix10bat.reg
echo @="%%SystemRoot%%\\System32\\wmphoto.dll,-400" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp\shell\open] >> %TEMP%\fix10bat.reg
echo "MuiVerb"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,\ >> %TEMP%\fix10bat.reg
echo   69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,\ >> %TEMP%\fix10bat.reg
echo   00,20,00,50,00,68,00,6f,00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,\ >> %TEMP%\fix10bat.reg
echo   72,00,5c,00,70,00,68,00,6f,00,74,00,6f,00,76,00,69,00,65,00,77,00,65,00,72,\ >> %TEMP%\fix10bat.reg
echo   00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,33,00,30,00,34,00,33,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp\shell\open\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget] >> %TEMP%\fix10bat.reg
echo "Clsid"="{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\Image Preview\command] >> %TEMP%\fix10bat.reg
echo @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\ >> %TEMP%\fix10bat.reg
echo   6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\ >> %TEMP%\fix10bat.reg
echo   25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\ >> %TEMP%\fix10bat.reg
echo   00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\ >> %TEMP%\fix10bat.reg
echo   6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\ >> %TEMP%\fix10bat.reg
echo   00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\ >> %TEMP%\fix10bat.reg
echo   5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\ >> %TEMP%\fix10bat.reg
echo   00,31,00,00,00 >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_CLASSES_ROOT\SystemFileAssociations\image\shell\Image Preview\DropTarget] >> %TEMP%\fix10bat.reg
echo "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"="" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities] >> %TEMP%\fix10bat.reg
echo "ApplicationDescription"="@%%ProgramFiles%%\\Windows Photo Viewer\\photoviewer.dll,-3069" >> %TEMP%\fix10bat.reg
echo "ApplicationName"="@%%ProgramFiles%%\\Windows Photo Viewer\\photoviewer.dll,-3009" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations] >> %TEMP%\fix10bat.reg
echo ".jpg"="PhotoViewer.FileAssoc.Jpeg" >> %TEMP%\fix10bat.reg
echo ".wdp"="PhotoViewer.FileAssoc.Wdp" >> %TEMP%\fix10bat.reg
echo ".jfif"="PhotoViewer.FileAssoc.JFIF" >> %TEMP%\fix10bat.reg
echo ".dib"="PhotoViewer.FileAssoc.Bitmap" >> %TEMP%\fix10bat.reg
echo ".png"="PhotoViewer.FileAssoc.Png" >> %TEMP%\fix10bat.reg
echo ".jxr"="PhotoViewer.FileAssoc.Wdp" >> %TEMP%\fix10bat.reg
echo ".bmp"="PhotoViewer.FileAssoc.Bitmap" >> %TEMP%\fix10bat.reg
echo ".jpe"="PhotoViewer.FileAssoc.Jpeg" >> %TEMP%\fix10bat.reg
echo ".jpeg"="PhotoViewer.FileAssoc.Jpeg" >> %TEMP%\fix10bat.reg
echo ".gif"="PhotoViewer.FileAssoc.Gif" >> %TEMP%\fix10bat.reg
echo ".tif"="PhotoViewer.FileAssoc.Tiff" >> %TEMP%\fix10bat.reg
echo ".tiff"="PhotoViewer.FileAssoc.Tiff" >> %TEMP%\fix10bat.reg
echo. >> %TEMP%\fix10bat.reg
reg import %TEMP%\fix10bat.reg
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Legacy Bootloader & Safe Mode
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
bcdedit /set {current} bootmenupolicy Legacy
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Uninstall OneDrive
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
%SystemRoot%\System32\OneDriveSetup /uninstall 2>nul
%SystemRoot%\SysWOW64\OneDriveSetup /uninstall 2>nul
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable Automatic Reboot
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
for /f %%a in ('powershell -Command Get-Date -format yyyyMMdd_HHmmss') do set datetime=%%a
move "%windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot" "%windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot_DisableByFix10Bat_%datetime%"
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable Defender (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10nodefender% == 1 goto fix10_nonodefender
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
:fix10_nonodefender
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Batch utilities (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10dropbatchutils% == 1 goto fix10_nodropbatchutils 
echo. > %SYSTEMROOT%\System32\xqacl.bat
echo. > %SYSTEMROOT%\System32\xqgod.bat
echo. > %SYSTEMROOT%\System32\xqacl_.ps1
echo @echo off >> %SYSTEMROOT%\System32\xqacl.bat
echo if not %%1.==. goto gotargs >> %SYSTEMROOT%\System32\xqacl.bat
echo powershell -Command Start-Process -FilePath $env:ComSpec -Verb runas -WorkingDirectory "%%cd%%" -ArgumentList /k,cd,"%%cd%%" >> %SYSTEMROOT%\System32\xqacl.bat
echo goto :eof >> %SYSTEMROOT%\System32\xqacl.bat
echo :gotargs >> %SYSTEMROOT%\System32\xqacl.bat
echo $workdir, $params = $args >> %SYSTEMROOT%\System32\xqacl_.ps1
echo Start-Process -FilePath "$env:ComSpec" -Verb runas -WorkingDirectory "$workdir" -ArgumentList "/c $params" >> %SYSTEMROOT%\System32\xqacl_.ps1
echo powershell -ExecutionPolicy bypass %%SYSTEMROOT%%\System32\xqacl_.ps1 %%cd%% %%* >> %SYSTEMROOT%\System32\xqacl.bat
echo @start "" "explorer" "shell:::{ED7BA470-8E54-465E-825C-99712043E01C}" >> %SYSTEMROOT%\System32\xqgod.bat
:fix10_nodropbatchutils 
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Remove Mixed Reality (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10removemixed% == 1 goto fix10_noremovemixed
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Holographic4 /v FirstRunSucceeded /t REG_DWORD /d 0
:fix10_noremovemixed 
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Delete Cortana (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10delcortana% == 1 goto fix10_nodelcortana
set dirbase="%SYSTEMROOT%\SystemApps\Microsoft.Windows.Cortana_"
for /D %%x in (%dirbase%*) do if not defined dir set "dir=%%x"
set proc="SearchUI.exe"
taskkill /f /im %proc%
takeown /f %dir% /r
icacls "%dir%\*" /t /c /grant %username%:f
timeout 2 & taskkill /f /im %proc% & rd /s /q %dir%
timeout 2 & taskkill /f /im %proc% & rd /s /q %dir%
timeout 2 & taskkill /f /im %proc% & rd /s /q %dir%
timeout 2 & taskkill /f /im %proc% & rd /s /q %dir%
timeout 2 & taskkill /f /im %proc% & rd /s /q %dir%
:fix10_nodelcortana
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable SmartScreen (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10disablesmartscreen% == 1 goto fix10_nodisablesmartscreen
schtasks /change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /DISABLE
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKU\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
:fix10_nodisablesmartscreen
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Install Linux Subsystem (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10installbash% == 1 goto fix10_noinstallbash
for /f %%a in ('powershell -Command "Write-Output (Get-WindowsOptionalFeature -Online | Out-String -stream | Select-String -Pattern \".* : Microsoft-Windows-Subsystem-Linux\" | Measure-Object -Line).Lines"') do set lxssinstalled=%%a
if not %lxssinstalled% == 0 goto fix10_noinstallbash rem already installed
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d "1" /f
start "" powershell -command "$host.ui.RawUI.WindowTitle = \"Linux Subsystem Installer\"; Enable-WindowsOptionalFeature -Online -FeatureName \"Microsoft-Windows-Subsystem-Linux\" -NoRestart; $host.ui.RawUI.WindowTitle = \"[Finished] Linux Subsystem Installer\"; pause"
:fix10_noinstallbash
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Disable Fast Startup (if enabled)
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if not %fix10disablehiberboot% == 1 goto fix10_nodisablehiberboot
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
:fix10_nodisablehiberboot
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
rem ///////////////// Script complete
rem /=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=/=
if "%silent%" == "1" goto endscriptnokey
color 2f
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo    OOO     K     K
echo   O   O    K    K
echo  O     O   K   K
echo  O     O   KKKK
echo  O     O   K   K
echo   O   O    K    K
echo    OOO     K     K
echo.
echo Restart recommended!
echo.
echo It is recommended to run this
echo script again every time after a
echo major Windows 10 upgrade.
echo.
echo Please review your privacy settings
echo before restarting by opening Run
echo and entering this command:
echo     ms-settings:privacy
echo (or press Win+I -> Privacy)
echo.
call :getsecondparameter %CMDCMDLINE%
if /i not "%CMDFLAG%" == "/c" goto endscript
echo You may now close this window.
echo.
:closewindow
pause >NUL 2>NUL
goto closewindow
rem call :setdefault value key
rem   Runs `set key=value` if key is
rem   not already defined
:setdefault
if defined %2 goto :eof
set %2=%1
goto :eof
rem call :getsecondparameter A B C D ...
rem   Stores second parameter given (B)
rem   to variable named CMDFLAG
:getsecondparameter
set CMDFLAG=%2
goto :eof
:endscript
pause
:endscriptnokey
echo.
color
endlocal
