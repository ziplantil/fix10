
# Fix10.bat full documentation
## for version 1.3.1
This document provides a list of the changes performed by Fix10.bat, as well as a detailed explanation for each one of them. 

For most of the changes, it is not known whether they are restricted to specific versions of Windows 10 (original, Anniversary, Creators, Fall Creators...) or editions (Home, Pro, Enterprise). If such information is known, it will be indicated for the affected changes.

The documentation will be provided in sections ordered according to their order of appearance in the source code of the batch file itself. If you
want to disable some of the features listed below, simply edit the fix10.bat file and remove or comment out the lines corresponding to that action.

# Disclaimer
The batch file in question requires administrative privileges to run on a system and is intended to only be run on Windows 10. Regardless of conditions, the script is run at your own risk, and the author of fix10.bat cannot be responsible for increased boot times (will likely happen) or, perhaps even worse, features removed from the system or the system refusing to function or start up properly, or any other adverse side effects. By running the batch file, you accept that you have read this disclaimer and understand its and the script's consequences.

# Initialization
The batch script requires administrative rights and checks whether the OS being run is Windows 10, with a warning if Windows 10 is not detected. If the batch script does not have administrative rights, it will attempt to elevate itself.

# Disable services
Several of the services are either disabled here or set to start on demand (so not automatically on startup).

## DiagTrack, Diagnostics Tracking Service
This service is also known as the **Connected User Experiences and Telemetry** starting from Windows 10 Anniversary Update onwards. DiagTrack is the service's actual underlying technical name, and is also how Fix10.bat refers to it in order to maintain compatibility. 

The service in question is used to upload telemetry information to Microsoft's servers, and the data sent is described in detail on Microsoft's website: https://docs.microsoft.com/en-us/windows/configuration/configure-windows-telemetry-in-your-organization
> Use this article to make informed decisions about how you might configure telemetry in your organization. Telemetry is a term that means different things to different people and organizations. For this article, we discuss telemetry as system data that is uploaded by the **Connected User Experience and Telemetry** component. The telemetry data is used to help keep Windows devices secure by identifying malware trends and other threats and to help Microsoft improve the quality of Windows and Microsoft services.

Disabling the service is used as a preventive measure to block any data from being sent. The drawbacks of leaving such telemetry on include its intrusiveness, questionable impact on privacy, and active usage of the active network connection (especially a problem on metered or limited connections). 

## dmwappushsvc, Dmwappushservice
*Since v1.3.0, these services are no longer automatically disabled by Fix10, but you can uncomment the lines if you want to.*

This service is the WAP Push Message Routing Service. Microsoft has not documented this service extensively, but it is used for system bootstrapping and provisioning, and is often also considered to be connected with telemetry (see the service above), so it is often recommended to disable it along DiagTrack.

**Important note: disabling this service will break the *sysprep* script: the script will simply freeze.** To fix this issue, simply enable the service again with the following command under the Command Line running as an administrator: `sc config Dmwappushsvc start= auto & net start Dmwappushsvc`

## diagnosticshub.standardcollector.service
The full name of this service is *Microsoft (R) Diagnostics Hub Standard Collector Service*. The service collected real-time ETW event data and processes it for diagnostic purposes. Since it is connected to telemetry, it is often disabled as well.

## TrkWks
TrkWks is the technical name of the *Distributed Link Tracking Client* service, which "*maintains links between NTFS files within a computer or across computers in a network domain*". The service is disabled mostly for optimization and telemetry purposes.

## WMPNetworkSvc
The *Windows Media Player Network Sharing Service* shares Windows Media Player libraries with other devices using UPnP. It is sometimes connected with high CPU usage and most people are likely to use something else for playing media, which is why the service isn't of any importance for them.

## DoSvc
DoSvc, or the *Delivery Optimization Service*, is used for Delivery Optimization and download updates on Windows Update. Since it seems necessary in order to Windows Update to function properly, the service is not disabled, but rather set to start up on demand (which is the default setting on some newer editions of Windows 10 as well).

## DcpSvc
DcpSvc, or *DataCollectionPublishingService*, was used in older versions of Windows 10 to send data to other applications. Starting it manually seems to be the default setting for it, and this is what Fix10.bat sets it to as well (since applications may need this service to run properly). The service is not present in newer versions of Windows 10 (Creators Update onwards?).

# Disable scheduled tasks
All the tasks mentioned here are disabled with the `schtasks` command.

## Microsoft Compatibility Appraiser
This scheduled task is used with the Customer Experience Improvement Program (CEIP), and is disabled, since Fix10.bat opts the computer out from CEIP. The task itself is used to check for program compatibility upon a major Windows 10 update, and could even be responsible for programs being uninstalled on upgrades.

## ProgramDataUpdater
This scheduled task is used with the Customer Experience Improvement Program (CEIP), and is disabled, since Fix10.bat opts the computer out from CEIP. Based on the task's name, it is used to collect program data of some kind.

## Consolidator, KernelCeipTask, UsbCeip
These scheduled tasks are used with the Customer Experience Improvement Program (CEIP), and is disabled, since Fix10.bat opts the computer out from CEIP. Consolidator is responsible for running `wsqmcons.exe`, for which the only documentation provided is 
> This program collects and sends usage data to Microsoft.
KernelCeipTask (The Kernel CEIP (Customer Experience Improvement Program) Task) "*collects additional information about the system and sends this data to Microsoft.*"
UsbCeip `collects Universal Serial Bus related statistics and information about your machine and sends it to the Windows Device Connectivity engineering group at Microsoft.`

# Search UI firewall
The PowerShell command executed under this section adds a new firewall rule that blocks the `SearchUI.exe` process from sending any information to the Internet. This will effectively break online searching in Windows Search as well as Cortana, but both are also disabled later on.

# Telemetry stuff
The somewhat less descriptive section disables the `AutoLogger-Diagtrack-Listener.etl` file by emptying it and preventing the system from modifying it using file permissions. This file is used for tracking event logs and is connected to telemetry, with some even accusing it of being a component of a "*keylogger*".

# Ultimate Performance
This command enables the Ultimate Performance power mode on Windows 10 Spring Creators Update and above. It is not selected by default, but will be visible under the Power settings.

# taskmgr, regedit, cmd
This section does a total of six registry changes: all of them involve the policies used to disable the Task Manager, Registry Editor and Command Interpreter. The registry changes simply disable these restrictions, allowing the tools to be used again if blocked that way. 

# Registry header
The registry file that starts to be generated here will be written into the temp directory (full filename `%TEMP%\fix10bat.reg`) and applied once it is finished. The registry changes are numerous, but documentation will be provided for every single one. The header section simply starts the generation of the .reg file by starting with the standard .reg header. 

# Registry HKLM
These changes all apply to `HKEY_LOCAL_MACHINE` and are therefore global for the computer.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
* `AUOptions`=`dword:00000002`
  * Sets the automatic updates to "Notify before download". [(Source)](https://docs.microsoft.com/en-us/windows/deployment/update/waas-wu-settings#configure-automatic-updates)
* `NoAutoUpdate`=`dword:00000000`
  * Enables automatic updates (but see above setting). [(Source)](https://support.microsoft.com/en-us/help/328010/how-to-configure-automatic-updates-by-using-group-policy-or-registry-s)
* `AUPowerManagement`=`dword:00000000`
  * Prohibits the system from waking up to perform updates.
* `NoAutoRebootWithLoggedOnUsers`=`dword:00000001`
  * Prohibits the system from restarting with users logged on. [(Source)](https://technet.microsoft.com/en-us/library/dd939923%28v=ws.10%29.aspx?f=255&MSPPError=-2147217396)
* `RebootRelaunchTimeout`=`dword:000005a0`
  * Sets the reboot relaunch timeout to the maximum value of 1440. This is the number of minutes between scheduled restart notifications. [(Source)](https://technet.microsoft.com/en-us/library/cc708449(v=ws.10).aspx)
* `RebootRelaunchTimeoutEnabled`=`dword:00000001`
  * Makes the change above effective. [(Source)](https://technet.microsoft.com/en-us/library/cc708449(v=ws.10).aspx)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU`
* Same registry values as above.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`
* `AUOptions`=`dword:00000002`
  * The same as under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows`
* `DisableFileSync`=`dword:00000001`
  * Disables OneDrive's file synchronization and effectively the integration itself.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config`
* `DownloadMode`=`dword:00000000`
* `DODownloadMode`=`dword:00000000`
  * Disables Delivery Optimization and sets updates to only be downloaded directly from Microsoft. 

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
## `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\CurrentVersion\DataCollection`
* `AllowTelemetry`=`dword:00000000`
  * Sets the Telemetry level to Security, which according to Microsoft, will transmit "[i]nformation that’s required to help keep Windows, Windows Server, and System Center secure, including data about the Connected User Experience and Telemetry component settings, the Malicious Software Removal Tool, and Windows Defender." Note that this is equal to "Basic" on Windows 10 Home and Pro. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/configure-windows-telemetry-in-your-organization)
* `DoNotShowFeedbackNotifications`=`dword:00000001`
  * Disables feedback notifications sent by or via the Feedback app. [(Source)](https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#experience-donotshowfeedbacknotifications)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection`
* `AllowTelemetry`=`dword:00000000`
  * Sets the Telemetry level to Security, similar to the setting under the key `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection`.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Siuf\Rules`
* `PeriodInNanoSeconds`=`dword:00000000`
* `NumberOfSIUFInPeriod`=`dword:00000000`
  * Prevents Windows from asking you for feedback. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata`
* `PreventDeviceMetadataFromNetwork`=`dword:00000001`
  * Prevents Windows from retrieving device metadata online.  [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent`
* `DisableSoftLanding`=`dword:00000001`
* `DisableWindowsConsumerFeatures`=`dword:00000001`
* `DisableWindowsSpotlightFeatures`=`dword:00000001`
  * Disables Windows Spotlight, which provides changing wallpapers, tips and advertisements on the Lock Screen. `DisableWindowsSpotlightFeatures` is only effective from Anniversary Update onwards. **According to Microsoft, some of these settings do not work on Windows 10 Home or Pro.** [(Source 1)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services), [(2)](https://docs.microsoft.com/en-us/windows/configuration/windows-spotlight)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo`
* `Enabled`=`dword:00000000`
  * Disables apps from using the advertising ID and resets it. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo`
* `DisabledByGroupPolicy`=`dword:00000001`
  * Disables apps from using the advertising ID and resets it. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\Software\Microsoft\SQMClient\Windows`
* `CEIPEnable`=`dword:00000000`
  * Opts the computer out from CEIP (Customer Experience Improvement Program). [(Source)](https://msdn.microsoft.com/en-us/library/dd405474(v=vs.85).aspx)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat`
* `AITEnable`=`dword:00000000`
  * Disables Application Impact Telemetry (AIT).
* `DisableUAR`=`dword:00000001`
  * Disables the Problem Steps Recorder. Both this and the setting above are related to telemetry.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search`
* `AllowCortana`=`dword:00000000`
  * Disallows Cortana from being used on the computer. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* `DisableWebSearch`=`dword:00000001`
  * Disallows web searches from being done using Windows Search. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* `ConnectedSearchUseWeb`=`dword:00000000`
  * Disables searching the web via Windows Search or web results from being shown in Windows Search. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* `ConnectedSearchPrivacy`=`dword:00000003`
  * Only sets anonymous info to be sent with Bing in web search, should it be enabled. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive`
* `DisableFileSyncNGSC`=`dword:00000001`
  * Disables OneDrive's file synchronization and effectively the integration itself. (To be exact, the value disables the OneDrive for Business Next Generation Sync Client, hence NGSC, but as a result OneDrive is disabled completely). [(Source)](https://support.microsoft.com/en-us/help/3145959/onedrive-for-business-next-generation-sync-client-onedrive-exe-exits-i)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive`
* `PreventNetworkTrafficPreUserSignIn`=`dword:00000001`
  * Disables OneDrive on the computer. The exact behavior is to prevent OneDrive from generating any network traffic prior to the user signing in. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization`
* `AllowInputPersonalization`=`dword:00000000`
  * Disables the "usage of cloud based speech services for Cortana, dictation, or Store applications". **According to Microsoft, this setting does not work on Windows 10 Home.** [(Source)](https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#privacy-allowinputpersonalization)
* `RestrictImplicitInkCollection`=`dword:00000001`
  * Disables the usage of contact and calendar data for the automatic learning of speech patterns. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* `RestrictImplicitTextCollection`=`dword:00000001`
  * Microsoft has not documented this setting, but it is very likely related to the above, and is probably used for spellchecking.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config`
* `AutoConnectAllowedOEM`=`dword:00000000`
  * Turns off Wi-Fi Sense and all Wi-Fi Sense features. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-wifi-sense-in-enterprise)

## `HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting`
* `value`=`dword:00000000`
  * Turns off Wi-Fi sense features.

## `HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots`
* `value`=`dword:00000000`
  * Turns off Wi-Fi sense features. **According to Microsoft, this setting does not work on Windows 10 Home.** [(Source)](https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-wifi#wifi-allowwifihotspotreporting)

# Registry HKCU for current user
These changes all apply to `HKEY_CURRENT_USER` and therefore only affect the user that runs the script.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
* `DontUsePowerShellOnWinX`=`dword:00000001`
  * Changes the PowerShell menu option under the Win+X menu to the classic Command Interpreter.
* `Hidden`=`dword:00000001`
  * Shows hidden files in File Explorer.
* `HideFileExt`=`dword:00000000`
  * Shows all file extensions in File Explorer.
* `HideDrivesWithNoMedia`=`dword:00000000`
  * Shows all drives regardless of whether they have media inserted in them.
* `ShowSyncProviderNotifications`=`dword:00000000`
  * Disables OneDrive and other advertisements, tips and notifications in File Explorer. 

## `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent`
* `DisableWindowsConsumerFeatures`=`dword:00000001`
* `DisableWindowsSpotlightFeatures`=`dword:00000001`
  * These two are related to the values with the same names under `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent` and disable Windows Spotlight features.

## `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace`
* `PenWorkspaceAppSuggestionsEnabled`=`dword:00000000`
  * Disables app suggestions in Windows Ink Workspace.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`
* `ContentDeliveryAllowed`=`dword:00000000`
  * Disables automatic content delivery, more exact details are unknown.
* `RotatingLockScreenEnabled`=`dword:00000000`
  * Disables Windows Spotlight's automatic changing lock screen wallpapers.
* `RotatingLockScreenOverlayEnabled`=`dword:00000000`
  * Disables tooltips and advertisements on Windows Spotlight's automatic changing lock screen wallpapers.
* `SilentInstalledAppsEnabled`=`dword:00000000`
  * Disables suggested apps from being installed automatically and silently.
* `SoftLandingEnabled`=`dword:00000000`
  * Disables tips and advertisements from being sent as notifications.
* `SubscribedContent-310093Enabled`=`dword:00000000`
  * Disables "*Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested*" [(Source)](https://www.reddit.com/r/sysadmin/comments/7bl1f2/has_anyone_found_a_canonical_mapping_of_windows/)
* `SubscribedContent-338387Enabled`=`dword:00000000`
  * Disables "*Get fun facts, tips and more from Windows and Cortana on your lock screen*" [(Source)](https://www.reddit.com/r/sysadmin/comments/7bl1f2/has_anyone_found_a_canonical_mapping_of_windows/)
* `SubscribedContent-338388Enabled`=`dword:00000000`
  * Disables "*Occasionally show suggestions in Start*" [(Source)](https://www.reddit.com/r/sysadmin/comments/7bl1f2/has_anyone_found_a_canonical_mapping_of_windows/)
* `SubscribedContent-338389Enabled`=`dword:00000000`
  * Disables "*Get tips, tricks, and suggestions as you use Windows*" [(Source)](https://www.reddit.com/r/sysadmin/comments/7bl1f2/has_anyone_found_a_canonical_mapping_of_windows/)
* `SubscribedContent-338393Enabled`=`dword:00000000`
  * Disables "*Show me suggested content in the Settings app*" [(Source)](https://www.reddit.com/r/sysadmin/comments/7bl1f2/has_anyone_found_a_canonical_mapping_of_windows/)
* `SubscribedContent-353694Enabled`=`dword:00000000`
  * Disables suggested content in the Settings app.
* `SubscribedContent-353696Enabled`=`dword:00000000`
  * Disables suggested content in the Settings app.
* `SystemPaneSuggestionsEnabled`=`dword:00000000`
  * Disables app suggestions in the Start Menu.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC`
* `Enabled`=`dword:00000000`
  * Disables "*Send Microsoft info about how I write to help us improve typing and writing in the future*".

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search`
* `CortanaEnabled`=`dword:00000000`
  * Disables Cortana from the current user.
* `BingSearchEnabled`=`dword:00000000`
  * Disables online Bing searching through Windows Search from the current user.
* `HistoryViewEnabled`=`dword:00000000`
  * Prevents Cortana from showing the (search?) history.
* `DeviceHistoryEnabled`=`dword:00000000`
  * Prevents Cortana from accessing the device history.
* `CortanaConsent`=`dword:00000000`
  * Denies consent from Cortana for user data.
* `AllowSearchToUseLocation`=`dword:00000000`
  * Prevents Cortana/Bing search from using your location.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings`
* `AcceptedPrivacyPolicy`=`dword:00000000`
  * Disables personalized learning by setting the privacy policy related to such features as denied. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore`
* `HarvestContacts`=`dword:00000000`
  * Disables the usage of contact info for personalized learning. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/manage-connections-from-windows-operating-system-components-to-microsoft-services)

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`
* `UxOption`=`dword:00000001`
  * Sets Windows to notify to schedule restart instead of automatically restarting.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization`
* `SystemSettingsDownloadMode`=`dword:00000003`
  * Restricts Windows Update's peer-to-peer updating to the local network only.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language`
* `Enabled`=`dword:00000000`
  * Prevents synchronization of language settings. This is also related to automatic learning of typing and speaking data.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization`
* `RestrictImplicitInkCollection`=`dword:00000001`
* `RestrictImplicitTextCollection`=`dword:00000001`
  * Same behavior as under `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization`.

## `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy`
* `TailoredExperiencesWithDiagnosticDataEnabled`=`dword:00000000`
  * Disables Tailored Experiences with Diagnostics Data after feature updates. [(Source)](https://docs.microsoft.com/en-us/windows/configuration/basic-level-windows-diagnostic-events-and-fields-1703)

## `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet`
* `SpyNetReporting`=`dword:00000000`
  * Leaves Microsoft MAPS.
* `SubmitSamplesConsent`=`dword:00000002`
  * Prevents file samples from being sent to Microsoft.

# Registry HKCU for default user
These changes all apply to `HKEY_USERS\.DEFAULT` and therefore affects the system or login user. The changed values are the same applied for the current user in the previous section. Despite the name, this does not affect a "*default user*", and it is hence recommended to run this script for all users separately, including new users created afterwards.

# Registry HKCR
These changes all apply to `HKEY_CLASSES_ROOT`. The only change done here is the addition of the "Open Command Window Here" option under the right-click menu of the File Explorer. This option has a localized name, an icon, and can only be viewed if Shift is held when the right-click menu is opened (to always show the option, remove the lines with `Extended`).

# Registry: Photo Viewer
Changes applied here will enable the classic Windows Photo Viewer. The exact patch `Restore_Windows_Photo_Viewer_ALL_USERS_with_Sort_order_fix.reg` originates from https://www.tenforums.com/tutorials/14312-restore-windows-photo-viewer-windows-10-a.html (the link has additional information).

At the end of this section, the generated registry file is finally applied with `reg import`.

# Legacy Bootloader & Safe Mode
This command enables the "legacy" Windows 7 boot loader and boot menu options in Windows 10. While this may slow down the startup process by a second or two, it brings back the ability to enter the boot menu directly with F8 and use it to enter Safe Mode, which makes the change welcome in the case Safe Mode will become necessary in order to fix an issue.

# Uninstall OneDrive
These two commands run the 32-bit and 64-bit editions of OneDriveSetup.exe with the /uninstall flag, effectively uninstalling OneDrive from the machine, since most users will not have a use for it, and Microsoft is known to advertise OneDrive with notifications as well as in the File Explorer.

# Disable Automatic Reboot 
These two commands modify the `Reboot` task template used by Windows Update, with the intended purpose being to completely disable Windows Update's ability to restart the computer of its own volition. The first command is used to get a formatted string representing the current date and time. 

# Batch utilities (if enabled)
If the config setting `fix10dropbatchutils` is set to `1` (`0` is the default setting), two batch files (so far) are dropped under `%SYSTEMROOT%` (usually `C:\Windows`) called `xqacl.bat` and `xqgod.bat`. 

`xqacl` allows starting elevated command lines (and simple commands, but the argument section is not supported), while `xqgod` acts as a shortcut to open the `All Tasks` folder (sometimes called *god mode*). They are dropped under the system directory to ensure that they can be run from the Run dialog and as commands.

# Disable Windows Defender (if enabled)
If the config setting `fix10nodefender` is set to `1` (`1` is the default setting), Windows Defender will be disabled by registry changes.

## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`
* `DisableAntiSpyware`=`dword:00000001`
  * Disables Windows Defender.
* `DisableRealtimeMonitoring`=`dword:00000001`
  * Disables Windows Defender real-time monitoring.
## `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
* `DisableBehaviorMonitoring`=`dword:00000001`
  * Disables Windows Defender behavior monitoring.
* `DisableOnAccessProtection`=`dword:00000001`
  * Disables Windows Defender on-access protection.
* `DisableScanOnRealtimeEnable`=`dword:00000001`
  * Disables Windows Defender process scanning.

# Remove Mixed Reality (if enabled)
If the config setting `fix10removemixed` is set to `1` (`0` is the default setting), a value called `FirstRunSucceeded` will be created in the registry key `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Holographic4` with the value `0`. This will signify a failure on the first run of Mixed Reality, removing it from Settings and, according to Microsoft, uninstalling it from the computer. It is not known whether this is the case anymore with newer versions of Windows 10.

# Delete Cortana (if enabled)
If the config setting `fix10delcortana` is set to `1` (`0` is the default setting), the script will literally *delete* Cortana files from the machine. This might cause severe issues later on, especially if later versions of Windows 10 will further tighten the Cortana integration. The exact steps involve finding the folder belonging to the app `Microsoft.Windows.Cortana` under the SystemApps folder, granting the running user full rights and then deleting it. In order to use Cortana again, you would have to reinstall it through PowerShell (`Get-AppXPackage -Name Microsoft.Windows.Cortana | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}`).

# Disable SmartScreen (if enabled)
If the config setting `fix10disablesmartscreen` is set to `1` (`0` is the default setting), the script will disable Windows SmartScreen. This is not recommended if the computer will also be actively used by non-power users. The exact changes done disable the `SmartScreenSpecific` scheduled task, and three registry changes:

* `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation : Enabled = 0 (REG_DWORD)`, same for `HKEY_USERS\.DEFAULT`
* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer : SmartScreenEnabled = "Off" (REG_SZ)`

# Install Linux Subsystem (if enabled)
If the config setting `fix10installbash` is set to `1` (`0` is the default setting), the script will install the Linux Subsystem for Windows if it isn't already detected to be installed. In order to do this, the Developer Mode is also enabled with the following registry changes:

* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock : AllowAllTrustedApps = 1 (REG_DWORD)`
* `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock : AllowDevelopmentWithoutDevLicense = 1 (REG_DWORD)`

after which a small script is run in PowerShell, with the crux being the call `Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart`.

# Disable Fast Startup (if enabled)
If the config setting `fix10disablehiberboot` is set to `1` (`0` is the default setting), the Fast Startup (*Hiberboot*) is disabled with a single registry change:

* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power : HiberbootEnabled = 0 (REG_DWORD)`

This is especially recommended for multi-boot setups, as Windows volumes might be inaccessible with Fast Startup enabled. This is because if Fast Startup is enabled, Windows never actually *shuts down*, but instead *hibernates*. The problem with Fast Startup is explained in great detail here: https://askubuntu.com/a/452080

# Script complete
Once the script is complete, the script finishes by writing a message to the screen. If the script was opened in an existing command line, control will be returned, but if the batch script was opened in its own window, the file will enter an infinite loop and ask the user to close the window. 

The final message encourages the user to check their privacy settings, provides a command to open them, advises to run the script after every major upgrade and then recommends the user to restart to apply the changes, as it is necessary to do so for some of the changes.

The final section also includes some subroutines used by the script itself.

# Command line switches
* `/q` - quiet mode, no confirmation (but messages will still get printed).
