# Fix10.bat

This is a batch file intended for power users to apply some registry and other small tweaks to Windows 10 to increase privacy and usability. Running the batch file is advised every time your system goes through a Windows 10 feature upgrade, as upgrades may reset some of the tweaks.

*Note:* If multiple users use the computer, the script must be run for every user individually.
*Note:* If you get weird syntax errors (such as "GOTO was unexpected at this time"), make sure the .bat file uses CRLF newlines (as Windows expects) and not LF newlines.

## Disclaimer

The batch file in question requires administrative privileges on the system it runs on and is intended to only be run on Windows 10. Regardless of any conditions, you run the batch file at your own risk, and the author of fix10.bat cannot be responsible for increased boot times (will likely happen) or, perhaps even worse, features removed from the system, the system refusing to function or start up properly, or any other adverse side effects. By running the batch file, you accept that you have read this disclaimer and understand its and the script's consequences.

## Notes on Windows 10 editions

Several of the modifications rely on registry settings, some of which are Group Policy settings. Since Microsoft thinks it knows better than Windows users, some of the changes might not work in all editions of Windows 10. The Home and Pro editions are most significantly affected. The longevity of the tweaks cannot be guaranteed, since future Windows 10 versions may also break some of them.

## List of changes applied

The changes are described in more detail in `DOCUMENT.md`.

* Disable diagnostics and tracking services
* Disable advertisements and "tips"
* Try to set Updates to Ask before Download
* Disable Windows Update automatic restarts
* Uninstall and disable OneDrive
* Disable Feedback notifications
* Disable Bing Search
* Disable Application Telemetry
* Disable Steps Recorder
* Disable "Delivery Optimization"
* Disable Wi-Fi Sense
* Turn off advertising ID
* Disable Suggested app download (you will still need to uninstall those already downloaded yourself)
* Disable Windows Spotlight
* Disable keylogger ("improve typing")
* Disable "Getting to know you"
* Opt out from CEIP
* Disable Cortana
* Leave Microsoft MAPS
* Restore Windows Photo Viewer ([source](https://www.tenforums.com/tutorials/14312-restore-windows-photo-viewer-windows-10-a.html))
* Re-enable Task Manager, Registry Editor and Command Interpreter
* Make Ultimate Performance power mode visible (but _not_ selected by default)
* Win+X: PowerShell to CMD
* Re-add CMD to Context menu (if Shift heöd down)
* Enable seconds in the tray
* Show file extensions, hidden files and all drives
* Disable Data Collection Publishing Service
* Enables Legacy Boot Loader + F8 Safe Mode 
  * This might increase boot times by a few seconds, but since it enables Advanced Boot Options (including options to enter Safe Mode), I consider it a fair trade-off.

All of these changes will be applied, but since the batch file is just a batch file, you can simply modify it to disable specific tweaks from being applied.

### Optional changes (must be enabled by editing the file)

At the beginning of a batch file there is a configuration section with a few options, which do the following:

* fix10nodefender (0 disables, 1 enables **(default)**)
  * If enabled, disables Windows Defender.
* fix10dropbatchutils (0 disables (default), 1 enables)
  * If enabled, drops two files, xqacl.bat and xqgod.bat under System32, which add the xqacl and xqgod commands for the Run dialog and command shells. xqacl allows opening an elevated command line, while xqgod opens the All Tasks "god mode" window.
* fix10removemixed (0 disables (default), 1 enables) 
  * If enabled, sets the Holographic FirstRunSucceeded flag to 0. If the computer is restarted with this flag, Mixed Reality should be automatically uninstalled from the computer.
* fix10delcortana (0 disables (default), 1 enables) 
  * If enabled, the script will delete Cortana and its files from the computer. To reinstall it, you must disable this flag and reinstall the package manually through PowerShell.
* fix10disablesmartscreen (0 disables (default), 1 enables) 
  * If enabled, the script will disable SmartScreen. This is a possible security liability, and is not recommended if the computer will be actively used by non-power users.
* fix10installbash (0 disables (default), 1 enables) 
  * If enabled, the script will enable Developer Mode and initiate the installation of the Windows Subsystem for Linux. The subsystem will not be installed if it is already detected.
* fix10disablehiberboot (0 disables (default), 1 enables) 
  * If enabled, the script will disable Fast Startup, thus making sure your system actually shuts down instead of just pretending to. This is especially useful for multi-boot setups.
