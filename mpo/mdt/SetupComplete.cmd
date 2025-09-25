@echo off
:: Log start time
echo SetupComplete.cmd started at %date% %time% >> %SystemRoot%\Panther\SetupComplete.log

:: Remove MDT-related folders
echo Copying MDT Logs to C:\Windows\Logs\MDT >> %SystemRoot%\Panther\SetupComplete.log
xcopy /S /I /E C:\MININT\SMSOSD\OSDLOGS C:\Windows\Logs\MDT >> %SystemRoot%\Panther\SetupComplete.log 2>&1
Copy C:\_SMSTaskSequence\Logs\*.* C:\Windows\Logs\MDT /Y >> %SystemRoot%\Panther\SetupComplete.log 2>&1
for %%F in (
	"C:\MININT"
	"C:\_SMSTaskSequence"
	"C:\Windows\Temp\ProvisioningPackages"
) do (
    if exist %%F (
        rmdir /s /q %%F
        echo Removed %%F >> %SystemRoot%\Panther\SetupComplete.log
    )
)

:: Remove MDT leftover files from root of C:
for %%F in (
    "C:\LTIBootstrap.vbs"
) do (
    if exist %%F (
        del /f /q %%F
        echo Deleted %%F >> %SystemRoot%\Panther\SetupComplete.log
    )
)

:: Log completion
echo SetupComplete.cmd finished at %date% %time% >> %SystemRoot%\Panther\SetupComplete.log
exit /b 0