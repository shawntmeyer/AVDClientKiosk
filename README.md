# Azure Virtual Desktop Client Kiosk

## Introduction

This repository contains a script and supporting artifacts to configure a Windows client operating system to act as a custom Azure Virtual Desktop (AVD) client kiosk using the [Remote Desktop Client for Windows](https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-remote-desktop-client?tabs=windows).

The solution consists of two main parts: User interface customizations and Remote Desktop client configurations.

The user interface customizations are configured using:

- A Shell Launcher or Multi-App configuration applied via the Assigned Access CSP WMI Bridge.
- a multi-user local group policy object for non-administrative users.
- a local group policy object that affects computer settings.
- an applocker policy that disables Windows Search, Notepad, Internet Explorer, WordPad, and Edge for all Non-Administrators.
- one or more provisioning packages that remove pinned items from the start menu and enable Shared PC mode when that switch is used.

The Remote Desktop client configurations are designed to enforce security of the client and access to the Azure Virtual Desktop service. The options can be summarized by the choice of triggers such as 'DeviceRemoval', 'IdleTimeout', or 'SessionDisconnect' (or supported combinations) and trigger actions such as 'Lock the workstation', 'Sign the user out of the workstation' or 'Reset the Remote Desktop client to remove cached credentials'.
 
This custom kiosk could be used for numerous scenarios including the three shown in Figure 1 below. These scenarios are discussed more in the sections below.

**Figure 1:** Azure Virtual Desktop Client Kiosk Usage Scenarios

![Azure Virtual Desktop Client Kiosk Usage Scenarios](docs/media/KioskTypes.png)

## Prerequisites

1. A currently [supported version of a Windows client operating system](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client) with the choice of editions based on the use of the **AVDClientShell** parameter as follows:
   1. The `AVDClientShell` option requires one of the following Windows client editions[^1]:
      - Education
      - Enterprise
      - Enterprise LTSC
      - IoT Enterprise
      - IoT Enterprise LTSC
   2. If you <ins>don't</ins> pick the `AVDClientShell` option, then supported Windows client editions include[^2]:
      - Education
      - Enterprise
      - Enterprise LTSC
      - IoT Enterprise
      - IoT Enterprise LTSC
      - Pro
      - Pro Education

2. The ability to run the installation script as SYSTEM. The instructions are provided in the [Installation section](#installation).

3. For Scenario 1 and 3, you'll need to [join the client device to Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/concept-directory-join) or [Entra ID Hybrid Join the device](https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join).

[^1]: For more information see [Shell Launcher Windows Edition Requirements](https://learn.microsoft.com/en-us/windows/configuration/assigned-access/shell-launcher/?tabs=intune#windows-edition-requirements).
[^2]: For more information see [Assigned Access Windows Edition Requirements](https://learn.microsoft.com/en-us/windows/configuration/assigned-access/overview?tabs=ps#windows-edition-requirements)

## User Interface

### Summary

The user interface experience is determined by several factors and parameters. The parameters are all documented in the [Parameters section](#parameters) below, but the following table outlines the resulting user interface based on the parameter values and operating system.

**Table 1:** Azure Virtual Desktop User Interface Summary

| AVDClientShell | AutoLogon | Operating System | User Interface |
|:--------------:|:---------:|------------------|----------------|
| True           | True      | Windows 10+ | The default explorer shell will be replaced with the Remote Desktop client for Windows via the Shell Launcher Assigned Access CSP. The Windows 10 (or later) client will automatically logon to the shell with 'KioskUser0' account. The user will be presented with a dialog to logon to Remote Desktop client. This is one option for the user interface in the Scenario 2 configuration. |
| True           | False     | Windows 10+ | The default explorer shell will be replaced with the Remote Desktop client for Windows via the Shell Launcher Assigned Access CSP. The user will sign-in to the device using Entra ID credentials and will be automatically signed in to the Remote Desktop client. |
| False          | True      | Windows 10 | The default shell remains explorer.exe; however, it is heavily customized and locked down to allow only the Remote Desktop client to be executed from the customized Start Menu. This configuration allows for easier user interaction with remote sessions, the Remote Desktop client interface, and Display Settings if the option is chosen. The Shell Launcher configuration of the Assigned Access CSP is used to configure the Windows 10 client with autologon to the shell with the 'KioskUser0' account. The user will be presented with a dialog to logon to Remote Desktop client. This is the other Windows 10 option for the user interface in the Scenario 2 configuration. |
| False          | True      | Windows 11 | A Multi-App Kiosk configuration is applied via the Assigned Access CSP which automatically locks down the explorer interface to only show the Remote Desktop client. This configuration allows for easier user interaction with remote sessions and the Remote Desktop client along with Display Settings if the option is chosen. The Windows 11 22H2+ client will automatically logon to the shell with 'KioskUser0' account. The user will be presented with a dialog to logon to Remote Desktop client. This is the other Windows 11 (and later) option for the user interface in the Scenario 2 configuration. |
| False          | False     | Windows 10 | *This is the default configuration if no parameters are specified when running the script on Windows 10.* The explorer shell is the default shell; however, it is heavily customized and locked down to allow only the Remote Desktop client to be executed from the customized Start Menu. This configuration allows for easier user interaction with remote sessions, the Remote Desktop client interface, and display settings if the option is chosen. The user will sign-in to the device using Entra ID credentials and will be automatically signed in to the Remote Desktop client. |
| False          | False     | Windows 11 | *This is the default configuration if no parameters are specified when running the script on Windows 11 22H2+.* A Multi-App Kiosk configuration is applied via the Assigned Access CSP which automatically locks down the explorer interface to only show the Remote Desktop client. This configuration allows for easier user interaction with remote sessions, the Remote Desktop client interface, and the display settings if the option is chosen. The user will sign-in to the device using Entra ID credentials and will be automatically signed in to the Remote Desktop client. |

### Examples

#### Multi-App Kiosk

When the operating system of the client device is Windows 11 22H2 or greater, and the `AVDClientShell` switch parameter is <u>not</u> specified, the device is configured using the [Multi-App Kiosk Assigned Access CSP](https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/customize/multi-app-kiosk).

The user interface experience with the `ShowDisplaySettings` switch parameter selected is shown in the video and figures below. You can also see that the remote desktop connection automatically launched because it was the only resource assigned to the user. Click on the first screenshot below to open the video on Youtube.

[![Watch the demo](https://img.youtube.com/vi/HWlUHZ5SBMU/maxresdefault.jpg)](https://youtu.be/HWlUHZ5SBMU)

The figure below illustrates the Multi-App interface and the ease at which a user can have multiple sessions open.

**Figure 2:** Multi-App Showing a client connection

![Multi-App Showing a client connection](docs/media/multi-app-showing-client-and-connection.png)

The figure below illustrates the Settings applet restricted to allow the user to adjust display settings. This would primarily be used in a multi-monitor scenario.

**Figure 3:** Multi-App Showing Display Settings

![Multi-App Showing a client connection](docs/media/displaySettings.png)

#### Shell Launcher

When the `AVDClientShell` parameter is selected on any operating system, the default user shell (explorer.exe) is replaced with the [Remote Desktop client](https://learn.microsoft.com/en-us/azure/virtual-desktop/users/connect-remote-desktop-client?tabs=windows) using the [Shell Launcher CSP](https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/customize/shell-launcher).

The user interface experience is shown in the video and figure below. Click on the first screenshot below to open the video on Youtube. 

[![Watch the demo](https://img.youtube.com/vi/w4rev491RK4/maxresdefault.jpg)](https://youtu.be/w4rev491RK4)

In the figure below, you can see that the interface no longer has a taskbar or Start Menu. This configuration makes it harder to interact with multiple open sessions after going full screen, but not impossible especially with keyboard shortcuts such as WINDOWSKEY-LEFT or RIGHT ARROW.

**Figure 4:** Shell Launcher full screen

![Shell Launcher full Screen](docs/media/shellLauncherInterface.png)

## Triggers and Actions

The tables below outline the actions taken based on the `Autologon` and *Trigger Action parameters*.

The first trigger action parameter is `DeviceRemovalAction`. This trigger is activated when a security device, defined as either a smart card or a FIDO2 token with a Vendor ID specified in the `DeviceVendorId` parameter is removed from the local system.

**Table 2:** Device Removal Action Summary

| AutoLogon | DeviceRemovalAction | DeviceType | Behavior |
| :-------: | :-----------------: | :--------: | :--- |
| True | ResetClient | Either | The client launch script creates a WMI Event Filter that fires when a user removes their authentication device - either a SmartCard (`SmartCard`) or a FIDO2 passkey device (`DeviceVendorId`) or closes the Remote Desktop client, then the launch script resets the client removing the cached credentials and restarts the launch script. |
| | Lock | SmartCard | The built-in Smart Card Policy removal service is configured using the [SmartCard removal behavior policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-smart-card-removal-behavior) to lock the system when the smart card is removed. |
| | Lock | FIDO2 | The client launch script creates a WMI Event Filter that fires when a user removes their [FIDO2 passkey device](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#passkeys-fido2) as specified using the `DeviceVendorID` parameter. When the event is detected, the script locks the computer. |
| | Logoff | SmartCard | The built-in Smart Card Policy removal service is configured using the [SmartCard removal behavior policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-smart-card-removal-behavior) to Force Logoff the user when the smart card is removed. |
| | Logoff | FIDO2 | The client launch script creates a WMI Event Filter that fires when a user removes their [FIDO2 passkey device](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#passkeys-fido2). When the event is detected, the script forcefully logs the user off the computer. |

The next trigger action parameter is `IdleTimeoutAction`. This trigger is activated when the local device has seen no user activity. It is measured via the inbuilt machine inactivity timer or via the custom launch script as defined in the table below.

**Table 3:** Idle Timeout Action Summary

| AutoLogon | IdleTimeoutAction | Behavior |
| :-------: | :---------------: | :------- |
| True | ResetClient | The client launch script starts a timer at 0. Every 30 seconds, it checks to see if there are cached credentials and no open Remote Connections to resources. If this condition is true, then it increments the counter by 30 seconds. If it is not True, then the counter is reset to 0. If the counter reaches the value specified by the `IdleTimeout` parameter, then the launch script resets the client removing the cached credentials and restarts the launch script. |
| | Lock | The system will lock the computer after the amount of time specified in the `IdleTimeout` parameter using the [Interactive Logon Machine Inactivity Limit built-in policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit) Windows. |
| | Logoff | The client launch script starts a timer at 0. Every 30 seconds, it checks to see if there are open Remote Connections to resources. If this condition there are no open connections, then it increments the counter by 30 seconds. If there are open connections, then the counter is reset to 0. If the counter reaches the value specified by the `IdleTimeout` parameter, then the launch script will logoff the user. |

The next trigger action parameter is `SystemDisconnectAction`. This trigger is activated when a remote desktop connection is disconnected by the system due to inactivity on the remote session host with Entra ID SSO configured to lock the computer or a user connects to the same remote session with another client.

**Table 4:** System Disconnect Action Summary

| AutoLogon | SystemDisconnectAction | Behavior |
| :-------: | :--------------------: | :------- |
| True | ResetClient | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 3 that indicates the connection was closed due to a remote connection (from another client system) or a locked or disconnected session. When these events are detected and there are no other open remote desktop connections, the launch script resets the client removing the cached credentials and restarts the launch script. |
| | Lock | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 3 that indicates the connection was closed due to a remote connection (from another client system) or a locked or disconnected session. When these events are detected and there are no other open remote desktop connections, the launch script locks the local computer. |
| | Logoff | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 3 that indicates the connection was closed due to a remote connection (from another client system) or a locked or disconnected session. When these events are detected and there are no other open remote desktop connections, the launch script signs the user out of the local computer. |

The next trigger action parameter is `UserDisconnectSignOffAction`. This trigger is activated when a user initiates a sign out in the remote session or disconnects the remote session. It is also triggered when the user closes the AVD Client on the local workstation.

**Table 5:** User Disconnect or SignOut Action Summary

| AutoLogon | UserDisconnectSignOutAction | Behavior |
| :-------: | :-------------------------: | :------- |
| True | ResetClient | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 1 or 2 that indicates the connection was closed by the user. When these events are detected and there are no other open remote desktop connections, the launch script resets the client removing the cached credentials and restarts the launch script. |
| | Lock | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 1 or 2 that indicates the connection was closed by the user. When these events are detected and there are no other open remote desktop connections, the launch script locks the local computer. |
| | Logoff | The client launch script creates a WMI Event Filter that fires when a Remote Desktop connection is closed based on an event ID 1026 in the 'Microsoft-Windows-TerminalServices-RDPClient/Operational' log. When this event is detected the event log is queried for reason code = 1 or 2 that indicates the connection was closed by the user. When these events are detected and there are no other open remote desktop connections, the launch script signs the user out of the local computer. |

## Installation

This section documents the parameters and the manual installation instructions

### Parameters

The table below describes each parameter and any requirements or usage information.

**Table 6:** Set-AVDClientKioskSettings.ps1 Parameters

| Parameter Name | Type | Description | Notes/Requirements |
|:---------------|:----:|:------------|:-------------------|
| `ApplySTIGs` | Switch | Determines if the latest DoD Security Technical Implementation Guide Group Policy Objects are automatically downloaded from [Cyber Command](https://public.cyber.mil/stigs/gpo) and applied via the Local Group Policy Object (LGPO) tool to the system. | If they are, then several delta settings are applied to allow the system to communicate with Entra Id and complete autologon (if applicable). Requires access to https://public.cyber.mil/stigs/gpo |
| `Autologon` | Switch | Determines if Autologon is enabled through the Shell Launcher or Multi-App Kiosk configuration. | When configured, Windows will automatically create a new user, 'KioskUser0', which will not have a password and be configured to automatically logon when Windows starts. **This is the primary parameter used to configure the kiosk for Scenario 2**. |
| `AVDClientShell` | Switch | Determines whether the default Windows shell (explorer.exe) is replaced by the Remote Desktop client for Windows. | When not specified the default shell is used and, on Windows 11 22H2 and later, the Multi-App Kiosk configuration is used along with additional local group policy settings and provisioning packages to lock down the shell. On Windows 10, only local group policy settings and provisioning packages are used to lock down the shell. |
| `EnvironmentAVD` | String | Determines the Azure environment to which you are connecting. | Determines the Url of the Remote Desktop Feed which varies by environment by setting the '$SubscribeUrl' variable and replacing placeholders in several files during installation. The possible values are 'AzureCloud', 'AzureChina', 'AzureUSGovernment', 'AzureGovernmentSecret', and 'AzureGovernmentTopSecret'. See [Air-Gapped Cloud Support](#air-gapped-cloud-support) for updating the code to support 'AzureGovernmentSecret' and 'AzureGovernmentTopSecret'. Default is 'AzureCloud' |
| `InstallAVDClient` | Switch | Determines if the latest Remote Desktop client for Windows and the Visual Studio C++ Redistributables are downloaded from the Internet and installed prior to configuration. | Requires access to https://go.microsoft.com/fwlink/?linkid=2139369 and https://aka.ms/vs/17/release/vc_redist.x64.exe |
| `SharedPC` | Switch | Determines if the computer is setup as a shared PC. The account management process is enabled and all user profiles are automatically deleted on logoff. | Only valid for direct logon mode ("Autologon" switch is not used). |
| `ShowSettings` | Switch | Determines if the Settings App and Control Panel are restricted to only allow access to the Display Settings page. If this value is not set, then the Settings app and Control Panel are not displayed or accessible. | Only valid when the `AVDClientShell` switch is not specified. |
| `DeviceRemovalAction` | string | determines what occurs when a FIDO Passkey device or SmartCard is removed from the system.  | The possible values are 'Lock', 'Logoff', or 'ResetClient'. |
| `DeviceVendorID` | String | Defines the Vendor ID of the hardware FIDO2 authentication token that, if removed, will trigger the action defined in `DeviceRemovalAction`. | You can find the Vendor ID by looking at the Hardware IDs property of the device in device manager. See the [example for a Yubikey](docs\media\HardwareIds.png). |
| `SmartCard` | Switch | Determines if SmartCard removal will trigger the action specified by `DeviceRemovalAction`. | This value is only used when `DeviceRemovalAction` is defined. |
| `IdleTimeoutAction` | string | Determines what occurs when the system is idle for a specified amount of time. | The possible values are 'Lock', 'Logoff', or 'ResetClient'. |
| `IdleTimeout` | int | Determines the number of seconds in the that system will wait before performing the action specified in the `IdleTimeoutAction` parameter. | |
| `SystemDisconnectAction` | string | Determines what occurs when the remote desktop session connection is disconnected by the system. This could be due to an IdleTimeout on the session host in the SSO scenario or the user has initiated a connection to the session host from another client. | The possible values are 'Lock', 'Logoff', or 'ResetClient'. |
| `UserDisconnectSignOutAction` | string | Determines what occurs when the user disconnects or signs out from the remote session. | The possible values are 'Lock', 'Logoff', or 'ResetClient'. |
| `Version` | Version |  Writes this value to a string value called 'version' at HKLM:\SOFTWARE\Kiosk registry key. | Allows tracking of the installed version using configuration management software such as Microsoft Endpoint Manager or Microsoft Endpoint Configuration Manager by querying the value of this registry value. |

### Air-Gapped Cloud Support

In order to use this solution in Microsoft's US Government Air-Gapped clouds, you'll need to get the cloud suffix from the environment. You can do this easily with PowerShell or get the information from our Air-Gapped cloud documentation.

#### PowerShell

1. Connect to the Azure Environment.

   ``` powershell
   Connect-AzAccount -Environment <EnvironmentName>
   ```

1. Then get the Resource Manager Url for the environment.

  ``` powershell
  $ResourceManagerUrl = (Get-AzEnvironment -Name <EnvironmentName>).ResourceManagerUrl
  ```

1. Then get the cloud suffix.

  ``` powershell
  $CloudSuffix = $ResourceManagerUrl.Replace('https://management.', '').Replace('/', '')
  ```

1. Replace the correct instance of <CLOUDSUFFIX> in the Set-AVDClientKioskSettings.ps1 file before running the script.

#### Air-Gapped Cloud Documentation

1. From a corporate Microsoft laptop or AVD session, access either [Azure Government Secret Virtual Desktop Infrastructure](https://review.learn.microsoft.com/en-us/microsoft-government-secret/azure/azure-government-secret/services/virtual-desktop-infrastructure/virtual-desktop?branch=live#subscribe-to-azure-virtual-desktop-in-the-windows-client) or [Azure Government Top Secret Virtual Desktop Infrastructure](https://review.learn.microsoft.com/en-us/microsoft-government-topsecret/azure/azure-government-top-secret/services/virtual-desktop-infrastructure/virtual-desktop?branch=live#subscribe-to-azure-virtual-desktop-in-the-windows-client) and catpure the value of the subscribe Url which will be in the form of 'https://rdweb.wvd.<CLOUDSUFFIX>'.

1. Replace the correct instance of <CLOUDSUFFIX> in the Set-AVDClientKioskSettings.ps1 file before running the script.

### Manual Installation

> [!Important]
> You need to run the PowerShell script with system priviledges. The easiest way to do this is to download [PSExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec). Then extract the Zip to a folder and open an administrative command prompt.

1. Either clone the repo or download it as a zip file. If downloading the repo as a zip file, then extract it to a new folder.

2. Execute PowerShell as SYSTEM by running the following command:

    ``` cmd
    psexec64 -s -i powershell
    ```

3. In the newly opened PowerShell window, execute the following:

    ``` powershell
    set-executionpolicy bypass -scope process
    ```

4. Change directories to the local 'source' directory.

5. Then execute the script using the correct parameters as exemplified below: (All options are not shown).

    - Scenario 1 Options

      - Lock the workstation when a SmartCard is Removed or 15 minutes of inactivity has occurred.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -DeviceRemovalAction 'Lock' -SmartCard -IdleTimeoutAction 'Lock' -IdleTimeout 900
        ```

      - Logoff the user when a Yubikey is Removed. Lock after 15 minutes of inactivity has occurred.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -DeviceRemovalAction 'Logoff' -DeviceVendorID '1050' -IdleTimeoutAction 'Lock' -IdleTimeout 900
        ```

      - Logoff the user when the user disconnects or signs out of a remote session. Lock after 15 minutes of inactivity.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -UserDisconnectSignOutAction 'Logoff' -IdleTimeoutAction 'Lock' -IdleTimeout 900
        ```

    - Scenario 2 Options

      - Reset when SmartCard is Removed:
  
        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -AutoLogon -DeviceRemovalAction 'ResetClient' -SmartCard
        ```

      - Reset when Yubikey is Removed

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -AutoLogon -DeviceRemovalAction 'ResetClient' -DeviceVendorID '1050'
        ```

      - Reset when Remote Sessions are disconnected

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -AutoLogon -SystemDisconnectAction 'ResetClient' -UserDisconnectSignOutAction 'ResetClient'
        ```

      - Reset when Remote Sessions are disconnected or 15 minutes of idle time has passed.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -AutoLogon -SystemDisconnectAction 'ResetClient' -UserDisconnectSignOutAction 'ResetClient' -IdleTimeoutAction 'ResetClient' -IdleTimeout 900
        ```
  
    - Scenario 3 Options

      For this scenario, you do **not** want to specify a Trigger, any Trigger Actions, or AutoLogon. Instead you would need to configure the system to autologon an Entra ID user using the [AutoLogon SysInternals utility](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon). In addition, you would want to assign only one Remote Application group with a single application to the Entra ID user and ensure that the session hosts in the pool hosting this application do not timeout the user session via the MachineInactivityLimit setting. The custom Launch-AVDClient.ps1 script would automatically launch this single remote application at logon.

      ``` powershell
      .\Set-AVDClientKioskSettings.ps1
      ```

    - Other Parameters

      - Replace the Windows default shell with the Remote Desktop client.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -AVDClientShell [other parameters]
        ```

      - Install the Remote Desktop client

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -InstallAVDClient [other parameters]
        ```

      - Allow Display and Audio Settings modification by kiosk users.

        ``` powershell
        .\Set-AVDClientKioskSettings.ps1 -ShowSettings [other parameters]
        ```

### Microsoft Endpoint Manager (Intune) Deployment

This configuration supports deployment through Intune as a Win32 App. The instructions for creating a Win32 application are available at https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-app-management.

The command line should be similar to:

``` cmd
powershell.exe -executionpolicy bypass -file Set-AVDClientKioskSettings.ps1 -SharedPC -DeviceID '1050' -EnvironmentAVD AzureCloud -ShowDisplaySettings -Triggers 'DeviceRemoval' -TriggerAction 'Lock'
```

You can utilize the DetectionScript.ps1 as a custom detection script in Intune which will automatically look for all the configurations applied by the script. you can also use a Registry detection method to read the value of ```HKEY_LOCAL_MACHINE\Software\Kiosk\version``` which should be equal to the value of the version parameter used in the deployment script. This would be useful for when you do not implement AutoLogon.

### Manual Removal

Remove the configuration from the PowerShell prompt using:

``` powershell
.\Remove-KioskSettings.ps1
```

## Troubleshooting

1. All events from the configuration scripts and scheduled tasks are logged to the **Application and Services Logs | AVD Client Kiosk** event log.
2. You can break autologon of the Kiosk User account during restart by holding down the [LEFT SHIFT] button down and continuously tap [ENTER] during restart all the way to the lock screen appears.
