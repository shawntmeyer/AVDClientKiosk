# Azure Virtual Desktop Client Kiosk Solutions

## Introduction

This repository contains scripts and supporting artifacts to configure a Windows client operating system to act as a custom Azure Virtual Desktop (AVD) client kiosk. The repository provides **two distinct kiosk solutions** to meet different organizational needs and client preferences.

## Kiosk Solutions Overview

### 1. Remote Desktop Client for Windows Kiosk

**Location:** [`source/RemoteDesktopClient/`](source/RemoteDesktopClient/)  
**Documentation:** [Remote Desktop Client Kiosk README](source/RemoteDesktopClient/README.md)

The traditional Remote Desktop Client for Windows kiosk solution provides comprehensive customization options and advanced trigger-based security actions. This solution is ideal for organizations requiring:

- **Advanced Security Features:** Smart card and FIDO2 device removal triggers with customizable actions (lock, logoff, reset client)
- **Session Management:** Automatic client reset based on connection events, idle timeouts, and user disconnect scenarios  
- **Complex Trigger Logic:** Detailed control over system responses to various security events

**Key Features:**

- Windows Operating System Autologon support
- Auto Subscription to the user feed
- Remote Desktop Client shell or Multi-App Kiosk with restricted user experience and customized Start Menu
- WMI Event-based monitoring and automated responses
- Support for Settings app access options
- Support for air-gapped government clouds

### 2. Windows App Kiosk

**Location:** [`source/WindowsApp/`](source/WindowsApp/)  
**Documentation:** [Windows App Kiosk README](source/WindowsApp/README.md)

The modern Windows App kiosk solution leverages Microsoft's latest remote desktop technology with streamlined configuration and built-in security features. This solution is ideal for organizations seeking:

- **Modern Technology:** Uses the latest Windows App with native Microsoft features
- **Simplified Configuration:** Streamlined setup with fewer complex parameters
- **Built-in Auto Logoff:** Native Windows App automatic logoff and reset capabilities
- **Easier Management:** Reduced complexity while maintaining security

**Key Features:**

- Windows Operating System Autologon support
- Windows App Single App Kiosk or Multi-App Kiosk with restricted user experience and customized Start Menu
- Native Windows App auto logoff behaviors (ResetAppOnCloseOnly, ResetAppAfterConnection, ResetAppOnCloseOrIdle)
- Streamlined provisioning package deployment
- Smart card integration with Windows security policies
- Modern user interface with Settings app access options

## Solution Comparison

| Feature | Remote Desktop Client | Windows App |
|---------|:---------------------:|:-----------:|
| **Client Technology** | Remote Desktop Client for Windows | Windows App |
| **Security Triggers** | Device Removal (Smart Card or FIDO2), Idle, Session Disconnect, App Close | Smart Card Removal, Idle, App Close |
| **Auto Logoff** | Custom Script-based | Native Windows App Features |
| **Setup Complexity** | Complex | Simple |
| **Maintenance** | Higher | Lower |

**Choose Remote Desktop Client Kiosk if you need:**

- Advanced security triggers and custom actions
- Maximum customization and control

**Choose Windows App Kiosk if you want:**

- Simplified configuration and maintenance
- Native Microsoft auto logoff features
- Streamlined user experience
- Easier long-term management

This kiosk solution can be used for numerous scenarios including secure remote access, shared workstations, and dedicated Azure Virtual Desktop endpoints.

## Prerequisites

### General Requirements

1. **Operating System:** A currently [supported version of Windows](https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client)
   - **Remote Desktop Client Kiosk:** Windows 11
   - **Windows App Kiosk:** Windows 11

2. **Windows Editions:** Depending on the kiosk configuration chosen, different Windows editions are supported:
   - **Remote Desktop Client Client Shell:** Education, Enterprise, Enterprise LTSC, IoT Enterprise, IoT Enterprise LTSC
   - **All Other configurations:** All above editions plus Pro and Pro Education

3. **Administrative Access:** The ability to run installation scripts with SYSTEM privileges (instructions provided in each solution's documentation)

4. **Device Management:** For most scenarios, devices should be [joined to Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/concept-directory-join) or [Entra ID Hybrid Joined](https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join)

### Solution-Specific Requirements

- **Remote Desktop Client Kiosk:** See [detailed requirements](source/RemoteDesktopClient/README.md#prerequisites)
- **Windows App Kiosk:** See [detailed requirements](source/WindowsApp/README.md#prerequisites)

## Getting Started

### Choose Your Solution

Select the appropriate kiosk solution based on your requirements:

#### Option 1: Remote Desktop Client for Windows Kiosk

**Best for:** Organizations needing advanced security features

📖 **[View Remote Desktop Client Kiosk Documentation](source/RemoteDesktopClient/README.md)**

**Quick Start:**

1. Navigate to `source/RemoteDesktopClient/`
2. Follow the installation instructions in the README
3. Run `Set-RemoteDesktopKioskSettings.ps1` with your desired parameters

#### Option 2: Windows App Kiosk

**Best for:** Modern Windows 11 deployments seeking simplified configuration

📖 **[View Windows App Kiosk Documentation](source/WindowsApp/README.md)**

**Quick Start:**

1. Navigate to `source/WindowsApp/`
2. Follow the installation instructions in the README  
3. Run `Set-WindowsAppKioskSettings.ps1` with your desired parameters

## Additional Resources

- [Azure Virtual Desktop Documentation](https://learn.microsoft.com/en-us/azure/virtual-desktop/)
- [Windows Assigned Access](https://learn.microsoft.com/en-us/windows/configuration/assigned-access/)
- [Entra ID Device Management](https://learn.microsoft.com/en-us/entra/identity/devices/)

## Support

For issues, questions, or contributions:

1. Check the solution-specific README for troubleshooting guidance
2. Review the repository issues for known problems
3. Create a new issue with detailed information about your environment and problem