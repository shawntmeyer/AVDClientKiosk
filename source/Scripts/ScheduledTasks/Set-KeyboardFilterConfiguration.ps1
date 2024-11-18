[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $EventLog,
    [Parameter(Mandatory = $true)]
    [string]
    $EventSource,
    [Parameter(Mandatory = $false)]
    [switch]
    $ShowDisplaySettings,
    [Parameter(Mandatory = $true)]
    [string]
    $TaskName
)
#region Variables
$Script:FullName = $MyInvocation.MyCommand.Path
$NameSpace = "root\standardcimv2\embedded"
$model = (Get-WMIObject -class Win32_ComputerSystem).Model
#endregion variables
Start-Transcript -Path "$env:SystemRoot\Logs\Configuration\Set-KeyboardFilterConfiguration.log" -Force
function Get-Setting([String] $Name) {
    <#
    .Synopsis
        Get a WMIObject by name from WEKF_Settings
    .Parameter Name
        The name of the setting, which is the key for the WEKF_Settings class.
    #>
    $Entry = Get-WMIObject -class WEKF_Settings -namespace $NameSpace | Where-Object { $_.Name -eq $Name }
    return $Entry
}

function Set-DisableKeyboardFilterForAdministrators([Bool] $Value) {
    <#
    .Synopsis
        Set the DisableKeyboardFilterForAdministrators setting to true or false.
    .Description
        Set DisableKeyboardFilterForAdministrators to true or false based on $Value
    .Parameter Value
        A Boolean value
    #>

    $Setting = Get-Setting("DisableKeyboardFilterForAdministrators")
    if ($Setting) {
        if ($Value) {
            $Setting.Value = "true" 
        }
        else {
            $Setting.Value = "false"
        }
        $Setting.Put() | Out-Null;
    }
    else {
        Write-Error "Unable to find DisableKeyboardFilterForAdministrators setting";
    }
}

function Enable-Predefined-Key($Id) {
    <#
    .Synopsis
        Toggle on a Predefined Key keyboard filter Rule
    .Description
        Use Get-WMIObject to enumerate all WEKF_PredefinedKey instances, filter against key value "Id", and set that instance's "Enabled"
        property to 1/true.
    .Example
        Enable-Predefined-Key "Ctrl+Alt+Del"
        Enable CAD filtering
    #>

    $predefined = Get-WMIObject -class WEKF_PredefinedKey -namespace $NameSpace | Where-Object { $_.Id -eq "$Id" }

    if ($predefined) {
        $predefined.Enabled = 1
        $predefined.Put() | Out-Null
        Write-Host Disabled $Id
    }
    else {
        Write-Error "$Id is not a valid predefined key"
    }
}

function Enable-Custom-Key($Id) {
    <#
    .Synopsis
        Toggle on a Custom Key keyboard filter Rule
    .Description
        Use Get-WMIObject to enumerate all WEKF_CustomKey instances, filter against key value "Id", and set that instance's "Enabled"
        property to 1/true.

        In the case that the Custom instance does not exist, add a new
        instance of WEKF_CustomKey using Set-WMIInstance.
    .Example
        Enable-Custom-Key "Ctrl+V"
        Enable filtering of the Ctrl + V sequence.
#>

    $custom = Get-WMIObject -class WEKF_CustomKey -namespace $NameSpace | Where-Object { $_.Id -eq "$Id" }

    if ($custom) {
        # Rule exists.  Just enable it.
        $custom.Enabled = 1
        $custom.Put() | Out-Null
        "Enabled Custom Filter $Id."

    }
    else {
        Set-WMIInstance -class WEKF_CustomKey -argument @{Id = "$Id" } -namespace $NameSpace | Out-Null
        "Added Custom Filter $Id."
    }
}

function Enable-Scancode($Modifiers, [int]$Code) {
    <#
    .Synopsis
        Toggle on a Scancode keyboard filter Rule
    .Description
        Use Get-WMIObject to enumerate all WEKF_Scancode instances, filter against key values of "Modifiers" and "Scancode", and set
        that instance's "Enabled" property to 1/true.

        In the case that the Scancode instance does not exist, add a new
        instance of WEKF_Scancode using Set-WMIInstance.
    .Example
        Enable-Scancode "Ctrl" 37
        Enable filtering of the Ctrl + keyboard scancode 37 (base-10)
        sequence.
#>

    $scancode =
    Get-WMIObject -class WEKF_Scancode -namespace $NameSpace | Where-Object {($_.Modifiers -eq $Modifiers) -and ($_.Scancode -eq $Code)}

    if ($scancode) {
        $scancode.Enabled = 1
        $scancode.Put() | Out-Null
        "Enabled Custom Scancode {0}+{1:X4}" -f $Modifiers, $Code
    }
    else {
        Set-WMIInstance -class WEKF_Scancode -argument @{Modifiers = "$Modifiers"; Scancode = $Code } -namespace $NameSpace | Out-Null
        "Added Custom Scancode {0}+{1:X4}" -f $Modifiers, $Code
    }
}
Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 900 -Message "Executing '$Script:FullName'."
Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 901 -Message "Disabling Keyboard Filter for Administrators."
Set-DisableKeyboardFilterForAdministrators $True
$PredefinedKeys = @{
    "Ctrl+Win+F" = "Open Find Computers"
    "Win+Break" = "Open System dialog box"
    "Win+F" = "Open Search"
    "Win+P" = "Cycle through Presentation Mode"
    "Win+R" = "Open Run Dialog"
    "Win+Tab" = "Cycle through Microsoft Store Apps. Also blocks the Windows+Ctrl+Tab and Windows+Shift+Tab combinations"
    "Win+B" = "Sets focus in the notification area"    
    "Win+K" = "Open Connect"
    "Win+H" = "Open Dictation"
    "Win+Q" = "Open Search Charm"    
    "Win+W" = "Open Windows Ink Workspaces"
    "Win+Z" = "Open App bar"
    "Win+/" = "Open input method editor (IME)"
    "Shift+Ctrl+Esc" = "Open Task Manager"
    "Win+L" = "Lock the device"
    "LaunchMail" = "Start Mail Key"
    "LaunchMediaSelect" = "Select Media Key"
    "LaunchApp1" = "Start Application 1 key"
    "LaunchApp2" = "Start Application 2 key"
}

If (!$ShowDisplaySettings) {
    $PredefinedKeys.Add('Win+I', 'Open Settings')
}

$PredefinedKeys.keys | ForEach-Object {
    $message = "Disabling Predefined Key Combination '{0}' to disable '{1}'." -f $_, $PredefinedKeys[$_]
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 902 -Message $message
    Enable-Predefined-Key($_)
}
If ($model -like '*Surface*') {
    $SurfaceKeys = @{
        "AltWin" = "Surface - Share Key"
        "CtrlWin" = "Surface - Devices key"
        "ShiftWin" = "Surface - Search key"
        "F21" = "Surface - Settings Key"
    }
    $SurfaceKeys.keys | ForEach-Object {
        $message = "Disabling Predefined Surface Key Combination '{0}' to disable '{1}'." -f $_, $SurfaceKeys[$_]
        Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 902 -Message $message
        Enable-Predefined-Key($_)
    }    
}

$CustomKeys = @{
    "Win+S" = "Open Search"
    "Win+;" = "Open Emojis"
    "Win+," = "Open Emojis"
    "Win+X" = "Open Quick Link Menu"
    "Win+Alt+Enter" = "Open Taskbar Settings"
    "Win+Ctrl+D" = "Add a Virtual Desktop"
    "Win+Ctrl+Left" = "Switch between virtual desktops you've created on the left"
    "Win+Ctrl+Right" = "Switch between virtual desktops you've created on the right"
    "Win+Ctrl+F4" = "Close the virtual desktop you're using"
}

$CustomKeys.keys | ForEach-Object {
    $message = "Disabling Custom Key Combination '{0}' to disable '{1}'." -f $_, $CustomKeys[$_]
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 902 -Message $message
    Enable-Custom-Key($_)
}

Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 905 -Message "Deleting Scheduled Task: '$TaskName'."
Get-ScheduledTask | Where-Object {$_.TaskName -eq "$TaskName"} | Unregister-ScheduledTask -Confirm:$False
Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 910 -Message "Ending Script: '$Script:FullName'."
Stop-Transcript