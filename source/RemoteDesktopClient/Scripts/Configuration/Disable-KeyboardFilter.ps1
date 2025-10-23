#
# Copyright (C) Microsoft. All rights reserved.
#

<#
.Synopsis
    This Windows PowerShell script shows how to enumerate all existing keyboard filter
    rules and how to disable them by setting the Enabled property directly.
.Description
    For each instance of WEKF_PredefinedKey, WEKF_CustomKey, and WEKF_Scancode,
    set the Enabled property to false/0 to disable the filter rule, thus
    allowing all key sequences through the filter.
#>

$Namespace = "root\standardcimv2\embedded"

$Classes = @(
    'WEKF_PredefinedKey'
    'WEKF_CustomKey'
)

ForEach ($Class in $Classes) {
    $WMIObject = Get-WMIObject -Class WEKF_PredefinedKey -Namespace $Namespace -ErrorAction SilentlyContinue
    If ($WMIObject) {
        $WMIObject | ForEach-Object {
            if ($_.Enabled) {
                $_.Enabled = 0;
                $_.Put() | Out-Null;
                Write-Host Disabled $_.Id
            }
        }   
    }    
}

$ScanCode = Get-WMIObject -class WEKF_Scancode -namespace $Namespace -ErrorAction SilentlyContinue

If ($ScanCode) {
    $ScanCode | ForEach-Object {
        if ($_.Enabled) {
            $_.Enabled = 0;
            $_.Put() | Out-Null;
            "Disabled {0}+{1:X4}" -f $_.Modifiers, $_.Scancode
        }
    }
}