$TaskName = '(AVD Client) - Delete Stale User Profiles'
# Delete any previously created scheduled task
Get-ScheduledTask | Where-Object {$_.TaskName -eq "$TaskName"} | Unregister-ScheduledTask -Confirm:$False

$EventTriggerClass = Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler
$EventTrigger = $EventTriggerClass | New-CimInstance -ClientOnly
$EventTrigger.Enabled = $true
# Create a Subscription to the Security Log and look for Event ID 4647 which indicates a logoff event.
$EventTrigger.SubScription = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[EventID=4647]]</Select></Query></QueryList>'
$EventTrigger.Delay = 'PT10S'

$StartupTrigger = New-ScheduledTaskTrigger -AtStartup

$Triggers = @(
    $EventTrigger,
    $StartupTrigger
)
$Command = 'Get-CimInstance -class Win32_UserProfile | where-object { $_.LocalPath -like ''C:\users\*'' -and $_.LocalPath -inotLike ''*kioskuser*'' -and $_.Loaded -eq $False -and (((Get-Date) - $_.LastUseTime) -gt (New-TimeSpan -Days 14))} | Remove-CimInstance'
$TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-command `"$Command`""
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
$RegisteredTask = Register-ScheduledTask -TaskName $TaskName -Description 'Delete User Profiles' -Action $TaskAction -Principal $TaskPrincipal -Settings $TaskSettings -Trigger $Triggers

$StartupTrigger = $RegisteredTask.Triggers | Where-Object {$_.Subscription -eq $null}
$StartupTrigger.Delay = 'PT5S'

do {
    Start-Sleep -Seconds 1
} until (Get-ScheduledTask | Where-Object {$_.TaskName -eq "$TaskName"})

$RegisteredTask | Set-ScheduledTask
