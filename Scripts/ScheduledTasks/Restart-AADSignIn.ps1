[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $EventLog = 'AVD Client Kiosk',
    [Parameter()]
    [string]
    $EventSource = 'AVD Client Restart'
)
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name=[System.IO.Path]::GetFileNameWithoutExtension($Script:File)

#QuickNotes
# Gone when cleared
#HKCU\Software\Microsoft\RDClientRadc

#region Main
Write-EventLog -LogName $EventLog -Source $EventSource -EventId 530 -EntryType Information -Message "Starting '$Script:Name'."

# Determine if client needs reset by looking at the following registry key. If this key exists then the client has cached feed information
# and other user settings/data that need to be cleared.

If (Test-Path -Path 'HKCU:\Software\Microsoft\RdClientRadc') { $CachePresent = $true }
$AADBroker = Get-Process | Where-Object {$_.Name -like 'Microsoft.AAD.BrokerPlugin*'}
$MSRDCW = Get-Process | Where-Object {$_.Name -eq 'msrdcw'}
$MSRDC = Get-Process | Where-Object {$_.Name -eq 'msrdc'}

# Quickly exit the script if there is no work to do.
If ($null -eq $AADBroker) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 531 -Message "The Microsoft.AAD.BrokerPlugin windows is not open. Nothing to do."
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 540 -Message "Ending '$Script:Name'."
    Exit 0
}

If ($MSRDC) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 533 -Message "There are open session host connections, quitting script."
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 540 -Message "Ending '$Script:Name'."
    Exit 0
} Else {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 532 -Message "There are no active client connections. Stopping the AAD Broker Plugin and restarting the AVD Client."
    $AADBroker | Stop-Process -Force
    $counter = 0
    Do {
        $counter ++
        Start-Sleep -Seconds 1
    } Until ($counter -eq 30 -or (!(Get-Process | Where-Object {$_.Name -like 'Microsoft.AAD.BrokerPlugin*'})))
}

# Only Reset the client if necessary
If ($CachePresent) {
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 534 -Message "Resetting the client to clear cached credentials."
    $reset = Start-Process -FilePath "$env:ProgramFiles\Remote Desktop\msrdcw.exe" -ArgumentList "/reset /f" -wait -PassThru
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 535 -Message "msrdcw.exe /reset exit code: [$($reset.ExitCode)]"
} Elseif ($MSRDCW) {
    $MSRDCW | Stop-Process -Force
    $counter = 0
    Do {
        $counter ++
        Start-Sleep -Seconds 1
    } Until ($counter -eq 30 -or (!(Get-Process | Where-Object {$_.Name -eq 'msrdcw'})))
}

Write-EventLog -LogName $EventLog -Source $EventSource -EntryType Information -EventId 540 -Message "Ending '$Script:Name'."
Exit 0
#endregion Main