Function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$EventLog,

        [Parameter(Mandatory=$true)]
        [string]$EventSource,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',
        
        [Parameter(Mandatory=$true)]
        [Int]$EventID,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    Write-EventLog -LogName $EventLog -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message -ErrorAction SilentlyContinue
    Switch ($EntryType) {
        'Information' { Write-Host $Message }
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message }
    }
}