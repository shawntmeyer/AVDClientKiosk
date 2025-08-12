Param
(
    [Parameter(Mandatory = $false)]
    [string]$DisableUpdates = 'True',
    [Parameter(Mandatory = $false)]
    [string]$DeploymentType = "Install"
)

#region Initialization

$Script:FullName = $MyInvocation.MyCommand.Path
$Script:File = $MyInvocation.MyCommand.Name
$Script:Name = [System.IO.Path]::GetFileNameWithoutExtension($Script:File)
$Script:Args = $null

If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {

        foreach($k in $MyInvocation.BoundParameters.keys)
        {
            switch($MyInvocation.BoundParameters[$k].GetType().Name)
            {
                "SwitchParameter" {if($MyInvocation.BoundParameters[$k].IsPresent) { $Script:Args += "-$k " } }
                "String"          { $Script:Args += "-$k `"$($MyInvocation.BoundParameters[$k])`" " }
                "Int32"           { $Script:Args += "-$k $($MyInvocation.BoundParameters[$k]) " }
                "Boolean"         { $Script:Args += "-$k `$$($MyInvocation.BoundParameters[$k]) " }
            }
        }
        If ($Script:Args) {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`" $($Script:Args)" -Wait -NoNewWindow
        } Else {
            Start-Process -FilePath "$env:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList "-File `"$($Script:FullName)`"" -Wait -NoNewWindow
        }
    }
    Catch {
        Throw "Failed to start 64-bit PowerShell"
    }
    Exit
}

Try {
    [bool]$DisableUpdates = [System.Convert]::ToBoolean($DisableUpdates)
} Catch {
    $DisableUpdates = $false
}
$SoftwareName = 'Amazon Workspaces'
$DownloadUrl = "https://d2td7dqidlhjx7.cloudfront.net/prod/global/windows/Amazon+WorkSpaces.msi"
$MSIProperties = 'ALLUSERS=1'

[String]$Script:LogDir = "$($env:SystemRoot)\Logs\Software"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Dir -Force
}

#endregion Initialization


#region Supporting Functions
Function Get-InternetFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [uri]$Url,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OutputDirectory,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$OutputFileName
    )

    Begin {
        ## Get the name of this function and write header
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
        Write-Verbose "Starting ${CmdletName} with the following parameters: $PSBoundParameters"
        $ProgressPreference = 'SilentlyContinue'
    }
    Process {

        $start_time = Get-Date

        If (!$OutputFileName) {
            Write-Verbose "${CmdletName}: No Output File Name specified. Trying to get file name from URL."
            If ((split-path -path $Url -leaf).Contains('.')) {

                $OutputFileName = split-path -path $url -leaf
                Write-Verbose "${CmdletName}: Url contains file name - '$OutputFileName'."
            }
            Else {
                Write-Verbose "${CmdletName}: Url does not contain file name. Trying 'Location' Response Header."
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect=$false
                $response=$request.GetResponse()
                $Location = $response.GetResponseHeader("Location")
                If ((split-path $Location -leaf) -like '*.*') {
                    $OutputFileName = [System.IO.Path]::GetFileName($Location)
                    Write-Verbose "${CmdletName}: File Name from 'Location' Response Header is '$OutputFileName'."
                }
                Else {
                    Write-Verbose "${CmdletName}: No 'Location' Response Header returned. Trying 'Content-Disposition' Response Header."
                    $result = Invoke-WebRequest -Method GET -Uri $Url -UseBasicParsing
                    $contentDisposition = $result.Headers.'Content-Disposition'
                    If ($contentDisposition) {
                        $OutputFileName = $contentDisposition.Split("=")[1].Replace("`"","")
                        Write-Verbose "${CmdletName}: File Name from 'Content-Disposition' Response Header is '$OutputFileName'."
                    }
                }
            }
        }

        If ($OutputFileName) { 
            $wc = New-Object System.Net.WebClient
            $OutputFile = Join-Path $OutputDirectory $OutputFileName
            Write-Verbose "${CmdletName}: Downloading file at '$url' to '$OutputFile'."
            Try {
                $wc.DownloadFile($url, $OutputFile)
                $time = (Get-Date).Subtract($start_time).Seconds
                
                Write-Verbose "${CmdletName}: Time taken: '$time' seconds."
                if (Test-Path -Path $outputfile) {
                    $totalSize = (Get-Item $outputfile).Length / 1MB
                    Write-Verbose "${CmdletName}: Download was successful. Final file size: '$totalsize' mb"
                    Return $OutputFile
                }
            }
            Catch {
                Write-Error "${CmdletName}: Error downloading file. Please check url."
                Return $Null
            }
        }
        Else {
            Write-Error "${CmdletName}: No OutputFileName specified. Unable to download file."
            Return $Null
        }
    }
    End {
        Write-Verbose "Ending ${CmdletName}"
    }
}

Function Remove-MSIApplications {
    <#
    .SYNOPSIS
        Removes all MSI applications matching the specified application name.
    .DESCRIPTION
        Removes all MSI applications matching the specified application name.
        Enumerates the registry for installed applications matching the specified application name and uninstalls that application using the product code, provided the uninstall string matches "msiexec".
    .PARAMETER Name
        The name of the application to uninstall. Performs a contains match on the application display name by default.
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name.
    .PARAMETER WildCard
        Specifies that the named application must be matched using a wildcard search.
    .PARAMETER Parameters
        Overrides the default parameters specified in the XML configuration file. Uninstall default is: "REBOOT=ReallySuppress /QN".
    .PARAMETER AddParameters
        Adds to the default parameters specified in the XML configuration file. Uninstall default is: "REBOOT=ReallySuppress /QN".
    .PARAMETER FilterApplication
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be used to filter the list of results returned by Get-InstalledApplication to only those that should be uninstalled.
        Properties that can be filtered upon: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER ExcludeFromUninstall
        Two-dimensional array that contains one or more (property, value, match-type) sets that should be excluded from uninstall if found.
        Properties that can be excluded: ProductCode, DisplayName, DisplayVersion, UninstallString, InstallSource, InstallLocation, InstallDate, Publisher, Is64BitApplication
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results.
    .PARAMETER LoggingOptions
        Overrides the default logging options specified in the XML configuration file. Default options are: "/L*v".
    .PARAMETER LogName
        Overrides the default log file name. The default log file name is generated from the MSI file name. If LogName does not end in .log, it will be automatically appended.
        For uninstallations, by default the product code is resolved to the DisplayName and version of the application.
    .PARAMETER PassThru
        Returns ExitCode, STDOut, and STDErr output from the process.
    .PARAMETER ContinueOnError
        Continue if an error occured while trying to start the processes. Default: $true.
    .EXAMPLE
        Remove-MSIApplications -Name 'Adobe Flash'
        Removes all versions of software that match the name "Adobe Flash"
    .EXAMPLE
        Remove-MSIApplications -Name 'Adobe'
        Removes all versions of software that match the name "Adobe"
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8 Update' -FilterApplication ('Is64BitApplication', $false, 'Exact'),('Publisher', 'Oracle Corporation', 'Exact')
        Removes all versions of software that match the name "Java 8 Update" where the software is 32-bits and the publisher is "Oracle Corporation".
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8 Update' -FilterApplication (,('Publisher', 'Oracle Corporation', 'Exact')) -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'Contains'))
        Removes all versions of software that match the name "Java 8 Update" and also have "Oracle Corporation" as the Publisher; however, it does not uninstall "Java 8 Update 45" of the software.
        NOTE: if only specifying a single row in the two-dimensional arrays, the array must have the extra parentheses and leading comma as in this example.
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8 Update' -ExcludeFromUninstall (,('DisplayName', 'Java 8 Update 45', 'Contains'))
        Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall "Java 8 Update 45" of the software.
        NOTE: if only specifying a single row in the two-dimensional array, the array must have the extra parentheses and leading comma as in this example.
    .EXAMPLE
        Remove-MSIApplications -Name 'Java 8 Update' -ExcludeFromUninstall
                ('Is64BitApplication', $true, 'Exact'),
                ('DisplayName', 'Java 8 Update 45', 'Exact'),
                ('DisplayName', 'Java 8 Update 4*', 'WildCard'),
                ('DisplayName', 'Java \d Update \d{3}', 'RegEx'),
                ('DisplayName', 'Java 8 Update', 'Contains')
        Removes all versions of software that match the name "Java 8 Update"; however, it does not uninstall 64-bit versions of the software, Update 45 of the software, or any Update that starts with 4.
    .NOTES
        More reading on how to create arrays if having trouble with -FilterApplication or -ExcludeFromUninstall parameter: http://blogs.msdn.com/b/powershell/archive/2007/01/23/array-literals-in-powershell.aspx
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullorEmpty()]
            [string]$Name,
            [Parameter(Mandatory=$false)]
            [switch]$Exact = $false,
            [Parameter(Mandatory=$false)]
            [switch]$WildCard = $false,
            [Parameter(Mandatory=$false)]
            [Alias('Arguments')]
            [ValidateNotNullorEmpty()]
            [string]$Parameters,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$AddParameters,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [array]$FilterApplication = @(@()),
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [array]$ExcludeFromUninstall = @(@()),
            [Parameter(Mandatory=$false)]
            [switch]$IncludeUpdatesAndHotfixes = $false,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [string]$LoggingOptions,
            [Parameter(Mandatory=$false)]
            [Alias('LogName')]
            [string]$private:LogName,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [switch]$PassThru = $false,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullorEmpty()]
            [boolean]$ContinueOnError = $true
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-Verbose "Starting ${CmdLetName} with the following parameters: $PSBoundParameters"
        }
        Process {
            ## Build the hashtable with the options that will be passed to Get-InstalledApplication using splatting
            [hashtable]$GetInstalledApplicationSplat = @{ Name = $name }
            If ($Exact) { $GetInstalledApplicationSplat.Add( 'Exact', $Exact) }
            ElseIf ($WildCard) { $GetInstalledApplicationSplat.Add( 'WildCard', $WildCard) }
            If ($IncludeUpdatesAndHotfixes) { $GetInstalledApplicationSplat.Add( 'IncludeUpdatesAndHotfixes', $IncludeUpdatesAndHotfixes) }
    
            [psobject[]]$installedApplications = Get-InstalledApplication @GetInstalledApplicationSplat
    
            Write-Verbose "${CmdLetName}: Found [$($installedApplications.Count)] application(s) that matched the specified criteria [$Name]."
    
            ## Filter the results from Get-InstalledApplication
            [Collections.ArrayList]$removeMSIApplications = New-Object -TypeName 'System.Collections.ArrayList'
            If (($null -ne $installedApplications) -and ($installedApplications.Count)) {
                ForEach ($installedApplication in $installedApplications) {
                    If ([string]::IsNullOrEmpty($installedApplication.ProductCode)) {
                        Write-Warning "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName)] because unable to discover MSI ProductCode from application's registry Uninstall subkey [$($installedApplication.UninstallSubkey)]."
                        Continue
                    }
    
                    #  Filter the results from Get-InstalledApplication to only those that should be uninstalled
                    If (($null -ne $FilterApplication) -and ($FilterApplication.Count)) {
                        Write-Verbose "${CmdletName}: Filter the results to only those that should be uninstalled as specified in parameter [-FilterApplication]."
                        [boolean]$addAppToRemoveList = $false
                        ForEach ($Filter in $FilterApplication) {
                            If ($Filter[2] -eq 'RegEx') {
                                If ($installedApplication.($Filter[0]) -match $Filter[1]) {
                                    [boolean]$addAppToRemoveList = $true
                                    Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of regex match against [-FilterApplication] criteria."
                                }
                            }
                            ElseIf ($Filter[2] -eq 'Contains') {
                                If ($installedApplication.($Filter[0]) -match [regex]::Escape($Filter[1])) {
                                    [boolean]$addAppToRemoveList = $true
                                    Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of contains match against [-FilterApplication] criteria." 
                                }
                            }
                            ElseIf ($Filter[2] -eq 'WildCard') {
                                If ($installedApplication.($Filter[0]) -like $Filter[1]) {
                                    [boolean]$addAppToRemoveList = $true
                                    Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of wildcard match against [-FilterApplication] criteria." 
                                }
                            }
                            ElseIf ($Filter[2] -eq 'Exact') {
                                If ($installedApplication.($Filter[0]) -eq $Filter[1]) {
                                    [boolean]$addAppToRemoveList = $true
                                    Write-Verbose "${CmdletName}: Preserve removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of exact match against [-FilterApplication] criteria." 
                                }
                            }
                        }
                    }
                    Else {
                        [boolean]$addAppToRemoveList = $true
                    }
    
                    #  Filter the results from Get-InstalledApplication to remove those that should never be uninstalled
                    If (($null -ne $ExcludeFromUninstall) -and ($ExcludeFromUninstall.Count)) {
                        ForEach ($Exclude in $ExcludeFromUninstall) {
                            If ($Exclude[2] -eq 'RegEx') {
                                If ($installedApplication.($Exclude[0]) -match $Exclude[1]) {
                                    [boolean]$addAppToRemoveList = $false
                                    Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of regex match against [-ExcludeFromUninstall] criteria." 
                                }
                            }
                            ElseIf ($Exclude[2] -eq 'Contains') {
                                If ($installedApplication.($Exclude[0]) -match [regex]::Escape($Exclude[1])) {
                                    [boolean]$addAppToRemoveList = $false
                                    Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of contains match against [-ExcludeFromUninstall] criteria." 
                                }
                            }
                            ElseIf ($Exclude[2] -eq 'WildCard') {
                                If ($installedApplication.($Exclude[0]) -like $Exclude[1]) {
                                    [boolean]$addAppToRemoveList = $false
                                    Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of wildcard match against [-ExcludeFromUninstall] criteria." 
                                }
                            }
                            ElseIf ($Exclude[2] -eq 'Exact') {
                                If ($installedApplication.($Exclude[0]) -eq $Exclude[1]) {
                                    [boolean]$addAppToRemoveList = $false
                                    Write-Verbose "${CmdletName}: Skipping removal of application [$($installedApplication.DisplayName) $($installedApplication.Version)] because of exact match against [-ExcludeFromUninstall] criteria." 
                                }
                            }
                        }
                    }
    
                    If ($addAppToRemoveList) {
                        Write-Verbose "${CmdletName}: Adding application to list for removal: [$($installedApplication.DisplayName) $($installedApplication.Version)]." 
                        $removeMSIApplications.Add($installedApplication)
                    }
                }
            }
    
            ## Build the hashtable with the options that will be passed to Execute-MSI using splatting
            [hashtable]$ExecuteMSISplat =  @{
                Action = 'Uninstall'
                Path = ''
                ContinueOnError = $ContinueOnError
            }
            If ($Parameters) { $ExecuteMSISplat.Add( 'Parameters', $Parameters) }
            ElseIf ($AddParameters) { $ExecuteMSISplat.Add( 'AddParameters', $AddParameters) }
            If ($LoggingOptions) { $ExecuteMSISplat.Add( 'LoggingOptions', $LoggingOptions) }
            If ($LogName) { $ExecuteMSISplat.Add( 'LogName', $LogName) }
            If ($PassThru) { $ExecuteMSISplat.Add( 'PassThru', $PassThru) }
            If ($IncludeUpdatesAndHotfixes) { $ExecuteMSISplat.Add( 'IncludeUpdatesAndHotfixes', $IncludeUpdatesAndHotfixes) }
    
            If (($null -ne $removeMSIApplications) -and ($removeMSIApplications.Count)) {
                ForEach ($removeMSIApplication in $removeMSIApplications) {
                    Write-Verbose "${CmdletName}: Remove application [$($removeMSIApplication.DisplayName) $($removeMSIApplication.Version)]." 
                    $ExecuteMSISplat.Path = $removeMSIApplication.ProductCode
                    If ($PassThru) {
                        [psobject[]]$ExecuteResults += Execute-MSI @ExecuteMSISplat
                    }
                    Else {
                        Execute-MSI @ExecuteMSISplat
                    }
                }
            }
            Else {
                Write-Log -Message 'No applications found for removal. Continue...' 
            }
        }
        End {
            If ($PassThru) { Write-Output -InputObject $ExecuteResults }
            Write-Verbose "Ending ${CmdletName}."
        }
}

Function Set-RegistryValue {
    [CmdletBinding()]
    param (
        [string]$Name,
        [string]$Path,
        [string]$PropertyType,
        [string]$Value
    )
    Write-Verbose "[Set-RegistryValue]: Setting Registry Value: $Name"
    If (!(Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $RemoteValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    If ($RemoteValue) {
        $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name
        If ($Value -ne $CurrentValue) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
        }
    } Else {
        New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
}

#endregion

## MAIN

If ($DeploymentType -ne 'UnInstall') {
    [string]$Script:LogName = "Install-" + ($SoftwareName -Replace ' ','') + ".log"
    Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
    Write-Output "Retrieving latest $SoftwareName version from Internet."
    $PathMSI = Get-InternetFile -Url $DownloadUrl -OutputDirectory "$Env:Temp" -OutputFileName 'AmazonWorkSpaces.msi'
    Write-Output "Installing '$SoftwareName' via cmdline:"
    Write-Output "     'msiexec.exe /i `"$pathMSI`" /qn $MSIProperties'"
    $Installer = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$pathMSI`" /qn $MSIProperties" -Wait -PassThru
    If ($($Installer.ExitCode) -eq 0) {
        Write-Output "'$SoftwareName' installed successfully."
        Remove-Item -Path $pathMSI -Force -ErrorAction SilentlyContinue
    }
    Else {
        Write-Error "The Installer exit code is $($Installer.ExitCode)"
    }
    Write-Output "Completed '$SoftwareName' Installation."

    If ($DisableUpdates) { Set-RegistryValue -Path 'HKLM:\SOFTWARE\WOW6432Node\Amazon\Amazon WorkSpaces Client' -PropertyType 'STRING' -Name 'clientUpgradeDisabled' -Value 1 }
}
# Uninstall
Else {
    [string]$Script:LogName = "UnInstall-" + ($SoftwareName -Replace ' ','') + ".log"
    Start-Transcript -Path "$Script:LogDir\$Script:LogName" -Force
    Write-Output "Removing $SoftwareName"
    Remove-MSIApplications -Name $SoftwareName -verbose
}

Stop-Transcript