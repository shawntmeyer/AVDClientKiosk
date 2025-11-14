Try {
    $SCPolicyService = Get-Service -Name SCPolicySvc
    $StartupCorrect = $SCPolicyService.StartType -eq 'Automatic'
    $StatusCorrect = $SCPolicyService.Status -eq 'Running'
    if ($StartupCorrect -and $StatusCorrect) {
        Write-Host 'Smart Card Policy Service is set to start automatically and is running'
        Exit 0
    } elseif ($StartupCorrect) {
        Write-Host 'Smart Card Policy Service is set to start automatically, but is not running.'
        Exit 1
    } else {
        Write-Host "Smart Card Policy service is set to start: $($SCPolicyService.StartType)"
        Exit 1
    }
}
Catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    Exit 1
}
