Try {
    $SCPolicyService = Get-Service -Name SCPolicySvc
    $SCPolicyService | Set-Service -StartupType Automatic
    $SCPolicyService | Start-Service
}
Catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    Exit 1
}