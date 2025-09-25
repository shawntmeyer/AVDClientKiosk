$OriginalFileName = 'libusb-win32_Generic_Device.inf'

If (Get-WindowsDriver -Online | Where-Object {$_.OriginalFileName -like "*$OriginalFileName"}) {
    Write-Host 'Installed'
}
