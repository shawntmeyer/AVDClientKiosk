Set oShell = WScript.CreateObject("WScript.Shell")
sPowerShellScriptPath = Replace(WScript.ScriptFullName, ".vbs", ".ps1")
sCmd = "Powershell.exe -executionpolicy Bypass -NoLogo -WindowStyle Hidden -file " & chr(34) sPowerShellScriptPath & chr(34)
oShell.Run(sCmd, 0, False)
Set oShell = Nothing
WScript.Quit