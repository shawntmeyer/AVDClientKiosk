Option Explicit

' Global variables
Dim subscribeUrl, shell, fso, wmiService, currentDate, logFolder, logPath, logFile

' Parse command line arguments
If WScript.Arguments.Count > 0 Then
    SubscribeUrl = WScript.Arguments(0)
Else
    SubscribeUrl = ""
End If

' Initialize
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set wmiService = GetObject("winmgmts:\\.\root\cimv2")
currentDate = Year(Date) & "-" & Right("0" & Month(Date), 2) & "-" & Right("0" & Day(Date), 2)
'logging
logFolder = shell.ExpandEnvironmentStrings("%TEMP%")
logPath = logFolder & "\Launch-AVDClient-" & currentDate & ".log"
set logFile = fso.OpenTextFile(logPath, 8, True)

' Helper Functions
Sub WriteLog(Message)
    logFile.WriteLine Now & " - " & Message
End Sub

Function ProcessExists(processName)
    Dim processes, process
    Set processes = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & processName & "'")
    ProcessExists = (processes.Count > 0)
End Function

Sub KillProcess(processName)
    Dim processes, process
    Set processes = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & processName & "'")
    For Each process In processes
        process.Terminate()
    Next
End Sub

Sub ResetMSRDCW()
    Dim counter, resetProcess, programFiles
    
    WriteLog "Resetting the Remote Desktop Client."
    
    If ProcessExists("msrdc.exe") Then
        WriteLog "Disconnecting all open session host connections."
        KillProcess "msrdc.exe"
        counter = 0
        Do While counter < 30 And ProcessExists("msrdc.exe")
            counter = counter + 1
            WScript.Sleep 1000
        Loop
    End If
    
    KillProcess "msrdcw.exe"
    KillProcess "Microsoft.AAD.BrokerPlugin.exe"
    
    WriteLog "Removing cached credentials and configuration from the client."
    programFiles = shell.ExpandEnvironmentStrings("%ProgramFiles%")
    
    Set resetProcess = shell.Exec("""" & programFiles & "\Remote Desktop\msrdcw.exe"" /reset /f")
    
    Do While resetProcess.Status = 0
       WScript.Sleep 100
    Loop
    
    WriteLog "msrdcw.exe /reset exit code: [" & resetProcess.ExitCode & "]"    
End Sub

Function RegistryKeyExists(keyPath)
    On Error Resume Next
    shell.RegRead keyPath
    RegistryKeyExists = (Err.Number = 0)
    On Error GoTo 0
End Function

Sub SetRegistryValue(keyPath, valueName, valueType, value)
    On Error Resume Next
    shell.RegWrite keyPath & "\" & valueName, value, valueType
    On Error GoTo 0
End Sub

' Start of the main script execution
logFile.WriteLine "==================== " & Now & " ===================="
logFile.WriteLine "Executing '" & WScript.ScriptFullName & "'."

' Handle Client Reset on launch
If RegistryKeyExists("HKCU\Software\Microsoft\RdClientRadc\") Then
    ResetMSRDCW
End If

' Turn off Telemetry
SetRegistryValue "HKCU\Software\Microsoft\RdClientRadc", "EnableMSRDCTelemetry", "REG_DWORD", 0

WriteLog "Starting Remote Desktop Client."

Dim msrdcwProcess, programFiles
programFiles = shell.ExpandEnvironmentStrings("%ProgramFiles%")

If SubscribeUrl <> "" Then
    Set msrdcwProcess = shell.Exec("""" & programFiles & "\Remote Desktop\Msrdcw.exe"" ms-rd:subscribe?url=" & SubscribeUrl)
Else
    Set msrdcwProcess = shell.Exec("""" & programFiles & "\Remote Desktop\Msrdcw.exe""")
End If

' Wait for the client to exit
WriteLog "Waiting for the Remote Desktop Client to exit."
Do While msrdcwProcess.Status = 0
    WScript.Sleep 5000
Loop

WriteLog "The Remote Desktop Client closed with exit code [" & msrdcwProcess.ExitCode & "]."

If msrdcwProcess.ExitCode <> -1 Then
    If RegistryKeyExists("HKCU\Software\Microsoft\RdClientRadc\") Then
        ResetMSRDCW
    End If
End If

WriteLog "Exiting """ & WScript.ScriptFullName & """"

dim oFolder, file, fileDate
Set oFolder = fso.GetFolder(logFolder)

For Each file In oFolder.Files
    If LCase(fso.GetExtensionName(file.Name)) = "log" Then
        If Left(file.Name, 17) = "Launch-AVDClient-" Then
            fileDate = file.DateLastModified
            WScript.Echo fileDate
            If DateDiff("d", fileDate, Now) > 7 Then
                On Error Resume Next
                file.Delete True
                On Error GoTo 0
            End If
        End If
    End If
Next
