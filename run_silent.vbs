Option Explicit

Dim shell, fso, root, launcher, pythonw, mainScript, command, exitCode
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
launcher = fso.BuildPath(root, "run.bat")
pythonw = fso.BuildPath(fso.BuildPath(root, "Runtime"), "pythonw.exe")
mainScript = fso.BuildPath(fso.BuildPath(root, "App"), "main.py")

If Not fso.FileExists(launcher) Then
    MsgBox "无法启动：缺少 run.bat。请恢复完整便携包。", 16, "SankakuSyncer"
    WScript.Quit 1
End If
If Not fso.FileExists(pythonw) Then
    MsgBox "无法启动：缺少 Runtime\pythonw.exe。请恢复完整便携包。", 16, "SankakuSyncer"
    WScript.Quit 1
End If
If Not fso.FileExists(mainScript) Then
    MsgBox "无法启动：缺少 App\main.py。请恢复完整便携包。", 16, "SankakuSyncer"
    WScript.Quit 1
End If

command = Chr(34) & launcher & Chr(34)
On Error Resume Next
exitCode = shell.Run(command, 0, True)
If Err.Number <> 0 Then
    MsgBox "启动失败。请运行 run_debug.bat 查看详细错误。", 16, "SankakuSyncer"
    WScript.Quit 1
End If
On Error GoTo 0

If exitCode <> 0 Then
    MsgBox "程序返回启动错误。请运行 run_debug.bat 查看详细信息。", 16, "SankakuSyncer"
    WScript.Quit exitCode
End If
