Option Explicit
CreateObject("WScript.Shell").Run Chr(34) & CreateObject("Scripting.FileSystemObject").BuildPath(CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName), "run.bat") & Chr(34), 0, False
