Dim ConvertedDir, InstallDir, ScriptName, WshShell

On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
If (Err = 0) then
  'Get the INSTALLDIR value via CustomActionData
  InstallDir = Session.Property("CustomActionData")

  'Remove all trailing backslashes to normalize
  Do While (Mid(InstallDir,Len(InstallDir),1) = "\")
    InstallDir = mid(InstallDir,1,Len(InstallDir)-1)
  Loop
  ConvertedDir = Replace(InstallDir, "\", "/")
  ScriptName = ConvertedDir & "\etc\shibboleth\keygen.bat"
  
  WshShell.Exec(ScriptName)
End If
