Dim WshShell, versionArray, versionElement, versionNumbers, regValue, foundVersionsStr
Set WshShell = CreateObject("WScript.Shell")

versionNumbers = Session.Property("OLDSHIBVERSIONSTOUNINSTALL")

versionArray = split( versionNumbers, ";" )

foundVersionsStr = ""

for each versionElement in versionArray
  if (versionElement<>"") then

    'if RegRead fails, it won't set regValue, and it will hold the last value instead.  Make sure the 'last' value is ""
    regValue = ""
    on error resume next
      regValue=WshShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shibboleth " & versionElement & "\UninstallString")
    if (regValue<>"") then
      foundVersionsStr = foundVersionsStr & "Shibboleth " & versionElement & vbCRLF
    end if

  end if
next

if (foundVersionsStr<>"") then
  Session.Property("OLDSHIBVERSIONSFOUND") = foundVersionsStr
end if