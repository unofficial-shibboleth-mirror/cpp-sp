'In order to get the list of versions to uninstall during deferred mode,
'We need to set UninstallOldShibVersions property during the Immediate
'Execution sequence.  We can then read the value via CustomActionData.
'To accomplish this, create a CA as follows:
'  Action: SetShibVersionsImmediate
'  Source: UninstallOldShibVersions
'  Type:   51
'  Target: [OLDSHIBVERSIONSFOUND]
'Sequence this action near the beginning of InstallExecuteSequence with
'  Condition: (NOT Installed) AND (OLDSHIBVERSIONSFOUND <> "") AND (OLDSHIBPERFORMUNINSTALL = "TRUE")


'*********************************
'* This code is the entire body of shib_uninstall_isapi_filter.vbs
'* The only exception is that the main function of that code is made
'* a Sub in this code so we can call it, and we pass it the InstallDir
'* from the Uninst.isu string instead of pulling it from the MSI.
'*********************************

Sub DeleteISAPIFilters(IISPath,dllPath)

  Dim filter, FiltersObj, LoadOrder, FilterArray, FilterItem

  Set FiltersObj = GetObject(IISPath & "/Filters")
  LoadOrder = FiltersObj.FilterLoadOrder

  for each filter in FiltersObj
    if (filter.Class = "IIsFilter") then
      if (filter.FilterPath = dllPath) then

        'Delete the found filter here
        'If there's anything to potentially delete...
        if (LoadOrder <> "") then
          FilterArray = split(LoadOrder,",")
          LoadOrder = ""
          for each FilterItem in FilterArray
            if (FilterItem <> filter.Name) then
              LoadOrder = LoadOrder & FilterItem & ","
            end if
          next
          'Remove trailing comma if any filters were kept
          if (LoadOrder <> "") then
            LoadOrder = mid(LoadOrder,1,len(LoadOrder)-1)
          end if

          'Set the Load Order to the new shibboleth-less order
          if (FiltersObj.FilterLoadOrder <> LoadOrder) then
            FiltersObj.FilterLoadOrder = LoadOrder
            FiltersObj.SetInfo
          end if
        end if

        'Delete the actual IISFilter object
        FiltersObj.Delete "IIsFilter",filter.Name

      end if
    end if
  next

End Sub


Sub DeleteFileExtensions(siteObj, dllPath)

Dim ScriptMaps, newScriptMaps
Dim line, lineArray, lineIndex
Dim fileExtension
Dim existsFlag

  ScriptMaps = siteObj.ScriptMaps
  redim newScriptMaps(0)
  lineIndex = 0
  'copy each entry from the old ScriptMaps to newScriptMaps
  'unless it is for dllPath
  for each line in ScriptMaps
    lineArray = split(line,",")
    if (lineArray(1) <> dllPath) then
      redim preserve newScriptMaps(lineIndex)
      newScriptMaps(lineIndex) = line
      lineIndex = lineIndex + 1
    else
      existsFlag = "exists"
    end if
  next
  'If we found dllPath, then use the newScriptMaps instead
  if (existsFlag = "exists") then
    siteObj.ScriptMaps = newScriptMaps
    siteObj.SetInfo
  end if

End Sub


Sub CleanUpISAPI(InstallDir)

Dim WebObj
'Dim InstallDir
Dim ShibISAPIPath
Dim site, siteObj, sitePath


'Don't show errors, we'll handle anything important
On Error Resume Next

'Attempt to get W3SVC.  If failure, end script (e.g. IIS isn't available)
Set WebObj = GetObject("IIS://LocalHost/W3SVC")
if (Err = 0) then

  'Get the INSTALLDIR value via CustomActionData
  'Commented out for embedding in this .vbs, passed instead
'  InstallDir = Session.Property("CustomActionData")

  'Remove all trailing backslashes to normalize
  do while (mid(InstallDir,Len(InstallDir),1) = "\")
    InstallDir = mid(InstallDir,1,Len(InstallDir)-1)
  loop
  'Set dll Path
  ShibISAPIPath = InstallDir & "\libexec\isapi_shib.dll"

  'Delete ISAPI Filter
  'First do the master service
  DeleteISAPIFilters "IIS://LocalHost/W3SVC",ShibISAPIPath
  'Now do the websites
  for each site in WebObj
    if (site.Class = "IIsWebServer") then
      sitePath = "IIS://LocalHost/W3SVC/" & site.Name
      DeleteISAPIFilters sitePath,ShibISAPIPath
    end if
  next

  'Delete File Extensions
  'First do the master service
  DeleteFileExtensions WebObj,ShibISAPIPath
  'Now do the websites
  for each site in WebObj
    if (site.Class = "IIsWebServer") then
      set siteObj = GetObject("IIS://LocalHost/W3SVC/" & site.Name & "/ROOT")
      DeleteFileExtensions siteObj,ShibISAPIPath
    end if
  next


  'Delete Web Services Extension (universal, no need to do for each site)
  WebObj.DeleteExtensionFileRecord ShibISAPIPath

'Last end if
end if

End Sub


'******** Begin Main Code ***************

Dim WshShell, WshEnv, versionArray, versionElement, versionNumbers, regValue, UninstallArray, uninstallStr, UninstIsuArray, path, pathArray, NewPathEnv

on error resume next
Set WshShell = CreateObject("WScript.Shell")

versionNumbers = Session.Property("CustomActionData")

versionArray = split( versionNumbers, vbCRLF )

for each versionElement in versionArray
  if (versionElement<>"") then

    'if RegRead fails, it won't set regValue, and it will hold the last value instead.  Make sure the 'last' value is ""
    regValue = ""
    on error resume next
      regValue=WshShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" & versionElement & "\UninstallString")
    if (regValue<>"") then
      UninstallArray = split( regValue, " -f")
      'Save off the INSTALLDIR path for later use
      UninstIsuArray = split(UninstallArray(1),"Uninst.isu")
      InstallDir = UninstIsuArray(0)

      'Now create the silent uninstall string and execute it
      uninstallStr=UninstallArray(0) & " -y -a -f" & UninstallArray(1)
      WshShell.Run( uninstallStr )

      'Remove entry from path environment variable
      Set WshEnv = WshShell.Environment("SYSTEM")
      PathEnv = WshEnv("PATH")
      NewPathEnv = ""
      PathArray = split(PathEnv,";")
      for each path in PathArray
        if ((path<>InstallDir & "lib\") AND (path<>InstallDir & "lib")) then
          NewPathEnv = NewPathEnv & path & ";"
        end if
      next
      NewPathEnv = mid(NewPathEnv,1,len(NewPathEnv)-1)
      WshEnv("PATH") = NewPathEnv

      'Clean up all the ISAPI filters and file extension
      CleanUpISAPI InstallDir

    end if

  end if
next