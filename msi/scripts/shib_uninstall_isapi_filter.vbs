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


'*** Begin Main Code ***
Dim WebObj
Dim InstallDir
Dim ShibISAPIPath
Dim site, siteObj, sitePath


'Don't show errors, we'll handle anything important
On Error Resume Next

'Attempt to get W3SVC.  If failure, end script (e.g. IIS isn't available)
Set WebObj = GetObject("IIS://LocalHost/W3SVC")
if (Err = 0) then

  'Get the INSTALLDIR value via CustomActionData
  InstallDir = Session.Property("CustomActionData")

  'Remove all trailing backslashes to normalize
  do while (mid(InstallDir,Len(InstallDir),1) = "\")
    InstallDir = mid(InstallDir,1,Len(InstallDir)-1)
  loop
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