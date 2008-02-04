Function ReadFile( filePath )
   Dim theFile

   'OpenTextFile args: <path>, 1 = ForReading
   'If you read an empty file, VBScript throws an error for some reason
   if (FileSystemObj.FileExists(filePath)) then
     Set theFile = FileSystemObj.GetFile(filePath)
     if (theFile.size > 0) then
       Set theFile = FileSystemObj.OpenTextFile(filePath, 1)
       ReadFile = theFile.ReadAll
     else
       ReadFile = ""
     end if
   else
     ReadFile = ""
   end if
End Function

Sub WriteFile( filePath, contents )
   Dim theFile

   'OpenTextFile args: <path>, 2 = ForWriting, True = create if not exist
   Set theFile = FileSystemObj.OpenTextFile(filePath, 2, True)
   theFile.Write contents
End Sub

Sub ReplaceInFile( filePath, lookForStr, replaceWithStr )
  Dim buffer

  buffer = ReadFile(filePath)
  if (buffer <> "") then
    buffer = Replace(buffer, lookForStr, replaceWithStr)
    WriteFile filePath, buffer
  end if
End Sub


Dim FileSystemObj, ConvertedDir, ConfigFile, XMLDir
Dim customData, msiProperties, InstallDir, ShibdPort

on error resume next
Set FileSystemObj = CreateObject("Scripting.FileSystemObject")
if (Err = 0) then

  'Get the INSTALLDIR and SHIBD_PORT values via CustomActionData
  customData = Session.Property("CustomActionData")
  msiProperties = split(customData,";@;")
  InstallDir = msiProperties(0)
  ShibdPort = msiProperties(1)

  'Remove all trailing backslashes to normalize
  do while (mid(InstallDir,Len(InstallDir),1) = "\")
    InstallDir = mid(InstallDir,1,Len(InstallDir)-1)
  loop
  ConvertedDir = Replace(InstallDir, "\", "/")
  ConfigDir = InstallDir & "\etc\shibboleth\"
  DistDir = ConfigDir & "dist\"

  'Perform actual Substitutions
  'Afterwards, if the config file doesn't already exist, copy up to etc/shibboleth
  'Also strip *.in for files in dist

  ConfigFile = DistDir & "shibd.logger.in"
  ReplaceInFile ConfigFile, "@-PKGLOGDIR-@", ConvertedDir & "/var/log/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "shibd.logger")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "shibd.logger", false
  End If
  If (FileSystemObj.FileExists(DistDir & "shibd.logger")) then
    FileSystemObj.DeleteFile DistDir & "shibd.logger", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "shibd.logger"

  ConfigFile = DistDir & "native.logger.in"
  ReplaceInFile ConfigFile, "@-SHIRELOGDIR-@", ConvertedDir & "/var/log/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "native.logger")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "native.logger", false
  End If
  If (FileSystemObj.FileExists(DistDir & "native.logger")) then
    FileSystemObj.DeleteFile DistDir & "native.logger", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "native.logger"

  ConfigFile = DistDir & "apache.config.in"
  ReplaceInFile ConfigFile, "@-PKGLIBDIR-@", ConvertedDir & "/lib/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGDOCDIR-@", ConvertedDir & "/share/doc/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "apache.config")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "apache.config", false
  End If
  If (FileSystemObj.FileExists(DistDir & "apache.config")) then
    FileSystemObj.DeleteFile DistDir & "apache.config", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "apache.config"

  ConfigFile = DistDir & "apache2.config.in"
  ReplaceInFile ConfigFile, "@-PKGLIBDIR-@", ConvertedDir & "/lib/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGDOCDIR-@", ConvertedDir & "/share/doc/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "apache2.config")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "apache2.config", false
  End If
  If (FileSystemObj.FileExists(DistDir & "apache2.config")) then
    FileSystemObj.DeleteFile DistDir & "apache2.config", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "apache2.config"

  ConfigFile = DistDir & "apache22.config.in"
  ReplaceInFile ConfigFile, "@-PKGLIBDIR-@", ConvertedDir & "/lib/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGDOCDIR-@", ConvertedDir & "/share/doc/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "apache22.config")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "apache22.config", false
  End If
  If (FileSystemObj.FileExists(DistDir & "apache22.config")) then
    FileSystemObj.DeleteFile DistDir & "apache22.config", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "apache22.config"

  ConfigFile = DistDir & "shibboleth2.xml"
  ReplaceInFile ConfigFile, "   <UnixListener address=""shibd.sock""/>", "<!-- <UnixListener address=""shibd.sock""/> -->"
  ReplaceInFile ConfigFile, "<!-- <TCPListener address=""127.0.0.1"" port=""12345"" acl=""127.0.0.1""/> -->", "<TCPListener address=""127.0.0.1"" port=""" & ShibdPort & """ acl=""127.0.0.1""/>"
  If (NOT FileSystemObj.FileExists(ConfigDir & "shibboleth2.xml")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "shibboleth2.xml", false
  End If

  'Now just copy the other non-edited files over as well (if possible)

  If (NOT FileSystemObj.FileExists(ConfigDir & "accessError.html")) then
    FileSystemObj.CopyFile DistDir & "accessError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "metadataError.html")) then
    FileSystemObj.CopyFile DistDir & "metadataError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "sessionError.html")) then
    FileSystemObj.CopyFile DistDir & "sessionError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "sslError.html")) then
    FileSystemObj.CopyFile DistDir & "sslError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "bindingTemplate.html")) then
    FileSystemObj.CopyFile DistDir & "bindingTemplate.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "localLogout.html")) then
    FileSystemObj.CopyFile DistDir & "localLogout.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "globalLogout.html")) then
    FileSystemObj.CopyFile DistDir & "globalLogout.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "openssl.cnf")) then
    FileSystemObj.CopyFile DistDir & "openssl.cnf", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "console.logger")) then
    FileSystemObj.CopyFile DistDir & "console.logger", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "shibboleth.logger")) then
    FileSystemObj.CopyFile DistDir & "shibboleth.logger", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "example-metadata.xml")) then
    FileSystemObj.CopyFile DistDir & "example-metadata.xml", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "attribute-map.xml")) then
    FileSystemObj.CopyFile DistDir & "attribute-map.xml", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "attribute-policy.xml")) then
    FileSystemObj.CopyFile DistDir & "attribute-policy.xml", ConfigDir, false
  End If

  ' Finally, fix up schema catalogs.
  
  XMLDir = InstallDir & "\share\xml\xmltooling\"
  ConfigFile = XMLDir & "catalog.xml"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@/", XMLDir

  XMLDir = InstallDir & "\share\xml\opensaml\"
  ConfigFile = XMLDir & "saml20-catalog.xml"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@/", XMLDir
  ConfigFile = XMLDir & "saml11-catalog.xml"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@/", XMLDir
  ConfigFile = XMLDir & "saml10-catalog.xml"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@/", XMLDir

  XMLDir = InstallDir & "\share\xml\shibboleth\"
  ConfigFile = XMLDir & "catalog.xml"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@/", XMLDir

'Last End If
End If