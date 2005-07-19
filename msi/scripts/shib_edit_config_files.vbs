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


Dim FileSystemObj, ConvertedDir, ConfigFile
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

  ConfigFile = DistDir & "AAP.xml.in"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "AAP.xml")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "AAP.xml", false
  End If
  If (FileSystemObj.FileExists(DistDir & "AAP.xml")) then
    FileSystemObj.DeleteFile DistDir & "AAP.xml", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "AAP.xml"
  
  ConfigFile = DistDir & "example-metadata.xml.in"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "example-metadata.xml")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "example-metadata.xml", false
  End If
  If (FileSystemObj.FileExists(DistDir & "example-metadata.xml")) then
    FileSystemObj.DeleteFile DistDir & "example-metadata.xml", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "example-metadata.xml"

  ConfigFile = DistDir & "IQ-metadata.xml.in"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  If (NOT FileSystemObj.FileExists(ConfigDir & "IQ-metadata.xml")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "IQ-metadata.xml", false
  End If
  If (FileSystemObj.FileExists(DistDir & "IQ-metadata.xml")) then
    FileSystemObj.DeleteFile DistDir & "IQ-metadata.xml", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "IQ-metadata.xml"

  ConfigFile = DistDir & "shibboleth.xml.in"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGSYSCONFDIR-@", ConvertedDir & "/etc/shibboleth"
  ReplaceInFile ConfigFile, "@-LIBEXECDIR-@", ConvertedDir & "/libexec"
  ReplaceInFile ConfigFile, "@-LOGDIR-@", ConvertedDir & "/var/log/shibboleth"
  ReplaceInFile ConfigFile, "@-PREFIX-@", ConvertedDir
  ReplaceInFile ConfigFile, "   <UnixListener address=""@-VARRUNDIR-@/shib-shar.sock""/>", "<!-- <UnixListener address=""@-VARRUNDIR-@/shib-shar.sock""/> -->"
  ReplaceInFile ConfigFile, "<!-- <TCPListener address=""127.0.0.1"" port=""12345"" acl=""127.0.0.1""/> -->", "<TCPListener address=""127.0.0.1"" port=""" & ShibdPort & """ acl=""127.0.0.1""/>"
  If (NOT FileSystemObj.FileExists(ConfigDir & "shibboleth.xml")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "shibboleth.xml", false
  End If
  If (FileSystemObj.FileExists(DistDir & "shibboleth.xml")) then
    FileSystemObj.DeleteFile DistDir & "shibboleth.xml", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "shibboleth.xml"

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
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGSYSCONFDIR-@", ConvertedDir & "/etc/shibboleth"
  ReplaceInFile ConfigFile, "@-LIBEXECDIR-@", ConvertedDir & "/libexec"
  ReplaceInFile ConfigFile, "@-PREFIX-@", ConvertedDir
  If (NOT FileSystemObj.FileExists(ConfigDir & "apache.config")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "apache.config", false
  End If
  If (FileSystemObj.FileExists(DistDir & "apache.config")) then
    FileSystemObj.DeleteFile DistDir & "apache.config", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "apache.config"

  ConfigFile = DistDir & "apache2.config.in"
  ReplaceInFile ConfigFile, "@-PKGXMLDIR-@", ConvertedDir & "/share/xml/shibboleth"
  ReplaceInFile ConfigFile, "@-PKGSYSCONFDIR-@", ConvertedDir & "/etc/shibboleth"
  ReplaceInFile ConfigFile, "@-LIBEXECDIR-@", ConvertedDir & "/libexec"
  ReplaceInFile ConfigFile, "@-PREFIX-@", ConvertedDir
  If (NOT FileSystemObj.FileExists(ConfigDir & "apache2.config")) then
    FileSystemObj.CopyFile ConfigFile, ConfigDir & "apache2.config", false
  End If
  If (FileSystemObj.FileExists(DistDir & "apache2.config")) then
    FileSystemObj.DeleteFile DistDir & "apache2.config", true
  End If
  FileSystemObj.MoveFile ConfigFile, DistDir & "apache2.config"


  'Now just copy the other non-edited files over as well (if possible)

  If (NOT FileSystemObj.FileExists(ConfigDir & "accessError.html")) then
    FileSystemObj.CopyFile DistDir & "accessError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "inqueue.pem")) then
    FileSystemObj.CopyFile DistDir & "inqueue.pem", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "metadataError.html")) then
    FileSystemObj.CopyFile DistDir & "metadataError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "openssl.cnf")) then
    FileSystemObj.CopyFile DistDir & "openssl.cnf", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "rmError.html")) then
    FileSystemObj.CopyFile DistDir & "rmError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "sessionError.html")) then
    FileSystemObj.CopyFile DistDir & "sessionError.html", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "shibboleth.logger")) then
    FileSystemObj.CopyFile DistDir & "shibboleth.logger", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "sp-example.crt")) then
    FileSystemObj.CopyFile DistDir & "sp-example.crt", ConfigDir, false
  End If

  If (NOT FileSystemObj.FileExists(ConfigDir & "sp-example.key")) then
    FileSystemObj.CopyFile DistDir & "sp-example.key", ConfigDir, false
  End If


'Last End If
End If