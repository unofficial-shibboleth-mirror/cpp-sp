# Microsoft Developer Studio Project File - Name="shib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=shib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "shib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "shib.mak" CFG="shib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "shib - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "shib - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "shib - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SHIB_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GR /GX /O2 /I "." /I "..\..\..\opensaml\c" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 log4cpp.lib xerces-c_2.lib xsec_lib_02.lib libeay32.lib saml_4.lib /nologo /dll /machine:I386 /out:"Release/shib_5.dll" /libpath:"..\..\..\opensaml\c\saml\Release" /libpath:"\openssl-0.9.7b\out32dll"

!ELSEIF  "$(CFG)" == "shib - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SHIB_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GR /GX /ZI /Od /I "." /I "..\..\..\opensaml\c" /D "_WINDOWS" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_AFXDLL" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 log4cppD.lib xerces-c_2D.lib xsec_lib_02D.lib libeay32.lib saml_4D.lib /nologo /dll /debug /machine:I386 /out:"Debug/shib_5D.dll" /pdbtype:sept /libpath:"..\..\..\opensaml\c\saml\Debug" /libpath:"\openssl-0.9.7b\out32dll.dbg"

!ENDIF 

# Begin Target

# Name "shib - Win32 Release"
# Name "shib - Win32 Debug"
# Begin Source File

SOURCE=.\AAP.cpp
# End Source File
# Begin Source File

SOURCE=.\ClubShibPOSTProfile.cpp
# End Source File
# Begin Source File

SOURCE=..\config_win32.h
# End Source File
# Begin Source File

SOURCE=.\Constants.cpp
# End Source File
# Begin Source File

SOURCE=.\internal.h
# End Source File
# Begin Source File

SOURCE=.\Metadata.cpp
# End Source File
# Begin Source File

SOURCE=.\SAMLBindingFactory.cpp
# End Source File
# Begin Source File

SOURCE=.\ScopedAttribute.cpp
# End Source File
# Begin Source File

SOURCE=".\shib-threads-win32.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-threads.h"
# End Source File
# Begin Source File

SOURCE=.\shib.h
# End Source File
# Begin Source File

SOURCE=.\ShibConfig.cpp
# End Source File
# Begin Source File

SOURCE=.\ShibPOSTProfile.cpp
# End Source File
# Begin Source File

SOURCE=.\ShibPOSTProfileFactory.cpp
# End Source File
# Begin Source File

SOURCE=.\SimpleAttribute.cpp
# End Source File
# Begin Source File

SOURCE=.\XML.cpp
# End Source File
# Begin Source File

SOURCE=.\XMLMetadata.cpp
# End Source File
# Begin Source File

SOURCE=.\XMLTrust.cpp
# End Source File
# End Target
# End Project
