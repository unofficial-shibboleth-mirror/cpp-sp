# Microsoft Developer Studio Project File - Name="shibtarget" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=shibtarget - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "shibtarget.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "shibtarget.mak" CFG="shibtarget - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "shibtarget - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "shibtarget - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "shibtarget - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SHIBTARGET_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GR /GX /O2 /I "." /I ".." /I "..\oncrpc" /I "..\..\..\opensaml\c" /D "NDEBUG" /D "_WINDOWS" /D "WIN32" /D "_MBCS" /D "WANT_TCP_SHAR" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 log4cpp.lib xerces-c_2.lib wsock32.lib saml_4.lib /nologo /dll /machine:I386 /out:"Release/shibtarget_4.dll" /libpath:"../../../opensaml/c/saml/Release" /export:shibrpc_prog_1 /export:shibrpc_ping_1
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "shibtarget - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SHIBTARGET_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GR /GX /ZI /Od /I "." /I ".." /I "..\oncrpc" /I "..\..\..\opensaml\c" /D "_DEBUG" /D "_AFXDLL" /D "_WINDOWS" /D "WIN32" /D "_MBCS" /D "WANT_TCP_SHAR" /FR /YX /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 log4cppD.lib xerces-c_2D.lib wsock32.lib saml_4D.lib /nologo /dll /debug /machine:I386 /out:"Debug/shibtarget_4D.dll" /pdbtype:sept /libpath:"../../../opensaml/c/saml/Debug" /export:shibrpc_prog_1 /export:shibrpc_ping_1
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "shibtarget - Win32 Release"
# Name "shibtarget - Win32 Debug"
# Begin Source File

SOURCE=.\internal.h
# End Source File
# Begin Source File

SOURCE=.\resource.h
# End Source File
# Begin Source File

SOURCE=".\shib-ccache.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-config.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-ini.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-mlp.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-rm.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-rpcerror.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-rpchandle.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-shire.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-sock.cpp"
# End Source File
# Begin Source File

SOURCE=".\shib-target.h"
# End Source File
# Begin Source File

SOURCE=".\shib-target.rc"
# End Source File
# Begin Source File

SOURCE=".\shibrpc-clnt.c"
# End Source File
# Begin Source File

SOURCE=".\shibrpc-server.cpp"
# End Source File
# Begin Source File

SOURCE=".\shibrpc-svc.c"
# End Source File
# Begin Source File

SOURCE=".\shibrpc-xdr.c"
# End Source File
# Begin Source File

SOURCE=.\shibrpc.h
# End Source File
# Begin Source File

SOURCE=.\XML.cpp
# End Source File
# Begin Source File

SOURCE=.\XMLRequestMapper.cpp
# End Source File
# End Target
# End Project
