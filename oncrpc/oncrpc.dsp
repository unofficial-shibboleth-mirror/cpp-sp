# Microsoft Developer Studio Project File - Name="oncrpc" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=oncrpc - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "oncrpc.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "oncrpc.mak" CFG="oncrpc - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "oncrpc - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "oncrpc - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "oncrpc - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "ONCRPC_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "." /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "ONCRPCDLL" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 wsock32.lib advapi32.lib /nologo /dll /machine:I386 /def:"oncrpc.def"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "oncrpc - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "ONCRPC_EXPORTS" /YX /FD /GZ  /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "." /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "ONCRPCDLL" /FR /YX /FD /GZ  /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib advapi32.lib /nologo /dll /debug /machine:I386 /def:"oncrpc.def" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "oncrpc - Win32 Release"
# Name "oncrpc - Win32 Debug"
# Begin Group "rpc"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\rpc\auth.h
# End Source File
# Begin Source File

SOURCE=.\rpc\auth_unix.h
# End Source File
# Begin Source File

SOURCE=.\rpc\bcopy.h
# End Source File
# Begin Source File

SOURCE=.\rpc\clnt.h
# End Source File
# Begin Source File

SOURCE=.\rpc\netdb.h
# End Source File
# Begin Source File

SOURCE=.\rpc\pmap_clnt.h
# End Source File
# Begin Source File

SOURCE=.\rpc\pmap_prot.h
# End Source File
# Begin Source File

SOURCE=.\rpc\pmap_rmt.h
# End Source File
# Begin Source File

SOURCE=.\rpc\rpc.h
# End Source File
# Begin Source File

SOURCE=.\rpc\rpc_msg.h
# End Source File
# Begin Source File

SOURCE=.\rpc\svc.h
# End Source File
# Begin Source File

SOURCE=.\rpc\svc_auth.h
# End Source File
# Begin Source File

SOURCE=.\rpc\types.h
# End Source File
# Begin Source File

SOURCE=.\rpc\xdr.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\auth_non.c
# End Source File
# Begin Source File

SOURCE=.\auth_uni.c
# End Source File
# Begin Source File

SOURCE=.\authunix.c
# End Source File
# Begin Source File

SOURCE=.\bcopy.c
# End Source File
# Begin Source File

SOURCE=.\bindresv.c
# End Source File
# Begin Source File

SOURCE=.\clnt_gen.c
# End Source File
# Begin Source File

SOURCE=.\clnt_per.c
# End Source File
# Begin Source File

SOURCE=.\clnt_raw.c
# End Source File
# Begin Source File

SOURCE=.\clnt_sim.c
# End Source File
# Begin Source File

SOURCE=.\clnt_tcp.c
# End Source File
# Begin Source File

SOURCE=.\clnt_udp.c
# End Source File
# Begin Source File

SOURCE=.\get_myad.c
# End Source File
# Begin Source File

SOURCE=.\getrpcen.c
# End Source File
# Begin Source File

SOURCE=.\getrpcpo.c
# End Source File
# Begin Source File

SOURCE=.\nt.c
# End Source File
# Begin Source File

SOURCE=.\oncrpc.def
# End Source File
# Begin Source File

SOURCE=.\oncrpc.rc
# End Source File
# Begin Source File

SOURCE=.\pmap_cln.c
# End Source File
# Begin Source File

SOURCE=.\pmap_get.c
# End Source File
# Begin Source File

SOURCE=.\pmap_gma.c
# End Source File
# Begin Source File

SOURCE=.\pmap_pr.c
# End Source File
# Begin Source File

SOURCE=.\pmap_pro.c
# End Source File
# Begin Source File

SOURCE=.\pmap_rmt.c
# End Source File
# Begin Source File

SOURCE=.\resource.h
# End Source File
# Begin Source File

SOURCE=.\rpc_call.c
# End Source File
# Begin Source File

SOURCE=.\rpc_comm.c
# End Source File
# Begin Source File

SOURCE=.\rpc_prot.c
# End Source File
# Begin Source File

SOURCE=.\svc.c
# End Source File
# Begin Source File

SOURCE=.\svc_auth.c
# End Source File
# Begin Source File

SOURCE=.\svc_autu.c
# End Source File
# Begin Source File

SOURCE=.\svc_raw.c
# End Source File
# Begin Source File

SOURCE=.\svc_run.c
# End Source File
# Begin Source File

SOURCE=.\svc_simp.c
# End Source File
# Begin Source File

SOURCE=.\svc_tcp.c
# End Source File
# Begin Source File

SOURCE=.\svc_udp.c
# End Source File
# Begin Source File

SOURCE=.\xdr.c
# End Source File
# Begin Source File

SOURCE=.\xdr_arra.c
# End Source File
# Begin Source File

SOURCE=.\xdr_floa.c
# End Source File
# Begin Source File

SOURCE=.\xdr_mem.c
# End Source File
# Begin Source File

SOURCE=.\xdr_rec.c
# End Source File
# Begin Source File

SOURCE=.\xdr_refe.c
# End Source File
# Begin Source File

SOURCE=.\xdr_stdi.c
# End Source File
# End Target
# End Project
