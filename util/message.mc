LanguageNames=(English=0x409:MSG00409)

MessageIdTypedef=WORD

MessageId=1
SymbolicName=CATEGORY_SHIBD
Language=English
Shibboleth Daemon
.

MessageId=
SymbolicName=CATEGORY_ISAPI
Language=English
Shibboleth Daemon ISAPI plugin
.


MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

FacilityNames=(Shibboleth=0x231:FACILITY_SYSTEM
               ShibbolethISAPI=0x232:FACILITY_RUNTIME
               )


MessageId=100
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_MESSAGE
Language=English
Shibboleth Daemon: %1!s!:  %2!s! %3!s! (%1!*x! : %2!x! '%3!ld!')  (%1!4d! : %2!I32d! '%3!3D!')
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIBISAPI_MESSAGE
Language=English
Shibboleth ISAPI plugin: %1
.
