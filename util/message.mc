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
SymbolicName=SHIBD_GENERIC_MESSAGE
Language=English
Shibboleth Daemon: %1!s!
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_STARTUP_FAILED
Language=English
Shibboleth Daemon startup failed.
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_START_FAILED
Language=English
Shibboleth Daemon startup: StartServiceCtrlDispatcher failed.
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_SET_SERVICE_STATUS_FAILED
Language=English
Shibboleth Daemon startup: SetServiceStatus failed.
.

MessageId=
Severity=Informational
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_STARTED
Language=English
Shibboleth Daemon started successfully.
.

MessageId=
Severity=Informational
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_STOPPING
Language=English
Shibboleth Daemon stopping...
.


MessageId=200
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIBISAPI_MESSAGE
Language=English
Shibboleth ISAPI plugin: %1
.
