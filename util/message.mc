LanguageNames=(Neutral=0x0:MSG00)

MessageIdTypedef=WORD

MessageId=1
SymbolicName=CATEGORY_SHIBD
Language=Neutral
Shibboleth Daemon
.

MessageId=
SymbolicName=CATEGORY_ISAPI
Language=Neutral
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
Language=Neutral
Shibboleth Daemon: %1!s!
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_STARTUP_FAILED
Language=Neutral
Shibboleth Daemon startup failed.
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_START_FAILED
Language=Neutral
Shibboleth Daemon startup: StartServiceCtrlDispatcher failed.
.

MessageId=
Severity=Error
Facility=Shibboleth
SymbolicName=SHIBD_SET_SERVICE_STATUS_FAILED
Language=Neutral
Shibboleth Daemon startup: SetServiceStatus failed.
.

MessageId=
Severity=Informational
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_STARTED
Language=Neutral
Shibboleth Daemon started successfully.
.

MessageId=
Severity=Informational
Facility=Shibboleth
SymbolicName=SHIBD_SERVICE_STOPPING
Language=Neutral
Shibboleth Daemon stopping...
.


MessageId=200
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_GENERIC_MESSAGE
Language=Neutral
Shibboleth ISAPI filter: %1
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_CANNOT_LOAD
Language=Neutral
Shibboleth ISAPI filter: Extension mode startup not possible, is the DLL loaded as a filter?
.

MessageId=
Severity=Warning
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_REENTRANT_INIT
Language=Neutral
Shibboleth ISAPI filter: Reentrant filter initialization, ignoring...
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_STARTUP_FAILED
Language=Neutral
Shibboleth ISAPI filter: Startup failed during library initialization, check native log for help.
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_STARTUP_FAILED_EXCEPTION
Language=Neutral
Shibboleth ISAPI filter: Startup failed during library initialization: %1!s!, check native log for help.
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_CANNOT_CREATE_ANTISPOOF
Language=Neutral
Shibboleth ISAPI filter: Failed to generate a random anti-spoofing key (if this is Windows 2000 set one manually).
.

MessageId=
Severity=Informational
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_INITIALIZED
Language=Neutral
Shibboleth ISAPI filter: Initialized...
.

MessageId=
Severity=Informational
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_SHUTDOWN
Language=Neutral
Shibboleth ISAPI filter: Shutdown...
.


MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_CRITICAL
Language=Neutral
Shibboleth ISAPI filter: Critical Error: %0!s!
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_CLIENT_ERROR
Language=Neutral
Shibboleth ISAPI filter: Client Error: %0!s!
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_MISSING_VARIABLE
Language=Neutral
Shibboleth ISAPI filter: Missing Variable %0!s!
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_EXCEPTION
Language=Neutral
Shibboleth ISAPI filter: Caught an Exception %0!s!
.

MessageId=
Severity=Error
Facility=ShibbolethISAPI
SymbolicName=SHIB_ISAPI_UNKNOWN_EXCEPTION
Language=Neutral
Shibboleth ISAPI filter: Caught an Unknown Exception.
.
