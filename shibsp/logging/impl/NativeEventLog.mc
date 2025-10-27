;#define SHIB_EVENT_SOURCE_NAME "ShibbolethSPAgent"

;/*
; * These are the "event" that the logging service products for SHIB_CRIT and so forth
; */
MessageId=0x1
Severity=Error
SymbolicName=SHIBSP_LOG_CRIT
Language=English
CRITICAL %1 : %2
.

MessageId=0x2
SymbolicName=SHIBSP_LOG_ERROR
Language=English
Error %1 : %2
.

MessageId=0x3
Severity=Warning
SymbolicName=SHIBSP_LOG_WARN
Language=English
Warn %1 : %2
.

MessageId=0x4
Severity=Informational
SymbolicName=SHIBSP_LOG_INFO
Language=English
Info %1 : %2
.

MessageId=0x5
Severity=Success
SymbolicName=SHIBSP_LOG_DEBUG
Language=English
Debug %1 : %2
.

;/*
; * These are the "Categories" required by the ReportEvent Api
; * We keep them separate from the events.
; */
MessageId=0x6
SymbolicName=SHIBSP_CATEGORY_CRIT
Language=English
CRITICAL Category
.

MessageId=0x7
SymbolicName=SHIBSP_CATEGORY_ERROR
Language=English
Error Category
.

MessageId=0x8
Severity=Warning
SymbolicName=SHIBSP_CATEGORY_WARN
Language=English
Warn Category
.

MessageId=0x9
Severity=Informational
SymbolicName=SHIBSP_CATEGORY_INFO
Language=English
Info Category
.

MessageId=0x10
Severity=Success
SymbolicName=SHIBSP_CATEGORY_DEBUG
Language=English
Debug Category
.

