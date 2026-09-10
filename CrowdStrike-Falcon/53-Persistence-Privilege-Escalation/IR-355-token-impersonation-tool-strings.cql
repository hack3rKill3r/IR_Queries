// IR-355 - Token Impersonation / Manipulation Strings
// Purpose: Hunt for common token abuse tooling and APIs.
// MITRE ATT&CK: T1134
#event_simpleName=ProcessRollup2
CommandLine=/(incognito|make_token|steal_token|token::elevate|DuplicateTokenEx|ImpersonateLoggedOnUser)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)