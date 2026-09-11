// IR-498 - Token / Session Theft Indicators
// MITRE ATT&CK: T1134
#event_simpleName=ProcessRollup2
CommandLine=/(steal_token|make_token|incognito|DuplicateTokenEx|ImpersonateLoggedOnUser|token::elevate)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)