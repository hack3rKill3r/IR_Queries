// IR-488 - Mimikatz Indicators
// MITRE ATT&CK: T1003
#event_simpleName=ProcessRollup2
CommandLine=/(mimikatz|sekurlsa|logonpasswords|lsadump|kerberos::golden|token::elevate)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)