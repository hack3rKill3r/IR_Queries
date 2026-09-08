// IR-029 - Mimikatz / Credential Dumping Strings
// Purpose: Search command lines for common Mimikatz and credential-dumping strings.
// MITRE ATT&CK: T1003
#event_simpleName=ProcessRollup2
CommandLine=/(mimikatz|sekurlsa|logonpasswords|lsadump|dcsync)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)