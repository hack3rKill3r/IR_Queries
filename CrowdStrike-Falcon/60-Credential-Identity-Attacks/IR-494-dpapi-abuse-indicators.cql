// IR-494 - DPAPI Abuse Indicators
// MITRE ATT&CK: T1555
#event_simpleName=ProcessRollup2
CommandLine=/(DPAPI|CryptUnprotectData|MasterKey|mimikatz.*dpapi)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)