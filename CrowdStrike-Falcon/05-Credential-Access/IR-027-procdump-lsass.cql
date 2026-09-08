// IR-027 - ProcDump Against LSASS
// Purpose: Identify ProcDump command lines targeting LSASS.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName=/^procdump(64)?\.exe$/i
CommandLine=/lsass/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)