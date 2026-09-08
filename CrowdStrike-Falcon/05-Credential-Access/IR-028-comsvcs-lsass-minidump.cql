// IR-028 - Comsvcs MiniDump LSASS
// Purpose: Identify rundll32/comsvcs.dll credential dumping patterns.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
CommandLine=/comsvcs.*MiniDump/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)