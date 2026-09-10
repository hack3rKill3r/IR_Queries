// IR-224 - Comsvcs MiniDump
// Purpose: Identify rundll32 + comsvcs.dll MiniDump behavior.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName="rundll32.exe"
CommandLine=/comsvcs\.dll.*MiniDump/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine,SHA256HashData], limit=20000)