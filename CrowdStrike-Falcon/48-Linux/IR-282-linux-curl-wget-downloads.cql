// IR-282 - Linux curl/wget Downloads
// Purpose: Identify command-line download activity on Linux.
// MITRE ATT&CK: T1105
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName=/^(curl|wget)$/i
CommandLine=/https?:\/\//i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)