// IR-141 - NET User Enumeration
// Purpose: Identify local/domain account discovery using net.exe or net1.exe.
// MITRE ATT&CK: T1087
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/\buser\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)