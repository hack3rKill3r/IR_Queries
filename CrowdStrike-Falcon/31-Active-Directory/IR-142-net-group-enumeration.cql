// IR-142 - NET Group Enumeration
// Purpose: Identify group discovery using net.exe or net1.exe.
// MITRE ATT&CK: T1069
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/\bgroup\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)