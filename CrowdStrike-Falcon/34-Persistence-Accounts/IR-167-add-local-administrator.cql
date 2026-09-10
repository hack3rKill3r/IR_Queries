// IR-167 - Add User to Local Administrators
// Purpose: Identify net.exe/net1.exe commands adding accounts to the local Administrators group.
// MITRE ATT&CK: T1098
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/localgroup.*administrators.*\/add/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)