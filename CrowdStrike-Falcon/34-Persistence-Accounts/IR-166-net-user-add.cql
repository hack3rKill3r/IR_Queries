// IR-166 - Add User with NET
// Purpose: Identify local/domain account creation using net.exe/net1.exe.
// MITRE ATT&CK: T1136
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/user.*\/add/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)