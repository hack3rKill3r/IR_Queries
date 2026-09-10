// IR-168 - NET User Password Change Review
// Purpose: Surface net.exe/net1.exe user commands for review of password/account manipulation.
// MITRE ATT&CK: T1098
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/\buser\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)