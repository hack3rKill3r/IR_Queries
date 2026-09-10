// IR-357 - Add Account to Domain Admins
// Purpose: Identify net.exe group modification targeting Domain Admins.
// MITRE ATT&CK: T1098 / T1136
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/group.*domain admins.*\/add/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)