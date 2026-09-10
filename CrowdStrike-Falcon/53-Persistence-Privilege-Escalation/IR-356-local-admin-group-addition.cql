// IR-356 - Add Account to Local Administrators
// MITRE ATT&CK: T1098 / T1136
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/localgroup.*administrators.*\/add/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)