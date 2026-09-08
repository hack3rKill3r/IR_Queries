// IR-031 - NET/NET1 Domain Discovery
// Purpose: Find common account, group, domain, and network discovery via net.exe/net1.exe.
// MITRE ATT&CK: T1087 / T1069 / T1018
#event_simpleName=ProcessRollup2
FileName=/^(net|net1)\.exe$/i
CommandLine=/(domain|group|user|accounts|view)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)