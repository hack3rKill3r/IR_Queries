// IR-038 - Network Discovery Commands
// Purpose: Identify common network and infrastructure discovery utilities.
// MITRE ATT&CK: T1016
#event_simpleName=ProcessRollup2
FileName=/^(ipconfig|arp|route|netstat|nslookup|ping|tracert)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)