// IR-163 - SecretsDump Indicators
// Purpose: Identify common Impacket secretsdump strings and associated artifacts.
// MITRE ATT&CK: T1003
#event_simpleName=ProcessRollup2
CommandLine=/(secretsdump|impacket-secretsdump|RemoteRegistry|sam\.save|security\.save)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)