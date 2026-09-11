// IR-487 - Impacket SecretsDump Indicators
// MITRE ATT&CK: T1003
#event_simpleName=ProcessRollup2
CommandLine=/(secretsdump|impacket-secretsdump|sam\.save|security\.save|just-dc|drsuapi)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)