// IR-484 - SAM / SYSTEM / SECURITY Hive Save
// MITRE ATT&CK: T1003.002
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/\bsave\b.*(SAM|SYSTEM|SECURITY)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)