// IR-346 - Registry Run Key Addition
// MITRE ATT&CK: T1547.001
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/add.*\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)