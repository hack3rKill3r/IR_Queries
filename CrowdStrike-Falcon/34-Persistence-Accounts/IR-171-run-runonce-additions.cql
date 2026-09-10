// IR-171 - Run / RunOnce Registry Additions
// Purpose: Identify reg.exe additions to common autostart locations.
// MITRE ATT&CK: T1547.001
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/add.*\\(Run|RunOnce)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)