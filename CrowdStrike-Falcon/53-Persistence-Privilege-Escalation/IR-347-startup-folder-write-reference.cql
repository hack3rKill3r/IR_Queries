// IR-347 - Startup Folder Persistence References
// Purpose: Identify command lines copying/writing payloads into Startup directories.
// MITRE ATT&CK: T1547.001
#event_simpleName=ProcessRollup2
CommandLine=/(Start Menu\\Programs\\Startup|shell:startup)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)